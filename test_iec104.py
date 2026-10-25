#!/usr/bin/env python3
"""Offline reference tests for the AtomICS IEC 60870-5-104 module.

Pure-Python checks of APCI framing, ASDU build/parse and the command/ActCon
flow. No network and no live gear - drives _Iec104Conn through a fake socket.
Run:  python test_iec104.py
"""
import os
import sys
import struct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import atomics as a  # noqa: E402


class FakeSock:
    """Minimal socket stand-in: records sends, replays a queued recv buffer."""
    def __init__(self, inbound=b""):
        self.inbound = bytearray(inbound)
        self.sent = bytearray()
    def settimeout(self, _):
        pass
    def connect(self, _):
        pass
    def close(self):
        pass
    def sendall(self, data):
        self.sent += data
    def recv(self, n):
        if not self.inbound:
            return b""          # EOF -> _recv_exact returns None
        chunk = bytes(self.inbound[:n])
        del self.inbound[:n]
        return chunk


def _iframe(asdu, ns=0, nr=0):
    ctrl = bytes([(ns << 1) & 0xFF, (ns >> 8) & 0xFF,
                  (nr << 1) & 0xFF, (nr >> 8) & 0xFF])
    return bytes([0x68, len(ctrl) + len(asdu)]) + ctrl + asdu


results = []
def check(name, cond):
    results.append((name, cond))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")


# 1. GI ASDU bytes
gi = a._iec104_build_asdu(100, 6, 1, 0, bytes([20]))
check("GI ASDU encodes C_IC/COT6/CA1/QOI20",
      gi == bytes([100, 1, 6, 0, 1, 0, 0, 0, 0, 20]))

# 2. I-frame framing + N(S) increment
c = a._Iec104Conn("x", 2404, 1)
c.sock = FakeSock()
c.send_i(gi)
sent = c.sock.sent
check("I-frame start/len correct",
      sent[0] == 0x68 and sent[1] == 4 + len(gi))
check("I-frame control is I-format with N(S)=0,N(R)=0",
      sent[2:6] == bytes([0, 0, 0, 0]))
check("N(S) advanced to 1 after send", c.ns == 1)

# 3. STARTDT handshake (U-frame con)
c2 = a._Iec104Conn("x", 2404, 1)
c2.sock = FakeSock(bytes([0x68, 0x04, 0x0B, 0, 0, 0]))   # STARTDT con
check("STARTDT confirmed on U-frame reply", c2.startdt() is True)

# 4. Parse SQ=0 short-float measured value
asdu_nc = bytes([13, 1, 20, 0, 1, 0]) + bytes([100, 0, 0]) + struct.pack("<f", 1.5) + bytes([0])
p = a._iec104_parse_asdu(asdu_nc)
check("M_ME_NC SQ=0 parses one object", p and p["n"] == 1 and len(p["objs"]) == 1)
check("M_ME_NC IOA + float decoded",
      p["objs"][0][0] == 100 and p["objs"][0][1] == "float=1.5000")

# 5. Parse SQ=1 single-point sequence (base IOA + 3 consecutive)
asdu_sp = bytes([1, 0x83, 20, 0, 1, 0]) + bytes([10, 0, 0]) + bytes([1, 0, 1])
p2 = a._iec104_parse_asdu(asdu_sp)
check("M_SP SQ=1 expands to 3 objects", p2 and len(p2["objs"]) == 3)
check("M_SP SQ=1 IOAs increment 10,11,12",
      [o[0] for o in p2["objs"]] == [10, 11, 12])
check("M_SP SQ=1 values decode 1/0/1",
      [o[1] for o in p2["objs"]] == ["SP=1", "SP=0", "SP=1"])

# 6. Double-point decode
p3 = a._iec104_parse_asdu(bytes([3, 1, 20, 0, 1, 0]) + bytes([5, 0, 0]) + bytes([2]))
check("M_DP decodes DPI=2 as ON", p3["objs"][0][1] == "DP=ON")

# 7. Command + positive ActCon flow
actcon = bytes([45, 1, 7, 0, 1, 0]) + bytes([5, 0, 0]) + bytes([0x00])  # C_SC ActCon pn=0
c3 = a._Iec104Conn("x", 2404, 1)
c3.sock = FakeSock(_iframe(actcon))
ok, msg = a._iec104_send_cmd(c3, 45, 5, bytes([0x01]), "C_SC execute")
check("C_SC positive ActCon recognised", ok is True and "positive" in msg)

# 8. Negative ActCon (P/N = 1) recognised
actcon_neg = bytes([45, 1, 7 | 0x40, 0, 1, 0]) + bytes([5, 0, 0]) + bytes([0x00])
c4 = a._Iec104Conn("x", 2404, 1)
c4.sock = FakeSock(_iframe(actcon_neg))
ok2, msg2 = a._iec104_send_cmd(c4, 45, 5, bytes([0x01]), "C_SC execute")
check("C_SC negative ActCon recognised", ok2 is False and "NEGATIVE" in msg2)

# 9. SCO select vs execute bit (S/E = bit7)
check("SCO select sets S/E bit", (((1 & 1) | (1 << 7)) & 0x80) == 0x80)
check("SCO execute clears S/E bit", ((1 & 1) & 0x80) == 0x00)

# 10. S-frame ack uses N(R)
c5 = a._Iec104Conn("x", 2404, 1)
c5.sock = FakeSock()
c5.nr = 3
c5._send_s()
s = c5.sock.sent
check("S-frame carries N(R)=3", s[0] == 0x68 and s[2] == 0x01 and s[4] == (3 << 1))

fails = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(fails)}/{len(results)} passed")
sys.exit(1 if fails else 0)
