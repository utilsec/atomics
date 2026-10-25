# AtomICS — OT/ICS Recon & Assessment Console

`atomics.py` v0.4.0 (Python) · `AtomICS.ps1` v1.1 (PowerShell, no-install) · Windows-first, Linux too

AtomICS is a single-file, menu-driven console for walking onto an unfamiliar
control-system segment and answering three questions without hurting anything:
*what is on this network, what does each device say about itself, and what is it
serving?* It rolls host discovery, a one-shot auto-fingerprint, and seven OT/ICS
protocol modules into one tool, and keeps a running asset inventory as you go.

It is a recon and assessment tool, not an exploitation framework. There are no
payloads, no DoS modules, and no credential attacks. It *can* change device
state — Modbus writes, the S7 DB/M/Q writes and STOP/START, and the IEC 104
control commands — but every one of those is clearly labelled and locked off
until you deliberately unlock them (`--active` / `-Active`).

> *(formerly **OT RUNG** — Recon Utility for Networked Gear; originally the
> "Modbus Swiss Army Knife". AtomICS began as the rebrand of OT RUNG v3.4 —
> same protocols, menus, and flags — and has grown from there. The PowerShell
> edition was briefly shipped as **SPRUNG**.)*

## Two editions, one tool

AtomICS ships in two editions that share the same name, menus, modes, and flags
— told apart only by file extension:

| Edition | File | Runtime | Use it when |
|---|---|---|---|
| **Python** | `atomics.py` | Python 3.8+ (stdlib core; a few optional packages) | Your laptop or assessment box, or anywhere you can run Python. Full feature set, including promiscuous layer-2 capture with scapy/Npcap. |
| **PowerShell** | `AtomICS.ps1` | Windows PowerShell 2.0+ — **nothing installed** | A locked-down plant jump box or engineering workstation with no Python, no pip, no Npcap, no modules. Runs on what ships in the box back to Windows 7 / Server 2008 R2. |

The PowerShell edition tracks the Python tool feature-for-feature as far as a
pure, in-box PowerShell can: it speaks all seven protocols directly on the wire
with raw sockets (no snap7, no pysnmp, no third-party stack). The one thing it
cannot do is promiscuous layer-2 capture — that needs a capture driver (Npcap),
which would break "install nothing." Everything else is here.

## ⚠️ Disclaimer

For training/education or **AUTHORIZED** assessment only, on systems you own or
are explicitly permitted to test. AtomICS speaks live OT/ICS protocols and
**must not** be used in production or on any network where safety and/or
operational availability cannot be guaranteed. Legacy controllers fault from
things IT gear shrugs off — assume the worst device on the segment. You are
solely responsible for how this tool is used. The disclaimer is printed in the
module docstring / header, the help screen, and the startup banner of both
editions.

## Quick start

**Python**

```
python atomics.py                      # SAFE MODE — reads, scans and polls only
python atomics.py 10.10.5.21           # same, pre-filling that IP as each module's default
python atomics.py --active             # unlock writes/control + active (transmitting) scans
python atomics.py --readonly           # hard-pin read-only (overrides --active)
python atomics.py --log                # also append a session log (atomics_log_<ts>.log)
python atomics.py --update-oui         # fetch a MAC-vendor database beside the script, then exit
```

**PowerShell** (note: run it with PowerShell, not `python`)

```
.\AtomICS.ps1                                             # SAFE MODE
powershell -ExecutionPolicy Bypass -File .\AtomICS.ps1    # from a shortcut / locked-down box
.\AtomICS.ps1 -Active                                     # unlock writes/control + active scans
.\AtomICS.ps1 -ReadOnly                                   # hard-pin read-only (overrides -Active)
.\AtomICS.ps1 -Log                                        # append a session log
.\AtomICS.ps1 -UpdateOui                                  # fetch a MAC-vendor database, then exit
.\AtomICS.ps1 -Help                                       # help screen
```

No install step, either edition. `atomics.py` runs from a USB stick on a jump
box with no internet (its core menu works on the standard library alone; the
optional packages below only unlock specific modules, and AtomICS tells you
which are missing at startup instead of crashing). `AtomICS.ps1` needs nothing
at all beyond in-box PowerShell.

## Safe mode (the default)

Both editions launch **read-only**. Two classes of operation are gated behind
`--active` (Python) / `-Active` (PowerShell):

* **Writes and state-changing control** — the Modbus write/flip/zero/fuzz/hold
  operations; the S7 DB/M/Q writes and STOP/START CPU; and the IEC 104 control
  commands (C_SC/C_DC/C_SE). All show `[LOCKED - safe mode]` until unlocked.
* **Active scans that transmit** — ARP / ICMP / SYN (Python); ICMP sweep and the
  TCP-connect scan (PowerShell). They put packets on the wire, so they are gated
  too.

Everything that is receive-only or a normal read stays available in safe mode:
the passive listener(s), the read-only auto-fingerprint, and every protocol poll
(Modbus reads, S7 CPU info, DNP3 polls, IEC 104 interrogation, and so on).

| Flag | Effect |
|---|---|
| *(none)* | Safe mode. Writes/control and active scans blocked. |
| `--active` / `-Active` | Operator opt-in. Writes execute **immediately** — no per-write prompt — and each one prints and logs a `[write] <target>=<value>` audit line. Active scans run. The one exception is the S7 **STOP CPU**, which still asks you to type the target IP, because its blast radius is the whole process. |
| `--readonly` / `-ReadOnly` | Hard override. Writes stay blocked even alongside the active flag, so a wrapper script or shell alias can pin a jump box read-only and no later argument can quietly undo it. |

The startup banner states the mode in plain language every time, so you always
know whether the session can change device state.

## The menu

Identical in both editions:

```
1. Network Discovery
2. Protocol Modules (Modbus, S7, EtherNet/IP, DNP3, BACnet, SNMP, IEC 60870-5-104)
3. Auto-Fingerprint (read-only)
4. Asset Register (N host(s), M open port(s))
5. Help
6. Exit
```

In the Python edition each module is loaded on demand and guards its own optional
dependency, so a missing package disables only that one module — the rest of the
tool keeps working. The PowerShell edition has no dependencies to miss.

### 1 · Network Discovery

A passive section (transmits nothing, available in safe mode) and an active
section (puts packets on the wire, gated by safe mode).

**Python**

```
1. Broadcast/multicast listen - no admin   (IP + hostnames: DHCP/mDNS/LLMNR/NBNS/SSDP)
2. Promiscuous listen - all traffic, needs admin   (adds MAC + unicast IT/OT)
3. ARP scan (layer 2, auto local subnet)        [LOCKED in safe mode]
4. ICMP scan (ping sweep)                        [LOCKED in safe mode]
5. SYN scan - single port                        [LOCKED in safe mode]
6. SYN scan - common IT ports                    [LOCKED in safe mode]
7. SYN scan - common OT ports                    [LOCKED in safe mode]
8. SYN scan - common IT + OT ports               [LOCKED in safe mode]
9. Back to main menu
```

* **Broadcast/multicast listen** binds unprivileged UDP sockets to the discovery
  ports (mDNS, LLMNR, SSDP, WS-Discovery, NBNS, DHCP) and joins the multicast
  groups. It harvests IP addresses and hostnames with **no root/Administrator and
  no Npcap**; DHCP also yields the client MAC, and the rest are filled in from the
  local ARP cache. (Joining a multicast group emits standard IGMP membership
  reports — ordinary host traffic, not a scan.)
* **Promiscuous listen** (Python only) is a raw layer-2 capture (scapy, Linux
  `AF_PACKET`, or Windows `SIO_RCVALL`) that additionally pulls source IP + MAC
  from unicast IT/OT traffic. Needs admin. *Note:* a plain switch port only
  delivers this host's own traffic plus broadcast/multicast, so seeing other
  hosts' unicast needs a hub or a SPAN/mirror port.
* **ARP / ICMP / SYN scans** take a single IP or a CIDR subnet (the ARP scan
  auto-targets the detected local subnet). With scapy + privileges they use true
  layer-2 ARP and half-open SYN; without them AtomICS falls back to a threaded
  TCP-connect scan and the system ping, so scanning still works unprivileged. A
  fat CIDR warns before expanding past 512 hosts.

**PowerShell** — same shape, within what in-box PowerShell can do:

* Local interface enumeration (WMI) and an **ARP cache read** (sends nothing,
  safe-mode available).
* The same **no-admin broadcast/multicast passive listener** (.NET UDP sockets:
  DHCP / mDNS / LLMNR / NBNS / SSDP / WS-Discovery; MACs filled from the ARP
  cache).
* An **ICMP sweep** and a **TCP-connect port scan** over the IT/OT port lists
  (both active, gated by safe mode).
* No promiscuous capture (needs Npcap) — use the Python edition for that.

The SYN/connect "OT ports" list covers the usual suspects — S7comm/102,
Modbus/502, Niagara Fox/1911, EtherNet-IP/44818 & 2222, DNP3/20000, BACnet/47808,
IEC 104/2404, OPC UA/4840, PROFINET RT, MELSEC, OMRON FINS, GE SRTP, and more.

### 2 · Protocol Modules

```
1. Modbus        2. S7 (Siemens)        3. EtherNet/IP (CIP)
4. DNP3          5. BACnet              6. SNMP
7. IEC 60870-5-104
```

| Module | Transport | What it does | Python dependency |
|---|---|---|---|
| **Modbus** | TCP/502 | Read coils/registers, scan for coils & registers (smart block scan within spec limits), Read Device Identity (FC 43), recon overview. **Write** coil/register, flip, zero, fuzz, hold — all safe-mode-locked. | `pymodbus` |
| **S7comm** | TCP/102 | **Read:** CPU info (module type, serial, AS name), order code / firmware, CPU state (RUN/STOP), protection level, block inventory, read a DB, read I/Q/M areas, recon overview. **Write (safe-mode-locked):** write a DB (byte/word/dword/int/real/bit), write M (flags) / Q (outputs), STOP CPU, START CPU. | `python-snap7` + native snap7 lib |
| **EtherNet/IP (CIP)** | TCP/UDP 44818 | ListIdentity (vendor / device type / product code / revision / serial / product name / state), ListServices, ListInterfaces, a RegisterSession handshake that confirms explicit messaging and closes itself, and UDP ListIdentity broadcast discovery (the EtherNet/IP analogue of BACnet Who-Is). Read-only — no CIP writes, Forward_Open, or attribute Sets. | pure stdlib |
| **DNP3** | TCP/20000 | Request link status (confirm outstation), integrity poll (Class 1/2/3/0), Class 0 poll (static data), read a specific object group/variation. Decodes IIN flags. | pure stdlib |
| **BACnet/IP** | UDP/47808 | Who-Is broadcast discovery, Who-Is to a specific IP/subnet-broadcast, ReadProperty for device name / vendor / model / firmware. | pure stdlib |
| **SNMP** | UDP/161 | Quick-recon summary (sysDescr, enterprise, engine time — a Shodan-style banner), full MIB dump to screen, limited walk, single-OID get, change community/version. | `pysnmp` (7.x) |
| **IEC 60870-5-104** | TCP/2404 | **Read:** STARTDT, general interrogation + counter interrogation, decode of the common monitored types (single/double point, normalized/scaled/float measured, counters). **Control (safe-mode-locked):** single command C_SC, double command C_DC, setpoints C_SE_NB/NC — each with Select-Before-Operate or direct-operate. | pure stdlib |

Modbus, S7 and IEC 104 can change device state; EtherNet/IP, DNP3, BACnet and
SNMP are read-only by nature. Every write and every control command is locked in
safe mode and runs only under `--active` / `-Active`.

**In the PowerShell edition all seven modules are spoken with raw
`System.Net.Sockets` directly** — there is no `pymodbus`, `python-snap7` or
`pysnmp` to install. S7comm, SNMP (v1/v2c), DNP3, BACnet and IEC 104 are built
and parsed as raw bytes in-box.

### 3 · Auto-Fingerprint

Point it at a single IP and it does the per-protocol legwork for you: a gentle
one-connection-at-a-time scan of the OT service ports (Modbus/502, S7/102,
EtherNet-IP/44818, DNP3/20000, IEC 104/2404) plus a direct probe of SNMP/161 and
BACnet/47808, then it runs each matching module's **read-only** recon against
whatever answered and folds the whole lot into the Asset Register in one pass.
It never writes or sends a control command in any mode, so it stays available in
safe mode. Six manual module selections become "point it at the box." A target
that is neither a valid IP nor a resolvable hostname is rejected up front.

As of **v0.4.0** the fingerprint **uses** the SNMP response rather than just
noting that 161 answered: when the default community replies it reads the system
group and folds the identity straight into the Asset Register — `sysName` →
hostname, `sysObjectID` enterprise number → vendor (via a verified OT
private-enterprise-number map: Siemens 4329, Schneider 3833, Hirschmann 248,
plus the common IT vendors), and `sysDescr` (vendor / model / order code /
firmware) → the versions column. The open default community is itself flagged as
a finding. It reuses the fields the SNMP summary already collected, so this costs
no extra queries and the probe stays strictly read-only.

### 4 · Asset Register

A shared, **session-lived, in-memory** inventory keyed by IP that *every* module
feeds automatically:

* Network Discovery contributes IPs, MACs, vendors and open ports.
* The passive listener(s) fold in whatever they overhear.
* Auto-fingerprint folds in everything it finds in its one-shot pass.
* The protocol modules contribute the service each host speaks plus a
  version/identity line — Modbus FC 43, S7 CPU info + order code/firmware, SNMP
  sysDescr, BACnet Who-Is/ReadProperty, DNP3 outstation confirmation, EtherNet/IP
  ListIdentity, and IEC 104 point counts.

View it, clear it, or export to **CSV / JSON** from its submenu. Nothing touches
disk until you export. The menu line carries a live host/open-port count, e.g.
`4. Asset Register (12 host(s), 47 open port(s))`.

**Export filenames are kept distinct per edition** so a shared field-kit folder
stays unambiguous: the Python tool writes `atomics_*` (e.g. `atomics_assets_*`,
`atomics_passive_*`, `atomics_snmp_*`, `atomics_log_*`); the PowerShell edition
writes `atomics_ps_*` (e.g. `atomics_ps_assets_*`).

## MAC vendor resolution (OUI)

Everywhere a MAC is shown, AtomICS appends the vendor —
`aa:bb:cc:dd:ee:ff (Rockwell Automation)`. Lookup is **longest-prefix** across
three IEEE tiers: MA-S / IAB (/36), then MA-M (/28), then MA-L (/24), so the
~45% of /24 ranges the registry subdivides resolve to the right registrant
instead of a guess. Randomized / locally-administered MACs are flagged as such
and never resolve (correctly).

Vendor names come **only** from a loaded OUI file — there is no hardcoded list.
AtomICS looks for one at `$ATOMICS_OUI_FILE` / `$env:ATOMICS_OUI_FILE` (legacy
`$RUNG_OUI_FILE` / `$env:SPRUNG_OUI_FILE` still honored), then for `oui.csv`,
`oui.txt`, `manuf`, `mac-vendors-export.csv` or `maclookup.csv` beside the script
or in the cwd (and one level of subfolders / up to two parents). It parses the
IEEE `oui.csv`/`oui.txt`, Wireshark `manuf`, and maclookup.app CSV formats. Both
editions share the same env var and the same three-tier matching.

Run **`--update-oui`** / **`-UpdateOui`** once on a machine with internet to
download a full database (~35k+ vendors) beside the script — it tries
maclookup.app, then IEEE, then Wireshark mirrors, keeping the first that returns
a real database, so one blocked source doesn't defeat it. Until a database is
loaded, globally-administered MACs show `(unknown vendor)` and a post-scan hint
points you at the updater.

## Options

**Python** (`atomics.py`)

```
positional:
  ip                 Optional target IP; used as the default for the chosen module

  --active           Enable writes/control + active (transmitting) scans. Writes
                     run immediately in this mode, each logged as a [write] line.
  --readonly         Hard override — writes stay blocked even with --active
  --log              Append a session log (atomics_log_<timestamp>.log beside the script)
  --update-oui       Download a MAC-vendor database beside the script, then exit
  -h, --help         Full help, with the disclaimer as its epilog
```

**PowerShell** (`AtomICS.ps1`)

```
  -Active            Enable writes/control + active (transmitting) scans
  -ReadOnly          Hard override — writes stay blocked even with -Active
  -Log               Append a session log (atomics_ps_log_<timestamp>.log)
  -UpdateOui         Download a MAC-vendor database beside the script, then exit
  -Help              Help screen (menus, modes and flags)
```

## Dependencies

**Python.** The core tool and the DNP3, BACnet and EtherNet/IP modules are pure
standard library. The rest are optional and each degrades gracefully:

| Package | Unlocks | Without it |
|---|---|---|
| `scapy` (+ Npcap on Windows, root/admin on Linux) | True layer-2 ARP / ICMP / SYN scans, promiscuous capture | Falls back to threaded TCP-connect scan + system ping; promiscuous listen uses the OS raw-socket path |
| `pymodbus` (3.7+) | Modbus module | Modbus menu reports the package is missing; rest of tool unaffected |
| `python-snap7` (+ native snap7 shared library) | S7comm module | S7 menu reports the package is missing |
| `pysnmp` (7.x, needs Python 3.9+) | SNMP module | SNMP menu reports the package is missing |

```
python -m pip install scapy pymodbus python-snap7 pysnmp
```

**PowerShell.** None. `AtomICS.ps1` uses only in-box Windows PowerShell 2.0+ and
`System.Net.Sockets`. That is the whole point of the edition: drop the one file
on a locked-down host and run it.

## Testing

Point AtomICS at the simulators rather than live gear. The portfolio's
simulated controllers answer real protocol traffic on their real ports:

* `plc_sim.py` — conveyor-line PLC (Modbus/TCP)
* `s7_bottling_sim.py` — Siemens S7 (S7comm/TCP 102)
* `enip_palletizer_sim.py` — Allen-Bradley CompactLogix (EtherNet/IP CIP)
* `dnp3_substation_sim.py` — distribution-substation RTU (DNP3/TCP 20000)
* `MOTH` (`moth.py`) — Modbus honeypot, to confirm your reads/writes land and alert

A typical dry run: start a simulator, launch AtomICS in safe mode, open the
matching Protocol Module (or run **Auto-Fingerprint** for a one-shot pass), and
confirm the identity/recon reads come back and the host lands in the Asset
Register. Add the active flag only when you intend to exercise a write against a
simulator or honeypot.

**Write/control testing.** The S7 writes and STOP/START are testable against
`s7_bottling_sim.py`. The IEC 104 module has **no simulator in the portfolio
yet** — exercise its interrogation and C_SC/C_DC/C_SE commands against a lab IEC
104 outstation or an open-source simulator (e.g. lib60870's example server) until
an AtomICS IEC 104 outstation sim is added. The Python IEC 104 framing, ASDU
build/parse, and command/ActCon flow are covered offline by `test_iec104.py`.

**PowerShell edition.** Because it speaks every protocol as raw bytes, test it
against the same simulators (the sims answer the exact byte formats the PS
modules build). Its Modbus, S7comm, EtherNet/IP and DNP3 paths have been
round-trip validated; BACnet, SNMP and IEC 104 should be confirmed against the
sims / a lab outstation before relying on them in the field.

---

*Vibe-coded by Mike Holcomb · [LinkedIn](https://www.linkedin.com/in/mikeholcomb) · [mikeholcomb.com](https://mikeholcomb.com)*
