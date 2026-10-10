# AtomICS — OT/ICS Recon & Assessment Console

`atomics.py` v0.1 · Python 3.8+ · standard library core (scapy / pymodbus / python-snap7 / pysnmp optional) · Windows-first, Linux too

AtomICS is a single-file, menu-driven console for walking onto an unfamiliar
control-system segment and answering three questions without hurting anything:
*what is on this network, what does each device say about itself, and what is it
serving?* It rolls host discovery and six OT/ICS protocol modules into one tool,
and keeps a running asset inventory as you go.

It is a recon and assessment tool, not an exploitation framework. There are no
payloads, no DoS modules, and no credential attacks. The only operations that
change device state are a handful of clearly labelled Modbus writes, and those
are locked off until you deliberately unlock them.

> *(formerly **OT RUNG** — Recon Utility for Networked Gear; originally the
> "Modbus Swiss Army Knife". v0.1 is the AtomICS rebrand of OT RUNG v3.4 — same
> protocols, same menus, same flags.)*

## ⚠️ Disclaimer

For training/education or **AUTHORIZED** assessment only, on systems you own or
are explicitly permitted to test. AtomICS speaks live OT/ICS protocols and
**must not** be used in production or on any network where safety and/or
operational availability cannot be guaranteed. Legacy controllers fault from
things IT gear shrugs off — assume the worst device on the segment. You are
solely responsible for how this tool is used. The disclaimer is printed in the
module docstring, the `--help` epilog, and the startup banner.

## Quick start

```
python atomics.py                      # SAFE MODE — reads, scans and polls only
python atomics.py 10.10.5.21           # same, pre-filling that IP as each module's default
python atomics.py --active             # unlock Modbus writes + active (transmitting) scans
python atomics.py --readonly           # hard-pin read-only (overrides --active)
python atomics.py --log                # also append a session log (atomics_log_<ts>.log)
python atomics.py --update-oui         # fetch a MAC-vendor database beside the script, then exit
```

No install step. `python atomics.py` runs from a USB stick on a jump box with no
internet. The core menu works on the standard library alone; the optional
packages below only unlock specific modules, and AtomICS tells you which are
missing at startup instead of crashing.

## Safe mode (the default)

AtomICS launches **read-only**. Two classes of operation are gated behind
`--active`:

* **Writes** — the Modbus write/flip/zero/fuzz/hold operations.
* **Active scans that transmit** — ARP, ICMP and the SYN scans put packets on
  the wire, so they are gated too. In the menu they show `[LOCKED - safe mode]`
  and refuse to run without `--active`.

Everything that is receive-only or a normal read stays available in safe mode:
the two passive listeners, and every protocol poll (Modbus reads, S7 CPU info,
DNP3 polls, and so on).

| Flag | Effect |
|---|---|
| *(none)* | Safe mode. Writes and active scans blocked. |
| `--active` | Operator opt-in. Writes execute **immediately** — no per-write prompt — and each one prints and logs a `[write] <target>=<value>` audit line. Active scans run. |
| `--readonly` | Hard override. Writes stay blocked even alongside `--active`, so a wrapper script or shell alias can pin a jump box read-only and no later argument can quietly undo it. |

The startup banner states the mode in plain language every time, so you always
know whether the session can change device state.

## The menu

```
1. Network Discovery
2. Protocol Modules (Modbus, S7, EtherNet/IP, DNP3, BACnet, SNMP)
3. Asset Register (N host(s), M open port(s))
4. Exit
```

Each module is loaded on demand and guards its own optional dependency, so a
missing package disables only that one module — the rest of the tool keeps
working.

### 1 · Network Discovery

Split into a passive section (transmits nothing) and an active section (puts
packets on the wire, gated by safe mode):

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
* **Promiscuous listen** is a raw layer-2 capture (scapy, Linux `AF_PACKET`, or
  Windows `SIO_RCVALL`) that additionally pulls source IP + MAC from unicast
  IT/OT traffic. Needs admin. *Note:* a plain switch port only delivers this
  host's own traffic plus broadcast/multicast, so seeing other hosts' unicast
  needs a hub or a SPAN/mirror port.
* **ARP / ICMP / SYN scans** take a single IP or a CIDR subnet (the ARP scan
  auto-targets the detected local subnet). With scapy + privileges they use true
  layer-2 ARP and half-open SYN; without them AtomICS falls back to a threaded
  TCP-connect scan and the system ping, so scanning still works unprivileged. A
  fat CIDR warns before expanding past 512 hosts.

The SYN "OT ports" list covers the usual suspects — S7comm/102, Modbus/502,
Niagara Fox/1911, EtherNet-IP/44818 & 2222, DNP3/20000, BACnet/47808, IEC 104/2404,
OPC UA/4840, PROFINET RT, MELSEC, OMRON FINS, GE SRTP, and more.

### 2 · Protocol Modules

```
1. Modbus        2. S7 (Siemens)        3. EtherNet/IP (CIP)
4. DNP3          5. BACnet              6. SNMP
```

| Module | Transport | What it does | Dependency |
|---|---|---|---|
| **Modbus** | TCP/502 | Read coils/registers, scan for coils & registers (smart block scan within spec limits), Read Device Identity (FC 43), recon overview. **Write** coil/register, flip, zero, fuzz, hold — all safe-mode-locked. | `pymodbus` |
| **S7comm** | TCP/102 | CPU info (module type, serial, AS name), order code / firmware, CPU state (RUN/STOP), protection level, block inventory (OB/FB/FC/DB counts), read a DB, read I/Q/M areas, recon overview. | `python-snap7` + native snap7 lib |
| **EtherNet/IP (CIP)** | TCP/UDP 44818 | ListIdentity (vendor / device type / product code / revision / serial / product name / state), ListServices, ListInterfaces, a RegisterSession handshake that confirms explicit messaging and closes itself, and UDP ListIdentity broadcast discovery (the EtherNet/IP analogue of BACnet Who-Is). Read-only — no CIP writes, Forward_Open, or attribute Sets. | pure stdlib |
| **DNP3** | TCP/20000 | Request link status (confirm outstation), integrity poll (Class 1/2/3/0), Class 0 poll (static data), read a specific object group/variation. Decodes IIN flags. | pure stdlib |
| **BACnet/IP** | UDP/47808 | Who-Is broadcast discovery, Who-Is to a specific IP/subnet-broadcast, ReadProperty for device name / vendor / model / firmware. | pure stdlib |
| **SNMP** | UDP/161 | Quick-recon summary (sysDescr, enterprise, engine time — a Shodan-style banner), full MIB dump to screen, limited walk, single-OID get, change community/version. | `pysnmp` (7.x) |

Only Modbus exposes writes, and each one is locked in safe mode. The other five
modules are read-only by nature.

### 3 · Asset Register

A shared, **session-lived, in-memory** inventory keyed by IP that *every* module
feeds automatically:

* Network Discovery contributes IPs, MACs, vendors and open ports.
* The passive listeners fold in whatever they overhear.
* The protocol modules contribute the service each host speaks plus a
  version/identity line — Modbus FC 43, S7 CPU info + order code/firmware, SNMP
  sysDescr, BACnet Who-Is/ReadProperty, DNP3 outstation confirmation, EtherNet/IP
  ListIdentity.

View it, clear it, or export to **CSV / JSON** from its submenu. Nothing touches
disk until you export. The menu line carries a live host/open-port count, e.g.
`3. Asset Register (12 host(s), 47 open port(s))`.

## MAC vendor resolution (OUI)

Everywhere a MAC is shown, AtomICS appends the vendor —
`aa:bb:cc:dd:ee:ff (Rockwell Automation)`. Lookup is **longest-prefix** across
three IEEE tiers: MA-S / IAB (/36), then MA-M (/28), then MA-L (/24), so the
~45% of /24 ranges the registry subdivides resolve to the right registrant
instead of a guess. Randomized / locally-administered MACs are flagged as such
and never resolve (correctly).

Vendor names come **only** from a loaded OUI file — there is no hardcoded list.
AtomICS looks for one at `$ATOMICS_OUI_FILE` (legacy `$RUNG_OUI_FILE` still
honored), then for `oui.csv`, `oui.txt`, `manuf`, `mac-vendors-export.csv` or
`maclookup.csv` beside the script or in the cwd (and one level of subfolders /
up to two parents). It parses the IEEE `oui.csv`/`oui.txt`, Wireshark `manuf`,
and maclookup.app CSV formats.

Run **`python atomics.py --update-oui`** once on a machine with internet to
download a full database (~35k+ vendors) beside the script — it tries
maclookup.app, then IEEE, then Wireshark mirrors, keeping the first that returns
a real database, so one blocked source doesn't defeat it. Until a database is
loaded, globally-administered MACs show `(unknown vendor)` and a post-scan hint
points you at `--update-oui`.

## Options

```
positional:
  ip                 Optional target IP; used as the default for the chosen module

  --active           Enable writes + active (transmitting) scans. Writes run
                     immediately in this mode, each logged as a [write] line.
  --readonly         Hard override — writes stay blocked even with --active
  --log              Append a session log (atomics_log_<timestamp>.log beside the script)
  --update-oui       Download a MAC-vendor database beside the script, then exit
  -h, --help         Full help, with the disclaimer as its epilog
```

## Dependencies

The core tool and the DNP3, BACnet and EtherNet/IP modules are pure standard
library. The rest are optional and each degrades gracefully:

| Package | Unlocks | Without it |
|---|---|---|
| `scapy` (+ Npcap on Windows, root/admin on Linux) | True layer-2 ARP / ICMP / SYN scans, promiscuous capture | Falls back to threaded TCP-connect scan + system ping; promiscuous listen uses the OS raw-socket path |
| `pymodbus` (3.7+) | Modbus module | Modbus menu reports the package is missing; rest of tool unaffected |
| `python-snap7` (+ native snap7 shared library) | S7comm module | S7 menu reports the package is missing |
| `pysnmp` (7.x, needs Python 3.9+) | SNMP module | SNMP menu reports the package is missing |

```
python -m pip install scapy pymodbus python-snap7 pysnmp
```

## Testing

Point AtomICS at the simulators rather than live gear. The portfolio's
simulated controllers answer real protocol traffic on their real ports:

* `plc_sim.py` — conveyor-line PLC (Modbus/TCP)
* `s7_bottling_sim.py` — Siemens S7 (S7comm/TCP 102)
* `enip_palletizer_sim.py` — Allen-Bradley CompactLogix (EtherNet/IP CIP)
* `dnp3_substation_sim.py` — distribution-substation RTU (DNP3/TCP 20000)
* `MOTH` (`moth.py`) — Modbus honeypot, to confirm your reads/writes land and alert

A typical dry run: start a simulator, launch `python atomics.py` in safe mode,
open the matching Protocol Module, and confirm the identity/recon reads come
back and the host lands in the Asset Register. Add `--active` only when you
intend to exercise a write against a simulator or honeypot.

---

*Vibe-coded by Mike Holcomb · [LinkedIn](https://www.linkedin.com/in/mikeholcomb) · [mikeholcomb.com](https://mikeholcomb.com)*
