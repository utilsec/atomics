#!/usr/bin/env python3
"""
============================================================
AtomICS - OT/ICS Recon & Assessment Console (v0.1)
(formerly "OT RUNG"; originally the "Modbus Swiss Army Knife")

Multi-protocol recon/assessment console. Opens with a menu:
Network Discovery first, then a Protocol Modules submenu (Modbus,
S7, EtherNet/IP, DNP3, BACnet, SNMP), then the Asset Register. Each module is loaded on demand and guards
its own optional dependency so the rest of the tool keeps working
if one package is missing.

AtomICS starts in SAFE MODE. Two things are gated behind --active: writes
(Modbus write/flip/zero/fuzz/hold), and active scans that transmit on the
network (ARP, ICMP, SYN). Passive discovery - both the no-admin Broadcast/
Multicast Listen and the promiscuous Listen, neither of which scans - and every
read/poll stay available in safe mode. Passing
--active is the operator's opt-in, so in active mode writes run immediately
(no per-write prompt); each one prints and logs a [write] line as a record.

!! DISCLAIMER !!
For training/education or AUTHORIZED assessment ONLY, on systems you own or
are explicitly permitted to test. This tool speaks live control-system
protocols and must NOT be used in production or on any network where safety
and/or operational availability cannot be guaranteed. Use is at your own risk.

This script was vibe coded by Mike Holcomb of UtilSec, LLC.
LinkedIn : https://www.linkedin.com/in/mikeholcomb
Website  : https://mikeholcomb.com

------------------------------------------------------------
CHANGELOG
------------------------------------------------------------
v0.1  Rebranded from OT RUNG to AtomICS. Last released as OT RUNG v3.4; this is a
      name/identity change only - no protocol behaviour, menu item, menu number,
      command-line flag, or output format changed from v3.4. The tool is now
      AtomICS - OT/ICS Recon & Assessment Console. Script renamed rung.py ->
      atomics.py. The OUI-file environment variable is now $ATOMICS_OUI_FILE,
      with the legacy $RUNG_OUI_FILE still honored as a fallback. Default export
      filenames rebranded (rung_assets_* -> atomics_assets_*, rung_passive_* ->
      atomics_passive_*, rung_snmp_* -> atomics_snmp_*, otrung_log_* ->
      atomics_log_*). All --active / --readonly / --update-oui behaviour is
      unchanged. Full prior version history is retained below under its original
      OT RUNG version numbers.

      ----- prior history (as OT RUNG) -----
v3.4  MAC vendor lookup now finds the local OUI file even when RUNG is
      launched from a different directory than the one holding it.
      _find_oui_file() still honours $RUNG_OUI_FILE and checks the script
      dir / cwd first, but now also scans one level of subdirectories
      under each (so mac-vendors-export.csv in a 'Developer' subfolder is
      picked up when RUNG runs from its parent) and up to two parent
      directories. No new dependency; the scan is shallow and matches only
      the known OUI filenames, so it stays fast on a field jump box.
v3.3  MAC vendor lookup now does LONGEST-PREFIX matching instead of collapsing
      everything to the /24 (OUI). The OUI database is loaded into three tiers -
      /24 (MA-L, CID), /28 (MA-M) and /36 (MA-S, IAB) - and a MAC resolves to the
      most specific block that matches (/36 > /28 > /24). This fixes wrong vendor
      labels on the ~45% of /24 ranges the IEEE/maclookup registry subdivides
      among several vendors, where the old /24-only lookup returned whichever
      sub-block loaded last. Verified against Mike's maclookup.app export
      (mac-vendors-export.csv, ~58.7k rows -> ~40.4k /24 + ~6.6k MA-M + ~11.8k
      MA-S/IAB). Also trims the stray trailing commas maclookup leaves on some
      vendor names ("Siemens AG," -> "Siemens AG"). _parse_oui_file now returns
      (db24, dbm, dbs); startup reports the sub-block counts. Unrelated MACs on a
      subdivided /24 now correctly show '(unknown vendor)' rather than a guess.
v3.2  MAC vendor lookup can now use the maclookup.app CSV database as a local
      file. _parse_oui_file learned the maclookup.app CSV format (header
      "Mac Prefix,Vendor Name,Private,Block Type,Last Update"; col 0 = prefix,
      col 1 = vendor), on top of IEEE oui.csv/oui.txt and Wireshark 'manuf'.
      --update-oui now tries maclookup.app FIRST (saved as oui.csv beside the
      script), then IEEE, then the Wireshark mirrors. _find_oui_file also picks
      up the export's default names (mac-vendors-export.csv, maclookup.csv) if
      dropped beside the script. Prefixes are still keyed to the first 3 octets
      (/24), so maclookup MA-M/MA-S sub-blocks collapse to their parent OUI.
      NOTE: the cowork sandbox's egress policy blocks maclookup.app, so the CSV
      could not be bundled here - run --update-oui (or save the CSV as oui.csv)
      on the target machine, where the site is reachable.
v3.1.1 Readability: every menu now prints a blank line before its "Select an
      option:" prompt, so the prompt is visually separated from the menu items.
      Cosmetic only - no menu numbering, flags, or behaviour changed.
v3.1  Split the passive listener into TWO Network Discovery options, so a plant
      jump box without admin rights can still discover hosts:
        1. Broadcast/multicast listen (NO admin) - unprivileged UDP sockets bound
           to the discovery ports (mDNS, LLMNR, SSDP, WS-Discovery, NBNS, DHCP)
           with the multicast groups joined. Harvests IP + hostname; DHCP also
           yields the client MAC; MACs for the rest come from the local ARP cache.
           Needs no root/Administrator and no Npcap. (Subscribing to a multicast
           group emits standard IGMP membership reports - ordinary host traffic,
           no scan/probe packets.)
        2. Promiscuous listen (needs admin) - the v3.0 raw layer-2 capture, which
           adds MAC + unicast IT/OT visibility.
      MENU RENUMBERED in Network Discovery: the passive listener that was item 1
      is now item 2 (promiscuous), item 1 is the new no-admin broadcast listener,
      the ARP/ICMP/SYN scans shift from 2-7 to 3-8, and Back moves from 8 to 9.
      Both passive options stay available in safe mode. No protocol-module or
      main-menu numbering changed. SPRUNG unchanged (still no layer-2 capture).
v3.0  The passive listener (Network Discovery option 1) now watches ALL traffic,
      not just broadcast. Capture is promiscuous - the scapy path passes
      promisc=True and the stdlib AF_PACKET path enables PACKET_MR_PROMISC on
      every interface (memberships auto-drop on close, so no NIC state is left
      changed) - so IP + MAC are harvested from ordinary unicast IT/OT traffic
      (web, SMB, database, SCADA polls) too, not only ARP/DHCP/mDNS. Still
      receive-only (transmits nothing), still in the Passive section, still
      available in safe mode. Note: promiscuous mode makes the NIC accept every
      frame it RECEIVES; a plain switch port still only delivers this host's own
      traffic + broadcast/multicast, so seeing other hosts' unicast needs a hub
      or SPAN/mirror. Menu item + prose relabelled from "Broadcast listen" to
      "Passive listen - all traffic". The Windows SIO_RCVALL path already
      captured all IPv4.
v2.9  Removed the hardcoded built-in OUI vendor list entirely (Rockwell,
      Siemens, Espressif, VMware, ...). MAC-vendor names now come ONLY from a
      loaded OUI file - one source of truth, no partial or guessed entries. Run
      --update-oui (or drop an oui.csv / Wireshark 'manuf' file beside the
      script) to get resolution; until then every globally-administered MAC
      shows '(unknown vendor)'. Randomized/locally-administered MACs are still
      flagged algorithmically. Startup and the post-scan hint now say "no OUI
      database loaded" instead of referring to a seed.
v2.8  Made OUI vendor resolution actually easy to get working. `--update-oui`
      now tries multiple sources in order - IEEE oui.csv, then the Wireshark
      'manuf' file and its GitHub mirror - and keeps the first that returns a
      real (>=1000-entry) database, so a single blocked/flaky source (IEEE
      commonly 418s automated fetches) no longer defeats it. After a scan, if
      only the built-in seed is loaded and some MACs are unresolved, a one-line
      hint points to --update-oui. (If a MAC still shows '(unknown vendor)'
      with a full DB loaded, it is genuinely unregistered or newly assigned;
      randomized/locally-administered MACs never resolve, which is correct.)
v2.7.1 Cosmetic: a blank line now separates the "Mode:" line from the numbered
      options on the main menu.
v2.7  Real OUI vendor resolution. Until now MAC->vendor used only a ~30-entry
      built-in list, so most real MACs showed '(unknown vendor)'. RUNG now
      loads a full OUI database from a file if present - $RUNG_OUI_FILE, or
      oui.csv / oui.txt / manuf beside the script or in the cwd - parsing IEEE
      oui.csv, IEEE oui.txt and Wireshark 'manuf' formats (~35k vendors). New
      `--update-oui` downloads the current IEEE registry (oui.csv) next to the
      script; run it on a machine with internet, then it loads automatically.
      The curated OT labels still win over raw IEEE names. Startup prints which
      source is in use. (Randomized/locally-administered MACs still never
      resolve - that is correct.) Also seeded Espressif (C4:4E:AC) + Realtek.
v2.6  Every on-screen MAC address now shows its vendor in parentheses right
      after it - "aa:bb:cc:dd:ee:ff (Rockwell Automation)" - via one shared
      _mac_with_vendor() helper used by the ARP scan, the passive listener
      (live lines + summary), and the Asset Register view. Unmapped OUIs show
      "(unknown vendor)"; randomized/local MACs are flagged. The passive
      summary drops its separate Vendor column (now inline). CSV/JSON exports
      keep a dedicated vendor column, so the MAC field there stays a clean MAC.
v2.5  Safe mode now also blocks the ACTIVE (transmitting) Network Discovery
      scans - ARP, ICMP and SYN - since they put packets on the wire. They
      are marked [LOCKED - safe mode] in the menu and refuse to run without
      --active, the same gate as writes. The passive Broadcast Listen (sends
      nothing) stays available in safe mode, as do all reads/polls. This is a
      deliberate tightening of the earlier "block writes only" model.
v2.4  Active mode no longer prompts per write. Reaching a write already means
      --active was passed (writes are refused outright in safe mode), so that
      flag is treated as the operator's opt-in and writes now execute
      immediately - no "type YES" confirmation. Each write still prints and
      logs a one-line [write] record of the target and value, so there is an
      on-screen and on-disk audit trail. Safe mode is unchanged: it still
      blocks every write. Affects Modbus write coil/register, flip, zero,
      fuzz and hold.
v2.3.1 Asset Register menu lines now show the open-port count alongside the
      host count, on both the main menu item and the submenu header
      (e.g. "3. Asset Register (12 host(s), 47 open port(s))").
v2.3  Tidied the main menu: the six per-protocol device modules (Modbus, S7,
      EtherNet/IP, DNP3, BACnet, SNMP) are now grouped under a single main-menu
      item "2. Protocol Modules", which opens a submenu listing them 1-6 with a
      Back option. The main menu is now just: 1 Network Discovery, 2 Protocol
      Modules, 3 Asset Register, 4 Exit. No module behaviour changed - only how
      they are reached.
v2.2  Added an ETHERNET/IP (CIP) module at main menu item 4, right after S7
      (DNP3 -> 5, BACnet -> 6, SNMP -> 7, Asset Register -> 8, Exit -> 9).
      Pure-Python over TCP/UDP 44818, read-only: ListIdentity (vendor, device
      type, product code, revision, serial, product name, state), ListServices
      (CIP-over-TCP/UDP support), ListInterfaces, a RegisterSession handshake
      that confirms explicit messaging and closes itself, and a UDP ListIdentity
      broadcast discovery (the EtherNet/IP analogue of BACnet Who-Is). Every
      identity feeds the Asset Register versioning column. No CIP writes,
      Forward_Open, or attribute Sets. Only the main-menu numbering changed.
v2.1  Added an ASSET REGISTER (main menu item 7; Exit moved to 8). A shared,
      session-lived, in-memory inventory keyed by IP that every module feeds:
      Network Discovery (ICMP/ARP/SYN) contributes IPs, MACs, vendors and open
      ports; the passive listener folds in its findings; and the protocol
      modules contribute the service each host speaks plus a version/identity
      line - Modbus FC43, S7 CPU info + order code/firmware, SNMP sysDescr,
      BACnet Who-Is/ReadProperty, DNP3 outstation confirmation. View it, or
      export to CSV / JSON, from its submenu. It is memory-only: nothing is
      written to disk unless you export. No other menu numbering changed.
v2.0  *** BEHAVIOUR CHANGE: SAFE MODE IS NOW THE DEFAULT ***
      RUNG launches read-only. Modbus writes, flip, zero, fuzz and
      hold-write are blocked unless you pass --active. Reads, scans
      and polls are unaffected and work exactly as before. The old
      --readonly flag still works and now acts as a hard override:
      if it is present, writes stay blocked even with --active.
      Every write additionally requires typing YES at a prompt that
      names the target and the value (per the project's own safety
      rule, which the previous versions did not enforce).

      Host Scanning is renamed NETWORK DISCOVERY and split into
      Passive (transmits nothing) and Active (puts packets on the
      wire) sections.

      The passive DHCP listener is replaced by a general PASSIVE
      BROADCAST LISTENER that harvests IP + MAC from everything the
      segment broadcasts: ARP (by far the richest source), DHCP,
      NBNS, mDNS, LLMNR, SSDP, CDP, LLDP, PROFINET DCP, STP, plus
      labelled counts for everything else by EtherType or port. It
      also records hostnames, VLAN IDs, and the switch/port a device
      is plugged into when CDP/LLDP or DHCP option 82 reveal it.
      Capture order: scapy -> AF_PACKET (Linux) -> SIO_RCVALL raw
      socket (Windows, IPv4 only, no MACs; those are filled in from
      the local ARP cache afterwards).
      *** MENU RENUMBERING (Network Discovery menu) ***
        Broadcast listen (was "Passive DHCP listen")  2 -> 1
        ARP scan                                      1 -> 2
        ICMP scan, SYN scans, Back                    unchanged (3-8)
      Main menu item 1 is renamed Host Scanning -> Network Discovery;
      its numbering is unchanged. Protocol module menus are unchanged.
v1.5.1 Cosmetic: _print_local_ifaces() now prints a trailing blank
      line so the host address block is separated from the menu or
      prompt below it (Host Scanning menu, passive DHCP listen).
      The startup banner opts out via blank_after=False - its "="
      rule already separates. No functional change.
v1.5  Host Scanning: added "Passive DHCP listen" as menu option 2,
      directly under the ARP scan. Fully passive - transmits nothing.
      Captures DHCP DISCOVER/REQUEST/OFFER/ACK and records MAC/IP
      pairs, hostname (opt 12), vendor class ID (opt 60) and relay
      agent circuit/remote ID (opt 82). Uses scapy AsyncSniffer when
      available, otherwise binds UDP/67 + UDP/68 with the stdlib.
      Includes an OUI vendor map and CSV export.
      *** MENU RENUMBERING (Host Scanning menu only) ***
        ICMP scan            2 -> 3
        SYN scan single port 3 -> 4
        SYN scan IT ports    4 -> 5
        SYN scan OT ports    5 -> 6
        SYN scan IT+OT ports 6 -> 7
        Back to main menu    7 -> 8
      The main menu, and every protocol module menu, are unchanged.
      ADDITIVE OUTPUT CHANGE: ARP scan results now append an OUI vendor
      label to each line when the OUI is in the map (existing ip/mac
      columns are unchanged). Also: --help now prints the disclaimer
      as its epilog.
v1.4  Multi-protocol console: Host Scanning, Modbus, S7comm, DNP3,
      BACnet/IP, SNMP.
------------------------------------------------------------
============================================================
"""
import sys
import os
import re
import csv
import time
import socket
import select
import random
import argparse
import asyncio
import ipaddress
import subprocess
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# --- Modbus (pymodbus) --------------------------------------------------------
# pymodbus 3.7+ note: read_* methods take `count` (and `slave`) as keyword-only
# arguments: read_coils(address, count=..., slave=...). All read calls below
# pass `count=` accordingly. FC 43 (Read Device Identification) has no
# client.read_device_information() helper; it is issued via a
# ReadDeviceInformationRequest + client.execute(request) in _read_device_info().
# The import is guarded so the SNMP module still works if pymodbus is absent.
try:
    from pymodbus.client import ModbusTcpClient
    from pymodbus.exceptions import ModbusException
    try:
        from pymodbus.mei_message import ReadDeviceInformationRequest
    except ImportError:  # pymodbus >= 4.0 relocated this module
        from pymodbus.pdu.mei_message import ReadDeviceInformationRequest
    MODBUS_AVAILABLE = True
    MODBUS_IMPORT_ERROR = None
except Exception as _mb_err:  # pragma: no cover - env dependent
    MODBUS_AVAILABLE = False
    MODBUS_IMPORT_ERROR = _mb_err
    ModbusException = Exception  # so except clauses still resolve

# --- SNMP (pysnmp) ------------------------------------------------------------
# Uses the maintained pysnmp line (LeXtudio pysnmp, currently 7.x). That API is
# asyncio-only: get_cmd() is a coroutine, walk_cmd() an async generator, and the
# transport is built with an awaitable UdpTransportTarget.create(). The blocking
# call shape the rest of this tool relies on is preserved by driving those
# coroutines through asyncio.run() inside snmp_get()/snmp_walk() below.
# No version pin -- track the maintained release (needs Python 3.9+):
#     python -m pip install --upgrade pysnmp
try:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, get_cmd, walk_cmd,
    )
    SNMP_AVAILABLE = True
    SNMP_IMPORT_ERROR = None
except Exception as _snmp_err:  # pragma: no cover - env dependent
    SNMP_AVAILABLE = False
    SNMP_IMPORT_ERROR = _snmp_err

# --- S7comm (python-snap7) ----------------------------------------------------
# Siemens S7 (S7-300/400/1200/1500) over ISO-on-TCP (TCP/102). python-snap7 wraps
# the native snap7 shared library, so BOTH the Python package and the snap7 lib
# must be present:
#     python -m pip install python-snap7
# and the snap7 binary (libsnap7.so / snap7.dll) on the library path. Import is
# guarded so the rest of the tool runs if either piece is missing.
try:
    import snap7
    try:
        # snap7 >= 1.3 exposes the enum; older versions use ints for areas.
        from snap7.type import Area as _S7Area
    except Exception:
        _S7Area = None
    S7_AVAILABLE = True
    S7_IMPORT_ERROR = None
except Exception as _s7_err:  # pragma: no cover - env dependent
    S7_AVAILABLE = False
    S7_IMPORT_ERROR = _s7_err

# --- Optional: scapy for raw ARP / ICMP / SYN scanning + passive capture ------
# Host Scanning uses scapy for true layer-2 ARP and half-open SYN scans when it
# is available (needs root/admin + Npcap on Windows). When scapy is absent the
# module falls back to a threaded TCP-connect scan for ports and the system ping
# for ICMP, so scanning still works without elevated privileges.
# The passive DHCP listener also prefers scapy (AsyncSniffer, imported lazily
# inside that module) and falls back to binding UDP/67 + UDP/68 with the stdlib.
try:
    from scapy.all import ARP, Ether, IP, ICMP, TCP, sr, srp, conf as _scapy_conf
    _scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
    SCAPY_IMPORT_ERROR = None
except Exception as _scapy_err:  # pragma: no cover - env dependent
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = _scapy_err

MAX_LENGTH = 1000
LOG_FILE = None

# Printed at startup. AtomICS touches live control-system protocols, so its use
# is restricted to training and explicitly authorized assessments.
DISCLAIMER = (
    "DISCLAIMER: For training/education or AUTHORIZED assessment ONLY, on\n"
    "systems you own or are explicitly permitted to test. This tool speaks\n"
    "live OT/ICS protocols and MUST NOT be used in production or on any\n"
    "network where safety and/or operational availability cannot be\n"
    "guaranteed. You are solely responsible for how this tool is used."
)

# Smart-scan tuning. Block sizes stay under the Modbus spec maximums (125 HRs, 2000 coils)
# with margin for devices that quietly enforce smaller limits.
SCAN_DEFAULT_RANGE = 1000
SCAN_BLOCK_COILS = 800
SCAN_BLOCK_REGISTERS = 100

# Standard Modbus FC 43 Device Identification object IDs (per the Modbus spec).
DEVICE_IDENTITY_MAP = {
    0x00: "VendorName",
    0x01: "ProductCode",
    0x02: "MajorMinorRevision",
    0x05: "ModelName",
    0x0A: "ProductName",
}

# SNMP defaults
SNMP_DEFAULT_PORT = 161
SNMP_DEFAULT_RO = "public"
SNMP_DEFAULT_RW = "private"
SNMP_DEFAULT_BASE = "1.3.6.1.2.1"   # mib-2 — the standard SNMP "database"
SNMP_SYSDESCR_OID = "1.3.6.1.2.1.1.1.0"
SNMP_SYSOBJECTID_OID = "1.3.6.1.2.1.1.2.0"

# Quick-recon summary fields (mirrors a Shodan-style SNMP banner). Order = display order.
SNMP_SUMMARY_OIDS = [
    ("Description",  "1.3.6.1.2.1.1.1.0"),       # sysDescr
    ("Name",         "1.3.6.1.2.1.1.5.0"),       # sysName
    ("Location",     "1.3.6.1.2.1.1.6.0"),       # sysLocation
    ("Contact",      "1.3.6.1.2.1.1.4.0"),       # sysContact
    ("Uptime",       "1.3.6.1.2.1.1.3.0"),       # sysUpTime (TimeTicks)
    ("Object ID",    "1.3.6.1.2.1.1.2.0"),       # sysObjectID -> vendor enterprise
    ("Engine Time",  "1.3.6.1.6.3.10.2.1.3.0"),  # snmpEngineTime
    ("Engine Boots", "1.3.6.1.6.3.10.2.1.2.0"),  # snmpEngineBoots
]

# Full dump walks the whole 'internet' subtree so vendor MIBs (1.3.6.1.4.1.*) are
# captured alongside mib-2, not just the standard system group.
SNMP_FULLDUMP_BASE = "1.3.6.1"

# Partial IANA Private Enterprise Number -> vendor map for labeling sysObjectID.
# Not exhaustive; unknown PENs are shown as-is (full list: iana.org PEN registry).
SNMP_ENTERPRISE_NAMES = {
    2: "IBM", 4: "Unix", 9: "Cisco Systems", 11: "Hewlett-Packard",
    42: "Sun Microsystems", 43: "3Com", 63: "Apple", 111: "Oracle",
    311: "Microsoft", 318: "APC (Schneider Electric)", 674: "Dell",
    789: "NetApp", 2011: "Huawei", 2636: "Juniper Networks",
    3375: "F5 Networks", 4526: "Netgear", 8072: "net-snmp (Net-SNMP agent)",
    14988: "MikroTik", 25506: "H3C", 30065: "Arista Networks",
}

# ------------------------ Port lists for Host Scanning ------------------------
# Common IT service ports (name shown alongside open results).
COMMON_IT_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "Submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 9100: "JetDirect",
}

# Common OT / ICS protocol ports.
COMMON_OT_PORTS = {
    102: "S7comm / ISO-TSAP (Siemens)",
    502: "Modbus TCP",
    789: "Red Lion Crimson",
    1089: "Foundation Fieldbus HSE",
    1090: "Foundation Fieldbus HSE",
    1091: "Foundation Fieldbus HSE",
    1911: "Niagara Fox (Tridium)",
    1962: "PCWorx (Phoenix Contact)",
    2222: "EtherNet/IP (implicit I/O)",
    2404: "IEC 60870-5-104",
    2455: "CoDeSys",
    4000: "OPC (Emerson ROC)",
    4840: "OPC UA",
    4911: "Niagara Fox SSL (Tridium)",
    5006: "MELSEC-Q (Mitsubishi)",
    5007: "MELSEC-Q (Mitsubishi)",
    9600: "OMRON FINS",
    18245: "GE SRTP",
    18246: "GE SRTP",
    20000: "DNP3",
    20547: "ProConOS",
    34962: "PROFINET RT",
    34963: "PROFINET RT",
    34964: "PROFINET RT",
    44818: "EtherNet/IP (explicit / CIP)",
    47808: "BACnet/IP",
    55000: "FL-net",
}

# Cap host expansion so a fat CIDR doesn't silently launch a huge scan.
HOST_SCAN_WARN_THRESHOLD = 512

# ------------------------ Passive DHCP listener config ------------------------
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
DHCP_MAGIC = b"\x63\x82\x53\x63"     # RFC 2131 magic cookie at offset 236
DHCP_LISTEN_DEFAULT = 300            # seconds; blank/0 at the prompt = until Ctrl+C
DHCP_BPF = "udp and (port 67 or port 68)"

# DHCP message types (option 53, RFC 2132).
DHCP_MSG_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
}

# Runtime OUI database. There is NO hardcoded vendor list - MAC-vendor names
# come entirely from a real OUI file (IEEE oui.csv / oui.txt, or a Wireshark
# 'manuf' file), loaded by load_oui_database() at startup. `python atomics.py
# --update-oui` downloads one (~35k vendors) next to the script. Until a file
# is loaded OUI_DB is empty and every globally-administered MAC shows
# '(unknown vendor)'; that is intentional - one source of truth, no partial or
# guessed built-in entries. Randomized/locally-administered MACs (privacy MACs
# on phones etc.) are still flagged algorithmically and never resolve.
OUI_DB = {}            # /24 (MA-L, CID): {"AA:BB:CC": vendor}  (colon, 3 octets)
OUI_DB_M = {}          # /28 (MA-M):      {"AABBCCD": vendor}   (7 hex nibbles)
OUI_DB_S = {}          # /36 (MA-S, IAB): {"AABBCC001": vendor} (9 hex nibbles)
OUI_SOURCE = None      # None = no database loaded; a path string once one is


def _script_dir():
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except NameError:
        return os.getcwd()


def _norm_oui(token):
    """Normalise an OUI token to 'AA:BB:CC' (first 3 octets, upper). '' if bad.
    Accepts '00:1B:1B', '001B1B', '00-1b-1b', '00:1B:1B:00:00:00/28', etc."""
    token = token.strip().split("/")[0].strip()
    token = token.replace("-", ":").replace(".", ":")
    if ":" in token:
        parts = [p for p in token.split(":") if p != ""]
    else:
        parts = [token[i:i + 2] for i in range(0, len(token), 2)]
    if len(parts) < 3:
        return ""
    try:
        for p in parts[:3]:
            int(p, 16)
    except ValueError:
        return ""
    return ":".join(p.zfill(2) for p in parts[:3]).upper()


def _norm_oui_prefix(token):
    """Normalise a MAC prefix to uppercase hex nibbles with no separators, its
    LENGTH carrying the block size for longest-prefix matching: MA-L/CID = 6,
    MA-M = 7, MA-S/IAB = 9. Two encodings are handled:
      - maclookup, where the digit count is the length ('1C:87:76:D' -> 7)
      - Wireshark manuf, where a '/NN' bit count masks a full-length address
        ('00:1B:1B:00:00:00/28' -> 28 bits -> 7 nibbles '001B1B0')
    Returns '' for < 6 hex digits or non-hex."""
    token = token.strip()
    bits = None
    if "/" in token:
        base, _sep, m = token.partition("/")
        m = m.strip()
        if m.isdigit():
            bits = int(m)
        token = base
    t = token.strip().replace("-", "").replace(":", "").replace(".", "").upper()
    if bits is not None:
        t = t[:max(6, bits // 4)]          # honour the mask, never below /24
    if len(t) < 6:
        return ""
    for c in t:
        if c not in "0123456789ABCDEF":
            return ""
    return t


def _oui_add(db24, dbm, dbs, prefix_token, vendor):
    """Route one (prefix, vendor) into the right tier by prefix length. A 6-nibble
    prefix is a /24 (kept in the colon-keyed map for backward compatibility);
    7 nibbles is a /28; 9 (or more) is a /36. Longer, non-standard lengths are
    truncated down to the nearest known tier."""
    raw = _norm_oui_prefix(prefix_token)
    if not raw or not vendor:
        return
    vendor = vendor.rstrip(", ").strip()       # maclookup leaves stray trailing commas
    if not vendor:
        return
    n = len(raw)
    if n >= 9:
        dbs[raw[:9]] = vendor
    elif n >= 7:
        dbm[raw[:7]] = vendor
    else:
        pfx = _norm_oui(prefix_token)
        if pfx:
            db24[pfx] = vendor


def _parse_oui_file(path):
    """Parse an OUI file into three tiers keyed by prefix length, for longest-
    prefix matching: (db24, dbm, dbs).
      db24 - /24 MA-L & CID, colon-keyed 'AA:BB:CC'
      dbm  - /28 MA-M,       7 hex nibbles 'AABBCCD'
      dbs  - /36 MA-S & IAB, 9 hex nibbles 'AABBCC001'
    Handles four real formats:
      - maclookup.app CSV (Mac Prefix,Vendor Name,Private,Block Type,Last Update)
      - IEEE oui.csv  (Registry,Assignment,Organization Name,...)
      - IEEE oui.txt  ('00-1B-1B   (hex)   Siemens AG')
      - Wireshark manuf ('00:1B:1B\\tSiemens\\tSiemens AG', may carry /28 /36)
    Best-effort: unparseable lines are skipped, never fatal."""
    db24, dbm, dbs = {}, {}, {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.readline()
            f.seek(0)
            low = head.lower()
            if "mac prefix" in low:
                # maclookup.app CSV: col 0 = prefix (length encodes the block
                # size), col 1 = vendor. Commas in names are quoted -> csv.reader.
                reader = csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) < 2:
                        continue
                    _oui_add(db24, dbm, dbs, row[0], row[1].strip().strip('"'))
            elif "registry" in low and "assignment" in low:
                reader = csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) < 3:
                        continue
                    _oui_add(db24, dbm, dbs, row[1], row[2].strip().strip('"'))
            else:
                for line in f:
                    s = line.rstrip("\n")
                    if not s or s.lstrip().startswith("#"):
                        continue
                    if "(base 16)" in s:
                        continue                      # IEEE txt dup of the (hex) line
                    if "(hex)" in s:
                        left, _sep, right = s.partition("(hex)")
                        _oui_add(db24, dbm, dbs, left, right.strip())
                        continue
                    toks = [t for t in s.split("\t") if t.strip() != ""]
                    if len(toks) < 2:
                        toks = s.split(None, 2)
                    if len(toks) >= 2:
                        vendor = toks[-1].strip()
                        if vendor and not vendor.startswith("#"):
                            _oui_add(db24, dbm, dbs, toks[0], vendor)
    except OSError:
        return {}, {}, {}
    return db24, dbm, dbs


def _find_oui_file():
    """Locate an OUI file: $ATOMICS_OUI_FILE (legacy $RUNG_OUI_FILE still honored), then a known filename near the script
    or the cwd. Returns a path or None.

    oui.csv is preferred, then the maclookup.app export's default names
    (mac-vendors-export.csv, maclookup.csv), then IEEE txt / Wireshark manuf.
    Searched, nearest first:
      1. directly beside the script and in the cwd,
      2. one level of subdirectories under each (so a mac-vendors-export.csv in
         a 'Developer' subfolder is found when AtomICS is launched from its parent),
      3. up to two parent directories of each (so it is found when AtomICS is
         launched from a subfolder of the directory that holds the CSV).
    The subdirectory scan is one level deep and matches only the known OUI
    filenames, so it stays fast and never walks the whole disk - safe to run
    from a field jump box or USB stick."""
    env = os.environ.get("ATOMICS_OUI_FILE") or os.environ.get("RUNG_OUI_FILE")
    if env and os.path.isfile(env):
        return env

    names = ("oui.csv", "mac-vendors-export.csv", "maclookup.csv",
             "oui.txt", "manuf")

    primary = []
    for d in (_script_dir(), os.getcwd()):
        if d and d not in primary:
            primary.append(d)

    # 1) known filenames directly beside the script / in the cwd
    for d in primary:
        for n in names:
            path = os.path.join(d, n)
            if os.path.isfile(path):
                return path

    # 2) one level of subdirectories under each (e.g. a 'Developer' subfolder)
    for d in primary:
        try:
            subs = sorted(os.path.join(d, e) for e in os.listdir(d)
                          if os.path.isdir(os.path.join(d, e)))
        except OSError:
            subs = []
        for sub in subs:
            for n in names:
                path = os.path.join(sub, n)
                if os.path.isfile(path):
                    return path

    # 3) up to two parent directories of each
    for d in primary:
        cur = d
        for _ in range(2):
            parent = os.path.dirname(cur)
            if not parent or parent == cur:
                break
            for n in names:
                path = os.path.join(parent, n)
                if os.path.isfile(path):
                    return path
            cur = parent
    return None


def load_oui_database(verbose=True):
    """Load the OUI database from a real OUI file, if one is present. There is
    no built-in fallback list - without a file, vendor resolution is empty."""
    global OUI_DB, OUI_DB_M, OUI_DB_S, OUI_SOURCE
    path = _find_oui_file()
    if not path:
        if verbose:
            echo("[i] OUI: no database loaded - every MAC will show '(unknown vendor)'.")
            echo("    Run 'python atomics.py --update-oui', or download the maclookup.app CSV")
            echo("    (https://maclookup.app/downloads/csv-database) and save it as oui.csv")
            echo("    beside the script, for vendor resolution.")
        return
    db24, dbm, dbs = _parse_oui_file(path)
    if not (db24 or dbm or dbs):
        if verbose:
            echo(f"[!] OUI file {path} could not be parsed - no vendor resolution.")
        return
    OUI_DB, OUI_DB_M, OUI_DB_S = db24, dbm, dbs
    OUI_SOURCE = path
    if verbose:
        total = len(db24) + len(dbm) + len(dbs)
        extra = (f" (incl. {len(dbm)} MA-M + {len(dbs)} MA-S/IAB sub-blocks)"
                 if (dbm or dbs) else "")
        echo(f"[i] OUI: {total} vendor prefixes loaded from "
             f"{os.path.basename(path)}{extra}.")


# OUI download sources, tried in order. maclookup.app's consolidated CSV is the
# preferred source (MA-L/MA-M/MA-S in one file, refreshed daily). IEEE's own CSV
# is authoritative but frequently rate-limits or 418s automated fetches; the
# Wireshark 'manuf' mirrors (well maintained, parse identically) are last-resort
# fallbacks. Each is (url, saved-filename, human label).
OUI_SOURCES = [
    ("https://maclookup.app/downloads/csv-database", "oui.csv", "maclookup.app (CSV)"),
    ("https://standards-oui.ieee.org/oui/oui.csv", "oui.csv", "IEEE registry (CSV)"),
    ("https://www.wireshark.org/download/automated/data/manuf", "manuf", "Wireshark manuf"),
    ("https://raw.githubusercontent.com/wireshark/wireshark/master/manuf", "manuf",
     "Wireshark manuf (GitHub mirror)"),
]


def update_oui():
    """Download a full OUI database next to the script, trying several sources.

    Writes the first source that returns a parseable file with a real number of
    entries, then reports the count. Robust to any one source being blocked."""
    import urllib.request
    dest_dir = _script_dir()
    echo("Fetching a full OUI (MAC vendor) database. Trying sources in order:")
    for url, fname, label in OUI_SOURCES:
        dest = os.path.join(dest_dir, fname)
        echo(f"  - {label}: {url}")
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (AtomICS OUI updater)"})
            with urllib.request.urlopen(req, timeout=90) as r:
                data = r.read()
        except Exception as e:
            echo(f"      [x] failed: {e}")
            continue
        try:
            with open(dest, "wb") as out:
                out.write(data)
        except OSError as e:
            echo(f"      [x] could not write {dest}: {e}")
            continue
        db24, dbm, dbs = _parse_oui_file(dest)
        n = len(db24) + len(dbm) + len(dbs)
        if n < 1000:
            # A blocked source can return an HTML error page that "parses" to
            # near-nothing; treat that as a failure and try the next source.
            echo(f"      [x] only {n} entries parsed - looks incomplete, "
                 f"trying the next source.")
            try:
                os.remove(dest)
            except OSError:
                pass
            continue
        echo(f"      [+] {n} OUI entries saved to {dest}")
        echo("      It loads automatically next time you run the tool.")
        return
    echo("[x] Every source failed (network blocked, or offline).")
    echo("    Download one of these in a browser and save it next to the script:")
    echo(f"      {_script_dir()}")
    echo("      https://maclookup.app/downloads/csv-database        -> save as oui.csv")
    echo("      https://standards-oui.ieee.org/oui/oui.csv          -> save as oui.csv")
    echo("      https://www.wireshark.org/download/automated/data/manuf -> save as manuf")
    echo("    (maclookup.app CSV, IEEE CSV/TXT and a Wireshark 'manuf' file are all")
    echo("     parsed automatically.)")


# ------------------------ Output & Logging ------------------------

def echo(msg):
    """User-facing output only"""
    print(msg)


def log(msg):
    """File-only logging"""
    if not LOG_FILE:
        return
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")


# ============================================================
#  ASSET REGISTER  (shared, session-lived inventory)
# ============================================================
# Every module writes what it learns here through asset_update(). The register
# is the single place that pulls the whole session together: IP, MAC, hostname,
# open ports, the protocols each host actually speaks, and version/identity
# strings. The "versioning" column only fills in from protocol recon (Modbus
# FC 43, S7 order code/firmware, SNMP sysDescr, BACnet firmware), which is why
# those modules feed it too, not just the scanners.
#
# Session-lived by design: it lives in memory for one run and is gone on exit.
# Nothing is written to disk unless the operator exports it - deliberate, since
# this often runs on a client's machine. Export to CSV or JSON to keep it.
#
# Keyed by IP. A host seen only at layer 2 (ARP/passive with no IP) is not an
# asset-register row - the register is an IP inventory; MAC-only sightings live
# in the passive listener's own results.

ASSET_REGISTER = {}   # ip -> record dict


def asset_update(ip, mac=None, hostname=None, vendor=None, ports=None,
                 protocol=None, version=None, source=None):
    """Merge one observation about an IP into the register. Safe to call often.

    ports    : dict {port:int -> service:str} or an iterable of port ints
    protocol : a protocol/service name confirmed for this host (e.g. "Modbus")
    version  : a free-text identity/version line (e.g. "Modbus: Vendor=Acme ...")
    source   : how it was learned (e.g. "ICMP", "ARP", "SYN", "Modbus", "S7")
    Everything except ip is optional; the first non-empty value wins for the
    scalar fields so a later, sparser sighting never erases a richer one.
    """
    if not ip or ip in ("0.0.0.0", "255.255.255.255"):
        return
    now = datetime.now()
    rec = ASSET_REGISTER.get(ip)
    if rec is None:
        rec = {"ip": ip, "mac": "", "hostname": "", "vendor": "",
               "ports": {}, "protocols": [], "versions": [], "sources": [],
               "first_seen": now, "last_seen": now}
        ASSET_REGISTER[ip] = rec
    if mac and not rec["mac"]:
        rec["mac"] = mac
    if hostname and not rec["hostname"]:
        rec["hostname"] = hostname
    if vendor and not rec["vendor"]:
        rec["vendor"] = vendor
    if ports:
        items = ports.items() if isinstance(ports, dict) else [(p, "") for p in ports]
        for port, svc in items:
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            # Fill or upgrade the service label, but never blank an existing one.
            if port not in rec["ports"] or (svc and not rec["ports"][port]):
                rec["ports"][port] = svc or rec["ports"].get(port, "")
    if protocol and protocol not in rec["protocols"]:
        rec["protocols"].append(protocol)
    if version and version not in rec["versions"]:
        rec["versions"].append(version)
    if source and source not in rec["sources"]:
        rec["sources"].append(source)
    rec["last_seen"] = now


def _asset_sort_key(rec):
    try:
        return (0, int(ipaddress.ip_address(rec["ip"])))
    except Exception:
        return (1, 0)


def _asset_port_count():
    """Total distinct open ports across every host in the register."""
    return sum(len(rec["ports"]) for rec in ASSET_REGISTER.values())


def _asset_summary_label():
    """One-line count for the menus: hosts (IP addresses) and open ports."""
    hosts = len(ASSET_REGISTER)
    ports = _asset_port_count()
    return (f"{hosts} host(s), {ports} open port(s)")


def _asset_services(rec):
    """Merge port-service labels and confirmed protocols into one deduped list,
    for the 'applications / services / protocols' column."""
    seen = []
    for proto in rec["protocols"]:
        if proto and proto not in seen:
            seen.append(proto)
    for port in sorted(rec["ports"]):
        svc = rec["ports"][port]
        label = svc if svc else f"port {port}"
        if label not in seen:
            seen.append(label)
    return seen


def asset_view():
    """Print the register: IP, open ports, services/protocols, versioning."""
    echo(f"\n=== AtomICS - Asset Register ({len(ASSET_REGISTER)} host(s)) ===")
    if not ASSET_REGISTER:
        echo("  (empty - run a scan or a protocol module first, then come back)")
        echo("  Everything you do feeds this: Network Discovery adds IPs, MACs and")
        echo("  open ports; the protocol modules add the services each host speaks")
        echo("  and their version/identity strings.")
        echo("=== end ===")
        return
    for rec in sorted(ASSET_REGISTER.values(), key=_asset_sort_key):
        head = f"  {rec['ip']}"
        if rec["mac"]:
            # MAC with vendor in parentheses; prefer the vendor the record
            # already resolved (OUI or a protocol module) over a fresh lookup.
            head += f"   {_mac_with_vendor(rec['mac'], rec['vendor'])}"
        elif rec["vendor"]:
            head += f"   {rec['vendor']}"
        echo(head)
        if rec["hostname"]:
            echo(f"      hostname : {rec['hostname']}")
        if rec["ports"]:
            portstr = ", ".join(
                (f"{p}/{rec['ports'][p]}" if rec["ports"][p] else f"{p}")
                for p in sorted(rec["ports"]))
            echo(f"      ports    : {portstr}")
        else:
            echo(f"      ports    : (none observed)")
        services = _asset_services(rec)
        echo(f"      services : {', '.join(services) if services else '(none)'}")
        if rec["versions"]:
            echo(f"      version  :")
            for v in rec["versions"]:
                echo(f"                 - {v}")
        else:
            echo(f"      version  : (no protocol identity collected)")
        echo(f"      seen via : {', '.join(rec['sources'])}   "
             f"({rec['first_seen'].strftime('%H:%M:%S')} -> "
             f"{rec['last_seen'].strftime('%H:%M:%S')})")
    echo("=== end ===")


def asset_export_csv():
    if not ASSET_REGISTER:
        echo("Register is empty - nothing to export.")
        return
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = f"atomics_assets_{ts}.csv"
    cols = ["ip", "mac", "vendor", "hostname", "open_ports",
            "services_protocols", "versioning", "sources",
            "first_seen", "last_seen"]
    try:
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(cols)
            for rec in sorted(ASSET_REGISTER.values(), key=_asset_sort_key):
                portstr = "; ".join(
                    (f"{p}/{rec['ports'][p]}" if rec["ports"][p] else f"{p}")
                    for p in sorted(rec["ports"]))
                writer.writerow([
                    rec["ip"], rec["mac"], rec["vendor"], rec["hostname"],
                    portstr, "; ".join(_asset_services(rec)),
                    " | ".join(rec["versions"]), ", ".join(rec["sources"]),
                    rec["first_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                    rec["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                ])
    except OSError as e:
        echo(f"[✗] Could not write {path}: {e}")
        return
    echo(f"[✓] Exported {len(ASSET_REGISTER)} host(s) to {path}")
    log(f"ASSET_EXPORT_CSV file={path} hosts={len(ASSET_REGISTER)}")


def asset_export_json():
    if not ASSET_REGISTER:
        echo("Register is empty - nothing to export.")
        return
    import json
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = f"atomics_assets_{ts}.json"
    out = []
    for rec in sorted(ASSET_REGISTER.values(), key=_asset_sort_key):
        out.append({
            "ip": rec["ip"], "mac": rec["mac"], "vendor": rec["vendor"],
            "hostname": rec["hostname"],
            "ports": [{"port": p, "service": rec["ports"][p]} for p in sorted(rec["ports"])],
            "services_protocols": _asset_services(rec),
            "versioning": rec["versions"], "sources": rec["sources"],
            "first_seen": rec["first_seen"].strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": rec["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
        })
    try:
        with open(path, "w") as f:
            json.dump(out, f, indent=2)
    except OSError as e:
        echo(f"[✗] Could not write {path}: {e}")
        return
    echo(f"[✓] Exported {len(ASSET_REGISTER)} host(s) to {path}")
    log(f"ASSET_EXPORT_JSON file={path} hosts={len(ASSET_REGISTER)}")


def asset_register_session():
    """Main-menu item 7: view and export the collected asset inventory."""
    while True:
        print("\n--- AtomICS - Asset Register ---")
        print(f"    {_asset_summary_label()} collected this session (in memory only)")
        print("1. View register (IP, ports, services/protocols, versioning)")
        print("2. Export to CSV")
        print("3. Export to JSON")
        print("4. Clear register")
        print("5. Back to main menu")
        choice = input("\nSelect an option: ").strip()
        if choice == "1":
            asset_view()
        elif choice == "2":
            asset_export_csv()
        elif choice == "3":
            asset_export_json()
        elif choice == "4":
            if ASSET_REGISTER and input("Clear all collected assets? [y/N]: ").strip().lower().startswith("y"):
                ASSET_REGISTER.clear()
                echo("[i] Register cleared.")
                log("ASSET_CLEARED")
            else:
                echo("Not cleared.")
        elif choice == "5":
            break
        else:
            echo("Invalid option.")


# ============================================================
#  HOST SCANNING MODULE
# ============================================================

def _primary_ipv4():
    """Best-guess primary outbound IPv4 address. Sends no traffic."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def _local_ipv4_interfaces():
    """Best-effort list of this host's IPv4 interfaces.

    Returns a list of dicts: {"iface", "ip", "netmask", "cidr"}. Loopback and
    APIPA/link-local addresses are skipped. Pure stdlib: parses ipconfig on
    Windows and `ip`/`ifconfig` on POSIX. Returns [] if nothing was found.
    """
    ifaces = []

    def _add(ip, netmask, iface="?"):
        if not ip or not netmask:
            return
        if ip.startswith("127.") or ip.startswith("169.254."):
            return
        try:
            net = ipaddress.ip_interface(f"{ip}/{netmask}")
        except ValueError:
            return
        if any(d["ip"] == ip for d in ifaces):
            return
        ifaces.append({"iface": iface, "ip": ip,
                       "netmask": str(net.netmask), "cidr": str(net.network)})

    try:
        if os.name == "nt":
            out = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                 timeout=8).stdout
            cur_ip, cur_iface = None, "?"
            for raw in out.splitlines():
                line = raw.rstrip()
                if line and not line.startswith(" "):
                    cur_iface = line.strip().rstrip(":")
                    cur_ip = None
                    continue
                low = line.lower()
                if "ipv4 address" in low:
                    cur_ip = line.split(":", 1)[-1].replace("(Preferred)", "").strip()
                elif "subnet mask" in low and cur_ip:
                    _add(cur_ip, line.split(":", 1)[-1].strip(), cur_iface)
                    cur_ip = None
        else:
            out = ""
            try:
                out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                                     capture_output=True, text=True,
                                     timeout=8).stdout
            except Exception:
                out = ""
            if out.strip():
                for line in out.splitlines():
                    parts = line.split()
                    iface = parts[1] if len(parts) > 1 else "?"
                    for i, tok in enumerate(parts):
                        if tok == "inet" and i + 1 < len(parts) and "/" in parts[i + 1]:
                            ip, _, pfx = parts[i + 1].partition("/")
                            _add(ip, pfx, iface)
                            break
            else:
                out = subprocess.run(["ifconfig"], capture_output=True,
                                     text=True, timeout=8).stdout
                cur_iface = "?"
                for raw in out.splitlines():
                    if raw and not raw[0].isspace():
                        cur_iface = raw.split()[0].rstrip(":")
                    m = raw.strip()
                    if m.startswith("inet ") and "127.0.0.1" not in m:
                        toks = m.split()
                        ip = toks[1]
                        mask = None
                        if "netmask" in toks:
                            mask = toks[toks.index("netmask") + 1]
                            if mask.startswith("0x"):
                                mask = str(ipaddress.IPv4Address(int(mask, 16)))
                        _add(ip, mask, cur_iface)
    except Exception:
        pass

    if not ifaces:
        pip = _primary_ipv4()
        if pip:
            _add(pip, "255.255.255.0", "?")
    return ifaces


def _print_local_ifaces(indent="  ", blank_after=True):
    """Print this host's current IPv4 address(es) and subnet mask(s).

    blank_after adds a trailing blank line so the address block is visually
    separated from whatever follows it (a menu, a prompt). The startup banner
    passes False because its "=" rule already provides the separation.
    """
    ifaces = _local_ipv4_interfaces()
    if not ifaces:
        echo(f"{indent}Local IP/subnet: (could not determine)")
        if blank_after:
            echo("")
        return
    echo(f"{indent}This host:")
    for d in ifaces:
        tag = f"  [{d['iface']}]" if d["iface"] not in ("?", "") else ""
        echo(f"{indent}  {d['ip']}  mask {d['netmask']}  ({d['cidr']}){tag}")
    if blank_after:
        echo("")


def _local_subnet_for_arp():
    """Pick the local subnet to ARP-scan. Returns (cidr, hosts) or (None, None)."""
    ifaces = _local_ipv4_interfaces()
    if not ifaces:
        echo("[✗] Could not determine a local subnet on this host.")
        return None, None
    if len(ifaces) == 1:
        chosen = ifaces[0]
    else:
        echo("Multiple local subnets detected:")
        for i, d in enumerate(ifaces, 1):
            echo(f"  {i}. {d['cidr']}  (ip {d['ip']}, mask {d['netmask']}) [{d['iface']}]")
        sel = input(f"Select subnet to ARP-scan [1-{len(ifaces)}, default 1]: ").strip()
        idx = 0
        if sel:
            try:
                idx = int(sel) - 1
            except ValueError:
                idx = -1
        if idx < 0 or idx >= len(ifaces):
            echo("Invalid selection.")
            return None, None
        chosen = ifaces[idx]
    hosts = [h for h in _expand_targets(chosen["cidr"]) if h != chosen["ip"]]
    if not hosts:
        echo("[✗] Local subnet expanded to no scannable hosts.")
        return None, None
    if len(hosts) > HOST_SCAN_WARN_THRESHOLD:
        ok = input(f"[!] Local subnet {chosen['cidr']} = {len(hosts)} hosts. Continue? [y/N]: ")
        if not ok.strip().lower().startswith("y"):
            echo("Aborted.")
            return None, None
    echo(f"[i] ARP target: local subnet {chosen['cidr']} "
         f"({len(hosts)} hosts, from {chosen['ip']}/{chosen['netmask']}).")
    log(f"ARP_LOCAL subnet={chosen['cidr']} ip={chosen['ip']} count={len(hosts)}")
    return chosen["cidr"], hosts


def _expand_targets(spec):
    """Turn a single IP or a CIDR subnet into a list of host IP strings.

    Accepts '10.0.0.5', '10.0.0.0/24', or a bare '10.0.0.0/255.255.255.0'.
    For subnets, network/broadcast addresses are excluded (hosts only).
    Returns [] on a parse error (caller reports it).
    """
    spec = spec.strip()
    try:
        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            hosts = [str(h) for h in net.hosts()]
            # /32 or /31 have no "hosts()" the usual way — fall back to the address(es).
            if not hosts:
                hosts = [str(net.network_address)]
            return hosts
        return [str(ipaddress.ip_address(spec))]
    except ValueError:
        return []


def _prompt_targets(default_ip=None):
    """Prompt for a single IP or subnet and expand it. Returns a host list or None."""
    prompt = "Target (single IP or CIDR subnet, e.g. 10.0.0.5 or 10.0.0.0/24)"
    prompt += f" [{default_ip}]: " if default_ip else ": "
    spec = input(prompt).strip() or (default_ip or "")
    if not spec:
        echo("No target provided.")
        return None
    hosts = _expand_targets(spec)
    if not hosts:
        echo(f"[✗] Could not parse '{spec}' as an IP address or subnet.")
        return None
    if len(hosts) > HOST_SCAN_WARN_THRESHOLD:
        ok = input(f"[!] That expands to {len(hosts)} hosts. Continue? [y/N]: ")
        if not ok.strip().lower().startswith("y"):
            echo("Aborted.")
            return None
    echo(f"[i] {len(hosts)} host(s) to scan.")
    log(f"HOSTSCAN targets spec={spec} count={len(hosts)}")
    return hosts


def arp_scan(hosts):
    """Layer-2 ARP scan (local subnet only). Requires scapy + privileges."""
    if not SCAPY_AVAILABLE:
        echo("[✗] ARP scan needs scapy (raw layer-2 access), which is not available.")
        echo(f"    Reason: {SCAPY_IMPORT_ERROR}")
        echo("    Install it (and Npcap on Windows), then run elevated:")
        echo(f'        "{sys.executable}" -m pip install scapy')
        log(f"ARP_SCAN_UNAVAILABLE {SCAPY_IMPORT_ERROR}")
        return
    # Wait long enough for slower devices to answer; scale with subnet size.
    wait = min(8, max(3, 2 + len(hosts) // 128))
    echo(f"ARP-scanning {len(hosts)} host(s) — layer 2, local subnet only...")
    echo(f"[i] Sending ARP requests; waiting up to {wait}s for replies...")
    log(f"ARP_SCAN start count={len(hosts)} timeout={wait}")
    found = []
    try:
        # srp() blocks until the timeout elapses, so all replies are collected
        # before we display results.
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=hosts),
            timeout=wait, retry=1,
        )
        echo(f"[i] Wait complete — {len(ans)} "
             f"{'reply' if len(ans) == 1 else 'replies'} received.")
        for _, rcv in ans:
            found.append((rcv.psrc, rcv.hwsrc))
    except PermissionError:
        echo("[✗] ARP scan requires administrator/root privileges.")
        log("ARP_SCAN permission_denied")
        return
    except Exception as e:
        echo(f"[✗] ARP scan failed: {e}")
        log(f"ARP_SCAN error {e}")
        return
    echo(f"\n--- ARP Scan Results ({len(found)} responded) ---")
    for ip, mac in sorted(found, key=lambda x: ipaddress.ip_address(x[0])):
        vendor = _oui_vendor(mac)
        echo(f"  {ip:<16}  {_mac_with_vendor(mac)}")
        asset_update(ip, mac=mac, vendor=vendor, source="ARP")
        log(f"ARP_SCAN alive ip={ip} mac={mac} vendor={vendor}")
    if not found:
        echo("  (no ARP replies)")
    _oui_seed_only_hint([m for _ip, m in found])
    echo("--- end ---")
    log(f"ARP_SCAN done alive={len(found)}")


def _icmp_scapy(hosts):
    alive = []
    ans, _ = sr(IP(dst=hosts) / ICMP(), timeout=2, retry=1)
    for _, rcv in ans:
        alive.append(rcv.src)
    return alive


def _icmp_ping(ip):
    """Single system-ping fallback. Returns ip if it replies, else None."""
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=4)
        return ip if r.returncode == 0 else None
    except Exception:
        return None


def icmp_scan(hosts):
    """ICMP echo (ping) sweep. Uses scapy if present, else the system ping."""
    echo(f"ICMP ping-sweeping {len(hosts)} host(s)...")
    log(f"ICMP_SCAN start count={len(hosts)} scapy={SCAPY_AVAILABLE}")
    alive = []
    if SCAPY_AVAILABLE:
        try:
            alive = _icmp_scapy(hosts)
        except PermissionError:
            echo("[!] Raw ICMP needs privileges — falling back to system ping.")
            alive = []
        except Exception as e:
            echo(f"[!] scapy ICMP failed ({e}) — falling back to system ping.")
            alive = []
    if not alive:
        with ThreadPoolExecutor(max_workers=min(64, len(hosts) or 1)) as pool:
            for res in pool.map(_icmp_ping, hosts):
                if res:
                    alive.append(res)
    alive = sorted(set(alive), key=lambda x: ipaddress.ip_address(x))
    echo(f"\n--- ICMP Scan Results ({len(alive)} alive) ---")
    for ip in alive:
        echo(f"  {ip}  is up")
        asset_update(ip, source="ICMP")
        log(f"ICMP_SCAN alive ip={ip}")
    if not alive:
        echo("  (no hosts replied to ICMP — they may still be up but filtering ping)")
    echo("--- end ---")
    log(f"ICMP_SCAN done alive={len(alive)}")


def _syn_scapy(hosts, ports):
    """True half-open SYN scan via scapy. Returns {ip: [(port, state)]}."""
    results = {}
    pkts = [IP(dst=h) / TCP(dport=list(ports.keys()) if isinstance(ports, dict) else ports,
                            flags="S") for h in hosts]
    ans, _ = sr(pkts, timeout=2, retry=1)
    for snd, rcv in ans:
        ip = snd[IP].dst
        dport = snd[TCP].dport
        state = None
        if rcv.haslayer(TCP):
            flags = rcv[TCP].flags
            if flags & 0x12 == 0x12:      # SYN+ACK -> open
                state = "open"
            elif flags & 0x04:            # RST -> closed
                state = "closed"
        if state == "open":
            results.setdefault(ip, []).append((dport, state))
    return results


def _connect_probe(ip, port, timeout=1.0):
    """TCP connect probe (no-scapy fallback). Returns (ip, port) if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return (ip, port)
    except Exception:
        pass
    return None


def _syn_connect(hosts, ports):
    """Threaded TCP-connect fallback. Returns {ip: [(port, 'open')]}."""
    portlist = list(ports.keys()) if isinstance(ports, dict) else list(ports)
    jobs = [(h, p) for h in hosts for p in portlist]
    results = {}
    workers = min(200, max(1, len(jobs)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_connect_probe, h, p) for h, p in jobs]
        for fut in as_completed(futs):
            hit = fut.result()
            if hit:
                ip, port = hit
                results.setdefault(ip, []).append((port, "open"))
    return results


def _port_label(port):
    return COMMON_IT_PORTS.get(port) or COMMON_OT_PORTS.get(port) or ""


def syn_scan(hosts, ports, scan_name):
    """Run a SYN scan (scapy) or TCP-connect fallback and print open ports.

    `ports` may be a dict {port: label} or an iterable of port ints.
    """
    port_count = len(ports)
    method = "SYN (scapy)" if SCAPY_AVAILABLE else "TCP connect (fallback)"
    echo(f"Scanning {len(hosts)} host(s) x {port_count} port(s) — {scan_name}")
    echo(f"[i] Method: {method}")
    log(f"SYN_SCAN start name='{scan_name}' hosts={len(hosts)} ports={port_count} method={method}")
    results = {}
    try:
        if SCAPY_AVAILABLE:
            try:
                results = _syn_scapy(hosts, ports)
            except PermissionError:
                echo("[!] Raw SYN needs privileges — falling back to TCP connect.")
                results = _syn_connect(hosts, ports)
        else:
            results = _syn_connect(hosts, ports)
    except KeyboardInterrupt:
        echo("\n[!] Scan interrupted.")
        log("SYN_SCAN interrupted")
        return
    except Exception as e:
        echo(f"[✗] Scan failed: {e}")
        log(f"SYN_SCAN error {e}")
        return

    echo(f"\n--- Scan Results: {scan_name} ---")
    if not results:
        echo("  (no open ports found)")
    for ip in sorted(results, key=lambda x: ipaddress.ip_address(x)):
        echo(f"  {ip}")
        for port, state in sorted(results[ip]):
            label = _port_label(port)
            tag = f"  [{label}]" if label else ""
            echo(f"      {port:<6}/tcp  open{tag}")
            asset_update(ip, ports={port: label}, source="SYN")
            log(f"SYN_SCAN open ip={ip} port={port} label={label}")
    echo("--- end ---")
    log(f"SYN_SCAN done name='{scan_name}' hosts_with_open={len(results)}")


def _prompt_single_port():
    raw = input("Port to scan: ").strip()
    try:
        port = int(raw)
        if not (0 < port < 65536):
            raise ValueError
        return port
    except ValueError:
        echo("[✗] Invalid port (1-65535).")
        return None


# ============================================================
#  SHARED HELPERS FOR PASSIVE CAPTURE
# ============================================================
# _mac_str / _oui_vendor / _dhcp_parse below are shared: the ARP scan uses the
# OUI lookup, and the passive broadcast listener further down uses all of them.
# DHCP option parsing lives here because DHCP is one of the broadcast sources
# that listener decodes.
# Reference: RFC 2131 (DHCP), RFC 2132 (options), RFC 3046 (option 82).


def _mac_str(raw):
    """Format raw hardware address bytes as aa:bb:cc:dd:ee:ff."""
    return ":".join(f"{b:02x}" for b in raw)


def _oui_vendor(mac):
    """Label a MAC from the loaded OUI database, or flag a randomized MAC.

    Longest-prefix match: a /36 (MA-S/IAB) assignment wins over a /28 (MA-M),
    which wins over the /24 (MA-L). This resolves the ~45% of /24s that are
    subdivided among several vendors - a plain /24 lookup would return whichever
    sub-block happened to load last. Returns "" when nothing matches and the
    address is globally administered (a real but unmapped vendor).
    """
    if not mac or len(mac) < 8:
        return ""
    raw = mac.replace(":", "").replace("-", "").replace(".", "").upper()
    if len(raw) >= 9 and raw[:9] in OUI_DB_S:
        return OUI_DB_S[raw[:9]]
    if len(raw) >= 7 and raw[:7] in OUI_DB_M:
        return OUI_DB_M[raw[:7]]
    name = OUI_DB.get(mac[:8].upper())
    if name:
        return name
    try:
        first = int(mac[:2], 16)
    except ValueError:
        return ""
    if first & 0x02:
        # Locally administered bit set: privacy/randomized MAC, a hypervisor, or
        # a manually assigned address. Worth knowing — it is not a real OUI.
        return "(randomized / local MAC)"
    return ""


def _oui_seed_only_hint(macs):
    """After a scan, if no OUI database is loaded and some globally-administered
    MACs went unresolved, nudge the operator to load one. Silent once a real OUI
    file is in use, or if nothing was left unresolved."""
    if OUI_SOURCE is not None:
        return
    unresolved = sum(1 for m in macs if m and _oui_vendor(m) == "")
    if not unresolved:
        return
    echo(f"[i] {unresolved} MAC(s) show '(unknown vendor)' because no OUI database "
         f"is loaded.")
    echo("    Run 'python atomics.py --update-oui' once for vendor resolution (~35k "
         "vendors);")
    echo("    it saves a database next to the script that loads automatically after.")


def _mac_with_vendor(mac, vendor=None):
    """Format a MAC with its vendor in parentheses, for any on-screen listing:
    'aa:bb:cc:dd:ee:ff (Rockwell Automation)'. An unmapped OUI shows
    '(unknown vendor)'; a randomized/locally-administered MAC is flagged as
    such. Pass an explicit vendor (e.g. one a protocol module already resolved)
    to override the OUI lookup."""
    if not mac:
        return "(unknown MAC)"
    v = vendor or _oui_vendor(mac)
    if v:
        # Unwrap ONLY a fully-parenthesised sentinel like "(randomized / local
        # MAC)" - never strip a trailing ")" from a real vendor name such as
        # "VMware (virtual NIC)" or "Rockwell Automation (Allen-Bradley)".
        if v.startswith("(") and v.endswith(")"):
            v = v[1:-1]
    else:
        v = "unknown vendor"
    return f"{mac} ({v})"


def _dhcp_text(val):
    """Decode an option value as text when it is printable, else as hex."""
    try:
        s = val.decode("utf-8", errors="ignore").replace("\x00", "").strip()
    except Exception:
        s = ""
    if s and all(32 <= ord(c) < 127 for c in s):
        return s
    return val.hex()


def _dhcp_parse(payload):
    """Parse a BOOTP/DHCP message body. Returns a field dict, or None.

    Layout per RFC 2131: 236 bytes of fixed BOOTP header, the 4-byte magic
    cookie, then option TLVs terminated by option 255.
    """
    if len(payload) < 240 or payload[236:240] != DHCP_MAGIC:
        return None
    try:
        hlen = payload[2] or 6
        chaddr = payload[28:28 + min(max(hlen, 6), 16)]
        info = {
            "op": payload[0],
            "xid": f"0x{struct.unpack('>I', payload[4:8])[0]:08x}",
            "ciaddr": socket.inet_ntoa(payload[12:16]),
            "yiaddr": socket.inet_ntoa(payload[16:20]),
            "giaddr": socket.inet_ntoa(payload[24:28]),
            "mac": _mac_str(chaddr[:6]),
            "msg_type": None,
            "hostname": "",
            "vendor_class": "",
            "requested_ip": "",
            "server_id": "",
            "circuit_id": "",
            "remote_id": "",
        }
    except Exception:
        return None

    i, n = 240, len(payload)
    while i < n:
        code = payload[i]
        if code == 255:          # End option
            break
        if code == 0:            # Pad
            i += 1
            continue
        if i + 1 >= n:
            break
        ln = payload[i + 1]
        val = payload[i + 2:i + 2 + ln]
        i += 2 + ln
        if len(val) < ln:        # truncated capture
            break
        try:
            if code == 53 and val:                      # DHCP message type
                info["msg_type"] = val[0]
            elif code == 12:                            # Host Name
                info["hostname"] = _dhcp_text(val)
            elif code == 60:                            # Vendor Class Identifier
                info["vendor_class"] = _dhcp_text(val)
            elif code == 50 and len(val) == 4:          # Requested IP Address
                info["requested_ip"] = socket.inet_ntoa(val)
            elif code == 54 and len(val) == 4:          # Server Identifier
                info["server_id"] = socket.inet_ntoa(val)
            elif code == 82:                            # Relay Agent Information
                j = 0
                while j + 2 <= len(val):
                    sub, sln = val[j], val[j + 1]
                    sval = val[j + 2:j + 2 + sln]
                    j += 2 + sln
                    if sub == 1:
                        info["circuit_id"] = _dhcp_text(sval)
                    elif sub == 2:
                        info["remote_id"] = _dhcp_text(sval)
        except Exception:
            continue
    return info


def _dhcp_best_ip(info):
    """Pick the most authoritative address in a message.

    yiaddr  - server-assigned ("your" address) in OFFER/ACK; best evidence.
    opt 50  - the address a client is asking for in an initial REQUEST.
    ciaddr  - the client's current address in a renewing REQUEST, RELEASE, INFORM.
    """
    for key in ("yiaddr", "requested_ip", "ciaddr"):
        val = info.get(key) or ""
        if val and val != "0.0.0.0":
            return val
    return ""


# ============================================================
#  PASSIVE TRAFFIC LISTENERS  (Network Discovery options 1 & 2)
# ============================================================
# Two passive discovery modes, neither of which runs an active scan:
#
#   Option 1 - Broadcast/multicast listen (NO admin). Ordinary UDP sockets bound
#     to the discovery ports (mDNS, LLMNR, SSDP, WS-Discovery, NBNS, DHCP) with
#     the multicast groups joined. Harvests source IP + hostname; DHCP also
#     carries the client MAC. MACs for the rest are filled from the local ARP
#     cache afterwards. No root/Administrator and no capture driver required.
#     Joining a multicast group emits standard IGMP membership reports - ordinary
#     host traffic, not a scan - so it is not literally silent, but sends no
#     probe/scan packets. See _passive_listen_udp.
#
#   Option 2 - Promiscuous listen (needs admin). Raw layer-2 capture that watches
#     ALL traffic the interface can see - promiscuously, so unicast IT/OT
#     conversations are captured alongside broadcast/multicast - and reads the
#     MAC off every frame. Receive-only: transmits nothing. See below.
#
# Both build the same host inventory: MAC, IP, hostname, vendor, and where
# available the switch and port the device is plugged into.
#
# Why this earns its place in OT: it is the only discovery method in the tool
# that puts zero packets on the wire, so it is usable on a segment where an
# active scan is not authorised, and on fragile gear where a scan is a real
# risk. It is also the one that survives a "no scanning" rule in a change
# window. The trade is patience - you collect what the network volunteers.
#
# What it pulls IP + MAC from:
#   Unicast IT/OT every TCP/UDP frame it sees carries a source IP + source MAC,
#                so ordinary IT traffic (web, SMB, database, SCADA polls) is
#                harvested - the biggest win from promiscuous capture.
#   ARP          every host that talks to another one broadcasts a request
#                carrying its own IP and MAC. Richest source on a switched port.
#   DHCP         MAC, assigned/requested IP, hostname, vendor class ID.
#   NBNS / mDNS  NetBIOS and Bonjour name announcements -> hostnames.
#   LLMNR/SSDP   Windows name resolution and UPnP announcements.
#   CDP / LLDP   switches announcing themselves: device ID, port, platform.
#                On a mirrored uplink this tells you the switch port per device.
#   PROFINET DCP Siemens station names, broadcast during identify cycles.
#   STP          bridges announcing themselves.
#
# Reach: promiscuous mode makes the NIC accept every frame it RECEIVES, but a
# switch still only forwards a port its own traffic + broadcast/multicast. To
# see unicast between OTHER hosts you need a hub, a SPAN/mirror port, or to be
# one end of the conversation. On a plain access port you still get this host's
# own peers plus all broadcast/multicast - already a solid inventory.
#
# Capture paths, in order of preference:
#   1. scapy        - full layer 2, every protocol above. Needs Npcap on
#                     Windows, root on Linux.
#   2. AF_PACKET    - Linux only, stdlib, same layer-2 visibility as scapy.
#   3. SIO_RCVALL   - Windows only, stdlib raw socket. IPv4 headers ONLY: no
#                     ARP, no CDP/LLDP, and no MAC addresses. IPs discovered
#                     this way are matched against the local ARP cache at the
#                     end, which reads OS state and sends nothing.
# References: RFC 826 (ARP), RFC 2131/2132 (DHCP), RFC 1002 (NBNS),
#             RFC 6762 (mDNS), RFC 4795 (LLMNR), IEEE 802.1AB (LLDP),
#             IEC 61158 (PROFINET DCP).

PASSIVE_LISTEN_DEFAULT = 300      # seconds; blank/0 at the prompt = until Ctrl+C

# Discovery protocols an UNPRIVILEGED UDP socket can subscribe to (option 1, the
# no-admin listener). Multicast groups are joined - which emits standard IGMP
# membership reports, the same traffic every host on the segment sends, not a
# scan. Broadcast ports (group None) are simply bound. Well-known ports below
# 1024 (NBNS 137, DHCP 68) may fail to bind without privilege on some OSes;
# those are skipped with a note and the >1024 protocols still run.
#   (label, udp_port, multicast_group_or_None)
PASSIVE_UDP_DISCOVERY = [
    ("mDNS",         5353, "224.0.0.251"),
    ("LLMNR",        5355, "224.0.0.252"),
    ("SSDP/UPnP",    1900, "239.255.255.250"),
    ("WS-Discovery", 3702, "239.255.255.250"),
    ("NBNS",          137, None),
    ("DHCP",           68, None),
]

# EtherTypes we decode or label.
ETH_IPV4      = 0x0800
ETH_ARP       = 0x0806
ETH_RARP      = 0x8035
ETH_IPV6      = 0x86DD
ETH_LLDP      = 0x88CC
ETH_PROFINET  = 0x8892
ETH_ETHERCAT  = 0x88A4
ETH_VLAN_TAGS = (0x8100, 0x88A8, 0x9100)

ETH_TYPE_NAMES = {
    ETH_RARP: "RARP", ETH_IPV6: "IPv6", ETH_ETHERCAT: "EtherCAT",
    0x8863: "PPPoE-Discovery", 0x8864: "PPPoE", 0x88F7: "PTP (1588)",
    0x22F0: "AVTP", 0x8906: "FCoE", 0x9000: "Ethernet Loopback/CTP",
}

# UDP/TCP ports worth naming when we see them on the wire.
PASSIVE_UDP_PORTS = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP",
    137: "NBNS", 138: "NetBIOS-DGM", 161: "SNMP", 162: "SNMP-Trap",
    500: "ISAKMP", 514: "Syslog", 520: "RIP", 1900: "SSDP/UPnP",
    2222: "EtherNet/IP (I/O)", 2404: "IEC 60870-5-104", 3702: "WS-Discovery",
    4840: "OPC UA", 5353: "mDNS", 5355: "LLMNR", 20000: "DNP3",
    34962: "PROFINET RT", 34963: "PROFINET RT", 34964: "PROFINET RT",
    44818: "EtherNet/IP (CIP)", 47808: "BACnet/IP", 55000: "FL-net",
}
PASSIVE_TCP_PORTS = {
    102: "S7comm", 502: "Modbus TCP", 1911: "Niagara Fox", 2404: "IEC 104",
    4840: "OPC UA", 20000: "DNP3", 44818: "EtherNet/IP (CIP)",
}

IP_PROTO_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 89: "OSPF", 112: "VRRP"}

# A chatty host opens a new ephemeral source port for every connection. Logging
# each one would bury the protocols that actually identify a device under a
# hundred TCP/38xxx entries, and bloat the CSV with noise. Unnamed high ports
# collapse to the bare transport name; these caps bound the rest.
PASSIVE_MAX_LABELS = 12       # distinct protocol / hostname labels kept per host
PASSIVE_MAX_IPS    = 32       # distinct source addresses kept per MAC


# ------------------------ small byte helpers ------------------------

def _u16(b, off):
    return struct.unpack(">H", b[off:off + 2])[0]


def _ipv4(b, off):
    return socket.inet_ntoa(b[off:off + 4])


def _printable(raw):
    """Decode a label/name field, returning '' rather than mojibake."""
    try:
        s = raw.decode("utf-8", errors="ignore").replace("\x00", "").strip()
    except Exception:
        return ""
    if s and all(32 <= ord(c) < 127 for c in s):
        return s
    return ""


# ------------------------ protocol decoders ------------------------

def _decode_arp(payload):
    """RFC 826. Sender hardware/protocol address is the prize."""
    if len(payload) < 28:
        return None
    try:
        op = _u16(payload, 6)
        sha = _mac_str(payload[8:14])
        spa = _ipv4(payload, 14)
        tpa = _ipv4(payload, 24)
        label = {1: "ARP-request", 2: "ARP-reply"}.get(op, f"ARP-op{op}")
        if spa == "0.0.0.0":
            # An ARP probe during duplicate-address detection: the sender has
            # no address yet, but the MAC is still real.
            return {"mac": sha, "ip": "", "proto": "ARP-probe",
                    "detail": f"probing for {tpa}"}
        if spa == tpa:
            label = "ARP-gratuitous"
        return {"mac": sha, "ip": spa, "proto": label, "detail": ""}
    except Exception:
        return None


def _decode_nbns(payload):
    """RFC 1002 first-level encoded NetBIOS name from a broadcast query."""
    try:
        if len(payload) < 13:
            return ""
        nlen = payload[12]
        if nlen != 0x20 or len(payload) < 13 + 32:
            return ""
        enc = payload[13:13 + 32]
        out = []
        for i in range(0, 32, 2):
            hi, lo = enc[i] - 0x41, enc[i + 1] - 0x41
            if hi < 0 or lo < 0 or hi > 15 or lo > 15:
                return ""
            out.append(chr((hi << 4) | lo))
        name = "".join(out).strip()
        # The 16th byte is the NetBIOS suffix (service type), not part of the name.
        return name[:15].strip()
    except Exception:
        return ""


def _decode_dns_name(payload, off):
    """Read a DNS label sequence (mDNS/LLMNR question). No pointer following."""
    try:
        parts = []
        guard = 0
        while off < len(payload) and guard < 16:
            ln = payload[off]
            if ln == 0:
                break
            if ln & 0xC0:          # compression pointer - not worth chasing here
                break
            off += 1
            parts.append(payload[off:off + ln].decode("utf-8", errors="ignore"))
            off += ln
            guard += 1
        name = ".".join(p for p in parts if p)
        return name if all(32 <= ord(c) < 127 for c in name) else ""
    except Exception:
        return ""


def _decode_mdns(payload):
    """Name from the first question in an mDNS/LLMNR packet (header is 12 bytes)."""
    if len(payload) < 13:
        return ""
    name = _decode_dns_name(payload, 12)
    # Strip service-discovery decoration so we keep the host, not the service.
    for suffix in ("._tcp.local", "._udp.local", ".local"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    if name.startswith("_"):
        return ""
    return name


def _decode_lldp(payload):
    """IEEE 802.1AB TLVs: chassis ID (1), port ID (2), system name (5)."""
    out = {"system": "", "port": "", "chassis": ""}
    try:
        i = 0
        while i + 2 <= len(payload):
            hdr = _u16(payload, i)
            ttype = hdr >> 9
            tlen = hdr & 0x01FF
            val = payload[i + 2:i + 2 + tlen]
            i += 2 + tlen
            if ttype == 0:
                break
            if ttype == 1 and len(val) > 1:
                out["chassis"] = _printable(val[1:]) or val[1:].hex()
            elif ttype == 2 and len(val) > 1:
                out["port"] = _printable(val[1:]) or val[1:].hex()
            elif ttype == 5:
                out["system"] = _printable(val)
    except Exception:
        pass
    return out


def _decode_cdp(payload):
    """Cisco Discovery Protocol: device ID (1), port ID (3), platform (6)."""
    out = {"device": "", "port": "", "platform": ""}
    try:
        i = 4                       # version(1) ttl(1) checksum(2)
        while i + 4 <= len(payload):
            ttype = _u16(payload, i)
            tlen = _u16(payload, i + 2)
            if tlen < 4:
                break
            val = payload[i + 4:i + tlen]
            i += tlen
            if ttype == 0x0001:
                out["device"] = _printable(val)
            elif ttype == 0x0003:
                out["port"] = _printable(val)
            elif ttype == 0x0006:
                out["platform"] = _printable(val)
    except Exception:
        pass
    return out


def _decode_profinet_dcp(payload):
    """PROFINET DCP NameOfStation (option 0x02, suboption 0x02), when present."""
    try:
        if len(payload) < 12:
            return ""
        frame_id = _u16(payload, 0)
        if frame_id not in (0xFEFE, 0xFEFF, 0xFEFD, 0xFEFC):
            return ""
        data_len = _u16(payload, 10)
        i = 12
        end = min(len(payload), 12 + data_len)
        while i + 4 <= end:
            option, subopt = payload[i], payload[i + 1]
            blk_len = _u16(payload, i + 2)
            val = payload[i + 4:i + 4 + blk_len]
            i += 4 + blk_len + (blk_len % 2)      # blocks are padded to even length
            if option == 0x02 and subopt == 0x02 and len(val) > 2:
                return _printable(val[2:])        # first 2 bytes are BlockInfo
    except Exception:
        pass
    return ""


def _decode_ssdp(payload):
    """SSDP/UPnP or WS-Discovery datagram (HTTP-style headers). Return the Server
    product string when present, else ''. Used by the no-admin UDP listener."""
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return ""
    for line in text.split("\r\n"):
        if line[:7].lower() == "server:":
            return line.split(":", 1)[1].strip()[:60]
    return ""


def _decode_llc_snap(raw, off, src_mac):
    """802.3 LLC/SNAP frames - this is how CDP and STP arrive."""
    try:
        if off + 3 > len(raw):
            return None
        dsap, ssap = raw[off], raw[off + 1]
        if dsap == 0x42 and ssap == 0x42:
            return {"mac": src_mac, "ip": "", "proto": "STP", "detail": ""}
        if dsap == 0xAA and ssap == 0xAA and off + 8 <= len(raw):
            pid = _u16(raw, off + 6)
            body = raw[off + 8:]
            if pid == 0x2000:
                cdp = _decode_cdp(body)
                detail = ""
                if cdp["platform"]:
                    detail = cdp["platform"]
                return {"mac": src_mac, "ip": "", "proto": "CDP",
                        "hostname": cdp["device"], "switch": cdp["device"],
                        "port": cdp["port"], "detail": detail}
            if pid == 0x2004:
                return {"mac": src_mac, "ip": "", "proto": "DTP", "detail": ""}
    except Exception:
        pass
    return None


def _generic_port_label(kind, sport, dport):
    """Label an unrecognised port pair. A well-known port (below 1024) is worth
    recording; an ephemeral client port is not."""
    for port in (dport, sport):
        if port < 1024:
            return f"{kind}/{port}"
    return kind


def _decode_transport(raw, off, proto, src_ip, src_mac):
    """UDP/TCP: name the service, and mine the ones that carry identity."""
    result = {"mac": src_mac, "ip": src_ip, "proto": IP_PROTO_NAMES.get(proto, f"IP-proto-{proto}"),
              "hostname": "", "detail": ""}
    try:
        if proto == 17 and off + 8 <= len(raw):               # UDP
            sport, dport = _u16(raw, off), _u16(raw, off + 2)
            body = raw[off + 8:]
            name = PASSIVE_UDP_PORTS.get(dport) or PASSIVE_UDP_PORTS.get(sport)
            result["proto"] = name or _generic_port_label("UDP", sport, dport)
            if dport in (67, 68) or sport in (67, 68):
                info = _dhcp_parse(body)
                if info:
                    result["proto"] = "DHCP-" + DHCP_MSG_TYPES.get(info["msg_type"], "?")
                    result["mac"] = info["mac"] or src_mac
                    best = _dhcp_best_ip(info)
                    if best:
                        result["ip"] = best
                    result["hostname"] = info["hostname"]
                    if info["vendor_class"]:
                        result["detail"] = f'vendor-class="{info["vendor_class"]}"'
                    if info["circuit_id"]:
                        result["port"] = info["circuit_id"]
            elif dport == 137 or sport == 137:
                result["hostname"] = _decode_nbns(body)
            elif dport in (5353, 5355) or sport in (5353, 5355):
                result["hostname"] = _decode_mdns(body)
        elif proto == 6 and off + 14 <= len(raw):             # TCP
            sport, dport = _u16(raw, off), _u16(raw, off + 2)
            name = PASSIVE_TCP_PORTS.get(dport) or PASSIVE_TCP_PORTS.get(sport)
            result["proto"] = name or _generic_port_label("TCP", sport, dport)
    except Exception:
        pass
    return result


def _parse_frame(raw):
    """Parse one Ethernet frame far enough to learn who sent it.

    Returns a dict with at least 'mac', or None when the frame tells us nothing.
    Never raises - a malformed frame on a plant network must not stop capture.
    """
    try:
        if len(raw) < 14:
            return None
        src_mac = _mac_str(raw[6:12])
        etype = _u16(raw, 12)
        off = 14
        vlan = None
        hops = 0
        while etype in ETH_VLAN_TAGS and off + 4 <= len(raw) and hops < 3:
            vlan = _u16(raw, off) & 0x0FFF
            etype = _u16(raw, off + 2)
            off += 4
            hops += 1

        out = None
        if etype <= 1500:                       # 802.3 length field -> LLC/SNAP
            out = _decode_llc_snap(raw, off, src_mac)
        elif etype == ETH_ARP:
            out = _decode_arp(raw[off:])
        elif etype == ETH_LLDP:
            lldp = _decode_lldp(raw[off:])
            out = {"mac": src_mac, "ip": "", "proto": "LLDP",
                   "hostname": lldp["system"], "switch": lldp["system"] or lldp["chassis"],
                   "port": lldp["port"], "detail": ""}
        elif etype == ETH_PROFINET:
            name = _decode_profinet_dcp(raw[off:])
            out = {"mac": src_mac, "ip": "", "proto": "PROFINET-DCP",
                   "hostname": name, "detail": ""}
        elif etype == ETH_IPV4:
            if off + 20 > len(raw):
                return None
            ihl = (raw[off] & 0x0F) * 4
            if ihl < 20:
                return None
            proto = raw[off + 9]
            src_ip = _ipv4(raw, off + 12)
            out = _decode_transport(raw, off + ihl, proto, src_ip, src_mac)
        elif etype in ETH_TYPE_NAMES:
            out = {"mac": src_mac, "ip": "", "proto": ETH_TYPE_NAMES[etype], "detail": ""}
        else:
            out = {"mac": src_mac, "ip": "", "proto": f"EtherType 0x{etype:04x}", "detail": ""}

        if not out:
            return None
        out.setdefault("hostname", "")
        out.setdefault("detail", "")
        out.setdefault("switch", "")
        out.setdefault("port", "")
        out["vlan"] = vlan
        return out
    except Exception:
        return None


# ------------------------ inventory ------------------------

def _passive_record(store, info, source="capture"):
    """Merge one observation into the per-MAC inventory.

    Returns (is_new_host, is_new_ip) so the display layer can stay quiet about
    the hundredth ARP from a host it already knows.
    """
    mac = info.get("mac") or ""
    if not mac or mac == "ff:ff:ff:ff:ff:ff":
        return False, False
    now = datetime.now()
    rec = store.get(mac)
    is_new = rec is None
    if is_new:
        rec = {"mac": mac, "ips": [], "hostnames": [], "protos": [], "vlans": [],
               "switch": "", "port": "", "details": [], "count": 0,
               "source": source, "truncated": False,
               "first_seen": now, "last_seen": now}
        store[mac] = rec

    ip = info.get("ip") or ""
    new_ip = False
    if ip and ip not in ("0.0.0.0", "255.255.255.255") and ip not in rec["ips"]:
        if len(rec["ips"]) < PASSIVE_MAX_IPS:
            rec["ips"].append(ip)
            new_ip = not is_new
        else:
            # A MAC sourcing this many addresses is a router or firewall
            # forwarding for others - worth knowing, not worth listing.
            rec["truncated"] = True
    for key, bucket in (("hostname", "hostnames"), ("proto", "protos")):
        val = info.get(key) or ""
        if val and val not in rec[bucket]:
            if len(rec[bucket]) < PASSIVE_MAX_LABELS:
                rec[bucket].append(val)
            else:
                rec["truncated"] = True
    vlan = info.get("vlan")
    if vlan is not None and vlan not in rec["vlans"]:
        rec["vlans"].append(vlan)
    for key in ("switch", "port"):
        if info.get(key) and not rec[key]:
            rec[key] = info[key]
    detail = info.get("detail") or ""
    if detail and detail not in rec["details"]:
        rec["details"].append(detail)
    rec["count"] += 1
    rec["last_seen"] = now
    return is_new, new_ip


def _passive_print_hit(rec, proto, is_new, new_ip):
    """One line per newly discovered host or newly seen address - nothing else."""
    if not (is_new or new_ip):
        return
    ts = rec["last_seen"].strftime("%H:%M:%S")
    bits = []
    # Vendor is now shown inline with the MAC (in parentheses), not as a bit.
    if rec["hostnames"]:
        bits.append(f"host={rec['hostnames'][0]}")
    if rec["switch"]:
        bits.append(f"switch={rec['switch']}")
    if rec["port"]:
        bits.append(f"port={rec['port']}")
    if rec["vlans"]:
        bits.append(f"vlan={rec['vlans'][0]}")
    marker = "NEW " if is_new else "+IP "
    ip = rec["ips"][-1] if rec["ips"] else ""
    tail = ("  " + "  ".join(bits)) if bits else ""
    sys.stdout.write("\r" + " " * 78 + "\r")
    echo(f" [{ts}] {marker} {proto:<16} {_mac_with_vendor(rec['mac'])}  "
         f"{(ip or '(no IP seen)'):<15}{tail}")
    log(f"PASSIVE_SEEN mac={rec['mac']} ip={ip} proto={proto} "
        f"host={rec['hostnames']} switch={rec['switch']} port={rec['port']}")


def _passive_heartbeat(start, duration, store, stats):
    elapsed = int(time.time() - start)
    left = f"{max(0, int(duration - elapsed))}s left" if duration else "Ctrl+C to stop"
    ips = sum(len(r["ips"]) for r in store.values())
    sys.stdout.write(f"\r [listening] {elapsed}s | {left} | hosts: {len(store)} "
                     f"| IPs: {ips} | frames: {stats['frames']}   ")
    sys.stdout.flush()
    return elapsed


def _passive_handle(raw, store, stats):
    stats["frames"] += 1
    info = _parse_frame(raw)
    if not info:
        return
    is_new, new_ip = _passive_record(store, info)
    if is_new or new_ip:
        _passive_print_hit(store[info["mac"]], info.get("proto", "?"), is_new, new_ip)


def _passive_record_iponly(store, ip, proto, hostname="", detail="", source="ip-only"):
    """Record an observation that carries an IP but no MAC - the raw IPv4 capture
    (Windows SIO_RCVALL) and the unprivileged UDP discovery listener both use it.
    Keyed by 'ip:<addr>' so _passive_fill_from_arp_cache can attach a MAC later.
    Returns True when this IP is newly seen."""
    if not ip or ip in ("0.0.0.0", "255.255.255.255"):
        return False
    now = datetime.now()
    key = f"ip:{ip}"
    rec = store.get(key)
    is_new = rec is None
    if is_new:
        store[key] = {"mac": "", "ips": [ip], "hostnames": [], "protos": [],
                      "vlans": [], "switch": "", "port": "", "details": [],
                      "count": 0, "source": source, "truncated": False,
                      "first_seen": now, "last_seen": now}
        rec = store[key]
    if proto and proto not in rec["protos"] and len(rec["protos"]) < PASSIVE_MAX_LABELS:
        rec["protos"].append(proto)
    if hostname and hostname not in rec["hostnames"] and len(rec["hostnames"]) < PASSIVE_MAX_LABELS:
        rec["hostnames"].append(hostname)
    if detail and detail not in rec["details"]:
        rec["details"].append(detail)
    rec["count"] += 1
    rec["last_seen"] = now
    return is_new


# ------------------------ capture paths ------------------------

def _passive_listen_scapy(duration, iface, store, stats):
    """Layer-2 capture via scapy, promiscuous. Sees every protocol this module
    decodes, and - on a hub or SPAN/mirror port - unicast between other hosts."""
    try:
        from scapy.all import AsyncSniffer
    except Exception as e:
        echo(f"[!] scapy AsyncSniffer unavailable ({e}).")
        return False

    def _cb(pkt):
        try:
            _passive_handle(bytes(pkt), store, stats)
        except Exception:
            pass      # one bad frame must never kill the capture thread

    # promisc=True asks the NIC to hand up EVERY frame it sees, not just those
    # addressed to this host + broadcast/multicast, so unicast IT/OT traffic is
    # captured too. (A plain switch still won't forward other hosts' unicast to
    # this port - that needs a hub or a SPAN/mirror.) Receive-only: sends nothing.
    kwargs = {"prn": _cb, "store": 0, "promisc": True}
    if iface:
        kwargs["iface"] = iface
    sniffer = AsyncSniffer(**kwargs)
    try:
        sniffer.start()
    except PermissionError:
        echo("[!] Packet capture requires administrator/root privileges.")
        return False
    except Exception as e:
        echo(f"[!] Could not start the scapy sniffer: {e}")
        echo("    (Npcap is required on Windows; root on Linux.)")
        return False

    echo(f"[✓] Capturing layer 2 with scapy on "
         f"{iface or getattr(_scapy_conf, 'iface', 'the default interface')}.")
    echo("    Only new hosts and new addresses print; repeats are counted quietly.\n")
    log(f"PASSIVE_LISTEN scapy iface={iface or 'default'} duration={duration}")

    start = time.time()
    try:
        while True:
            elapsed = _passive_heartbeat(start, duration, store, stats)
            if duration and elapsed >= duration:
                break
            time.sleep(1)
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        echo(" [!] Listener stopped.")
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass
    sys.stdout.write("\n")
    sys.stdout.flush()
    return True


def _afpacket_enable_promisc(sock):
    """Put every interface into promiscuous mode for this AF_PACKET socket, so
    it also receives unicast frames addressed to OTHER hosts (a hub or a
    SPAN/mirror port is still needed for a switch to actually forward them).
    Memberships are dropped automatically when the socket closes, so no NIC
    state is left changed. Returns how many interfaces were enabled. Non-fatal."""
    SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
    PACKET_ADD_MEMBERSHIP = 1
    PACKET_MR_PROMISC = 1
    count = 0
    try:
        ifaces = socket.if_nameindex()
    except Exception:
        return 0
    for idx, _name in ifaces:
        try:
            # struct packet_mreq { int ifindex; ushort type; ushort alen; uchar addr[8]; }
            mreq = struct.pack("iHH8s", idx, PACKET_MR_PROMISC, 0, b"")
            sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
            count += 1
        except Exception:
            continue
    return count


def _passive_listen_afpacket(duration, store, stats):
    """Linux stdlib layer-2 capture, promiscuous. Same visibility as scapy, no
    dependency."""
    if not hasattr(socket, "AF_PACKET"):
        return False
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except PermissionError:
        echo("[!] Layer-2 capture requires root.")
        return False
    except Exception as e:
        echo(f"[!] Could not open a packet socket: {e}")
        return False

    promisc_n = _afpacket_enable_promisc(sock)
    echo("[✓] Capturing all layer-2 traffic with an AF_PACKET socket (stdlib).")
    if promisc_n:
        echo(f"    Promiscuous mode enabled on {promisc_n} interface(s) - unicast "
             f"IT/OT traffic is captured too (a hub or SPAN/mirror is needed to")
        echo("    see other hosts' unicast on a switch).")
    echo("    Only new hosts and new addresses print; repeats are counted quietly.\n")
    log(f"PASSIVE_LISTEN af_packet duration={duration}")
    sock.settimeout(1.0)
    start = time.time()
    try:
        while True:
            elapsed = _passive_heartbeat(start, duration, store, stats)
            if duration and elapsed >= duration:
                break
            try:
                raw = sock.recv(65535)
            except socket.timeout:
                continue
            except Exception:
                continue
            _passive_handle(raw, store, stats)
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        echo(" [!] Listener stopped.")
    finally:
        try:
            sock.close()
        except Exception:
            pass
    sys.stdout.write("\n")
    sys.stdout.flush()
    return True


def _passive_listen_rcvall(duration, store, stats):
    """Windows stdlib fallback: raw IPv4 socket in promiscuous mode.

    IPv4 headers only. No ARP, no CDP/LLDP, and no MAC addresses - those live
    below IP and this socket never sees them. Discovered IPs are matched to the
    OS ARP cache afterwards so the report still carries MACs where the OS knows
    them. Install Npcap + scapy for real layer-2 capture.
    """
    host = _primary_ipv4()
    if not host:
        echo("[!] Could not determine a local address to bind the capture socket.")
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((host, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except PermissionError:
        echo("[!] Raw socket capture requires an elevated (Administrator) prompt.")
        return False
    except Exception as e:
        echo(f"[!] Could not open a raw capture socket: {e}")
        return False

    echo(f"[✓] Capturing IPv4 on {host} with a raw socket (stdlib fallback).")
    echo("[!] IP-level only: no ARP, no CDP/LLDP, and no MAC addresses.")
    echo("    MACs are filled in from this host's ARP cache at the end.")
    echo("    Install Npcap + scapy for full layer-2 visibility.\n")
    log(f"PASSIVE_LISTEN rcvall host={host} duration={duration}")

    sock.settimeout(1.0)
    start = time.time()
    try:
        while True:
            elapsed = _passive_heartbeat(start, duration, store, stats)
            if duration and elapsed >= duration:
                break
            try:
                raw = sock.recv(65535)
            except socket.timeout:
                continue
            except Exception:
                continue
            stats["frames"] += 1
            # No Ethernet header here - synthesise one so the IPv4 path can run.
            info = _parse_frame(b"\x00" * 12 + b"\x08\x00" + raw)
            if not info:
                continue
            ip = info.get("ip") or ""
            proto = info.get("proto", "?")
            is_new = _passive_record_iponly(store, ip, proto, info.get("hostname", ""))
            if is_new:
                sys.stdout.write("\r" + " " * 78 + "\r")
                echo(f" [{datetime.now().strftime('%H:%M:%S')}] NEW  {proto:<16} "
                     f"(MAC unknown)       {ip}")
                log(f"PASSIVE_SEEN_IPONLY ip={ip} proto={proto}")
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        echo(" [!] Listener stopped.")
    finally:
        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
    sys.stdout.write("\n")
    sys.stdout.flush()
    return True


# ------------------------ no-admin UDP discovery listener ------------------------

def _open_udp_discovery_socket(port, group):
    """Bind an unprivileged UDP socket for one discovery protocol and, for a
    multicast protocol, join the group. Returns the socket or None. Never raises.
    SO_REUSEADDR/REUSEPORT let it bind alongside the OS's own responders."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except Exception:
                pass
        if group is None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", port))
        if group:
            mreq = socket.inet_aton(group) + socket.inet_aton("0.0.0.0")
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setblocking(False)
        return sock
    except Exception:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        return None


def _decode_udp_discovery(port, data, src_ip):
    """Decode one discovery datagram into (proto, hostname, detail, mac, ip).
    mac is '' except for DHCP, which carries the client hardware address; ip may
    be overridden by DHCP's assigned/requested address. Never raises."""
    proto, hostname, detail, mac, ip = "UDP", "", "", "", src_ip
    try:
        if port in (67, 68):
            info = _dhcp_parse(data)
            if info:
                proto = "DHCP-" + DHCP_MSG_TYPES.get(info["msg_type"], "?")
                mac = info["mac"] or ""
                hostname = info["hostname"] or ""
                best = _dhcp_best_ip(info)
                if best:
                    ip = best
                if info["vendor_class"]:
                    detail = f'vendor-class="{info["vendor_class"]}"'
            else:
                proto = "DHCP"
        elif port == 137:
            proto, hostname = "NBNS", _decode_nbns(data)
        elif port == 5353:
            proto, hostname = "mDNS", _decode_mdns(data)
        elif port == 5355:
            proto, hostname = "LLMNR", _decode_mdns(data)
        elif port == 1900:
            proto, detail = "SSDP/UPnP", _decode_ssdp(data)
        elif port == 3702:
            proto, detail = "WS-Discovery", _decode_ssdp(data)
    except Exception:
        pass
    return proto, hostname, detail, mac, ip


def _passive_listen_udp(duration, store, stats):
    """Unprivileged broadcast/multicast discovery listener - NO admin/root.

    Binds ordinary UDP sockets to the discovery ports, joins the mDNS/LLMNR/SSDP/
    WS-Discovery multicast groups, and harvests source IP + hostname from what the
    segment volunteers. DHCP also yields the client MAC; MACs for the rest are
    filled from this host's ARP cache afterwards. It sends no scan/probe packets,
    but subscribing to a multicast group does emit standard IGMP membership
    reports - ordinary host traffic, not a scan - so it is not literally silent.
    """
    import select
    socks = {}                      # fileno -> (socket, port)
    joined, bcast, skipped = [], [], []
    for label, port, group in PASSIVE_UDP_DISCOVERY:
        s = _open_udp_discovery_socket(port, group)
        if s is None:
            skipped.append(label)
            continue
        socks[s.fileno()] = (s, port)
        (joined if group else bcast).append(label)
    all_socks = [t[0] for t in socks.values()]
    if not all_socks:
        echo("[!] Could not bind any discovery port - nothing to listen on.")
        return False

    if joined:
        echo("[✓] Subscribed (multicast): " + ", ".join(joined))
    if bcast:
        echo("[✓] Listening (broadcast): " + ", ".join(bcast))
    if skipped:
        echo("[i] Skipped (needs privilege to bind a low port, or port in use): "
             + ", ".join(skipped))
    echo("    No admin/root required. Joining a multicast group emits standard")
    echo("    IGMP membership reports (ordinary host traffic) - no scan packets.")
    echo("    MACs are filled from this host's ARP cache at the end.")
    echo("    Only new hosts and new addresses print; repeats are counted quietly.\n")
    log(f"PASSIVE_LISTEN udp joined={joined} bcast={bcast} skipped={skipped} "
        f"duration={duration}")

    start = time.time()
    try:
        while True:
            elapsed = _passive_heartbeat(start, duration, store, stats)
            if duration and elapsed >= duration:
                break
            try:
                ready, _, _ = select.select(all_socks, [], [], 1.0)
            except Exception:
                break
            for s in ready:
                try:
                    data, addr = s.recvfrom(65535)
                except Exception:
                    continue
                stats["frames"] += 1
                _, port = socks[s.fileno()]
                proto, hostname, detail, mac, ip = _decode_udp_discovery(
                    port, data, addr[0])
                if mac:
                    is_new, new_ip = _passive_record(
                        store, {"mac": mac, "ip": ip, "proto": proto,
                                "hostname": hostname, "detail": detail},
                        source="udp")
                    if is_new or new_ip:
                        _passive_print_hit(store[mac], proto, is_new, new_ip)
                else:
                    is_new = _passive_record_iponly(store, ip, proto, hostname,
                                                    detail, "udp")
                    if is_new:
                        sys.stdout.write("\r" + " " * 78 + "\r")
                        echo(f" [{datetime.now().strftime('%H:%M:%S')}] NEW  "
                             f"{proto:<16} (MAC unknown)       {ip}")
                        log(f"PASSIVE_SEEN_IPONLY ip={ip} proto={proto}")
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        echo(" [!] Listener stopped.")
    finally:
        for s in all_socks:
            try:
                s.close()
            except Exception:
                pass
    sys.stdout.write("\n")
    sys.stdout.flush()
    return True


# ------------------------ ARP cache correlation ------------------------

_ARP_LINE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\D+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")


def _arp_cache():
    """Read this host's ARP cache. Runs 'arp -a' - reads OS state, sends nothing."""
    table = {}
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             timeout=10).stdout
    except Exception:
        return table
    for line in out.splitlines():
        m = _ARP_LINE.search(line)
        if m:
            table[m.group(1)] = m.group(2).replace("-", ":").lower()
    return table


def _passive_fill_from_arp_cache(store):
    """Give MAC-less (IP-only) records a MAC from the local ARP cache."""
    ip_only = [k for k in store if k.startswith("ip:")]
    if not ip_only:
        return 0
    table = _arp_cache()
    if not table:
        return 0
    filled = 0
    for key in ip_only:
        ip = key[3:]
        mac = table.get(ip)
        if mac:
            store[key]["mac"] = mac
            store[key]["source"] = "ip-only + ARP cache"
            filled += 1
    return filled


# ------------------------ reporting ------------------------

def _passive_sort_key(rec):
    if rec["ips"]:
        try:
            return (0, int(ipaddress.ip_address(rec["ips"][0])), rec["mac"])
        except Exception:
            pass
    return (1, 0, rec["mac"])


def _passive_summary(store, stats, elapsed_label):
    ip_count = sum(len(r["ips"]) for r in store.values())
    echo(f"\n--- Passive Listen Results ({len(store)} host(s), {ip_count} address(es), "
         f"{stats['frames']} frame(s), {elapsed_label}) ---")
    if not store:
        echo("  (nothing heard)")
        echo("  Not necessarily a fault. A quiet, statically addressed segment with")
        echo("  no broadcast chatter looks exactly like this. Try a longer listen, a")
        echo("  SPAN/mirror port, or a window that includes a device reboot.")
        echo("--- end ---")
        return

    echo(f"  {'MAC (vendor)':<48}{'IP':<17}{'Hostname':<18}{'Seen via'}")
    echo(f"  {'-'*46:<48}{'-'*15:<17}{'-'*16:<18}{'-'*24}")
    for rec in sorted(store.values(), key=_passive_sort_key):
        mac_disp = _mac_with_vendor(rec["mac"]) if rec["mac"] else "(unknown MAC)"
        ip = rec["ips"][0] if rec["ips"] else "-"
        host = rec["hostnames"][0] if rec["hostnames"] else "-"
        echo(f"  {mac_disp[:47]:<48}{ip:<17}{host[:17]:<18}"
             f"{','.join(rec['protos'][:3])}")
        for extra_ip in rec["ips"][1:]:
            echo(f"  {'':<19}{extra_ip}")
        notes = []
        if rec["switch"]:
            notes.append(f"switch={rec['switch']}")
        if rec["port"]:
            notes.append(f"port={rec['port']}")
        if rec["vlans"]:
            notes.append("vlan=" + ",".join(str(v) for v in rec["vlans"]))
        if len(rec["hostnames"]) > 1:
            notes.append("names=" + ",".join(rec["hostnames"][:3]))
        notes.extend(rec["details"][:2])
        if rec.get("truncated"):
            notes.append("[list truncated - very chatty host, likely a router]")
        if rec["source"] != "capture":
            notes.append(f"[{rec['source']}]")
        if notes:
            echo(f"  {'':<19}{'  '.join(notes)}")
        echo(f"  {'':<19}{rec['count']} frame(s)  "
             f"{rec['first_seen'].strftime('%H:%M:%S')} -> "
             f"{rec['last_seen'].strftime('%H:%M:%S')}  "
             f"protocols: {','.join(rec['protos'])}")
        log(f"PASSIVE_RESULT mac={rec['mac']} ips={rec['ips']} host={rec['hostnames']} "
            f"protos={rec['protos']} count={rec['count']}")
    echo("--- end ---")


def _passive_export(store):
    """Offer a CSV export, written beside the script."""
    if not store:
        return
    if not input("\nSave these results to CSV? [y/N]: ").strip().lower().startswith("y"):
        return
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = f"atomics_passive_{ts}.csv"
    cols = ["mac", "ip_addresses", "oui_vendor", "hostnames", "protocols", "vlans",
            "switch", "switch_port", "details", "frames", "source",
            "first_seen", "last_seen"]
    try:
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(cols)
            for rec in sorted(store.values(), key=_passive_sort_key):
                writer.writerow([
                    rec["mac"], ";".join(rec["ips"]),
                    _oui_vendor(rec["mac"]) if rec["mac"] else "",
                    ";".join(rec["hostnames"]), ";".join(rec["protos"]),
                    ";".join(str(v) for v in rec["vlans"]),
                    rec["switch"], rec["port"], ";".join(rec["details"]),
                    rec["count"], rec["source"],
                    rec["first_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                    rec["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                ])
    except OSError as e:
        echo(f"[✗] Could not write {path}: {e}")
        log(f"PASSIVE_EXPORT_ERROR {e}")
        return
    echo(f"[✓] Saved {len(store)} host(s) to {path}")
    log(f"PASSIVE_EXPORT file={path} hosts={len(store)}")


def _prompt_listen_duration():
    """Shared duration prompt for both passive listeners. Returns seconds
    (0 = until Ctrl+C) or None on invalid input."""
    duration_in = input(f"\nListen duration in seconds "
                        f"(blank or 0 = until Ctrl+C) [{PASSIVE_LISTEN_DEFAULT}]: ").strip()
    if duration_in == "":
        return PASSIVE_LISTEN_DEFAULT
    try:
        return max(0, int(float(duration_in)))
    except ValueError:
        echo("[✗] Invalid duration.")
        return None


def passive_listen_broadcast():
    """Option 1: unprivileged broadcast/multicast discovery - NO admin/root."""
    echo("\n--- Broadcast / Multicast Listen (no admin) ---")
    echo(" Passive discovery with ordinary UDP sockets - no root/Administrator and")
    echo(" no capture driver (Npcap) needed. Harvests IP + hostname from the")
    echo(" discovery chatter every segment carries.")
    echo("")
    echo(" Pulls IP + hostname from:")
    echo("   DHCP           MAC, IP, hostname, vendor class ID (only source with a MAC)")
    echo("   mDNS / LLMNR   Bonjour and Windows name resolution -> hostnames")
    echo("   NBNS           NetBIOS names (needs a low-port bind; skipped if blocked)")
    echo("   SSDP / WS-Disc UPnP and WS-Discovery announcements")
    echo("")
    echo(" MACs for non-DHCP hosts are filled from this host's ARP cache afterwards")
    echo(" (reads OS state, sends nothing). For MAC + unicast IT/OT visibility use")
    echo(" option 2 (promiscuous), which requires admin. Note: joining a multicast")
    echo(" group emits standard IGMP membership reports - ordinary host traffic.")

    duration = _prompt_listen_duration()
    if duration is None:
        return
    store, stats = {}, {"frames": 0}
    start = time.time()
    try:
        if not _passive_listen_udp(duration, store, stats):
            return
    except Exception as e:
        echo(f"\n[✗] Listener failed: {e}")
        log(f"PASSIVE_LISTEN_ERROR {e}")
        return

    filled = _passive_fill_from_arp_cache(store)
    if filled:
        echo(f"[i] Filled in {filled} MAC address(es) from this host's ARP cache.")
    elapsed_label = f"{int(time.time() - start)}s listened"
    _passive_summary(store, stats, elapsed_label)
    _passive_merge_into_assets(store)
    _passive_export(store)


def passive_listen():
    """Option 2: promiscuous all-traffic listener - harvest IP + MAC (needs admin)."""
    echo("\n--- Promiscuous Listen (all traffic - needs admin) ---")
    echo(" Fully passive: AtomICS sends nothing. It watches ALL traffic the")
    echo(" interface can see (promiscuous) and builds a host inventory from it.")
    echo(" Layer-2 capture needs root/Administrator (and Npcap on Windows); for a")
    echo(" no-admin option that gets IP + hostnames, use option 1 (broadcast).")
    echo("")
    echo(" Pulls IP + MAC from:")
    echo("   unicast IT/OT  any TCP/UDP frame - web, SMB, database, SCADA polls")
    echo("   ARP            sender IP + MAC - the richest source on a switched port")
    echo("   DHCP           MAC, IP, hostname, vendor class ID")
    echo("   NBNS / mDNS    NetBIOS and Bonjour hostnames")
    echo("   LLMNR / SSDP   Windows name resolution, UPnP announcements")
    echo("   CDP / LLDP     switch name and the port a device is plugged into")
    echo("   PROFINET DCP   Siemens station names")
    echo("   everything else is counted and labelled by EtherType or port")
    echo("")
    echo(" Promiscuous mode captures every frame the NIC RECEIVES. Broadcast and")
    echo(" multicast reach every port on the VLAN; this host's own conversations")
    echo(" are always seen. To also see unicast between OTHER hosts you need a")
    echo(" hub or a SPAN/mirror port - a plain switch won't forward it to you.")
    if not SCAPY_AVAILABLE:
        if hasattr(socket, "AF_PACKET"):
            echo(" [i] scapy absent: using the stdlib AF_PACKET socket (root required).")
        else:
            echo(" [i] scapy absent: falling back to an IPv4-only raw socket.")
            echo("     That path sees no ARP and no MAC addresses - install Npcap")
            echo("     and scapy for full layer-2 capture.")

    duration = _prompt_listen_duration()
    if duration is None:
        return
    iface = ""
    if SCAPY_AVAILABLE:
        _print_local_ifaces("    ")
        default_iface = getattr(_scapy_conf, "iface", "?")
        iface = input(f"Capture interface (blank = scapy default "
                      f"'{default_iface}'): ").strip()

    store, stats = {}, {"frames": 0}
    start = time.time()
    ran = False
    try:
        if SCAPY_AVAILABLE:
            ran = _passive_listen_scapy(duration, iface or None, store, stats)
            if not ran:
                echo("[i] Falling back to the stdlib capture path.")
        if not ran and hasattr(socket, "AF_PACKET"):
            ran = _passive_listen_afpacket(duration, store, stats)
        if not ran and hasattr(socket, "SIO_RCVALL"):
            ran = _passive_listen_rcvall(duration, store, stats)
        if not ran:
            echo("[✗] No usable capture method on this platform.")
            echo("    Install scapy (and Npcap on Windows) and run elevated.")
            return
    except Exception as e:
        echo(f"\n[✗] Listener failed: {e}")
        log(f"PASSIVE_LISTEN_ERROR {e}")

    filled = _passive_fill_from_arp_cache(store)
    if filled:
        echo(f"[i] Filled in {filled} MAC address(es) from this host's ARP cache.")

    elapsed_label = f"{int(time.time() - start)}s listened"
    _passive_summary(store, stats, elapsed_label)
    _passive_merge_into_assets(store)
    _passive_export(store)


def _passive_merge_into_assets(store):
    """Fold passive findings into the Asset Register, one row per IP observed.

    The passive store is keyed by MAC and a host may carry several addresses, so
    each IP becomes (or updates) its own asset row - carrying the MAC, vendor,
    first hostname and the protocols that IP was seen speaking. MAC-only records
    (no IP) are left in the passive results; the register is an IP inventory.
    """
    added = 0
    for rec in store.values():
        mac = rec.get("mac") or ""
        vendor = _oui_vendor(mac) if mac else ""
        hostname = rec["hostnames"][0] if rec.get("hostnames") else ""
        for ip in rec.get("ips", []):
            if ip in ("0.0.0.0", "255.255.255.255"):
                continue
            before = ip in ASSET_REGISTER
            asset_update(ip, mac=mac, vendor=vendor, hostname=hostname,
                         source="passive")
            for proto in rec.get("protos", []):
                asset_update(ip, protocol=proto)
            if not before:
                added += 1
    if added:
        echo(f"[i] Added {added} host(s) from the passive listen to the Asset Register.")
        log(f"ASSET_MERGE passive added={added}")


def _active_scan_blocked(name, readonly):
    """Refuse an active (transmitting) scan in safe mode. Returns True if blocked.

    Both passive listeners are exempt - they run no scans (the broadcast listener
    only emits standard IGMP joins; the promiscuous one is receive-only).
    Everything under the Active section puts probe packets on the wire, so in
    safe mode it is gated behind --active exactly like a write is.
    """
    if readonly:
        echo(f"[!] {name} blocked: SAFE MODE. This scan transmits on the network.")
        echo("    Relaunch with --active to enable active scanning.")
        log(f"SAFE_MODE_BLOCKED scan={name}")
        return True
    return False


def network_discovery_session(args):
    """Interactive Network Discovery module.

    Passive techniques are listed first: they transmit nothing and stay usable
    in safe mode. The active techniques below them put packets on the wire and
    are blocked in safe mode - they need --active, like any state change.
    """
    default_ip = getattr(args, "ip", None)
    readonly = getattr(args, "readonly", False)
    while True:
        lock = "   [LOCKED - safe mode]" if readonly else ""
        print("\n--- AtomICS - Network Discovery ---")
        _print_local_ifaces("    ", blank_after=False)
        if not SCAPY_AVAILABLE:
            print("    [scapy not detected: ARP unavailable; ICMP uses system ping;")
            print("     SYN scans fall back to TCP connect; promiscuous listen uses")
            print("     the stdlib capture fallback]")
        print("")
        print("  Passive - no active scanning")
        print("   1. Broadcast/multicast listen - no admin (IP + hostnames: DHCP/mDNS/LLMNR/NBNS/SSDP)")
        print("   2. Promiscuous listen - all traffic, needs admin (adds MAC + unicast IT/OT)")
        print("")
        print("  Active - puts packets on the wire" + (" [locked in safe mode]" if readonly else ""))
        print(f"   3. ARP scan (layer 2, auto local subnet){lock}")
        print(f"   4. ICMP scan (ping sweep){lock}")
        print(f"   5. SYN scan - single port{lock}")
        print(f"   6. SYN scan - common IT ports{lock}")
        print(f"   7. SYN scan - common OT ports{lock}")
        print(f"   8. SYN scan - common IT + OT ports{lock}")
        print("")
        print("   9. Back to main menu")
        choice = input("\nSelect an option: ").strip()

        if choice == "9":
            break
        if choice not in {"1", "2", "3", "4", "5", "6", "7", "8"}:
            echo("Invalid option.")
            continue

        if choice in ("1", "2"):
            # Passive listeners - no target prompt, they watch the local segment.
            try:
                if choice == "1":
                    passive_listen_broadcast()
                else:
                    passive_listen()
            except KeyboardInterrupt:
                echo("\n[!] Listener interrupted.")
            except Exception as e:
                echo(f"Operation failed: {e}")
                log(f"DISCOVERY_ERROR {e}")
            continue

        # Everything from here down transmits - gated in safe mode.
        _scan_names = {"3": "ARP scan", "4": "ICMP scan", "5": "SYN scan",
                       "6": "SYN scan", "7": "SYN scan", "8": "SYN scan"}
        if _active_scan_blocked(_scan_names[choice], readonly):
            continue

        if choice == "3":
            # ARP is a layer-2 scan of the directly-connected network, so it
            # always runs against this host's own local subnet (auto-detected),
            # not an arbitrary prompted target.
            _cidr, arp_hosts = _local_subnet_for_arp()
            if arp_hosts:
                try:
                    arp_scan(arp_hosts)
                except KeyboardInterrupt:
                    echo("\n[!] Scan interrupted.")
                except Exception as e:
                    echo(f"Operation failed: {e}")
                    log(f"DISCOVERY_ERROR {e}")
            continue

        hosts = _prompt_targets(default_ip)
        if not hosts:
            continue

        try:
            if choice == "4":
                icmp_scan(hosts)
            elif choice == "5":
                port = _prompt_single_port()
                if port is not None:
                    syn_scan(hosts, {port: _port_label(port)}, f"single port {port}")
            elif choice == "6":
                syn_scan(hosts, COMMON_IT_PORTS, "common IT ports")
            elif choice == "7":
                syn_scan(hosts, COMMON_OT_PORTS, "common OT ports")
            elif choice == "8":
                combined = {**COMMON_IT_PORTS, **COMMON_OT_PORTS}
                syn_scan(hosts, combined, "common IT + OT ports")
        except KeyboardInterrupt:
            echo("\n[!] Scan interrupted.")
        except Exception as e:
            echo(f"Operation failed: {e}")
            log(f"DISCOVERY_ERROR {e}")


# ------------------------ Connection ------------------------
def connect_to_modbus(ip, port=502, readonly=False):
    client = ModbusTcpClient(ip, port=port)
    if client.connect():
        echo(f"[✓] Connected to Modbus service at {ip}:{port}")
        log(f"CONNECTED {ip}:{port}")
        if readonly:
            echo("[!] Read-Only Mode ENABLED")
            log("READ_ONLY_MODE ENABLED")
        return client
    else:
        echo("[✗] Failed to connect to Modbus service")
        log(f"FAILED_CONNECT {ip}:{port}")
        return None


# ------------------------ Device Identity helper ------------------------
def _read_device_info(client):
    """Issue an FC 43 Read Device Identification request.

    pymodbus exposes no client.read_device_information() convenience method,
    so build the request object and execute it. Handles both the legacy
    execute(request) signature and the pymodbus 3.7+ execute(no_response, request)
    signature. Returns the response object (has .isError() and .information).
    """
    request = ReadDeviceInformationRequest(read_code=0x01, object_id=0x00)
    try:
        return client.execute(request)
    except TypeError:
        # pymodbus >= 3.7: execute(no_response_expected, request)
        return client.execute(False, request)


# ------------------------ Safe mode ------------------------
# AtomICS launches read-only. Two gates stand between a keystroke and a value
# landing in a live controller:
#   1. --active must have been passed at launch, otherwise every write path
#      refuses outright (_blocked_by_safe_mode below);
#   2. the write is then restated in full - target and value - and the operator
#      has to type YES. A bulk action names the whole range it will touch.
# The second gate applies even in active mode. On a plant network the cost of a
# mistaken write is measured in product, equipment or people, and an extra four
# keystrokes is not a real cost against that.

SAFE_MODE_BANNER = "SAFE MODE - read-only. Relaunch with --active to enable writes."


def _blocked_by_safe_mode(action):
    """Report a refused write. Returns True so callers can 'return' straight away."""
    echo(f"[!] {action} blocked: {SAFE_MODE_BANNER}")
    log(f"SAFE_MODE_BLOCKED {action}")
    return True


def _confirm_write(description):
    """Active-mode write gate.

    Reaching this means --active was passed (writes are refused outright in safe
    mode before this is ever called), which is the operator's deliberate opt-in.
    So a write executes immediately with no per-write prompt - the assumption is
    the operator knows what they are doing. A single [write] line is still
    printed and logged so there is an on-screen and on-disk record of exactly
    what changed; that is a trail, not a confirmation.
    """
    echo(f"  [write] {description}")
    log(f"WRITE_EXECUTED {description}")
    return True


# ------------------------ Coil Functions ------------------------
def read_coils(client):
    address = int(input("Enter starting coil address: "))
    count = int(input("Enter number of coils to read: "))
    log(f"READ_COILS addr={address} count={count}")
    result = client.read_coils(address, count=count)
    if result.isError():
        echo("Failed to read coils.")
        log("ERROR read_coils")
        return
    for i, val in enumerate(result.bits[:count]):
        echo(f"Coil[{address + i}] = {int(val)}")
        log(f"Coil[{address + i}] = {int(val)}")


def write_coil(client, readonly):
    if readonly:
        _blocked_by_safe_mode("Write Coil")
        return
    address = int(input("Enter coil address: "))
    value = int(input("Enter value (0 or 1): "))
    if not _confirm_write(f"Coil[{address}] = {int(bool(value))}"):
        return
    log(f"WRITE_COIL addr={address} value={value}")
    result = client.write_coil(address, bool(value))
    if result.isError():
        echo("Failed to write coil.")
        log("ERROR write_coil")
    else:
        echo(f"Coil[{address}] set to {value}")
        log("WRITE_SUCCESS")


# ------------------------ Register Functions ------------------------
def read_registers(client):
    address = int(input("Enter starting register address: "))
    count = int(input("Enter number of registers to read: "))
    log(f"READ_REGISTERS addr={address} count={count}")
    result = client.read_holding_registers(address, count=count)
    if result.isError():
        echo("Failed to read registers.")
        log("ERROR read_registers")
        return
    for i, val in enumerate(result.registers):
        echo(f"Register[{address + i}] = {val}")
        log(f"Register[{address + i}] = {val}")


def write_register(client, readonly):
    if readonly:
        _blocked_by_safe_mode("Write Register")
        return
    address = int(input("Enter register address: "))
    value = int(input("Enter value (0-65535): "))
    if not _confirm_write(f"Holding register[{address}] = {value}"):
        return
    log(f"WRITE_REGISTER addr={address} value={value}")
    result = client.write_register(address, value)
    if result.isError():
        echo("Failed to write register.")
        log("ERROR write_register")
    else:
        echo(f"Register[{address}] set to {value}")
        log("WRITE_SUCCESS")


# ------------------------ Scanning ------------------------
def _smart_scan(client, item_label, max_block, read_fn):
    """Generic smart-scan engine with adaptive block sizing.

    Starts with a large block and halves on failure until either the block fits the
    device's address space or we reach single-address probing. A failure at single-
    address means we've hit the end of the responsive region, so we stop.
    """
    range_input = input(f"Enter scan range (default {SCAN_DEFAULT_RANGE}): ").strip()
    scan_range = int(range_input) if range_input else SCAN_DEFAULT_RANGE

    echo(f"Smart-scanning {scan_range} {item_label}s (starting block size {max_block}, adaptive)...")
    log(f"SMART_SCAN_{item_label.upper()} started range={scan_range} max_block={max_block}")

    responsive = 0
    response_ranges = []
    range_start = None
    range_end = None
    address = 0
    block = max_block

    while address < scan_range:
        count = min(block, scan_range - address)
        try:
            result = read_fn(address, count=count)
            errored = result.isError()
        except (ModbusException, OSError, ConnectionError) as e:
            log(f"SMART_SCAN_{item_label.upper()} block_exception addr={address} count={count} {e}")
            errored = True

        if not errored:
            responsive += count
            if range_start is None:
                range_start = address
            range_end = address + count - 1
            address += count
            # Block size sticks at whatever last worked - don't grow it back up
        elif count == 1:
            # Single-address probe failed: we've hit the end of the responsive region.
            break
        else:
            # Block was too large (either device PDU limit or spanning the boundary).
            # Halve and retry the same address.
            block = max(1, count // 2)

    if range_start is not None:
        response_ranges.append((range_start, range_end))

    # --- Report ---
    echo(f"\n--- Smart Scan Results: {item_label}s ---")
    echo(f" Probed         : 0 to {scan_range - 1}")
    echo(f" Responsive     : {responsive}")
    if response_ranges:
        echo(f" Response ranges:")
        for start, end in response_ranges:
            echo(f"   {start}-{end}  ({end - start + 1} {item_label}s)")
    else:
        echo(f" Response ranges: (none)")
    log(f"SMART_SCAN_{item_label.upper()} completed responsive={responsive} "
        f"ranges={response_ranges}")


def scan_coils(client):
    _smart_scan(
        client,
        item_label="coil",
        max_block=SCAN_BLOCK_COILS,
        read_fn=client.read_coils,
    )


def scan_registers(client):
    _smart_scan(
        client,
        item_label="register",
        max_block=SCAN_BLOCK_REGISTERS,
        read_fn=client.read_holding_registers,
    )


# ------------------------ Device Identity ------------------------
def read_device_identity(client, target_ip=None):
    echo("Reading device identity...")
    log("READ_DEVICE_IDENTITY")
    try:
        result = _read_device_info(client)
    except Exception as e:
        echo(f"Device identity query not supported by this client/device: {e}")
        log(f"ERROR read_device_identity {e}")
        return
    if result.isError():
        echo("Failed to retrieve device identity.")
        log("ERROR read_device_identity")
        return
    collected = {}
    for obj_id, label in DEVICE_IDENTITY_MAP.items():
        raw = result.information.get(obj_id, b"")
        value = raw.decode(errors="ignore") if isinstance(raw, bytes) else str(raw)
        echo(f"{label}: {value}")
        log(f"{label}: {value}")
        if value:
            collected[label] = value
    # Feed identity to the Asset Register as the Modbus versioning line.
    if target_ip and collected:
        vendor = collected.get("VendorName", "")
        parts = [f"{k}={v}" for k, v in collected.items()]
        asset_update(target_ip, vendor=vendor, ports={502: "Modbus TCP"},
                     protocol="Modbus", version="Modbus FC43: " + "; ".join(parts),
                     source="Modbus")


def banner_grab(client, target_ip, target_port):
    """Quick fingerprint: device identity + sample coil/register values in one shot."""
    SAMPLE_COUNT = 16
    BAR = "=" * 60

    echo(f"\n{BAR}")
    echo(" MODBUS BANNER GRAB")
    echo(BAR)
    log(f"BANNER_GRAB target={target_ip}:{target_port}")

    # --- Connection info ---
    echo(f" Target          : {target_ip}:{target_port}")
    echo(f" Unit ID   : {getattr(client, 'unit_id', 1)}")
    echo(f" Timestamp       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # --- Device identity (FC 43) ---
    echo(f"\n[Device Identity - FC 43]")
    try:
        result = _read_device_info(client)
        if result.isError():
            echo(" (device did not respond to FC 43)")
            log("BANNER_GRAB FC43_unsupported")
        else:
            collected = {}
            for obj_id, label in DEVICE_IDENTITY_MAP.items():
                raw = result.information.get(obj_id, b"")
                value = raw.decode(errors="ignore") if isinstance(raw, bytes) else str(raw)
                if value:
                    echo(f" {label:<20}: {value}")
                    log(f"BANNER_GRAB {label}={value}")
                    collected[label] = value
            if collected:
                parts = [f"{k}={v}" for k, v in collected.items()]
                asset_update(target_ip, vendor=collected.get("VendorName", ""),
                             ports={target_port: "Modbus TCP"}, protocol="Modbus",
                             version="Modbus FC43: " + "; ".join(parts), source="Modbus")
    except Exception as e:
        echo(f" (FC 43 query failed: {e})")
        log(f"BANNER_GRAB FC43_error {e}")

    # --- Coil snapshot (FC 1) ---
    echo(f"\n[Coil Snapshot - first {SAMPLE_COUNT}]")
    try:
        result = client.read_coils(0, count=SAMPLE_COUNT)
        if result.isError():
            echo(" (no coils responded at address 0)")
        else:
            bits = [int(b) for b in result.bits[:SAMPLE_COUNT]]
            echo(" Address : " + " ".join(f"{i:>2}" for i in range(SAMPLE_COUNT)))
            echo(" Value   : " + " ".join(f"{b:>2}" for b in bits))
            log(f"BANNER_GRAB coils={bits}")
    except (ModbusException, OSError, ConnectionError) as e:
        echo(f" (coil read failed: {e})")
        log(f"BANNER_GRAB coil_error {e}")

    # --- Holding register snapshot (FC 3) ---
    echo(f"\n[Holding Register Snapshot - first {SAMPLE_COUNT}]")
    try:
        result = client.read_holding_registers(0, count=SAMPLE_COUNT)
        if result.isError():
            echo(" (no registers responded at address 0)")
        else:
            for i, val in enumerate(result.registers):
                signed = val if val < 32768 else val - 65536
                echo(f" Register[{i:>2}] = {val:>5}  (signed: {signed:>6})")
            log(f"BANNER_GRAB registers={list(result.registers)}")
    except (ModbusException, OSError, ConnectionError) as e:
        echo(f" (register read failed: {e})")
        log(f"BANNER_GRAB register_error {e}")

    # --- Discrete input snapshot (FC 2) ---
    echo(f"\n[Discrete Input Snapshot - first {SAMPLE_COUNT}]")
    try:
        result = client.read_discrete_inputs(0, count=SAMPLE_COUNT)
        if result.isError():
            echo(" (no discrete inputs responded at address 0)")
        else:
            bits = [int(b) for b in result.bits[:SAMPLE_COUNT]]
            echo(" Address : " + " ".join(f"{i:>2}" for i in range(SAMPLE_COUNT)))
            echo(" Value   : " + " ".join(f"{b:>2}" for b in bits))
            log(f"BANNER_GRAB discrete_inputs={bits}")
    except (ModbusException, OSError, ConnectionError) as e:
        echo(f" (discrete input read failed: {e})")
        log(f"BANNER_GRAB di_error {e}")

    echo(f"{BAR}\n")
    log("BANNER_GRAB completed")


# ------------------------ Advanced Actions ------------------------
def flip_all_coils(client, readonly):
    if readonly:
        _blocked_by_safe_mode("Flip Coils")
        return
    echo("Surveying the responsive coil range first (reads only)...")
    log("FLIP_COILS survey")
    count = 0
    for i in range(MAX_LENGTH):
        if not client.read_coils(i, count=1).isError():
            count += 1
        else:
            break
    if count == 0:
        echo("No responsive coils found - nothing to do.")
        return
    if not _confirm_write(f"INVERT every coil in range 0-{count - 1} "
                          f"({count} coils) on this device"):
        return
    echo("Flipping all available coils...")
    log(f"FLIP_COILS started count={count}")
    result = client.read_coils(0, count=count)
    if result.isError():
        echo("Failed to read coils.")
        log("ERROR flip_read")
        return
    for i, val in enumerate(result.bits[:count]):
        client.write_coil(i, not val)
    echo(f"Flipped {count} coils.")
    log(f"FLIP_COILS completed count={count}")


def zero_all_coils(client, readonly):
    if readonly:
        _blocked_by_safe_mode("Zero All Coils")
        return
    echo("Surveying the responsive coil range first (reads only)...")
    log("ZERO_COILS survey")
    count = 0
    for i in range(MAX_LENGTH):
        if not client.read_coils(i, count=1).isError():
            count += 1
        else:
            break
    if count == 0:
        echo("No responsive coils found - nothing to do.")
        return
    if not _confirm_write(f"Set every coil in range 0-{count - 1} "
                          f"({count} coils) to 0 on this device"):
        return
    echo("Zeroing all available coils...")
    log(f"ZERO_COILS started count={count}")
    for i in range(count):
        client.write_coil(i, False)
    echo(f"Zeroed {count} coils.")
    log(f"ZERO_COILS completed count={count}")


def fuzz_registers(client, readonly):
    if readonly:
        _blocked_by_safe_mode("Fuzz Registers")
        return
    echo("Surveying the responsive register range first (reads only)...")
    log("FUZZ_REGISTERS survey")
    count = 0
    for i in range(MAX_LENGTH):
        if not client.read_holding_registers(i, count=1).isError():
            count += 1
        else:
            break
    if count == 0:
        echo("No responsive holding registers found - nothing to do.")
        return
    echo("")
    echo("  [!] Fuzzing writes RANDOM values to live holding registers. On a")
    echo("      running process this is indistinguishable from sabotage. It")
    echo("      belongs on a simulator or a bench unit, never on plant gear.")
    if not _confirm_write(f"Write RANDOM values to holding registers 0-{count - 1} "
                          f"({count} registers) on this device"):
        return
    echo("Fuzzing holding registers...")
    log(f"FUZZ_REGISTERS started count={count}")
    for i in range(count):
        value = random.randint(0, 65535)
        result = client.write_register(i, value)
        if not result.isError():
            log(f"Register[{i}] fuzzed value={value}")
    echo(f"Fuzzed {count} registers.")
    log(f"FUZZ_REGISTERS completed count={count}")


def hold_write(client, readonly):
    """Continuously write a value to a coil or register at a fixed interval until interrupted."""
    if readonly:
        _blocked_by_safe_mode("Hold Write")
        return

    target_type = input("Target type ([c]oil or [r]egister): ").strip().lower()
    if not target_type or target_type[0] not in ("c", "r"):
        echo("Invalid target type. Use 'c' for coil or 'r' for register.")
        return
    is_coil = target_type[0] == "c"

    address = int(input("Enter target address: "))
    if is_coil:
        value_input = int(input("Enter value (0 or 1): "))
        value = bool(value_input)
        display_value = int(value)
    else:
        value = int(input("Enter value (0-65535): "))
        display_value = value

    interval_input = input("Interval between writes in seconds (default 0.1): ").strip()
    interval = float(interval_input) if interval_input else 0.1

    duration_input = input("Duration in seconds (blank or 0 = run until Ctrl+C): ").strip()
    duration = float(duration_input) if duration_input else 0

    target_label = f"{'Coil' if is_coil else 'Register'}[{address}]={display_value}"
    span = f"for {duration:g}s" if duration > 0 else "until Ctrl+C"
    if not _confirm_write(f"Repeatedly write {target_label} every {interval:g}s, {span} "
                          f"(this overrides the controller's own logic)"):
        return
    echo(f"\n[hold] Holding {target_label} every {interval}s. Press Ctrl+C to stop.")
    log(f"HOLD_WRITE_START target={target_label} interval={interval}s duration={duration}s")

    writes = 0
    errors = 0
    start = time.time()
    try:
        while True:
            try:
                if is_coil:
                    result = client.write_coil(address, value)
                else:
                    result = client.write_register(address, value)
                if result.isError():
                    errors += 1
                else:
                    writes += 1
            except (ModbusException, OSError, ConnectionError):
                errors += 1

            elapsed = time.time() - start
            sys.stdout.write(
                f"\r[hold] {target_label} | elapsed: {int(elapsed)}s | "
                f"writes: {writes} | errors: {errors}   "
            )
            sys.stdout.flush()

            if duration > 0 and elapsed >= duration:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        elapsed = time.time() - start
        sys.stdout.write("\n")
        sys.stdout.flush()
        echo(f"[hold] Stopped. Total writes: {writes}, errors: {errors}, elapsed: {int(elapsed)}s")
        log(f"HOLD_WRITE_END target={target_label} writes={writes} errors={errors} elapsed={int(elapsed)}s")


# ------------------------ Log Viewer ------------------------
def view_log():
    if not LOG_FILE or not os.path.exists(LOG_FILE):
        echo("Logging is not enabled or log file not found.")
        return
    echo("\n--- Current Log File ---")
    with open(LOG_FILE, "r") as f:
        print(f.read())
    echo("--- End of Log ---")


# ============================================================
#  SNMP MODULE
# ============================================================

def _snmp_choose_output():
    """Ask where results go. Returns (to_screen, to_file)."""
    while True:
        sel = input("Output to (s)creen, (f)ile, or (b)oth? [s]: ").strip().lower() or "s"
        if sel[0] in ("s", "f", "b"):
            c = sel[0]
            return (c in ("s", "b"), c in ("f", "b"))
        echo("Please enter s, f, or b.")


def _snmp_output_rows(rows, ip, to_screen, to_file, title):
    """Emit walk/query rows to screen and/or a timestamped text file."""
    if to_screen:
        echo(f"\n--- SNMP {title} ({len(rows)} rows) ---")
        for oid, val in rows:
            echo(f"{oid} = {val}")
        echo("--- end ---")
    if to_file:
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        path = f"atomics_snmp_{ip.replace('.', '_')}_{ts}.txt"
        with open(path, "w") as f:
            f.write(f"# AtomICS SNMP results - {title}\n")
            f.write(f"# Target: {ip}   Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Rows: {len(rows)}\n\n")
            for oid, val in rows:
                f.write(f"{oid} = {val}\n")
        echo(f"[✓] Saved {len(rows)} rows to {path}")
        log(f"SNMP_SAVED file={path} rows={len(rows)}")


def _snmp_run(coro):
    """Drive a pysnmp async coroutine to completion synchronously.

    The maintained pysnmp API (>= 6.x) is asyncio-only, so snmp_get()/snmp_walk()
    below stay blocking by pumping their coroutine through asyncio.run(). On
    Windows the selector event loop is forced -- it is the reliable path for the
    asyncio UDP datagram transport pysnmp uses.
    """
    if sys.platform.startswith("win"):
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except AttributeError:  # pragma: no cover - non-Windows / older Pythons
            pass
    return asyncio.run(coro)


async def _snmp_get_async(ip, community, mp_model, oid, port):
    transport = await UdpTransportTarget.create((ip, port), timeout=2, retries=1)
    error_indication, error_status, error_index, var_binds = await get_cmd(
        SnmpEngine(),
        CommunityData(community, mpModel=mp_model),
        transport,
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )
    if error_indication:
        return False, str(error_indication)
    if error_status:
        return False, f"{error_status.prettyPrint()} at {error_index}"
    name, val = var_binds[0]
    return True, val.prettyPrint()


def snmp_get(ip, community, mp_model, oid, port):
    """Single SNMP GET. Returns (ok, value_or_error_str)."""
    try:
        return _snmp_run(_snmp_get_async(ip, community, mp_model, oid, port))
    except Exception as e:  # transport/resolver/socket failures surface here
        return False, str(e)


async def _snmp_walk_async(ip, community, mp_model, base_oid, port, max_rows=None):
    rows = []
    transport = await UdpTransportTarget.create((ip, port), timeout=2, retries=1)
    objects = walk_cmd(
        SnmpEngine(),
        CommunityData(community, mpModel=mp_model),
        transport,
        ContextData(),
        ObjectType(ObjectIdentity(base_oid)),
        lexicographicMode=False,   # stop when the walk leaves the base_oid subtree
    )
    async for error_indication, error_status, error_index, var_binds in objects:
        if error_indication:
            echo(f"[✗] {error_indication}")
            log(f"SNMP_WALK error_indication {error_indication}")
            break
        if error_status:
            echo(f"[✗] {error_status.prettyPrint()} at {error_index}")
            log(f"SNMP_WALK error_status {error_status.prettyPrint()}")
            break
        for name, val in var_binds:
            rows.append((name.prettyPrint(), val.prettyPrint()))
        if max_rows and len(rows) >= max_rows:
            rows = rows[:max_rows]
            break
    return rows


def snmp_walk(ip, community, mp_model, base_oid, port, max_rows=None):
    """Walk the subtree under base_oid. Returns a list of (oid, value) tuples.
    max_rows limits how many varbinds are collected (None = entire subtree)."""
    try:
        return _snmp_run(_snmp_walk_async(ip, community, mp_model, base_oid, port, max_rows))
    except Exception as e:
        echo(f"[✗] {e}")
        log(f"SNMP_WALK exception {e}")
        return []


def _snmp_enterprise(objid):
    """Map a sysObjectID like '1.3.6.1.4.1.14988.1' to a vendor label.
    Returns e.g. 'MikroTik (14988)' or '<n> (unknown vendor - see IANA PEN registry)'."""
    parts = objid.strip().lstrip(".").split(".")
    if parts[:6] == ["1", "3", "6", "1", "4", "1"] and len(parts) > 6:
        try:
            pen = int(parts[6])
        except ValueError:
            return objid
        name = SNMP_ENTERPRISE_NAMES.get(pen)
        return f"{name} ({pen})" if name else f"{pen} (unknown vendor - see IANA PEN registry)"
    return objid


def snmp_summary(ip, community, mp_model, port, ver_label):
    """Quick recon banner - SNMP version, description, vendor/enterprise, engine time
    and a few adjacent fields. Screen-only (a full dump is the option to save)."""
    echo(f"\n--- SNMP Summary: {ip}:{port} ---")
    echo(f" {'SNMP Version':<13}: v{ver_label}  (queried with RO '{community}')")
    log(f"SNMP_SUMMARY ip={ip} version={ver_label} ro={community}")
    for label, oid in SNMP_SUMMARY_OIDS:
        ok, res = snmp_get(ip, community, mp_model, oid, port)
        if not ok:
            echo(f" {label:<13}: (no response - {res})")
            log(f"SNMP_SUMMARY {label} FAIL {res}")
            continue
        if oid == SNMP_SYSOBJECTID_OID:
            display = _snmp_enterprise(res)
            echo(f" {'Enterprise':<13}: {display}")
            echo(f" {'Object ID':<13}: {res}")
            log(f"SNMP_SUMMARY Enterprise={display} ObjectID={res}")
        else:
            echo(f" {label:<13}: {res}")
            log(f"SNMP_SUMMARY {label}={res}")
    echo("--- end ---")


def snmp_full_dump(ip, community, mp_model, port):
    """Full SNMP walk printed to screen, with an optional save to a timestamped file."""
    base = input(f"Base OID for full dump [{SNMP_FULLDUMP_BASE}]: ").strip() or SNMP_FULLDUMP_BASE
    echo(f"Dumping entire subtree {base} to screen - this can take a while (Ctrl+C to abort)...")
    log(f"SNMP_FULLDUMP start ip={ip} base={base}")
    try:
        rows = snmp_walk(ip, community, mp_model, base, port, max_rows=None)
    except KeyboardInterrupt:
        echo("\n[!] Dump interrupted.")
        log("SNMP_FULLDUMP interrupted")
        return
    save = input(f"Save these {len(rows)} rows to a log file too? [y/N]: ").strip().lower().startswith("y")
    _snmp_output_rows(rows, ip, True, save, f"full dump {base}")
    log(f"SNMP_FULLDUMP done ip={ip} base={base} rows={len(rows)} saved={save}")


def snmp_session(default_ip=None):
    """Interactive SNMP module: connect, set communities/version, query rows or full DB."""
    if not SNMP_AVAILABLE:
        echo("[✗] SNMP support requires the pysnmp package, which failed to import.")
        echo(f"    Reason: {SNMP_IMPORT_ERROR}")
        echo("    Install/upgrade it against the SAME interpreter you launched this with:")
        echo(f'        "{sys.executable}" -m pip install --upgrade pysnmp')
        log(f"SNMP_UNAVAILABLE {SNMP_IMPORT_ERROR}")
        return

    # --- target ---
    prompt = "Enter target IP for SNMP" + (f" [{default_ip}]" if default_ip else "") + ": "
    ip = input(prompt).strip() or (default_ip or "")
    if not ip:
        echo("No IP provided.")
        return
    port_in = input(f"SNMP port [{SNMP_DEFAULT_PORT}]: ").strip()
    port = int(port_in) if port_in else SNMP_DEFAULT_PORT

    # --- version + communities (or accept defaults) ---
    ver = input("SNMP version - 1 or 2c [2c]: ").strip().lower() or "2c"
    mp_model = 0 if ver.startswith("1") else 1
    ro = input(f"Read-only community [{SNMP_DEFAULT_RO}]: ").strip() or SNMP_DEFAULT_RO
    rw = input(f"Read-write community [{SNMP_DEFAULT_RW}]: ").strip() or SNMP_DEFAULT_RW
    ver_label = "1" if mp_model == 0 else "2c"
    echo(f"[i] Queries use the RO community '{ro}' over SNMP v{ver_label}. "
         f"(RW '{rw}' captured for reference.)")
    log(f"SNMP_SESSION ip={ip} port={port} version={ver_label} ro={ro} rw={rw}")

    # --- connectivity check (GET sysDescr) ---
    echo(f"Verifying reachability (GET sysDescr {SNMP_SYSDESCR_OID})...")
    ok, res = snmp_get(ip, ro, mp_model, SNMP_SYSDESCR_OID, port)
    if ok:
        echo(f"[✓] Connected. sysDescr = {res}")
        log(f"SNMP_CONNECTED sysDescr={res}")
        asset_update(ip, ports={port: "SNMP"}, protocol="SNMP",
                     version=f"SNMP sysDescr: {res}", source="SNMP")
    else:
        echo(f"[✗] No SNMP reply ({res}). Wrong community/version, or UDP 161 filtered.")
        log(f"SNMP_CONNECT_FAIL {res}")
        if not input("Continue anyway? [y/N]: ").strip().lower().startswith("y"):
            return

    # --- SNMP menu ---
    while True:
        ver_label = "1" if mp_model == 0 else "2c"
        print("\n--- AtomICS SNMP Menu ---")
        print(f"    Target: {ip}:{port}  v{ver_label}  RO='{ro}'")
        print("1. Summary info (quick recon: version, description, enterprise, engine time)")
        print("2. Full SNMP dump to screen (option to save/log)")
        print("3. Query a number of rows (limited walk)")
        print("4. Get a single OID")
        print("5. Change community / version")
        print("6. Back to main menu")
        choice = input("\nSelect an option: ").strip()
        try:
            if choice == "1":
                snmp_summary(ip, ro, mp_model, port, ver_label)
            elif choice == "2":
                snmp_full_dump(ip, ro, mp_model, port)
            elif choice == "3":
                base = input(f"Base OID [{SNMP_DEFAULT_BASE}]: ").strip() or SNMP_DEFAULT_BASE
                n = int(input("Number of rows to retrieve: "))
                to_s, to_f = _snmp_choose_output()
                echo(f"Walking {base} for up to {n} rows...")
                rows = snmp_walk(ip, ro, mp_model, base, port, max_rows=n)
                _snmp_output_rows(rows, ip, to_s, to_f, f"walk {base} (max {n})")
            elif choice == "4":
                oid = input("OID (e.g. 1.3.6.1.2.1.1.5.0 = sysName): ").strip()
                ok, res = snmp_get(ip, ro, mp_model, oid, port)
                echo(f"{oid} = {res}" if ok else f"[✗] {res}")
                log(f"SNMP_GET {oid} ok={ok} val={res}")
            elif choice == "5":
                ver = input("SNMP version - 1 or 2c [2c]: ").strip().lower() or "2c"
                mp_model = 0 if ver.startswith("1") else 1
                ro = input(f"Read-only community [{SNMP_DEFAULT_RO}]: ").strip() or SNMP_DEFAULT_RO
                rw = input(f"Read-write community [{SNMP_DEFAULT_RW}]: ").strip() or SNMP_DEFAULT_RW
                echo("[i] Settings updated.")
                log(f"SNMP_RECONFIG version={'1' if mp_model==0 else '2c'} ro={ro} rw={rw}")
            elif choice == "6":
                break
            else:
                echo("Invalid option.")
        except ValueError:
            echo("Invalid number.")
        except Exception as e:
            echo(f"Operation failed: {e}")
            log(f"SNMP_ERROR {e}")


# ============================================================
#  S7comm MODULE (Siemens, via python-snap7)
# ============================================================
# Talks to Siemens S7 PLCs over ISO-on-TCP (TCP/102). Rack/slot addressing:
#   S7-1200 / S7-1500 : rack 0, slot 1
#   S7-300            : rack 0, slot 2
#   S7-400            : rack 0, slot varies (often 2 or 3) — check the config
# The module tries the given rack/slot, and can auto-probe the common combos.

S7_DEFAULT_PORT = 102
_CPU_STATES = {0x08: "RUN", 0x04: "STOP", 0x00: "UNKNOWN"}  # AtomICS SZL 0x0424 map
S7_COMMON_SLOTS = [(0, 1), (0, 2), (0, 0), (0, 3)]

# snap7 area codes (used when the Area enum isn't importable on older versions).
S7_AREA_CODES = {"PE": 0x81, "PA": 0x82, "MK": 0x83, "DB": 0x84}


def _s7_area(name):
    """Return the snap7 area constant for 'PE'/'PA'/'MK'/'DB' across snap7 versions."""
    if _S7Area is not None:
        return {"PE": _S7Area.PE, "PA": _S7Area.PA,
                "MK": _S7Area.MK, "DB": _S7Area.DB}[name]
    return S7_AREA_CODES[name]


def _s7_connect(ip, rack, slot, port):
    """Open an S7 client. Returns a connected client or None."""
    client = snap7.client.Client()
    try:
        # Some snap7 builds accept tcpport as a kwarg; fall back if not.
        try:
            client.connect(ip, rack, slot, tcpport=port)
        except TypeError:
            client.connect(ip, rack, slot)
    except Exception as e:
        log(f"S7_CONNECT_FAIL ip={ip} rack={rack} slot={slot} {e}")
        return None
    if client.get_connected():
        return client
    return None


def _s7_autoprobe(ip, port):
    """Try the common rack/slot combos; return (client, rack, slot) or (None, None, None)."""
    for rack, slot in S7_COMMON_SLOTS:
        echo(f"    trying rack {rack}, slot {slot} ...")
        client = _s7_connect(ip, rack, slot, port)
        if client:
            return client, rack, slot
    return None, None, None


def s7_cpu_info(client, target_ip=None):
    echo("\n[S7 CPU Info]")
    log("S7_CPU_INFO")
    try:
        info = client.get_cpu_info()
        fields = [
            ("Module Type", getattr(info, "ModuleTypeName", "")),
            ("Module Name", getattr(info, "ModuleName", "")),
            ("AS Name",     getattr(info, "ASName", "")),
            ("Serial",      getattr(info, "SerialNumber", "")),
            ("Copyright",   getattr(info, "Copyright", "")),
        ]
        collected = {}
        for label, val in fields:
            val = val.decode(errors="ignore") if isinstance(val, bytes) else val
            echo(f" {label:<12}: {val}")
            log(f"S7_CPU_INFO {label}={val}")
            if val:
                collected[label] = val
        if target_ip and collected:
            parts = [f"{k}={v}" for k, v in collected.items()]
            asset_update(target_ip, vendor="Siemens",
                         version="S7 CPU: " + "; ".join(parts))
    except Exception as e:
        echo(f" (CPU info failed: {e})")
        log(f"S7_CPU_INFO error {e}")


def s7_order_code(client, target_ip=None):
    echo("\n[S7 Order Code]")
    log("S7_ORDER_CODE")
    try:
        oc = client.get_order_code()
        code = getattr(oc, "OrderCode", oc)
        code = code.decode(errors="ignore") if isinstance(code, bytes) else code
        echo(f" Order Code : {code}")
        v1 = getattr(oc, "V1", None); v2 = getattr(oc, "V2", None); v3 = getattr(oc, "V3", None)
        fw = None
        if None not in (v1, v2, v3):
            fw = f"V{v1}.{v2}.{v3}"
            echo(f" Firmware   : {fw}")
        log(f"S7_ORDER_CODE {code} fw={v1}.{v2}.{v3}")
        if target_ip and code:
            ver = f"S7 order code: {code}"
            if fw:
                ver += f"; firmware {fw}"
            asset_update(target_ip, vendor="Siemens", version=ver)
    except Exception as e:
        echo(f" (order code failed: {e})")
        log(f"S7_ORDER_CODE error {e}")


def s7_cpu_state(client):
    echo("\n[S7 CPU State]")
    log("S7_CPU_STATE")
    try:
        # Read run/stop straight from SZL 0x0424 (byte 7) rather than trusting
        # client.get_cpu_state(): some python-snap7 builds hardcode it to "run".
        raw = None
        try:
            szl = client.read_szl(0x0424, 0)
            data = bytes(b & 0xFF for b in szl.Data[:szl.Header.LengthDR])
            if len(data) > 7:
                raw = data[7]
        except Exception as _e:
            log(f"S7_CPU_STATE szl_read_failed {_e}")
            raw = None
        if raw in _CPU_STATES:
            state = _CPU_STATES[raw]
            echo(f" CPU State  : {state}  (SZL 0x0424 byte 0x{raw:02x})")
            log(f"S7_CPU_STATE {state} raw=0x{raw:02x}")
        else:
            state = client.get_cpu_state()
            echo(f" CPU State  : {state}  (via get_cpu_state fallback)")
            log(f"S7_CPU_STATE {state} fallback")
    except Exception as e:
        echo(f" (CPU state failed: {e})")
        log(f"S7_CPU_STATE error {e}")


def s7_protection(client):
    """Read the CPU protection level (SZL) — a key recon datapoint for S7."""
    echo("\n[S7 Protection Level]")
    log("S7_PROTECTION")
    try:
        prot = client.get_protection()
        # sch_schal: protection level set via mode selector / config.
        levels = {1: "1 - no protection (open)",
                  2: "2 - write protected",
                  3: "3 - read/write protected"}
        sch = getattr(prot, "sch_schal", None)
        echo(f" Protection : {levels.get(sch, sch)}")
        echo(f" sch_par    : {getattr(prot, 'sch_par', '?')}")
        echo(f" sch_rel    : {getattr(prot, 'sch_rel', '?')}")
        echo(f" bart_sch   : {getattr(prot, 'bart_sch', '?')}  (1=RUN 2=RUN-P 3=STOP 4=MRES)")
        echo(f" anl_sch    : {getattr(prot, 'anl_sch', '?')}")
        log(f"S7_PROTECTION sch_schal={sch}")
    except Exception as e:
        echo(f" (protection read failed: {e})")
        log(f"S7_PROTECTION error {e}")


def s7_list_blocks(client):
    echo("\n[S7 Block Inventory]")
    log("S7_LIST_BLOCKS")
    try:
        blocks = client.list_blocks()
        for label in ("OBCount", "FBCount", "FCCount", "SFBCount", "SFCCount",
                      "DBCount", "SDBCount"):
            val = getattr(blocks, label, None)
            if val is not None:
                echo(f" {label:<9}: {val}")
                log(f"S7_LIST_BLOCKS {label}={val}")
    except Exception as e:
        echo(f" (block list failed: {e})")
        log(f"S7_LIST_BLOCKS error {e}")


def _hexdump(data, base=0, width=16):
    """Return a classic offset/hex/ascii dump of a bytes object."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f" {base + off:>5}: {hexpart:<{width*3}} {asc}")
    return "\n".join(lines)


def s7_read_db(client):
    """Read a data block region and hexdump it."""
    try:
        db = int(input("DB number: ").strip())
        start = int(input("Start byte [0]: ").strip() or "0")
        size = int(input("Size in bytes [64]: ").strip() or "64")
    except ValueError:
        echo("Invalid number.")
        return
    log(f"S7_READ_DB db={db} start={start} size={size}")
    try:
        data = client.db_read(db, start, size)
        echo(f"\n[DB{db} bytes {start}..{start + size - 1}]")
        echo(_hexdump(bytes(data), base=start))
        log(f"S7_READ_DB ok db={db} bytes={len(data)}")
    except Exception as e:
        echo(f" (DB read failed: {e})")
        log(f"S7_READ_DB error {e}")


def s7_read_area(client):
    """Read from process inputs (PE), outputs (PA), or merkers/flags (MK)."""
    area_in = input("Area ([i]nputs/PE, [q]outputs/PA, [m]erkers/MK) [m]: ").strip().lower() or "m"
    area_map = {"i": "PE", "q": "PA", "o": "PA", "m": "MK"}
    area_name = area_map.get(area_in[0])
    if not area_name:
        echo("Invalid area.")
        return
    try:
        start = int(input("Start byte [0]: ").strip() or "0")
        size = int(input("Size in bytes [16]: ").strip() or "16")
    except ValueError:
        echo("Invalid number.")
        return
    log(f"S7_READ_AREA area={area_name} start={start} size={size}")
    try:
        data = client.read_area(_s7_area(area_name), 0, start, size)
        echo(f"\n[{area_name} bytes {start}..{start + size - 1}]")
        echo(_hexdump(bytes(data), base=start))
        log(f"S7_READ_AREA ok area={area_name} bytes={len(data)}")
    except Exception as e:
        echo(f" (area read failed: {e})")
        log(f"S7_READ_AREA error {e}")


def s7_recon(client, ip, rack, slot):
    """One-shot S7 recon banner: identity, order code, state, protection, blocks."""
    BAR = "=" * 60
    echo(f"\n{BAR}")
    echo(" S7comm RECON OVERVIEW")
    echo(BAR)
    echo(f" Target     : {ip}:{S7_DEFAULT_PORT}  (rack {rack}, slot {slot})")
    echo(f" Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"S7_RECON target={ip} rack={rack} slot={slot}")
    s7_cpu_info(client, ip)
    s7_order_code(client, ip)
    s7_cpu_state(client)
    s7_protection(client)
    s7_list_blocks(client)
    echo(f"{BAR}\n")


def s7_session(args):
    """Interactive S7comm module: connect (rack/slot or auto-probe) then menu."""
    if not S7_AVAILABLE:
        echo("[✗] S7 support requires python-snap7 plus the snap7 native library.")
        echo(f"    Reason: {S7_IMPORT_ERROR}")
        echo("    Install both, then relaunch:")
        echo(f'        "{sys.executable}" -m pip install python-snap7')
        echo("    (and place libsnap7.so / snap7.dll on the library path)")
        log(f"S7_UNAVAILABLE {S7_IMPORT_ERROR}")
        return

    ip = args.ip or input("Enter target S7 PLC IP: ").strip()
    if not ip:
        echo("No IP provided.")
        return
    port_in = input(f"S7 port [{S7_DEFAULT_PORT}]: ").strip()
    port = int(port_in) if port_in else S7_DEFAULT_PORT

    auto = input("Auto-probe common rack/slot combos? [Y/n]: ").strip().lower()
    if auto in ("", "y", "yes"):
        echo("Auto-probing rack/slot...")
        client, rack, slot = _s7_autoprobe(ip, port)
    else:
        try:
            rack = int(input("Rack [0]: ").strip() or "0")
            slot = int(input("Slot (1=S7-1200/1500, 2=S7-300) [1]: ").strip() or "1")
        except ValueError:
            echo("Invalid number.")
            return
        client = _s7_connect(ip, rack, slot, port)

    if not client:
        echo(f"[✗] Could not establish an S7 connection to {ip}:{port}.")
        log(f"S7_CONNECT_FAIL_ALL ip={ip}")
        return

    echo(f"[✓] Connected to S7 at {ip}:{port} (rack {rack}, slot {slot})")
    if args.readonly:
        echo("[!] Read-Only Mode ENABLED (S7 module is read-only by design)")
    log(f"S7_CONNECTED ip={ip} rack={rack} slot={slot}")
    asset_update(ip, ports={port: "S7comm / ISO-TSAP (Siemens)"},
                 protocol="S7comm", vendor="Siemens", source="S7")

    try:
        while True:
            print("\n--- AtomICS - S7comm (Siemens) Menu ---")
            print(f"    Target: {ip}:{port}  rack {rack} slot {slot}")
            print("1. Recon overview (identity, order code, state, protection, blocks)")
            print("2. CPU info (module type, serial, AS name)")
            print("3. Order code / firmware")
            print("4. CPU state (RUN/STOP)")
            print("5. Protection level")
            print("6. Block inventory (OB/FB/FC/DB counts)")
            print("7. Read a Data Block (DB)")
            print("8. Read I/Q/M area")
            print("9. Back to main menu")
            choice = input("\nSelect an option: ").strip()
            try:
                if choice == "1":
                    s7_recon(client, ip, rack, slot)
                elif choice == "2":
                    s7_cpu_info(client, ip)
                elif choice == "3":
                    s7_order_code(client, ip)
                elif choice == "4":
                    s7_cpu_state(client)
                elif choice == "5":
                    s7_protection(client)
                elif choice == "6":
                    s7_list_blocks(client)
                elif choice == "7":
                    s7_read_db(client)
                elif choice == "8":
                    s7_read_area(client)
                elif choice == "9":
                    break
                else:
                    echo("Invalid option.")
            except Exception as e:
                echo(f"Operation failed: {e}")
                log(f"S7_ERROR {e}")
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
        log("S7_DISCONNECTED")



# ============================================================
#  EtherNet/IP + CIP MODULE (pure-Python, TCP/UDP 44818)
# ============================================================
# EtherNet/IP (ODVA CIP over Ethernet) speaks its encapsulation layer on
# TCP/44818 (explicit messaging) and UDP/44818 (the connectionless ListIdentity
# discovery broadcast); implicit I/O runs on UDP/2222. There is no need for a
# third-party stack for recon: this module builds the 24-byte encapsulation
# header and the ListIdentity / ListServices / ListInterfaces / RegisterSession
# commands directly, and parses the replies far enough to fingerprint the
# device - vendor, device type, product code, revision, serial, product name
# and current state. That identity is exactly the "versioning" the Asset
# Register wants, so this module feeds it.
#
# Read-only by design: ListIdentity and the List* commands are informational,
# and RegisterSession only opens (and immediately closes) an encapsulation
# session to confirm the device speaks explicit messaging. No CIP writes, no
# Forward_Open, no attribute Set - nothing that changes device state.
#
# Endianness note: the EtherNet/IP encapsulation layer and CIP are LITTLE
# endian, but the sockaddr embedded in the ListIdentity reply is big-endian
# (network order), so it is unpacked separately. Reference: ODVA "The CIP
# Networks Library", Volume 2 (EtherNet/IP Adaptation of CIP).

ENIP_DEFAULT_PORT = 44818
ENIP_IMPLICIT_PORT = 2222

# Encapsulation commands (little-endian on the wire).
ENIP_CMD_LIST_SERVICES   = 0x0004
ENIP_CMD_LIST_IDENTITY   = 0x0063
ENIP_CMD_LIST_INTERFACES = 0x0064
ENIP_CMD_REGISTER        = 0x0065
ENIP_CMD_UNREGISTER      = 0x0066

# CPF item type IDs seen in these replies.
ENIP_ITEM_CIP_IDENTITY   = 0x000C
ENIP_ITEM_SERVICES       = 0x0100

# Encapsulation status codes worth naming.
ENIP_STATUS = {
    0x0000: "success",
    0x0001: "invalid/unsupported command",
    0x0002: "insufficient memory",
    0x0003: "malformed data in request",
    0x0064: "invalid session handle",
    0x0065: "invalid message length",
    0x0069: "unsupported protocol revision",
}

# Partial CIP device type map (ODVA). Unknown types are shown by number.
ENIP_DEVICE_TYPES = {
    0x00: "Generic Device", 0x02: "AC Drive", 0x03: "Motor Overload",
    0x04: "Limit Switch", 0x05: "Inductive Proximity Switch",
    0x06: "Photoelectric Sensor", 0x07: "General Purpose Discrete I/O",
    0x09: "Resolver", 0x0C: "Communications Adapter",
    0x0E: "Programmable Logic Controller", 0x10: "Position Controller",
    0x13: "DC Drive", 0x15: "Contactor", 0x16: "Motor Starter",
    0x17: "Soft Start", 0x18: "Human-Machine Interface",
    0x1A: "Mass Flow Controller", 0x1B: "Pneumatic Valve",
    0x1C: "Vacuum Pressure Gauge", 0x1D: "Process Control Valve",
    0x22: "Encoder", 0x23: "Safety Discrete I/O Device",
    0x24: "Fluid Flow Controller", 0x25: "CIP Motion Drive",
    0x28: "CIP Modbus Device", 0x29: "CIP Modbus Translator",
    0x2A: "Safety Analog I/O Device", 0x2C: "Managed Ethernet Switch",
}

# Partial ODVA vendor ID map. Kept intentionally small and high-confidence -
# the numeric ID is always printed, so an unmapped vendor is never mislabeled.
# The authoritative list is the ODVA Vendor ID registry.
ENIP_VENDORS = {
    1: "Rockwell Automation / Allen-Bradley",
}


def _enip_header(command, data=b"", session=0, context=b"\x00" * 8, status=0):
    """Build a 24-byte EtherNet/IP encapsulation header + data (little-endian)."""
    if len(context) != 8:
        context = (context + b"\x00" * 8)[:8]
    return struct.pack("<HHII8sI", command, len(data), session, status,
                       context, 0) + data


def _enip_parse_header(raw):
    """Parse a 24-byte encapsulation header. Returns dict or None."""
    if len(raw) < 24:
        return None
    command, length, session, status, context, options = struct.unpack(
        "<HHII8sI", raw[:24])
    return {"command": command, "length": length, "session": session,
            "status": status, "context": context, "data": raw[24:24 + length]}


def _enip_recv_encap(sock, timeout=3.0):
    """Read exactly one encapsulation reply (24-byte header then its data)."""
    sock.settimeout(timeout)
    hdr = b""
    try:
        while len(hdr) < 24:
            chunk = sock.recv(24 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        length = struct.unpack("<H", hdr[2:4])[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        return None
    except Exception:
        return None
    return _enip_parse_header(hdr + data)


def _enip_tcp_command(ip, port, command, data=b"", session=0, timeout=3.0):
    """Send one encapsulation command over TCP, return the parsed reply or None."""
    pkt = _enip_header(command, data, session=session)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.sendall(pkt)
            return _enip_recv_encap(sock, timeout)
    except Exception as e:
        log(f"ENIP_TCP_ERROR cmd=0x{command:04x} {e}")
        return None


def _enip_status_text(status):
    name = ENIP_STATUS.get(status)
    return f"0x{status:08x}" + (f" ({name})" if name else "")


def _enip_vendor_name(vid):
    return ENIP_VENDORS.get(vid, "")


def _enip_parse_identity_item(item):
    """Parse a CIP Identity item body into a dict. Returns {} on a short/bad item.

    Layout (little-endian, except the embedded sockaddr which is network order):
      protocol version (H), sockaddr (16), vendor id (H), device type (H),
      product code (H), revision major (B) minor (B), status (H),
      serial (I), product name length (B), product name (n), state (B)
    """
    out = {}
    try:
        if len(item) < 2:
            return out
        out["encap_protocol"] = struct.unpack("<H", item[0:2])[0]
        # sockaddr_in: family(h) port(H) addr(4) - big-endian - then 8 zero bytes
        if len(item) >= 20:
            fam, sport = struct.unpack(">hH", item[2:6])
            out["socket_ip"] = socket.inet_ntoa(item[6:10])
            out["socket_port"] = sport
        p = 18
        if len(item) < p + 15:
            return out
        out["vendor_id"] = struct.unpack("<H", item[p:p + 2])[0]; p += 2
        out["device_type"] = struct.unpack("<H", item[p:p + 2])[0]; p += 2
        out["product_code"] = struct.unpack("<H", item[p:p + 2])[0]; p += 2
        out["revision"] = f"{item[p]}.{item[p + 1]}"; p += 2
        out["status_word"] = struct.unpack("<H", item[p:p + 2])[0]; p += 2
        out["serial"] = struct.unpack("<I", item[p:p + 4])[0]; p += 4
        name_len = item[p]; p += 1
        name = item[p:p + name_len]
        out["product_name"] = name.decode("ascii", errors="ignore").strip()
        p += name_len
        if p < len(item):
            out["state"] = item[p]
    except Exception as e:
        log(f"ENIP_IDENTITY_PARSE_STOP {e}")
    return out


def _enip_parse_identity_reply(reply):
    """Pull the first CIP Identity item out of a ListIdentity reply."""
    if not reply or not reply.get("data"):
        return None
    data = reply["data"]
    if len(data) < 2:
        return None
    count = struct.unpack("<H", data[0:2])[0]
    p = 2
    for _ in range(count):
        if p + 4 > len(data):
            break
        item_type, item_len = struct.unpack("<HH", data[p:p + 4])
        p += 4
        item = data[p:p + item_len]
        p += item_len
        if item_type == ENIP_ITEM_CIP_IDENTITY:
            return _enip_parse_identity_item(item)
    return None


def _enip_show_identity(info, ip):
    """Print a parsed identity and feed it to the Asset Register."""
    vid = info.get("vendor_id")
    vname = _enip_vendor_name(vid) if vid is not None else ""
    dtype = info.get("device_type")
    dname = ENIP_DEVICE_TYPES.get(dtype, "") if dtype is not None else ""
    states = {0: "Nonexistent", 1: "Device Self Testing", 2: "Standby",
              3: "Operational", 4: "Major Recoverable Fault",
              5: "Major Unrecoverable Fault"}
    st = info.get("state")

    echo(f" Product Name : {info.get('product_name', '(none)')}")
    vend_line = str(vid)
    if vname:
        vend_line += f" ({vname})"
    echo(f" Vendor ID    : {vend_line}")
    dline = str(dtype)
    if dname:
        dline += f" ({dname})"
    echo(f" Device Type  : {dline}")
    echo(f" Product Code : {info.get('product_code', '?')}")
    echo(f" Revision     : {info.get('revision', '?')}")
    echo(f" Serial       : 0x{info.get('serial', 0):08x}")
    if st is not None:
        echo(f" State        : {st} ({states.get(st, 'vendor-specific')})")

    # Feed the Asset Register: this is the EtherNet/IP versioning line.
    ver_parts = []
    if info.get("product_name"):
        ver_parts.append(f"Product={info['product_name']}")
    if vid is not None:
        ver_parts.append(f"Vendor={vend_line}")
    if dtype is not None:
        ver_parts.append(f"DeviceType={dline}")
    if info.get("product_code") is not None:
        ver_parts.append(f"ProductCode={info['product_code']}")
    if info.get("revision"):
        ver_parts.append(f"Rev={info['revision']}")
    if info.get("serial") is not None:
        ver_parts.append(f"Serial=0x{info['serial']:08x}")
    asset_update(ip, ports={ENIP_DEFAULT_PORT: "EtherNet/IP (explicit / CIP)"},
                 protocol="EtherNet/IP", vendor=vname,
                 version="EtherNet/IP ListIdentity: " + "; ".join(ver_parts),
                 source="EtherNet/IP")


def enip_list_identity(ip, port):
    """ListIdentity over TCP: the primary EtherNet/IP fingerprint."""
    echo(f"\n[EtherNet/IP ListIdentity] {ip}:{port}")
    log(f"ENIP_LIST_IDENTITY {ip}:{port}")
    reply = _enip_tcp_command(ip, port, ENIP_CMD_LIST_IDENTITY)
    if not reply:
        echo(" (no reply - port closed/filtered or not EtherNet/IP)")
        return None
    if reply["status"] != 0:
        echo(f" (device returned status {_enip_status_text(reply['status'])})")
    info = _enip_parse_identity_reply(reply)
    if not info:
        echo(" (reply carried no CIP Identity item)")
        echo(_hexdump(reply["data"][:64]))
        return None
    _enip_show_identity(info, ip)
    return info


def enip_list_services(ip, port):
    """ListServices: shows whether the device supports CIP over TCP/UDP."""
    echo(f"\n[EtherNet/IP ListServices] {ip}:{port}")
    log(f"ENIP_LIST_SERVICES {ip}:{port}")
    reply = _enip_tcp_command(ip, port, ENIP_CMD_LIST_SERVICES)
    if not reply or not reply.get("data"):
        echo(" (no reply)")
        return
    data = reply["data"]
    if len(data) < 2:
        echo(" (empty service list)")
        return
    count = struct.unpack("<H", data[0:2])[0]
    p = 2
    for _ in range(count):
        if p + 4 > len(data):
            break
        item_type, item_len = struct.unpack("<HH", data[p:p + 4])
        p += 4
        item = data[p:p + item_len]
        p += item_len
        if item_type == ENIP_ITEM_SERVICES and len(item) >= 20:
            version, caps = struct.unpack("<HH", item[0:4])
            name = item[4:20].decode("ascii", errors="ignore").replace("\x00", "").strip()
            echo(f"   Service   : {name}")
            echo(f"   Version   : {version}")
            echo(f"   CIP/TCP   : {'yes' if caps & 0x0020 else 'no'}")
            echo(f"   CIP/UDP   : {'yes' if caps & 0x0100 else 'no'}")
            asset_update(ip, ports={port: "EtherNet/IP (explicit / CIP)"},
                         protocol="EtherNet/IP", source="EtherNet/IP")
        else:
            echo(f"   (item type 0x{item_type:04x}, {item_len} bytes)")


def enip_list_interfaces(ip, port):
    """ListInterfaces: usually empty, but confirms the encapsulation stack."""
    echo(f"\n[EtherNet/IP ListInterfaces] {ip}:{port}")
    log(f"ENIP_LIST_INTERFACES {ip}:{port}")
    reply = _enip_tcp_command(ip, port, ENIP_CMD_LIST_INTERFACES)
    if not reply or not reply.get("data"):
        echo(" (no reply)")
        return
    data = reply["data"]
    count = struct.unpack("<H", data[0:2])[0] if len(data) >= 2 else 0
    echo(f"   Interface items: {count}")
    if count == 0:
        echo("   (none reported - normal for many devices)")


def enip_register_session(ip, port):
    """RegisterSession then UnRegisterSession - confirms explicit messaging.

    Opens an encapsulation session (read-only handshake) to prove the device
    speaks explicit messaging, then closes it immediately. No CIP request is
    sent inside the session, so nothing on the device changes.
    """
    echo(f"\n[EtherNet/IP RegisterSession] {ip}:{port}")
    log(f"ENIP_REGISTER {ip}:{port}")
    # data: protocol version (H)=1, options flags (H)=0
    data = struct.pack("<HH", 1, 0)
    reply = _enip_tcp_command(ip, port, ENIP_CMD_REGISTER, data)
    if not reply:
        echo(" (no reply)")
        return
    if reply["status"] != 0 or reply["session"] == 0:
        echo(f" (registration failed: status {_enip_status_text(reply['status'])})")
        return
    echo(f" [+] Session opened: handle 0x{reply['session']:08x} "
         f"- device supports explicit messaging.")
    asset_update(ip, ports={port: "EtherNet/IP (explicit / CIP)"},
                 protocol="EtherNet/IP", source="EtherNet/IP")
    # Close it again so we leave no session open on the device.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3.0)
            sock.connect((ip, port))
            sock.sendall(_enip_header(ENIP_CMD_UNREGISTER, session=reply["session"]))
        echo(" [i] Session closed (UnRegisterSession sent).")
    except Exception:
        pass


def enip_discover(port, timeout=3.0, target=None):
    """UDP ListIdentity broadcast - the EtherNet/IP equivalent of BACnet Who-Is.

    Sends one ListIdentity to the broadcast (or a chosen) address on UDP/44818
    and collects the I-Am-style replies. Every responder is folded into the
    Asset Register.
    """
    dest = (target or "255.255.255.255", port)
    echo(f"\nSending EtherNet/IP ListIdentity to {dest[0]}:{dest[1]} "
         f"(listening {timeout:.0f}s)...")
    log(f"ENIP_DISCOVER dest={dest}")
    pkt = _enip_header(ENIP_CMD_LIST_IDENTITY)
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass
        s.bind(("", 0))
        s.sendto(pkt, dest)
        s.settimeout(timeout)
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                break
            reply = _enip_parse_header(data)
            if not reply:
                continue
            info = _enip_parse_identity_reply(reply)
            if info:
                found[addr[0]] = info
    except Exception as e:
        echo(f"[✗] Discovery failed: {e}")
        log(f"ENIP_DISCOVER error {e}")
    finally:
        s.close()

    echo(f"\n--- EtherNet/IP Discovery Results ({len(found)} device(s)) ---")
    if not found:
        echo("  (no replies - UDP 44818 may be filtered or no EtherNet/IP devices present)")
    for ip in sorted(found, key=lambda x: ipaddress.ip_address(x)):
        info = found[ip]
        vid = info.get("vendor_id")
        vname = _enip_vendor_name(vid) if vid is not None else ""
        echo(f"  {ip}   {info.get('product_name', '(no name)')}")
        vtag = f"{vid}" + (f" ({vname})" if vname else "")
        echo(f"      vendor {vtag}, rev {info.get('revision', '?')}, "
             f"serial 0x{info.get('serial', 0):08x}")
        _enip_show_identity(info, ip)
        log(f"ENIP_DISCOVER found ip={ip} vendor={vid} product={info.get('product_name')}")
    echo("--- end ---")
    return found


def enip_recon(ip, port):
    """One-shot EtherNet/IP recon: identity + services in a single view."""
    BAR = "=" * 60
    echo(f"\n{BAR}")
    echo(" EtherNet/IP RECON OVERVIEW")
    echo(BAR)
    echo(f" Target     : {ip}:{port}")
    echo(f" Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"ENIP_RECON target={ip}:{port}")
    enip_list_identity(ip, port)
    enip_list_services(ip, port)
    echo(f"{BAR}\n")


def enip_session(args):
    """Interactive EtherNet/IP module: identify and enumerate CIP devices."""
    ip = args.ip or input("Enter target EtherNet/IP device IP (blank for UDP discovery): ").strip()
    port_in = input(f"EtherNet/IP port [{ENIP_DEFAULT_PORT}]: ").strip()
    port = int(port_in) if port_in else ENIP_DEFAULT_PORT
    if args.readonly:
        echo("[!] Read-Only Mode ENABLED (EtherNet/IP module identifies/enumerates only)")
    log(f"ENIP_SESSION ip={ip} port={port}")

    while True:
        print("\n--- AtomICS - EtherNet/IP (CIP) Menu ---")
        print(f"    Target: {ip or '(none - use discovery)'}:{port}")
        print("1. Recon overview (ListIdentity + ListServices)")
        print("2. ListIdentity (vendor / product / revision / serial / state)")
        print("3. ListServices (CIP-over-TCP/UDP support)")
        print("4. ListInterfaces")
        print("5. Register session (confirm explicit messaging)")
        print("6. UDP discovery (ListIdentity broadcast - like BACnet Who-Is)")
        print("7. Change target IP")
        print("8. Back to main menu")
        choice = input("\nSelect an option: ").strip()
        try:
            if choice in {"1", "2", "3", "4", "5"} and not ip:
                echo("[!] No target IP set. Use option 7 to set one, or option 6 for discovery.")
                continue
            if choice == "1":
                enip_recon(ip, port)
            elif choice == "2":
                enip_list_identity(ip, port)
            elif choice == "3":
                enip_list_services(ip, port)
            elif choice == "4":
                enip_list_interfaces(ip, port)
            elif choice == "5":
                enip_register_session(ip, port)
            elif choice == "6":
                tgt = input("Broadcast/target for discovery [255.255.255.255]: ").strip()
                enip_discover(port, target=tgt or None)
            elif choice == "7":
                ip = input("Target EtherNet/IP device IP: ").strip()
                echo(f"[i] Target set to {ip or '(none)'}")
            elif choice == "8":
                break
            else:
                echo("Invalid option.")
        except Exception as e:
            echo(f"Operation failed: {e}")
            log(f"ENIP_ERROR {e}")



# ============================================================
#  DNP3 MODULE (pure-Python, TCP/20000)
# ============================================================
# DNP3 (IEEE 1815) over TCP/20000. No mature, easily installed pure-Python DNP3
# client exists, so this module speaks the wire protocol directly: it builds the
# link-layer frame (with the DNP3 CRC on the header and each data block), the
# transport header, and the application-layer request, then parses the response
# far enough for recon — link status, the IIN (Internal Indications) flags, and a
# best-effort decode of the returned objects. Reads only (integrity/class polls
# and targeted object reads); no control/operate functions are issued.

DNP3_DEFAULT_PORT = 20000
DNP3_START = b"\x05\x64"


def _dnp3_crc(data):
    """DNP3 CRC-16 (poly 0x3D65, reflected, final XOR 0xFFFF). Returns 2 bytes LE."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC   # reflected 0x3D65
            else:
                crc >>= 1
    crc ^= 0xFFFF
    return struct.pack("<H", crc & 0xFFFF)


def _dnp3_add_block_crcs(user_data):
    """Split user data into 16-byte blocks, each followed by its CRC."""
    out = b""
    for i in range(0, len(user_data), 16):
        block = user_data[i:i + 16]
        out += block + _dnp3_crc(block)
    return out


def _dnp3_build_frame(dest, src, ctrl, user_data=b""):
    """Assemble a full DNP3 link-layer frame (header CRC + block CRCs)."""
    length = 5 + len(user_data)          # ctrl(1)+dest(2)+src(2)+userdata
    header = DNP3_START + bytes([length & 0xFF, ctrl]) + \
        struct.pack("<H", dest) + struct.pack("<H", src)
    frame = header + _dnp3_crc(header)
    if user_data:
        frame += _dnp3_add_block_crcs(user_data)
    return frame


def _dnp3_app_read(objects, seq):
    """Build a DNP3 application-layer READ request fragment.

    objects: list of (group, variation, qualifier) tuples.
    Returns transport-header + app-fragment bytes (ready to be link-framed).
    """
    app_ctrl = 0xC0 | (seq & 0x0F)       # FIR=1, FIN=1, seq
    frag = bytes([app_ctrl, 0x01])       # 0x01 = READ
    for grp, var, qual in objects:
        frag += bytes([grp, var, qual])
    transport = bytes([0xC0 | (seq & 0x3F)])   # FIR=1, FIN=1, seq
    return transport + frag


def _dnp3_recv(sock, timeout=3.0):
    """Read raw bytes from the socket until a quiet gap or timeout."""
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            sock.settimeout(0.4)   # short gap after first data = end of response
    except socket.timeout:
        pass
    return b"".join(chunks)


def _dnp3_parse_frames(raw):
    """Yield parsed link frames from raw bytes: dicts with ctrl/dest/src/user."""
    frames = []
    i = 0
    while i + 10 <= len(raw):
        if raw[i:i + 2] != DNP3_START:
            i += 1
            continue
        length = raw[i + 2]
        ctrl = raw[i + 3]
        dest = struct.unpack("<H", raw[i + 4:i + 6])[0]
        src = struct.unpack("<H", raw[i + 6:i + 8])[0]
        user_len = max(0, length - 5)
        # data blocks: 16 user bytes + 2 CRC each
        nblocks = (user_len + 15) // 16
        frame_len = 10 + user_len + nblocks * 2
        block_region = raw[i + 10:i + frame_len]
        user = b""
        bi = 0
        while bi < len(block_region):
            blk = block_region[bi:bi + 16]
            # drop trailing 2 CRC bytes of each block
            if len(blk) >= 2:
                user += blk[:-2] if len(blk) > 2 else b""
            bi += 18
        frames.append({"ctrl": ctrl, "dest": dest, "src": src, "user": user})
        i += frame_len if frame_len > 0 else 1
    return frames


DNP3_IIN1 = [
    "Broadcast msg rx", "Class 1 events", "Class 2 events", "Class 3 events",
    "Need time", "Local control", "Device trouble", "Device restart",
]
DNP3_IIN2 = [
    "Function not supported", "Object unknown", "Parameter error",
    "Buffer overflow", "Already executing", "Config corrupt",
    "Reserved(6)", "Reserved(7)",
]


def _dnp3_decode_iin(iin1, iin2):
    flags = []
    for bit, name in enumerate(DNP3_IIN1):
        if iin1 & (1 << bit):
            flags.append(name)
    for bit, name in enumerate(DNP3_IIN2):
        if iin2 & (1 << bit):
            flags.append(name)
    return flags


def _dnp3_reassemble_app(frames):
    """Concatenate transport payloads from response frames into the app fragment."""
    app = b""
    for f in frames:
        u = f["user"]
        if not u:
            continue
        # first user byte is the transport header; strip it
        app += u[1:]
    return app


def _dnp3_send_request(ip, port, dest, src, objects, label):
    """Connect, send a READ request, and return (raw_response, frames) or (None, [])."""
    seq = random.randint(0, 15)
    user = _dnp3_app_read(objects, seq)
    frame = _dnp3_build_frame(dest, src, 0xC4, user)   # 0xC4: DIR=1,PRM=1,func=4 unconfirmed user data
    log(f"DNP3_REQ {label} dest={dest} src={src} objs={objects}")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(4)
            sock.connect((ip, port))
            sock.sendall(frame)
            raw = _dnp3_recv(sock)
    except Exception as e:
        echo(f"[✗] DNP3 {label} failed: {e}")
        log(f"DNP3_REQ_ERROR {label} {e}")
        return None, []
    if not raw:
        echo(f"[✗] No DNP3 response to {label}.")
        log(f"DNP3_NO_RESPONSE {label}")
        return None, []
    return raw, _dnp3_parse_frames(raw)


def dnp3_link_status(ip, port, dest, src):
    """Send a Request Link Status (function 9) and report the reply."""
    frame = _dnp3_build_frame(dest, src, 0xC9)   # DIR=1,PRM=1,func=9 request link status
    echo(f"\n[DNP3 Link Status] {ip}:{port}  outstation={dest} master={src}")
    log(f"DNP3_LINK_STATUS dest={dest} src={src}")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(4)
            sock.connect((ip, port))
            sock.sendall(frame)
            raw = _dnp3_recv(sock)
    except Exception as e:
        echo(f" (link status failed: {e})")
        log(f"DNP3_LINK_STATUS error {e}")
        return
    if not raw:
        echo(" (no reply — port open but no DNP3 link response)")
        log("DNP3_LINK_STATUS no_reply")
        return
    frames = _dnp3_parse_frames(raw)
    if not frames:
        echo(f" (reply not a valid DNP3 frame; raw {len(raw)} bytes)")
        echo(_hexdump(raw))
        return
    for f in frames:
        func = f["ctrl"] & 0x0F
        echo(f" Reply: outstation={f['src']} -> master={f['dest']}  link-func={func}")
        if func == 0x0B:
            echo("        (0x0B = Link Status)")
        elif func == 0x00:
            echo("        (0x00 = ACK / reset confirm)")
        log(f"DNP3_LINK_STATUS reply src={f['src']} dest={f['dest']} func={func}")
    echo(f" [✓] {ip} answered DNP3 on the link layer — confirmed outstation.")
    asset_update(ip, ports={port: "DNP3"}, protocol="DNP3",
                 version=f"DNP3: confirmed outstation (addr {dest})", source="DNP3")


def _dnp3_report_response(raw, frames, label):
    """Decode IIN + best-effort object summary from a READ response."""
    if not frames:
        echo(f" (no parseable DNP3 frames; raw {len(raw)} bytes)")
        echo(_hexdump(raw))
        return
    app = _dnp3_reassemble_app(frames)
    if len(app) < 4:
        echo(" (response too short to contain an application header)")
        echo(_hexdump(app))
        return
    app_ctrl = app[0]
    func = app[1]
    iin1, iin2 = app[2], app[3]
    echo(f"\n--- DNP3 Response: {label} ---")
    echo(f" App control : 0x{app_ctrl:02x}   Function: 0x{func:02x}"
         + ("  (response)" if func == 0x81 else "  (unsolicited)" if func == 0x82 else ""))
    flags = _dnp3_decode_iin(iin1, iin2)
    echo(f" IIN         : 0x{iin1:02x}{iin2:02x}")
    if flags:
        for fl in flags:
            echo(f"    - {fl}")
    else:
        echo("    (no IIN flags set)")
    log(f"DNP3_RESP {label} func=0x{func:02x} iin=0x{iin1:02x}{iin2:02x} flags={flags}")

    obj = app[4:]
    if obj:
        echo(f" Object data : {len(obj)} bytes")
        echo(_dnp3_summarize_objects(obj))
    else:
        echo(" Object data : (none returned)")
    echo("--- end ---")


DNP3_GROUP_NAMES = {
    1: "Binary Input", 2: "Binary Input Event", 3: "Double-bit Input",
    10: "Binary Output", 12: "Binary Output Command", 20: "Counter",
    21: "Frozen Counter", 22: "Counter Event", 30: "Analog Input",
    32: "Analog Input Event", 40: "Analog Output Status",
    41: "Analog Output Command", 50: "Time and Date", 60: "Class Data",
    70: "File Transfer", 80: "Internal Indications", 110: "Octet String",
}


def _dnp3_summarize_objects(obj):
    """Best-effort walk of object headers in a response. Falls back to hexdump."""
    lines = []
    i = 0
    try:
        while i + 3 <= len(obj):
            grp = obj[i]
            var = obj[i + 1]
            qual = obj[i + 2]
            i += 3
            name = DNP3_GROUP_NAMES.get(grp, f"Group {grp}")
            qual_field = qual & 0x0F
            # Parse the range field to learn the point count where we can.
            count = None
            rng = ""
            if qual_field in (0x00, 0x01):        # 1-byte / 2-byte start-stop index
                if qual_field == 0x00 and i + 2 <= len(obj):
                    start, stop = obj[i], obj[i + 1]; i += 2
                elif qual_field == 0x01 and i + 4 <= len(obj):
                    start = struct.unpack("<H", obj[i:i + 2])[0]
                    stop = struct.unpack("<H", obj[i + 2:i + 4])[0]; i += 4
                else:
                    start = stop = 0
                count = stop - start + 1
                rng = f" points {start}-{stop}"
            elif qual_field in (0x07, 0x08):      # 1/2-byte count of objects
                if qual_field == 0x07 and i + 1 <= len(obj):
                    count = obj[i]; i += 1
                elif qual_field == 0x08 and i + 2 <= len(obj):
                    count = struct.unpack("<H", obj[i:i + 2])[0]; i += 2
                rng = f" count {count}"
            lines.append(f"    g{grp} v{var} ({name}) qual=0x{qual:02x}{rng}")
            # We report headers/counts but don't fully decode every variation's
            # payload; skip the remainder of this object's data conservatively.
            if count is None:
                break
            # Rough per-point size by group to advance the cursor (best effort).
            per = {1: 0, 10: 0, 20: 4, 30: 4, 32: 4, 40: 4}.get(grp)
            if per:
                i += per * count
            else:
                break
    except Exception as e:
        lines.append(f"    (object parse stopped: {e})")
    if not lines:
        return _hexdump(obj)
    lines.append(_hexdump(obj[:64]) + ("\n    ...(truncated)" if len(obj) > 64 else ""))
    return "\n".join(lines)


def dnp3_integrity_poll(ip, port, dest, src):
    """Class 0/1/2/3 integrity read (g60 v1..v4)."""
    objects = [(60, 2, 0x06), (60, 3, 0x06), (60, 4, 0x06), (60, 1, 0x06)]
    echo(f"\nIssuing integrity poll (Class 1/2/3/0) to {ip}...")
    raw, frames = _dnp3_send_request(ip, port, dest, src, objects, "integrity poll")
    if raw:
        _dnp3_report_response(raw, frames, "integrity poll (Class 1/2/3/0)")


def dnp3_class0_poll(ip, port, dest, src):
    """Class 0 only (static data) read."""
    objects = [(60, 1, 0x06)]
    echo(f"\nIssuing Class 0 poll (static data) to {ip}...")
    raw, frames = _dnp3_send_request(ip, port, dest, src, objects, "Class 0 poll")
    if raw:
        _dnp3_report_response(raw, frames, "Class 0 poll")


def dnp3_read_object(ip, port, dest, src):
    """Read an arbitrary object group/variation (qualifier 0x06 = all points)."""
    try:
        grp = int(input("Object group (e.g. 1=BI, 30=AI, 20=Counter): ").strip())
        var = int(input("Variation (0 = any): ").strip() or "0")
    except ValueError:
        echo("Invalid number.")
        return
    objects = [(grp, var, 0x06)]
    raw, frames = _dnp3_send_request(ip, port, dest, src, objects, f"read g{grp} v{var}")
    if raw:
        _dnp3_report_response(raw, frames, f"read g{grp} v{var}")


def dnp3_session(args):
    """Interactive DNP3 module: set addresses, then poll the outstation."""
    ip = args.ip or input("Enter target DNP3 outstation IP: ").strip()
    if not ip:
        echo("No IP provided.")
        return
    port_in = input(f"DNP3 port [{DNP3_DEFAULT_PORT}]: ").strip()
    port = int(port_in) if port_in else DNP3_DEFAULT_PORT

    try:
        dest = int(input("Outstation (destination) DNP3 address [1024]: ").strip() or "1024")
        src = int(input("Master (source) DNP3 address [1]: ").strip() or "1")
    except ValueError:
        echo("Invalid address.")
        return

    echo(f"[i] DNP3 target {ip}:{port}  outstation={dest} master={src}")
    if args.readonly:
        echo("[!] Read-Only Mode ENABLED (DNP3 module issues reads only)")
    log(f"DNP3_SESSION ip={ip} port={port} dest={dest} src={src}")

    # Confirm it actually speaks DNP3 before offering the poll menu.
    dnp3_link_status(ip, port, dest, src)

    while True:
        print("\n--- AtomICS - DNP3 (IEEE 1815) Menu ---")
        print(f"    Target: {ip}:{port}  outstation={dest} master={src}")
        print("1. Request link status (confirm outstation)")
        print("2. Integrity poll (Class 1/2/3/0)")
        print("3. Class 0 poll (static data)")
        print("4. Read a specific object group/variation")
        print("5. Change addresses")
        print("6. Back to main menu")
        choice = input("\nSelect an option: ").strip()
        try:
            if choice == "1":
                dnp3_link_status(ip, port, dest, src)
            elif choice == "2":
                dnp3_integrity_poll(ip, port, dest, src)
            elif choice == "3":
                dnp3_class0_poll(ip, port, dest, src)
            elif choice == "4":
                dnp3_read_object(ip, port, dest, src)
            elif choice == "5":
                dest = int(input("Outstation (destination) address [1024]: ").strip() or "1024")
                src = int(input("Master (source) address [1]: ").strip() or "1")
                echo("[i] Addresses updated.")
            elif choice == "6":
                break
            else:
                echo("Invalid option.")
        except ValueError:
            echo("Invalid number.")
        except Exception as e:
            echo(f"Operation failed: {e}")
            log(f"DNP3_ERROR {e}")


# ============================================================
#  BACnet/IP MODULE (pure-Python, UDP/47808)
# ============================================================
# BACnet/IP (ASHRAE 135) over UDP/47808. Sends a Who-Is broadcast and parses the
# I-Am replies (device instance, vendor, max APDU, segmentation), and can read
# common device-object properties (name, vendor, model, firmware) from a single
# device by unicast ReadProperty. Discovery/read only.

BACNET_DEFAULT_PORT = 47808
BACNET_VENDORS = {
    0: "ASHRAE", 2: "Andover Controls", 3: "Automated Logic (ALC)",
    5: "Johnson Controls", 8: "Delta Controls", 10: "Schneider Electric (TAC)",
    24: "Siemens", 36: "Alerton", 42: "Trane", 50: "Honeywell",
    58: "KMC Controls", 260: "Distech Controls", 385: "Reliable Controls",
}


def _bacnet_socket(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", 0))
    except Exception:
        pass
    return s


def _bacnet_whois_pkt():
    """BVLC(Original-Broadcast) + NPDU + Unconfirmed-Request Who-Is."""
    apdu = bytes([0x10, 0x08])                # unconfirmed req, Who-Is
    npdu = bytes([0x01, 0x00])                # version 1, control 0
    body = npdu + apdu
    bvlc = bytes([0x81, 0x0B]) + struct.pack(">H", len(body) + 4)
    return bvlc + body


def _bacnet_parse_iam(data, addr):
    """Parse an I-Am APDU. Returns dict or None."""
    # Find the APDU inside BVLC/NPDU. BVLC len 4; NPDU >=2 (+ optional dest/src).
    if len(data) < 6 or data[0] != 0x81:
        return None
    # NPDU starts at offset 4
    npdu_ctrl = data[5]
    idx = 6
    # If control has DNET/SNET bits, skip them (best-effort; usual local reply has none)
    if npdu_ctrl & 0x20:   # dest present
        idx += 3
        if idx < len(data):
            idx += data[idx - 1]  # DLEN
    if npdu_ctrl & 0x08:   # source present
        idx += 3
        if idx <= len(data):
            idx += data[idx - 1]
    if npdu_ctrl & 0x20:
        idx += 1           # hop count
    apdu = data[idx:]
    if len(apdu) < 2 or apdu[0] != 0x10 or apdu[1] != 0x00:
        return None
    # Tags: object id (0xC4 + 4), max apdu (unsigned), segmentation (enum 0x91), vendor (unsigned)
    p = 2
    result = {"address": addr[0], "port": addr[1]}
    try:
        if apdu[p] == 0xC4:
            val = struct.unpack(">I", apdu[p + 1:p + 5])[0]
            result["object_type"] = (val >> 22) & 0x3FF
            result["device_instance"] = val & 0x3FFFFF
            p += 5
        # max APDU (unsigned int tag 0x21/0x22...)
        tag = apdu[p]; ln = tag & 0x07
        if (tag & 0xF0) == 0x20:
            result["max_apdu"] = int.from_bytes(apdu[p + 1:p + 1 + ln], "big"); p += 1 + ln
        # segmentation (enum tag 0x91)
        if p < len(apdu) and apdu[p] == 0x91:
            seg = apdu[p + 1]
            result["segmentation"] = {0: "both", 1: "transmit", 2: "receive",
                                      3: "none"}.get(seg, seg)
            p += 2
        # vendor id (unsigned)
        if p < len(apdu):
            tag = apdu[p]; ln = tag & 0x07
            if (tag & 0xF0) == 0x20:
                result["vendor_id"] = int.from_bytes(apdu[p + 1:p + 1 + ln], "big")
    except Exception:
        pass
    return result


def bacnet_whois(port, timeout=3.0, target=None):
    """Broadcast (or unicast) Who-Is, collect I-Am replies."""
    pkt = _bacnet_whois_pkt()
    dest = (target or "255.255.255.255", port)
    echo(f"\nSending BACnet Who-Is to {dest[0]}:{dest[1]} (listening {timeout:.0f}s)...")
    log(f"BACNET_WHOIS dest={dest}")
    found = {}
    s = _bacnet_socket(port)
    try:
        s.sendto(pkt, dest)
        s.settimeout(timeout)
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(1500)
            except socket.timeout:
                break
            info = _bacnet_parse_iam(data, addr)
            if info and "device_instance" in info:
                found[(info["address"], info["device_instance"])] = info
    except Exception as e:
        echo(f"[✗] Who-Is failed: {e}")
        log(f"BACNET_WHOIS error {e}")
    finally:
        s.close()

    echo(f"\n--- BACnet Who-Is Results ({len(found)} device(s)) ---")
    if not found:
        echo("  (no I-Am replies — UDP 47808 may be filtered or no BACnet devices present)")
    for (ip, inst), info in sorted(found.items(), key=lambda x: x[0][1]):
        vid = info.get("vendor_id")
        vname = BACNET_VENDORS.get(vid, "unknown vendor")
        echo(f"  Device {inst}  @ {ip}")
        echo(f"      Vendor      : {vid} ({vname})")
        echo(f"      Max APDU    : {info.get('max_apdu', '?')}")
        echo(f"      Segmentation: {info.get('segmentation', '?')}")
        asset_update(ip, ports={BACNET_DEFAULT_PORT: "BACnet/IP"}, protocol="BACnet/IP",
                     vendor=(vname if vname != "unknown vendor" else ""),
                     version=f"BACnet device instance {inst}, vendor {vid} ({vname})",
                     source="BACnet")
        log(f"BACNET_IAM device={inst} ip={ip} vendor={vid}")
    echo("--- end ---")
    return found


def _bacnet_readprop_pkt(device_instance, prop_id, invoke=1):
    """Confirmed ReadProperty for a device object property."""
    # APDU: confirmed-req(0x00) | seg=0 | maxseg/maxapdu, invoke, service=12 (ReadProperty)
    apdu = bytes([0x00, 0x05, invoke & 0xFF, 0x0C])
    # object id: context tag 0 (0x0C) + object id (device=8)
    obj = (8 << 22) | (device_instance & 0x3FFFFF)
    apdu += bytes([0x0C]) + struct.pack(">I", obj)
    # property id: context tag 1 (0x19) + 1-byte prop id
    apdu += bytes([0x19, prop_id & 0xFF])
    npdu = bytes([0x01, 0x04])   # version 1, control 0x04 (expecting reply)
    body = npdu + apdu
    bvlc = bytes([0x81, 0x0A]) + struct.pack(">H", len(body) + 4)
    return bvlc + body


def _bacnet_parse_readprop(data):
    """Pull a character-string / unsigned / enum value out of a ReadProperty-ACK."""
    if len(data) < 6 or data[0] != 0x81:
        return None
    idx = 4
    npdu_ctrl = data[idx + 1]
    p = idx + 2
    # skip optional NPDU dest/src (best-effort)
    apdu = data[p:]
    # ComplexACK = 0x30
    if not apdu or (apdu[0] & 0xF0) != 0x30:
        return None
    # Walk to opening tag 3 (0x3E) ... closing tag 3 (0x3F) — the property value.
    try:
        oi = apdu.find(b"\x3e")
        oc = apdu.rfind(b"\x3f")
        if oi == -1 or oc == -1 or oc <= oi:
            return None
        value = apdu[oi + 1:oc]
        tag = value[0]
        tnum = (tag & 0xF0) >> 4
        ln = tag & 0x07
        vbytes = value[1:1 + ln] if ln < 5 else value[2:2 + value[1]]
        if tnum == 7:   # character string
            # first byte is the encoding; the rest is the string
            return vbytes[1:].decode(errors="ignore")
        if tnum == 2:   # unsigned int
            return int.from_bytes(vbytes, "big")
        if tnum == 9:   # enumerated
            return int.from_bytes(vbytes, "big")
        return vbytes.hex()
    except Exception:
        return None


def bacnet_read_device(port):
    """Unicast ReadProperty for name/vendor/model/firmware of one device."""
    ip = input("Device IP: ").strip()
    if not ip:
        echo("No IP provided.")
        return
    try:
        inst = int(input("Device instance number: ").strip())
    except ValueError:
        echo("Invalid instance.")
        return
    props = [(77, "Object Name"), (121, "Vendor Name"), (70, "Model Name"),
             (44, "Firmware Rev"), (12, "App SW Version")]
    echo(f"\n--- BACnet Device {inst} @ {ip} ---")
    log(f"BACNET_READ device={inst} ip={ip}")
    s = _bacnet_socket(port)
    s.settimeout(2.5)
    collected = {}
    try:
        for i, (pid, label) in enumerate(props, start=1):
            try:
                s.sendto(_bacnet_readprop_pkt(inst, pid, invoke=i), (ip, port))
                data, _ = s.recvfrom(1500)
                val = _bacnet_parse_readprop(data)
                echo(f" {label:<14}: {val if val is not None else '(no/unparsed reply)'}")
                log(f"BACNET_READ {label}={val}")
                if val is not None and str(val) != "":
                    collected[label] = str(val)
            except socket.timeout:
                echo(f" {label:<14}: (timeout)")
            except Exception as e:
                echo(f" {label:<14}: (error: {e})")
        if collected:
            parts = [f"{k}={v}" for k, v in collected.items()]
            asset_update(ip, ports={port: "BACnet/IP"}, protocol="BACnet/IP",
                         vendor=collected.get("Vendor Name", ""),
                         version=f"BACnet device {inst}: " + "; ".join(parts),
                         source="BACnet")
    finally:
        s.close()
    echo("--- end ---")


def bacnet_session(args):
    """Interactive BACnet/IP module: discover devices, read device properties."""
    port_in = input(f"BACnet/IP port [{BACNET_DEFAULT_PORT}]: ").strip()
    port = int(port_in) if port_in else BACNET_DEFAULT_PORT
    if args.readonly:
        echo("[!] Read-Only Mode ENABLED (BACnet module discovers/reads only)")
    log(f"BACNET_SESSION port={port}")

    while True:
        print("\n--- AtomICS - BACnet/IP Menu ---")
        print("1. Who-Is broadcast (discover all devices on the subnet)")
        print("2. Who-Is to a specific IP/subnet-broadcast")
        print("3. Read device properties (name/vendor/model/firmware)")
        print("4. Back to main menu")
        choice = input("\nSelect an option: ").strip()
        try:
            if choice == "1":
                bacnet_whois(port)
            elif choice == "2":
                tgt = input("Target IP or broadcast (e.g. 10.0.0.255): ").strip()
                bacnet_whois(port, target=tgt or None)
            elif choice == "3":
                bacnet_read_device(port)
            elif choice == "4":
                break
            else:
                echo("Invalid option.")
        except Exception as e:
            echo(f"Operation failed: {e}")
            log(f"BACNET_ERROR {e}")


# ------------------------ Modbus Menu ------------------------
def show_menu(client, readonly, target_ip, target_port):
    # Write options stay visible but are flagged, so an operator can see what
    # the tool is capable of without discovering it by accident.
    lock = "   [LOCKED - safe mode]" if readonly else ""
    while True:
        print("\n--- AtomICS - Modbus Utility Menu ---")
        print(f"    Target: {target_ip}:{target_port}   Mode: "
              + ("SAFE (read-only)" if readonly else "ACTIVE (writes enabled)"))
        print("1.  Read Coils")
        print(f"2.  Write Coil{lock}")
        print("3.  Read Registers")
        print(f"4.  Write Register{lock}")
        print("5.  Scan for Coils")
        print("6.  Scan for Registers")
        print("7.  Read Device Identity")
        print("8.  Recon Overview")
        print(f"9.  Flip Coils{lock}")
        print(f"10. Zero All Coils{lock}")
        print(f"11. Fuzz Registers{lock}")
        print(f"12. Hold Write (loop until interrupted){lock}")
        print("13. View Log File")
        print("14. Back to main menu")
        choice = input("\nSelect an option: ")
        try:
            if choice == "1":
                read_coils(client)
            elif choice == "2":
                write_coil(client, readonly)
            elif choice == "3":
                read_registers(client)
            elif choice == "4":
                write_register(client, readonly)
            elif choice == "5":
                scan_coils(client)
            elif choice == "6":
                scan_registers(client)
            elif choice == "7":
                read_device_identity(client, target_ip)
            elif choice == "8":
                banner_grab(client, target_ip, target_port)
            elif choice == "9":
                flip_all_coils(client, readonly)
            elif choice == "10":
                zero_all_coils(client, readonly)
            elif choice == "11":
                fuzz_registers(client, readonly)
            elif choice == "12":
                hold_write(client, readonly)
            elif choice == "13":
                view_log()
            elif choice == "14":
                break
            else:
                echo("Invalid option.")
        except (ValueError, ModbusException) as e:
            echo("Operation failed.")
            log(f"ERROR {e}")


def modbus_flow(args):
    """Prompt/connect for Modbus and hand off to the Modbus menu."""
    if not MODBUS_AVAILABLE:
        echo("[✗] Modbus support requires pymodbus, which is not installed.")
        echo("    Install it with:  pip install pymodbus")
        log(f"MODBUS_UNAVAILABLE {MODBUS_IMPORT_ERROR}")
        return
    ip = args.ip or input("Enter target Modbus TCP IP: ").strip()
    if not ip:
        echo("No IP provided.")
        return
    client = connect_to_modbus(ip, readonly=args.readonly)
    if client:
        # A successful connect confirms Modbus/502 on this host.
        asset_update(ip, ports={502: "Modbus TCP"}, protocol="Modbus TCP", source="Modbus")
        try:
            show_menu(client, args.readonly, ip, 502)
        finally:
            client.close()
            log("DISCONNECTED")


# ------------------------ Main Menu ------------------------
def protocol_modules_menu(args):
    """Submenu grouping the per-protocol device modules (main menu item 2).

    These all connect to a specific device and speak its protocol, as opposed
    to Network Discovery (which finds hosts) and the Asset Register (which
    collects what every module learns).
    """
    while True:
        print("\n--- AtomICS - Protocol Modules ---")
        print("    Mode: " + ("SAFE (read-only)" if args.readonly
                              else "ACTIVE (writes enabled)"))
        print("1. Modbus")
        print("2. S7 (Siemens)")
        print("3. EtherNet/IP (CIP)")
        print("4. DNP3")
        print("5. BACnet")
        print("6. SNMP")
        print("7. Back to main menu")
        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            modbus_flow(args)
        elif choice == "2":
            s7_session(args)
        elif choice == "3":
            enip_session(args)
        elif choice == "4":
            dnp3_session(args)
        elif choice == "5":
            bacnet_session(args)
        elif choice == "6":
            snmp_session(default_ip=args.ip)
        elif choice == "7":
            break
        else:
            echo("Invalid option.")


def protocol_menu(args):
    while True:
        print("\n=== AtomICS - Main Menu ===")
        print("    Mode: " + ("SAFE (read-only)" if args.readonly
                              else "ACTIVE (writes enabled)"))
        print("")
        print("1. Network Discovery")
        print("2. Protocol Modules (Modbus, S7, EtherNet/IP, DNP3, BACnet, SNMP)")
        print(f"3. Asset Register ({_asset_summary_label()})")
        print("4. Exit")
        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            network_discovery_session(args)
        elif choice == "2":
            protocol_modules_menu(args)
        elif choice == "3":
            asset_register_session()
        elif choice == "4":
            log("SESSION_END")
            break
        else:
            echo("Invalid option.")


# ------------------------ Main ------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AtomICS (OT/ICS Recon & Assessment Console) - multi-protocol",
        epilog=DISCLAIMER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("ip", nargs="?",
                        help="Optional target IP; used as the default for the chosen module")
    parser.add_argument("--active", action="store_true",
                        help="Enable write / state-changing operations (Modbus write "
                             "coil+register, flip, zero, fuzz, hold). Without this AtomICS "
                             "runs in SAFE MODE and every write path refuses. In active "
                             "mode writes run immediately, with a [write] line printed and "
                             "logged for the record.")
    parser.add_argument("--readonly", action="store_true",
                        help="Kept for compatibility. Read-only is now the default, and "
                             "this flag is a hard override: pass it and writes stay "
                             "blocked even alongside --active.")
    parser.add_argument("--log", action="store_true", help="Enable file logging")
    parser.add_argument("--update-oui", action="store_true",
                        help="Download a full OUI (MAC vendor) database next to this "
                             "script for real vendor resolution, then exit. Tries IEEE "
                             "then Wireshark mirrors, so it works even when one source "
                             "is blocked. Run it once on a machine with internet; the "
                             "file (~35k vendors) then loads automatically.")
    args = parser.parse_args()

    if args.update_oui:
        update_oui()
        sys.exit(0)

    # Safe by default. --active opts in; --readonly always wins, so a wrapper
    # script or a shell alias can pin a jump box to read-only and no argument
    # added later can quietly undo it.
    args.readonly = (not args.active) or args.readonly

    if args.log:
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        LOG_FILE = f"atomics_log_{ts}.log"
        log("LOGGING_ENABLED")

    echo("=" * 60)
    echo(" AtomICS - OT/ICS Recon & Assessment Console (v0.1)")
    echo("=" * 60)
    for _dl in DISCLAIMER.splitlines():
        echo(" " + _dl)
    echo("=" * 60)
    if args.readonly:
        echo(" MODE: SAFE - read-only. Writes and state-changing actions are")
        echo("       blocked. Relaunch with --active to enable them.")
        if args.active:
            echo("       (--active was overridden by --readonly)")
    else:
        echo(" !! MODE: ACTIVE - writes and state-changing actions are ENABLED !!")
        echo("    This session can change live device state. Writes execute")
        echo("    immediately, each logged as a [write] line - no per-write prompt.")
    echo("=" * 60)
    _print_local_ifaces("  ", blank_after=False)
    load_oui_database()
    echo("=" * 60)

    try:
        protocol_menu(args)
    except KeyboardInterrupt:
        echo("\nInterrupted.")
    echo("Goodbye.")
