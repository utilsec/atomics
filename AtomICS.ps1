#Requires -Version 2
<#
============================================================
 AtomICS - OT/ICS Recon & Assessment Console (PowerShell Edition)  v1.1

 This is the no-install, single-file PowerShell edition of AtomICS (the
 Python "OT/ICS Recon & Assessment Console", atomics.py; formerly OT RUNG).
 It exists so a version of AtomICS can run on a locked-down Windows host - a
 plant jump box, an engineering workstation - with NOTHING installed: no
 Python, no pip, no Npcap, no modules. It uses only what ships in the box back
 to Windows 7 / Server 2008 R2 and Windows PowerShell 2.0.

 As of v1.1 this edition tracks the Python tool feature-for-feature as far as a
 pure, in-box PowerShell can:
   Network Discovery : local interfaces, ARP cache read, a NO-ADMIN
                       broadcast/multicast passive listener (DHCP / mDNS /
                       LLMNR / NBNS / SSDP / WS-Discovery), ICMP sweep and a
                       TCP-connect port scan over the IT/OT port lists.
   Protocol Modules  : Modbus/TCP, S7comm (Siemens), EtherNet/IP (CIP), DNP3,
                       BACnet/IP, SNMP (v1/v2c), and IEC 60870-5-104 - each
                       spoken directly on the wire with raw sockets, no DLLs.
   Auto-Fingerprint  : point it at one IP; it connect-scans the OT ports then
                       runs each matching module's read-only recon in one pass.
   Asset Register    : in-memory inventory every module feeds; CSV / JSON export.

 NOT in this edition, and why:
   Promiscuous layer-2 capture (sniffing unicast IT/OT, CDP/LLDP/PROFINET) -
     needs a raw capture driver. On Windows that means Npcap (an install) or
     pktmon (Win10 / Server 2016+), neither of which fits "install nothing on
     Win7". The no-admin passive listener below gets IP + hostnames without it;
     for full promiscuous capture use the Python AtomICS with Npcap.

 !! DISCLAIMER !!
 For training/education or AUTHORIZED assessment ONLY, on systems you own or
 are explicitly permitted to test. This tool speaks live control-system
 protocols and must NOT be used in production or on any network where safety
 and/or operational availability cannot be guaranteed. Use is at your own risk.

 SAFE MODE: AtomICS starts read-only. Two things need -Active: writes and
 state-changing control (Modbus write/flip/zero/fuzz/hold; the S7 DB/M/Q writes
 and STOP/START; the IEC 104 C_SC/C_DC/C_SE commands), and the active scans that
 transmit (ICMP sweep, TCP connect scan). The ARP cache read and the passive
 listener send nothing and stay available in safe mode. Passing -Active is the
 operator's opt-in, so in active mode writes run immediately (no per-write
 prompt); each prints and logs a [write] record. The one exception is S7 STOP,
 which still asks for the target IP. -ReadOnly is a hard override: pass it and
 writes/active-scans stay blocked even with -Active, so a shortcut or alias can
 pin a box read-only.

 This script was vibe coded by Mike Holcomb of UtilSec, LLC.
 LinkedIn : https://www.linkedin.com/in/mikeholcomb
 Website  : https://www.utilsec.com

 Compatibility notes (Windows PowerShell 2.0):
   - No -shl / -shr operators (added in 3.0): all byte packing uses
     [math]::Floor-based arithmetic and -band instead.
   - No [pscustomobject] literal: records are built with New-Object PSObject.
   - No Get-Net* cmdlets: interfaces come from WMI, the ARP table from arp -a.
   - No -in / -notin operators: membership is tested with -contains.
   - No -Parallel: scans and polls are sequential by design, which also matches
     the OT rule of being gentle on the wire (one connection at a time).
   - All protocol modules use System.Net.Sockets directly - no third-party
     stack, no snap7/pysnmp. S7comm, SNMP, DNP3, BACnet and IEC 104 are spoken
     as raw bytes, so there is nothing to install.

 Changelog
   v1.1  Renamed the PowerShell edition SPRUNG -> AtomICS (file AtomICS.ps1), to
         match the Python tool: the two editions now share one name, told apart
         only by extension (atomics.py vs AtomICS.ps1). Name/identity change
         only - no protocol, menu, flag, or output behaviour changed. Export
         filename prefixes sprung_* -> atomics_ps_* (kept distinct from the
         Python tool's own atomics_* so a shared field-kit folder stays
         unambiguous). OUI env var is $env:ATOMICS_OUI_FILE (shared with the
         Python tool); legacy $env:SPRUNG_OUI_FILE still honored.
   v1.0  Full-parity PowerShell rebuild (shipped under the name SPRUNG),
         tracking atomics.py v0.4.0 as closely as an in-box PowerShell can.
         Added, all PS 2.0-safe and pure-socket:
           * Menu restructure to match AtomICS: Main = Network Discovery /
             Protocol Modules / Auto-Fingerprint / Asset Register / Help / Exit.
           * In-memory ASSET REGISTER fed by every module (IP, MAC+vendor,
             hostname, open ports, protocols, version/identity); CSV + JSON
             export (atomics_ps_assets_*). Memory-only until exported.
           * NO-ADMIN passive listener in Network Discovery: ordinary UDP
             sockets bound to the discovery ports, multicast groups joined -
             harvests IP + hostname from DHCP / mDNS / LLMNR / NBNS / SSDP /
             WS-Discovery, DHCP also yields the client MAC, the rest filled
             from the ARP cache. No Npcap, no Administrator. CSV export.
           * OUI engine overhaul to match the Python tool: three-tier
             longest-prefix matching (/36 MA-S/IAB > /28 MA-M > /24 MA-L),
             maclookup.app CSV format alongside IEEE oui.csv/oui.txt and
             Wireshark 'manuf', subdirectory + parent-directory file search,
             and the maclookup.app source tried first by -UpdateOui. $env:
             ATOMICS_OUI_FILE honored (legacy $env:SPRUNG_OUI_FILE still works).
           * Protocol Modules submenu with SEVEN modules. New since v0.7:
               - S7comm (TCP/102): raw TPKT/COTP/S7. CPU info, order code +
                 firmware, CPU state, protection level, block inventory, DB and
                 I/Q/M reads; Write DB, Write M/Q, STOP and START CPU (-Active).
               - EtherNet/IP (TCP/UDP 44818): ListIdentity / ListServices /
                 ListInterfaces / RegisterSession + UDP discovery.
               - DNP3 (TCP/20000): link status, integrity / Class 0 polls,
                 arbitrary object reads, with the DNP3 CRC and block framing.
               - BACnet/IP (UDP/47808): Who-Is discovery + ReadProperty.
               - SNMP (UDP/161): v1/v2c GET + limited walk via raw BER; summary,
                 full dump, enterprise/vendor decode of sysObjectID.
               - IEC 60870-5-104 (TCP/2404): APCI I/S/U framing, General +
                 Counter interrogation, single/double/setpoint commands (-Active)
                 with Select-Before-Operate or direct-operate.
           * AUTO-FINGERPRINT: one-shot read-only interrogation of a single IP
             across the OT ports; folds everything into the Asset Register.
           * HELP screen (menu item + -Help) describing menus, modes and flags.
         Safe mode now also gates the active Network Discovery scans (ICMP, TCP
         connect) - they transmit - while the passive listener and ARP cache
         read stay available. Writes/control keep the v0.2 model: no per-write
         prompt in active mode, a [write] audit line instead (S7 STOP excepted).
   v0.7  Removed the hardcoded built-in OUI seed; vendor names come ONLY from a
         loaded OUI file.
   v0.6  -UpdateOui tries several sources (IEEE, Wireshark manuf + mirror).
   v0.5  Real OUI vendor resolution from a loaded file; -UpdateOui downloads one.
   v0.4  MAC vendor shown in parentheses after every MAC.
   v0.3  Renamed the PowerShell edition to AtomICS; safe mode gates active scans.
   v0.2  Active mode no longer prompts per write ([write] audit line instead).
   v0.1  First PowerShell edition: Network Discovery + Modbus, safe-mode default.
============================================================
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string] $IP,

    [switch] $Active,
    [switch] $ReadOnly,
    [switch] $Log,
    [switch] $UpdateOui,
    [switch] $Help
)

# Safe by default. -Active opts in; -ReadOnly always wins, so a wrapper script
# or shortcut can pin a jump box to read-only and no later flag undoes it.
$script:SafeMode  = (-not $Active) -or $ReadOnly
$script:LogFile   = $null
$script:ScriptDir = $null
try { $script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path } catch { }
if (-not $script:ScriptDir) { $script:ScriptDir = (Get-Location).Path }

# ------------------------------------------------------------
#  Constants
# ------------------------------------------------------------
$script:Version = "v1.1"

$script:Disclaimer = @(
    "DISCLAIMER: For training/education or AUTHORIZED assessment ONLY, on",
    "systems you own or are explicitly permitted to test. This tool speaks",
    "live OT/ICS protocols and MUST NOT be used in production or on any",
    "network where safety and/or operational availability cannot be",
    "guaranteed. You are solely responsible for how this tool is used."
)

$script:ModbusDefaultPort = 502
$script:ScanDefaultRange  = 1000
$script:ScanBlockCoils    = 800
$script:ScanBlockRegs     = 100
$script:MaxLength         = 10000     # survey ceiling for flip/zero/fuzz
$script:HostScanWarn      = 512

# Bit masks for coil/bit unpacking (no -shl available on PS 2.0).
$script:BitMasks = @(1, 2, 4, 8, 16, 32, 64, 128)

# Modbus FC 43 device identity object IDs (per the Modbus spec).
$script:DeviceIdMap = @(
    @(0x00, "VendorName"),
    @(0x01, "ProductCode"),
    @(0x02, "MajorMinorRevision"),
    @(0x05, "ModelName"),
    @(0x0A, "ProductName")
)

# Common IT service ports (mirrors atomics.py).
$script:CommonItPorts = @{
    21 = "FTP"; 22 = "SSH"; 23 = "Telnet"; 25 = "SMTP"; 53 = "DNS";
    80 = "HTTP"; 110 = "POP3"; 111 = "RPCbind"; 135 = "MSRPC"; 139 = "NetBIOS";
    143 = "IMAP"; 161 = "SNMP"; 389 = "LDAP"; 443 = "HTTPS"; 445 = "SMB";
    465 = "SMTPS"; 587 = "Submission"; 636 = "LDAPS"; 993 = "IMAPS"; 995 = "POP3S";
    1433 = "MSSQL"; 1521 = "Oracle"; 3306 = "MySQL"; 3389 = "RDP";
    5432 = "PostgreSQL"; 5900 = "VNC"; 5985 = "WinRM"; 8080 = "HTTP-alt";
    8443 = "HTTPS-alt"; 9100 = "JetDirect"
}

# Common OT / ICS protocol ports (mirrors atomics.py).
$script:CommonOtPorts = @{
    102 = "S7comm / ISO-TSAP (Siemens)"; 502 = "Modbus TCP";
    789 = "Red Lion Crimson"; 1089 = "Foundation Fieldbus HSE";
    1090 = "Foundation Fieldbus HSE"; 1091 = "Foundation Fieldbus HSE";
    1911 = "Niagara Fox (Tridium)"; 1962 = "PCWorx (Phoenix Contact)";
    2222 = "EtherNet/IP (implicit I/O)"; 2404 = "IEC 60870-5-104";
    2455 = "CoDeSys"; 4000 = "OPC (Emerson ROC)"; 4840 = "OPC UA";
    4911 = "Niagara Fox SSL (Tridium)"; 5006 = "MELSEC-Q (Mitsubishi)";
    5007 = "MELSEC-Q (Mitsubishi)"; 9600 = "OMRON FINS"; 18245 = "GE SRTP";
    18246 = "GE SRTP"; 20000 = "DNP3"; 20547 = "ProConOS";
    34962 = "PROFINET RT"; 34963 = "PROFINET RT"; 34964 = "PROFINET RT";
    44818 = "EtherNet/IP (explicit / CIP)"; 47808 = "BACnet/IP"; 55000 = "FL-net"
}

# OT service ports probed by Auto-Fingerprint, in order (tcp_port, label).
$script:AutoFpTcp = @(
    @(502,   "Modbus TCP"),
    @(102,   "S7comm / ISO-TSAP (Siemens)"),
    @(44818, "EtherNet/IP (explicit / CIP)"),
    @(20000, "DNP3"),
    @(2404,  "IEC 60870-5-104")
)

# ------------------------------------------------------------
#  Output & logging
# ------------------------------------------------------------
# Write-Host -ForegroundColor is the reliable colour path on legacy conhost
# (ANSI escapes are not interpreted there), and it degrades cleanly. Body text
# is bright white because grey is unreadable on a real plant terminal.
function Write-Body { param([string] $Text) Write-Host $Text -ForegroundColor White }
function Write-Head { param([string] $Text)
    Write-Host ""
    Write-Host $Text -ForegroundColor Cyan
}
function Write-Ok   { param([string] $Text) Write-Host ("[+] " + $Text) -ForegroundColor Green }
function Write-Info { param([string] $Text) Write-Host ("[i] " + $Text) -ForegroundColor White }
function Write-Warn2{ param([string] $Text) Write-Host ("[!] " + $Text) -ForegroundColor Yellow }
function Write-Bad  { param([string] $Text) Write-Host ("[x] " + $Text) -ForegroundColor Red }

function Write-LogLine {
    param([string] $Text)
    if (-not $script:LogFile) { return }
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    try { Add-Content -Path $script:LogFile -Value ("[" + $ts + "] " + $Text) } catch { }
}

function Get-ModeLabel {
    if ($script:SafeMode) { return "Safe Mode" }
    return "Active Mode"
}

# Standard menu header: "=== AtomICS - <Name> (Safe/Active Mode) ===".
function Write-MenuTitle {
    param([string] $Name)
    Write-Host ""
    Write-Host ("=== AtomICS - " + $Name + " (" + (Get-ModeLabel) + ") ===") -ForegroundColor Cyan
}

# ------------------------------------------------------------
#  Safe mode
# ------------------------------------------------------------
# One gate stands between a keystroke and a value landing in a live controller:
# -Active must have been passed at launch, or every write path refuses. Passing
# -Active is the operator's deliberate opt-in, so once in active mode a write
# executes immediately with no per-write prompt. A one-line [write] record is
# still printed and logged so there is an on-screen and on-disk trail.
function Test-SafeBlocked {
    param([string] $Action)
    if ($script:SafeMode) {
        Write-Warn2 ($Action + " blocked: SAFE MODE (read-only). Relaunch with -Active to enable writes.")
        Write-LogLine ("SAFE_MODE_BLOCKED " + $Action)
        return $true
    }
    return $false
}

# Active (transmitting) scans - ICMP sweep, TCP connect scan - are gated in
# safe mode exactly like writes: they put packets on the wire. The ARP CACHE
# read and the passive listener are exempt (they send nothing).
function Test-ScanBlocked {
    param([string] $Name)
    if ($script:SafeMode) {
        Write-Warn2 ($Name + " blocked: SAFE MODE. This scan transmits on the network. Relaunch with -Active for active scanning.")
        Write-LogLine ("SAFE_MODE_BLOCKED scan=" + $Name)
        return $true
    }
    return $false
}

function Confirm-Write {
    # Reaching here means -Active was passed (safe mode refuses writes before
    # this is called), so proceed without prompting. It records rather than
    # confirms: a one-line [write] trail on screen and in the log.
    param([string] $Description)
    Write-Body ("  [write] " + $Description)
    Write-LogLine ("WRITE_EXECUTED " + $Description)
    return $true
}

# ------------------------------------------------------------
#  Byte helpers (PS 2.0 has no -shl / -shr)
# ------------------------------------------------------------
function Get-HiByte { param([int] $Value) return ([int][math]::Floor($Value / 256) -band 0xFF) }
function Get-LoByte { param([int] $Value) return ($Value -band 0xFF) }
function Get-U16BE  { param([byte[]] $Buf, [int] $Off) return (([int] $Buf[$Off]) * 256 + [int] $Buf[$Off + 1]) }
function Get-U32BE  {
    param([byte[]] $Buf, [int] $Off)
    return ([long]([int] $Buf[$Off]) * 16777216 + [long]([int] $Buf[$Off + 1]) * 65536 `
            + [long]([int] $Buf[$Off + 2]) * 256 + [long]([int] $Buf[$Off + 3]))
}
# Pack an integer into N big-endian bytes.
function ConvertTo-BytesBE {
    param([long] $Value, [int] $Width)
    $out = New-Object byte[] $Width
    for ($i = $Width - 1; $i -ge 0; $i--) {
        $out[$i] = [byte]($Value -band 0xFF)
        $Value = [math]::Floor($Value / 256)
    }
    return ,$out
}
# IEEE-754 single <-> 4 big-endian bytes (BitConverter is little-endian on x86).
function ConvertTo-FloatBE {
    param([double] $Value)
    $le = [System.BitConverter]::GetBytes([single] $Value)
    [array]::Reverse($le)
    return ,$le
}
function ConvertFrom-FloatBE {
    param([byte[]] $Buf, [int] $Off)
    $tmp = @($Buf[$Off], $Buf[$Off + 1], $Buf[$Off + 2], $Buf[$Off + 3])
    [array]::Reverse($tmp)
    return [System.BitConverter]::ToSingle([byte[]] $tmp, 0)
}
# Signed 16-bit from two big-endian bytes.
function Get-S16BE {
    param([byte[]] $Buf, [int] $Off)
    $v = Get-U16BE $Buf $Off
    if ($v -gt 32767) { $v = $v - 65536 }
    return $v
}
# Classic offset/hex/ascii dump.
function Format-HexDump {
    param([byte[]] $Data, [int] $Base = 0, [int] $Width = 16)
    if (-not $Data -or $Data.Length -eq 0) { return "  (no data)" }
    $lines = @()
    for ($off = 0; $off -lt $Data.Length; $off += $Width) {
        $hex = ""
        $asc = ""
        for ($i = 0; $i -lt $Width; $i++) {
            if (($off + $i) -lt $Data.Length) {
                $b = [int] $Data[$off + $i]
                $hex += ("{0:x2} " -f $b)
                if ($b -ge 32 -and $b -lt 127) { $asc += [char] $b } else { $asc += "." }
            } else {
                $hex += "   "
            }
        }
        $lines += ("  {0,5}: {1} {2}" -f ($Base + $off), $hex, $asc)
    }
    return ($lines -join "`n")
}
# ============================================================
#  OUI / MAC-vendor engine (three-tier longest-prefix match)
# ============================================================
# There is NO hardcoded vendor list. The three tiers start empty and fill from
# a real OUI file: maclookup.app CSV, IEEE oui.csv / oui.txt, or a Wireshark
# 'manuf' file. A MAC resolves to the most specific block that matches
# (/36 MA-S/IAB > /28 MA-M > /24 MA-L), which fixes the ~45% of /24 ranges the
# registry subdivides among several vendors. Parsing mirrors the Python AtomICS
# so the two tools resolve identically. Until a file is loaded every
# globally-administered MAC shows "(unknown vendor)"; randomized/locally-
# administered MACs are still flagged algorithmically.
$script:OuiDb24   = @{}     # /24 (MA-L, CID): key "AA:BB:CC"
$script:OuiDbM    = @{}     # /28 (MA-M):      key 7 hex nibbles "AABBCCD"
$script:OuiDbS    = @{}     # /36 (MA-S, IAB): key 9 hex nibbles "AABBCC001"
$script:OuiSource = $null   # path once a database is loaded

# Normalise a token to 'AA:BB:CC' (first 3 octets). '' if bad. (/24 key.)
function ConvertTo-OuiPrefix {
    param([string] $Token)
    if (-not $Token) { return "" }
    $t = ($Token.Split("/")[0]).Trim().Replace("-", ":").Replace(".", ":")
    if ($t.Contains(":")) {
        $parts = @($t.Split(":") | Where-Object { $_ -ne "" })
    } else {
        $parts = @()
        for ($i = 0; ($i + 2) -le $t.Length; $i += 2) { $parts += $t.Substring($i, 2) }
    }
    if ($parts.Count -lt 3) { return "" }
    $out = @()
    for ($i = 0; $i -lt 3; $i++) {
        $pp = ([string] $parts[$i]).PadLeft(2, "0")
        if ($pp -notmatch '^[0-9A-Fa-f]{2}$') { return "" }
        $out += $pp.ToUpper()
    }
    return ($out -join ":")
}

# Normalise a prefix to uppercase hex nibbles, no separators - its LENGTH
# carries the block size (6=/24, 7=/28, 9=/36). Honours maclookup's digit-count
# encoding AND Wireshark manuf's '/NN' bit mask.
function ConvertTo-OuiPrefixLen {
    param([string] $Token)
    if (-not $Token) { return "" }
    $t = $Token.Trim()
    $bits = $null
    if ($t.Contains("/")) {
        $parts = $t.Split("/")
        $t = $parts[0]
        $tmp = 0
        if ($parts.Count -gt 1 -and [int]::TryParse(($parts[1]).Trim(), [ref] $tmp)) { $bits = $tmp }
    }
    $t = $t.Replace("-", "").Replace(":", "").Replace(".", "").ToUpper()
    if ($bits -ne $null) {
        $keep = [int][math]::Floor($bits / 4)
        if ($keep -lt 6) { $keep = 6 }
        if ($t.Length -gt $keep) { $t = $t.Substring(0, $keep) }
    }
    if ($t.Length -lt 6) { return "" }
    if ($t -notmatch '^[0-9A-F]+$') { return "" }
    return $t
}

# Route one (prefix, vendor) into the right tier by prefix length.
function Add-OuiEntry {
    param([string] $PrefixToken, [string] $Vendor)
    $raw = ConvertTo-OuiPrefixLen $PrefixToken
    if (-not $raw -or -not $Vendor) { return }
    $v = $Vendor.Trim().TrimEnd(',', ' ').Trim()   # maclookup leaves trailing commas
    if (-not $v) { return }
    $n = $raw.Length
    if ($n -ge 9) { $script:OuiDbS[$raw.Substring(0, 9)] = $v }
    elseif ($n -ge 7) { $script:OuiDbM[$raw.Substring(0, 7)] = $v }
    else {
        $pfx = ConvertTo-OuiPrefix $PrefixToken
        if ($pfx) { $script:OuiDb24[$pfx] = $v }
    }
}

# Fold an OUI file into the three tiers. Returns the number of NEW entries.
# Best-effort; never fatal. Handles maclookup.app CSV, IEEE oui.csv/oui.txt,
# and Wireshark 'manuf'.
function Import-OuiFile {
    param([string] $Path)
    $before = $script:OuiDb24.Count + $script:OuiDbM.Count + $script:OuiDbS.Count
    $head = $null
    try {
        $reader = New-Object System.IO.StreamReader($Path)
        $head = $reader.ReadLine()
        $reader.Close()
    } catch { return 0 }
    if ($head -eq $null) { return 0 }
    $low = ([string] $head).ToLower()

    if ($low.Contains("mac prefix")) {
        $rows = $null
        try { $rows = Import-Csv -Path $Path } catch { return 0 }
        foreach ($r in $rows) { Add-OuiEntry ([string] $r.'Mac Prefix') ([string] $r.'Vendor Name') }
    } elseif ($low.Contains("registry") -and $low.Contains("assignment")) {
        $rows = $null
        try { $rows = Import-Csv -Path $Path } catch { return 0 }
        foreach ($r in $rows) { Add-OuiEntry ([string] $r.Assignment) ([string] $r.'Organization Name') }
    } else {
        $lines = $null
        try { $lines = Get-Content -Path $Path } catch { return 0 }
        foreach ($line in $lines) {
            $s = [string] $line
            if (-not $s -or $s.TrimStart().StartsWith("#")) { continue }
            if ($s.Contains("(base 16)")) { continue }
            if ($s.Contains("(hex)")) {
                $bits = $s -split "\(hex\)", 2
                if ($bits.Count -ge 2) { Add-OuiEntry ([string] $bits[0]) (([string] $bits[1]).Trim()) }
                continue
            }
            $toks = @($s -split "`t" | Where-Object { $_.Trim() -ne "" })
            if ($toks.Count -lt 2) { $toks = @($s -split "\s{2,}" | Where-Object { $_.Trim() -ne "" }) }
            if ($toks.Count -ge 2) {
                $vendor = ([string] $toks[$toks.Count - 1]).Trim()
                if ($vendor -and -not $vendor.StartsWith("#")) { Add-OuiEntry ([string] $toks[0]) $vendor }
            }
        }
    }
    $after = $script:OuiDb24.Count + $script:OuiDbM.Count + $script:OuiDbS.Count
    return ($after - $before)
}

# Locate an OUI file: $env:ATOMICS_OUI_FILE (legacy $env:SPRUNG_OUI_FILE still
# honored), then known filenames beside the script / cwd, one level of
# subdirectories under each, then up to two parent directories.
function Find-OuiFile {
    $envfile = $env:ATOMICS_OUI_FILE
    if (-not $envfile) { $envfile = $env:SPRUNG_OUI_FILE }
    if ($envfile -and (Test-Path -LiteralPath $envfile)) { return $envfile }

    $names = @("oui.csv", "mac-vendors-export.csv", "maclookup.csv", "oui.txt", "manuf")
    $primary = @()
    foreach ($d in @($script:ScriptDir, (Get-Location).Path)) {
        if ($d -and ($primary -notcontains $d)) { $primary += $d }
    }
    foreach ($d in $primary) {
        foreach ($n in $names) {
            $pp = Join-Path $d $n
            if (Test-Path -LiteralPath $pp) { return $pp }
        }
    }
    foreach ($d in $primary) {
        $subs = @()
        try { $subs = @(Get-ChildItem -Path $d -ErrorAction Stop | Where-Object { $_.PSIsContainer }) } catch { $subs = @() }
        foreach ($sub in $subs) {
            foreach ($n in $names) {
                $pp = Join-Path $sub.FullName $n
                if (Test-Path -LiteralPath $pp) { return $pp }
            }
        }
    }
    foreach ($d in $primary) {
        $cur = $d
        for ($k = 0; $k -lt 2; $k++) {
            $parent = Split-Path -Parent $cur
            if (-not $parent -or $parent -eq $cur) { break }
            foreach ($n in $names) {
                $pp = Join-Path $parent $n
                if (Test-Path -LiteralPath $pp) { return $pp }
            }
            $cur = $parent
        }
    }
    return $null
}

function Import-OuiDatabaseAtStartup {
    $path = Find-OuiFile
    if (-not $path) {
        Write-Info "OUI: no database loaded - every MAC shows '(unknown vendor)'."
        Write-Body "    Run with -UpdateOui, or save the maclookup.app CSV as oui.csv (or a"
        Write-Body "    Wireshark 'manuf' / IEEE oui.csv) beside the script, for vendor names."
        return
    }
    [void](Import-OuiFile $path)
    if (($script:OuiDb24.Count + $script:OuiDbM.Count + $script:OuiDbS.Count) -eq 0) {
        Write-Warn2 ("OUI file " + $path + " could not be parsed - no vendor resolution.")
        return
    }
    $script:OuiSource = $path
}

function Update-OuiDatabase {
    # maclookup.app's consolidated CSV first (MA-L/M/S in one file), then IEEE,
    # then Wireshark 'manuf' and its GitHub mirror. Keep the first real database.
    $sources = @(
        @("https://maclookup.app/downloads/csv-database", "oui.csv", "maclookup.app (CSV)"),
        @("https://standards-oui.ieee.org/oui/oui.csv", "oui.csv", "IEEE registry (CSV)"),
        @("https://www.wireshark.org/download/automated/data/manuf", "manuf", "Wireshark manuf"),
        @("https://raw.githubusercontent.com/wireshark/wireshark/master/manuf", "manuf", "Wireshark manuf (GitHub mirror)")
    )
    Write-Info "Fetching a full OUI (MAC vendor) database. Trying sources in order:"
    foreach ($src in $sources) {
        $url = $src[0]; $fname = $src[1]; $label = $src[2]
        $dest = Join-Path $script:ScriptDir $fname
        Write-Body ("  - " + $label + ": " + $url)
        try {
            # Prefer TLS 1.2 where the .NET version supports it (older boxes default to SSL3/TLS1).
            try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch { }
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent", "Mozilla/5.0 (AtomICS/AtomICS OUI updater)")
            $wc.DownloadFile($url, $dest)
        } catch {
            Write-Body ("      [x] failed: " + $_.Exception.Message)
            continue
        }
        $script:OuiDb24 = @{}; $script:OuiDbM = @{}; $script:OuiDbS = @{}
        $added = Import-OuiFile $dest
        if ($added -lt 1000) {
            Write-Body ("      [x] only " + $added + " entries parsed - looks incomplete, trying next source.")
            try { Remove-Item -LiteralPath $dest -ErrorAction SilentlyContinue } catch { }
            continue
        }
        Write-Ok ("Saved " + $dest + " (" + $added + " entries) - loads automatically next run.")
        return
    }
    Write-Bad "Every source failed (network blocked, or offline)."
    Write-Body "    Download one of these in a browser and save it next to the script:"
    Write-Body ("      " + $script:ScriptDir)
    Write-Body "      https://maclookup.app/downloads/csv-database            -> save as oui.csv"
    Write-Body "      https://standards-oui.ieee.org/oui/oui.csv              -> save as oui.csv"
    Write-Body "      https://www.wireshark.org/download/automated/data/manuf -> save as manuf"
}

# Longest-prefix MAC vendor lookup. Returns "" when nothing matches and the
# address is globally administered; "(randomized / local MAC)" for a locally-
# administered address.
function Get-OuiVendor {
    param([string] $Mac)
    if (-not $Mac -or $Mac.Length -lt 8) { return "" }
    $raw = $Mac.Replace(":", "").Replace("-", "").Replace(".", "").ToUpper()
    if ($raw.Length -ge 9 -and $script:OuiDbS.ContainsKey($raw.Substring(0, 9))) { return $script:OuiDbS[$raw.Substring(0, 9)] }
    if ($raw.Length -ge 7 -and $script:OuiDbM.ContainsKey($raw.Substring(0, 7))) { return $script:OuiDbM[$raw.Substring(0, 7)] }
    $k24 = $Mac.Substring(0, 8).ToUpper()
    if ($script:OuiDb24.ContainsKey($k24)) { return $script:OuiDb24[$k24] }
    $firstOctet = 0
    try { $firstOctet = [Convert]::ToInt32($Mac.Substring(0, 2), 16) } catch { return "" }
    if ($firstOctet -band 0x02) { return "(randomized / local MAC)" }
    return ""
}

# Format a MAC with its vendor in parentheses. Pass an explicit vendor (e.g.
# one a protocol module already resolved) to override the OUI lookup.
function Format-MacVendor {
    param([string] $Mac, [string] $Vendor = "")
    if (-not $Mac) { return "(unknown MAC)" }
    $v = $Vendor
    if (-not $v) { $v = Get-OuiVendor $Mac }
    if ($v) {
        # Unwrap ONLY a fully-parenthesised sentinel like "(randomized / local
        # MAC)" - never strip a trailing ")" from a real name like "VMware (NIC)".
        if ($v.StartsWith("(") -and $v.EndsWith(")")) { $v = $v.Substring(1, $v.Length - 2) }
    } else {
        $v = "unknown vendor"
    }
    return ($Mac + " (" + $v + ")")
}

# After a scan, nudge the operator to load an OUI DB if none is loaded and some
# globally-administered MACs went unresolved. Silent once a real file is in use.
function Show-OuiHint {
    param([string[]] $Macs)
    if ($script:OuiSource -ne $null) { return }
    $unresolved = 0
    foreach ($m in $Macs) { if ($m -and (Get-OuiVendor $m) -eq "") { $unresolved++ } }
    if ($unresolved -eq 0) { return }
    Write-Info ("" + $unresolved + " MAC(s) show '(unknown vendor)' because no OUI database is loaded.")
    Write-Body "    Run with -UpdateOui once for vendor resolution (it saves a database beside"
    Write-Body "    the script that loads automatically after)."
}
# ============================================================
#  ASSET REGISTER (shared, session-lived, in-memory)
# ============================================================
# Every module writes what it learns here through Update-Asset. Keyed by IP:
# MAC+vendor, hostname, open ports, protocols spoken, and version/identity
# strings. Memory-only for one run; nothing hits disk unless exported.
$script:AssetRegister = @{}   # ip -> PSObject record

function Get-IpSortKey {
    param([string] $IPAddr)
    $a = $null
    if ([System.Net.IPAddress]::TryParse($IPAddr, [ref] $a) -and $IPAddr -match '^\d+\.\d+\.\d+\.\d+$') {
        $b = $a.GetAddressBytes()
        return ([long] $b[0] * 16777216 + [long] $b[1] * 65536 + [long] $b[2] * 256 + [long] $b[3])
    }
    return 0
}

function Update-Asset {
    param(
        [string] $IPAddr,
        [string] $Mac = "",
        [string] $Hostname = "",
        [string] $Vendor = "",
        $Ports = $null,            # hashtable port->svc, or array of ints
        [string] $Protocol = "",
        [string] $Version = "",
        [string] $Source = ""
    )
    if (-not $IPAddr -or $IPAddr -eq "0.0.0.0" -or $IPAddr -eq "255.255.255.255") { return }
    $now = Get-Date
    $rec = $null
    if ($script:AssetRegister.ContainsKey($IPAddr)) { $rec = $script:AssetRegister[$IPAddr] }
    if (-not $rec) {
        $rec = New-Object PSObject
        $rec | Add-Member NoteProperty IP $IPAddr
        $rec | Add-Member NoteProperty MAC ""
        $rec | Add-Member NoteProperty Hostname ""
        $rec | Add-Member NoteProperty Vendor ""
        $rec | Add-Member NoteProperty Ports (New-Object System.Collections.Hashtable)
        $rec | Add-Member NoteProperty Protocols @()
        $rec | Add-Member NoteProperty Versions @()
        $rec | Add-Member NoteProperty Sources @()
        $rec | Add-Member NoteProperty FirstSeen $now
        $rec | Add-Member NoteProperty LastSeen $now
        $script:AssetRegister[$IPAddr] = $rec
    }
    if ($Mac -and -not $rec.MAC) { $rec.MAC = $Mac }
    if ($Hostname -and -not $rec.Hostname) { $rec.Hostname = $Hostname }
    if ($Vendor -and -not $rec.Vendor) { $rec.Vendor = $Vendor }
    if ($Ports) {
        if ($Ports -is [System.Collections.IDictionary]) {
            foreach ($p in @($Ports.Keys)) {
                $pi = [int] $p
                $svc = [string] $Ports[$p]
                if (-not $rec.Ports.ContainsKey($pi)) { $rec.Ports[$pi] = $svc }
                elseif ($svc -and -not $rec.Ports[$pi]) { $rec.Ports[$pi] = $svc }
            }
        } else {
            foreach ($p in @($Ports)) {
                $pi = 0
                if ([int]::TryParse([string] $p, [ref] $pi)) {
                    if (-not $rec.Ports.ContainsKey($pi)) { $rec.Ports[$pi] = "" }
                }
            }
        }
    }
    if ($Protocol -and ($rec.Protocols -notcontains $Protocol)) { $rec.Protocols += $Protocol }
    if ($Version -and ($rec.Versions -notcontains $Version)) { $rec.Versions += $Version }
    if ($Source -and ($rec.Sources -notcontains $Source)) { $rec.Sources += $Source }
    $rec.LastSeen = $now
}

function Get-AssetPortCount {
    $n = 0
    foreach ($rec in $script:AssetRegister.Values) { $n += $rec.Ports.Count }
    return $n
}

function Get-AssetSummary {
    return ("" + $script:AssetRegister.Count + " host(s), " + (Get-AssetPortCount) + " open port(s)")
}

function Get-AssetServices {
    param($Rec)
    $seen = @()
    foreach ($p in $Rec.Protocols) { if ($p -and ($seen -notcontains $p)) { $seen += $p } }
    foreach ($port in ($Rec.Ports.Keys | Sort-Object)) {
        $svc = [string] $Rec.Ports[$port]
        $label = $svc
        if (-not $label) { $label = "port " + $port }
        if ($seen -notcontains $label) { $seen += $label }
    }
    return $seen
}

function Get-SortedAssets {
    return @($script:AssetRegister.Values | Sort-Object { Get-IpSortKey $_.IP })
}

function Format-AssetPortStr {
    param($Rec, [string] $Sep = ", ")
    $parts = @()
    foreach ($p in ($Rec.Ports.Keys | Sort-Object)) {
        $svc = [string] $Rec.Ports[$p]
        if ($svc) { $parts += ("" + $p + "/" + $svc) } else { $parts += ("" + $p) }
    }
    return ($parts -join $Sep)
}

function Show-AssetRegister {
    Write-Host ""
    Write-Host ("=== AtomICS - Asset Register (" + $script:AssetRegister.Count + " host(s)) ===") -ForegroundColor Cyan
    if ($script:AssetRegister.Count -eq 0) {
        Write-Body "  (empty - run a scan or a protocol module first, then come back)"
        Write-Body "  Network Discovery adds IPs, MACs and open ports; the protocol modules"
        Write-Body "  add the services each host speaks and their version/identity strings."
        Write-Body "=== end ==="
        return
    }
    foreach ($rec in (Get-SortedAssets)) {
        $head = "  " + $rec.IP
        if ($rec.MAC) { $head += "   " + (Format-MacVendor $rec.MAC $rec.Vendor) }
        elseif ($rec.Vendor) { $head += "   " + $rec.Vendor }
        Write-Body $head
        if ($rec.Hostname) { Write-Body ("      hostname : " + $rec.Hostname) }
        if ($rec.Ports.Count -gt 0) { Write-Body ("      ports    : " + (Format-AssetPortStr $rec)) }
        else { Write-Body "      ports    : (none observed)" }
        $services = Get-AssetServices $rec
        if ($services.Count -gt 0) { Write-Body ("      services : " + ($services -join ", ")) }
        else { Write-Body "      services : (none)" }
        if ($rec.Versions.Count -gt 0) {
            Write-Body "      version  :"
            foreach ($v in $rec.Versions) { Write-Body ("                 - " + $v) }
        } else {
            Write-Body "      version  : (no protocol identity collected)"
        }
        Write-Body ("      seen via : " + ($rec.Sources -join ", ") + "   (" `
                    + $rec.FirstSeen.ToString("HH:mm:ss") + " -> " + $rec.LastSeen.ToString("HH:mm:ss") + ")")
    }
    Write-Body "=== end ==="
}

function Export-AssetCsv {
    if ($script:AssetRegister.Count -eq 0) { Write-Body "Register is empty - nothing to export."; return }
    $path = "atomics_ps_assets_" + (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss") + ".csv"
    $rows = @()
    foreach ($rec in (Get-SortedAssets)) {
        $o = New-Object PSObject
        $o | Add-Member NoteProperty ip $rec.IP
        $o | Add-Member NoteProperty mac $rec.MAC
        $o | Add-Member NoteProperty vendor $rec.Vendor
        $o | Add-Member NoteProperty hostname $rec.Hostname
        $o | Add-Member NoteProperty open_ports (Format-AssetPortStr $rec "; ")
        $o | Add-Member NoteProperty services_protocols ((Get-AssetServices $rec) -join "; ")
        $o | Add-Member NoteProperty versioning ($rec.Versions -join " | ")
        $o | Add-Member NoteProperty sources ($rec.Sources -join ", ")
        $o | Add-Member NoteProperty first_seen $rec.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss")
        $o | Add-Member NoteProperty last_seen $rec.LastSeen.ToString("yyyy-MM-dd HH:mm:ss")
        $rows += $o
    }
    try {
        $rows | Export-Csv -Path $path -NoTypeInformation
        Write-Ok ("Exported " + $script:AssetRegister.Count + " host(s) to " + $path)
        Write-LogLine ("ASSET_EXPORT_CSV file=" + $path + " hosts=" + $script:AssetRegister.Count)
    } catch { Write-Bad ("Could not write " + $path + ": " + $_.Exception.Message) }
}

# PS 2.0 has no ConvertTo-Json, so emit JSON by hand.
function ConvertTo-JsonString {
    param([string] $S)
    if ($S -eq $null) { return '""' }
    $sb = ""
    foreach ($ch in $S.ToCharArray()) {
        $code = [int][char] $ch
        if ($code -eq 34) { $sb += '\"' }
        elseif ($code -eq 92) { $sb += '\\' }
        elseif ($code -lt 32) { $sb += ('\u{0:x4}' -f $code) }
        else { $sb += [string] $ch }
    }
    return '"' + $sb + '"'
}

function Export-AssetJson {
    if ($script:AssetRegister.Count -eq 0) { Write-Body "Register is empty - nothing to export."; return }
    $path = "atomics_ps_assets_" + (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss") + ".json"
    $items = @()
    foreach ($rec in (Get-SortedAssets)) {
        $portObjs = @()
        foreach ($p in ($rec.Ports.Keys | Sort-Object)) {
            $portObjs += ('    {"port": ' + $p + ', "service": ' + (ConvertTo-JsonString ([string] $rec.Ports[$p])) + '}')
        }
        $svcArr = @()
        foreach ($s in (Get-AssetServices $rec)) { $svcArr += (ConvertTo-JsonString $s) }
        $verArr = @()
        foreach ($v in $rec.Versions) { $verArr += (ConvertTo-JsonString $v) }
        $srcArr = @()
        foreach ($s in $rec.Sources) { $srcArr += (ConvertTo-JsonString $s) }
        $obj = @()
        $obj += '  {'
        $obj += ('    "ip": ' + (ConvertTo-JsonString $rec.IP) + ',')
        $obj += ('    "mac": ' + (ConvertTo-JsonString $rec.MAC) + ',')
        $obj += ('    "vendor": ' + (ConvertTo-JsonString $rec.Vendor) + ',')
        $obj += ('    "hostname": ' + (ConvertTo-JsonString $rec.Hostname) + ',')
        $obj += ('    "ports": [' + ($portObjs -join ", ") + '],')
        $obj += ('    "services_protocols": [' + ($svcArr -join ", ") + '],')
        $obj += ('    "versioning": [' + ($verArr -join ", ") + '],')
        $obj += ('    "sources": [' + ($srcArr -join ", ") + '],')
        $obj += ('    "first_seen": ' + (ConvertTo-JsonString $rec.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss")) + ',')
        $obj += ('    "last_seen": ' + (ConvertTo-JsonString $rec.LastSeen.ToString("yyyy-MM-dd HH:mm:ss")))
        $obj += '  }'
        $items += ($obj -join "`n")
    }
    $json = "[`n" + ($items -join ",`n") + "`n]`n"
    try {
        Set-Content -Path $path -Value $json
        Write-Ok ("Exported " + $script:AssetRegister.Count + " host(s) to " + $path)
        Write-LogLine ("ASSET_EXPORT_JSON file=" + $path + " hosts=" + $script:AssetRegister.Count)
    } catch { Write-Bad ("Could not write " + $path + ": " + $_.Exception.Message) }
}

function Invoke-AssetRegister {
    while ($true) {
        Write-MenuTitle "Asset Register"
        Write-Host ""
        Write-Body ("    " + (Get-AssetSummary) + " collected this session (in memory only)")
        Write-Host ""
        Write-Body "1. View register"
        Write-Body "2. Export to CSV"
        Write-Body "3. Export to JSON"
        Write-Body "4. Clear register"
        Write-Body "5. Back to main menu"
        $choice = (Read-Host "`nSelect an option").Trim()
        if ($choice -eq "1") { Show-AssetRegister }
        elseif ($choice -eq "2") { Export-AssetCsv }
        elseif ($choice -eq "3") { Export-AssetJson }
        elseif ($choice -eq "4") {
            if ($script:AssetRegister.Count -gt 0 -and ((Read-Host "Clear all collected assets? [y/N]") -match '^(y|yes)$')) {
                $script:AssetRegister = @{}
                Write-Info "Register cleared."
                Write-LogLine "ASSET_CLEARED"
            } else { Write-Body "Not cleared." }
        }
        elseif ($choice -eq "5") { break }
        else { Write-Body "Invalid option." }
    }
}

# ============================================================
#  NETWORK DISCOVERY
# ============================================================
function ConvertTo-CidrBits {
    param([string] $Mask)
    $bits = 0
    foreach ($octet in $Mask.Split(".")) {
        $v = 0
        try { $v = [int] $octet } catch { return $null }
        foreach ($m in $script:BitMasks) { if ($v -band $m) { $bits++ } }
    }
    return $bits
}

function Get-LocalInterfaces {
    $result = @()
    try {
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop
    } catch { return $result }
    foreach ($a in $adapters) {
        if (-not $a.IPAddress) { continue }
        for ($i = 0; $i -lt $a.IPAddress.Length; $i++) {
            $ip = $a.IPAddress[$i]
            if ($ip -notmatch '^\d+\.\d+\.\d+\.\d+$') { continue }
            if ($ip.StartsWith("127.") -or $ip.StartsWith("169.254.")) { continue }
            $mask = ""
            if ($a.IPSubnet -and $i -lt $a.IPSubnet.Length) { $mask = $a.IPSubnet[$i] }
            $bits = ConvertTo-CidrBits $mask
            $rec = New-Object PSObject
            $rec | Add-Member NoteProperty Interface ([string] $a.Description)
            $rec | Add-Member NoteProperty IP $ip
            $rec | Add-Member NoteProperty Mask $mask
            $rec | Add-Member NoteProperty CidrBits $bits
            $result += $rec
        }
    }
    return $result
}

function Show-LocalInterfaces {
    param([string] $Indent = "    ")
    $ifaces = Get-LocalInterfaces
    if (-not $ifaces -or $ifaces.Count -eq 0) {
        Write-Body ($Indent + "This host: (could not determine local IPv4 interfaces)")
        return
    }
    Write-Body ($Indent + "This host:")
    foreach ($d in $ifaces) {
        $cidr = ""
        if ($d.CidrBits -ne $null) { $cidr = "/" + $d.CidrBits }
        Write-Body ($Indent + "  " + $d.IP + "  mask " + $d.Mask + $cidr + "  [" + $d.Interface + "]")
    }
}

function Expand-Ipv4Targets {
    param([string] $Spec)
    $Spec = $Spec.Trim()
    if ($Spec -notmatch "/") {
        $addr = $null
        if ([System.Net.IPAddress]::TryParse($Spec, [ref] $addr) -and $Spec -match '^\d+\.\d+\.\d+\.\d+$') { return @($Spec) }
        return @()
    }
    $parts = $Spec.Split("/")
    if ($parts.Length -ne 2) { return @() }
    $base = $parts[0]
    $bits = -1
    try { $bits = [int] $parts[1] } catch { return @() }
    if ($base -notmatch '^\d+\.\d+\.\d+\.\d+$' -or $bits -lt 0 -or $bits -gt 32) { return @() }
    $baseAddr = $null
    if (-not [System.Net.IPAddress]::TryParse($base, [ref] $baseAddr)) { return @() }
    $ob = $baseAddr.GetAddressBytes()
    $baseInt = ([long] $ob[0]) * 16777216 + ([long] $ob[1]) * 65536 + ([long] $ob[2]) * 256 + [long] $ob[3]
    if ($bits -eq 32) { return @($base) }
    $hostBits = 32 - $bits
    $size = [long][math]::Pow(2, $hostBits)
    $maskInt = 4294967296 - $size
    $network = $baseInt -band $maskInt
    $first = $network + 1
    $last = $network + $size - 2
    if ($size -le 2) { $first = $network; $last = $network + $size - 1 }
    $hosts = @()
    for ($v = $first; $v -le $last; $v++) {
        $o0 = [int][math]::Floor($v / 16777216) -band 0xFF
        $o1 = [int][math]::Floor($v / 65536) -band 0xFF
        $o2 = [int][math]::Floor($v / 256) -band 0xFF
        $o3 = [int]($v -band 0xFF)
        $hosts += ("" + $o0 + "." + $o1 + "." + $o2 + "." + $o3)
    }
    return $hosts
}

function Request-Targets {
    param([string] $DefaultIp)
    $prompt = "Target (single IP or CIDR, e.g. 10.0.0.5 or 10.0.0.0/24)"
    if ($DefaultIp) { $prompt = $prompt + " [" + $DefaultIp + "]" }
    $spec = (Read-Host $prompt).Trim()
    if (-not $spec -and $DefaultIp) { $spec = $DefaultIp }
    if (-not $spec) { Write-Bad "No target provided."; return $null }
    $hosts = Expand-Ipv4Targets $spec
    if (-not $hosts -or $hosts.Count -eq 0) {
        Write-Bad ("Could not parse '" + $spec + "' as an IPv4 address or CIDR.")
        return $null
    }
    if ($hosts.Count -gt $script:HostScanWarn) {
        $ok = Read-Host ("[!] That expands to " + $hosts.Count + " hosts. Continue? [y/N]")
        if ($ok -notmatch '^(y|yes)$') { Write-Body "Aborted."; return $null }
    }
    Write-Info ("" + $hosts.Count + " host(s) to scan.")
    Write-LogLine ("DISCOVERY targets spec=" + $spec + " count=" + $hosts.Count)
    return $hosts
}

# ---- ARP cache (passive: reads OS state, sends nothing) ----
function Get-ArpCache {
    $table = @{}
    $out = ""
    try { $out = (& arp -a 2>$null | Out-String) } catch { return $table }
    foreach ($line in $out.Split("`n")) {
        $m = [regex]::Match($line, '(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})')
        if ($m.Success) {
            $mac = ($m.Groups[2].Value -replace "-", ":").ToLower()
            $table[$m.Groups[1].Value] = $mac
        }
    }
    return $table
}

function Show-ArpCache {
    Write-Head "--- ARP Cache (passive - reads this host's table, sends nothing) ---"
    Write-Info "Shows only hosts this machine has recently communicated with."
    $table = Get-ArpCache
    if (-not $table -or $table.Count -eq 0) { Write-Body "  (ARP cache empty or unreadable)"; return }
    Write-LogLine ("ARP_CACHE entries=" + $table.Count)
    $macs = @()
    foreach ($ip in ($table.Keys | Sort-Object { Get-IpSortKey $_ })) {
        $mac = $table[$ip]
        $macs += $mac
        Write-Body ("  " + $ip.PadRight(16) + "  " + (Format-MacVendor $mac))
        Update-Asset -IPAddr $ip -Mac $mac -Vendor (Get-OuiVendor $mac) -Source "ARP cache"
        Write-LogLine ("ARP_CACHE ip=" + $ip + " mac=" + $mac)
    }
    Show-OuiHint $macs
    if ((Read-Host "`nSave to CSV? [y/N]") -match '^(y|yes)$') {
        $path = "atomics_ps_arpcache_" + (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss") + ".csv"
        $rows = @()
        foreach ($ip in ($table.Keys | Sort-Object { Get-IpSortKey $_ })) {
            $o = New-Object PSObject
            $o | Add-Member NoteProperty IP $ip
            $o | Add-Member NoteProperty MAC $table[$ip]
            $o | Add-Member NoteProperty Vendor (Get-OuiVendor $table[$ip])
            $rows += $o
        }
        try { $rows | Export-Csv -Path $path -NoTypeInformation; Write-Ok ("Saved " + $rows.Count + " row(s) to " + $path) }
        catch { Write-Bad ("Could not write " + $path + ": " + $_.Exception.Message) }
    }
}

# ---- ICMP sweep ----
function Invoke-IcmpSweep {
    param([string[]] $Hosts, [int] $TimeoutMs = 400)
    Write-Head "--- ICMP Ping Sweep ---"
    Write-Info ("Pinging " + $Hosts.Count + " host(s), " + $TimeoutMs + "ms timeout each (sequential).")
    $ping = New-Object System.Net.NetworkInformation.Ping
    $alive = @()
    $done = 0
    foreach ($h in $Hosts) {
        $done++
        Write-Host ("`r [sweep] " + $done + "/" + $Hosts.Count + " - alive: " + $alive.Count + "   ") -NoNewline -ForegroundColor White
        try {
            $reply = $ping.Send($h, $TimeoutMs)
            if ($reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { $alive += $h }
        } catch { }
    }
    Write-Host ""
    Write-Head ("--- ICMP Results (" + $alive.Count + " alive) ---")
    if ($alive.Count -eq 0) { Write-Body "  (no hosts replied - they may be up but filtering ICMP)" }
    foreach ($h in ($alive | Sort-Object { Get-IpSortKey $_ })) {
        Write-Body ("  " + $h + "  is up")
        Update-Asset -IPAddr $h -Source "ICMP"
        Write-LogLine ("ICMP alive ip=" + $h)
    }
    Write-LogLine ("ICMP_SWEEP done alive=" + $alive.Count)
}

# ---- TCP connect scan (one connection at a time - gentle on the wire) ----
function Test-TcpPort {
    param([string] $IPAddr, [int] $Port, [int] $TimeoutMs = 400)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($IPAddr, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok -and $client.Connected) { $client.EndConnect($iar); return $true }
        return $false
    } catch { return $false }
    finally { try { $client.Close() } catch { } }
}

function Get-PortLabel {
    param([int] $Port)
    if ($script:CommonItPorts.ContainsKey($Port)) { return $script:CommonItPorts[$Port] }
    if ($script:CommonOtPorts.ContainsKey($Port)) { return $script:CommonOtPorts[$Port] }
    return ""
}

function Invoke-TcpScan {
    param([string[]] $Hosts, [int[]] $Ports, [string] $ScanName, [int] $TimeoutMs = 400)
    Write-Head ("--- TCP Connect Scan: " + $ScanName + " ---")
    Write-Info ("" + $Hosts.Count + " host(s) x " + $Ports.Count + " port(s), one connection at a time.")
    $total = $Hosts.Count * $Ports.Count
    $done = 0; $found = 0
    $results = @()
    foreach ($h in $Hosts) {
        $openOnHost = @()
        foreach ($p in $Ports) {
            $done++
            if (($done % 8) -eq 0 -or $done -eq $total) {
                Write-Host ("`r [scan] " + $done + "/" + $total + " - open: " + $found + "    ") -NoNewline -ForegroundColor White
            }
            if (Test-TcpPort $h $p $TimeoutMs) { $openOnHost += $p; $found++ }
        }
        if ($openOnHost.Count -gt 0) {
            $rec = New-Object PSObject
            $rec | Add-Member NoteProperty IP $h
            $rec | Add-Member NoteProperty OpenPorts $openOnHost
            $results += $rec
        }
    }
    Write-Host ""
    Write-Head ("--- Scan Results: " + $ScanName + " ---")
    if ($results.Count -eq 0) { Write-Body "  (no open ports found)" }
    foreach ($r in $results) {
        Write-Body ("  " + $r.IP)
        foreach ($p in ($r.OpenPorts | Sort-Object)) {
            $label = Get-PortLabel $p
            $tag = ""
            if ($label) { $tag = "  [" + $label + "]" }
            Write-Body ("      " + ([string] $p).PadRight(6) + "/tcp  open" + $tag)
            $ph = @{}; $ph[$p] = $label
            Update-Asset -IPAddr $r.IP -Ports $ph -Source "SYN"
            Write-LogLine ("TCP_OPEN ip=" + $r.IP + " port=" + $p + " label=" + $label)
        }
    }
    Write-LogLine ("TCP_SCAN done name='" + $ScanName + "' hosts_with_open=" + $results.Count)
}
# ------------------------------------------------------------
#  No-admin passive listener (broadcast / multicast UDP)
# ------------------------------------------------------------
# Ordinary UDP sockets bound to the discovery ports, multicast groups joined.
# Harvests IP + hostname from the chatter every segment carries; DHCP also
# yields the client MAC, the rest filled from the ARP cache afterwards. Sends no
# scan packets (joining a multicast group emits standard IGMP membership reports,
# ordinary host traffic). No admin, no Npcap. Promiscuous unicast capture needs
# Npcap and is Python-only.
$script:PassiveUdp = @(
    @("mDNS",         5353, "224.0.0.251"),
    @("LLMNR",        5355, "224.0.0.252"),
    @("SSDP/UPnP",    1900, "239.255.255.250"),
    @("WS-Discovery", 3702, "239.255.255.250"),
    @("NBNS",          137, $null),
    @("DHCP",           68, $null)
)
$script:DhcpMsgTypes = @{
    1 = "DISCOVER"; 2 = "OFFER"; 3 = "REQUEST"; 4 = "DECLINE";
    5 = "ACK"; 6 = "NAK"; 7 = "RELEASE"; 8 = "INFORM"
}

function Format-Ipv4Bytes {
    param([byte[]] $B, [int] $Off = 0)
    return ("" + [int] $B[$Off] + "." + [int] $B[$Off + 1] + "." + [int] $B[$Off + 2] + "." + [int] $B[$Off + 3])
}

function ConvertFrom-DhcpText {
    param([byte[]] $Val)
    $s = ""
    try { $s = [System.Text.Encoding]::ASCII.GetString($Val) } catch { $s = "" }
    $s = $s.Replace([string][char] 0, "").Trim()
    if ($s -and ($s -match '^[\x20-\x7e]+$')) { return $s }
    $hex = ""
    foreach ($b in $Val) { $hex += ("{0:x2}" -f [int] $b) }
    return $hex
}

function Get-DhcpInfo {
    param([byte[]] $Payload)
    if ($Payload.Length -lt 240) { return $null }
    if ($Payload[236] -ne 0x63 -or $Payload[237] -ne 0x82 -or $Payload[238] -ne 0x53 -or $Payload[239] -ne 0x63) { return $null }
    $info = @{}
    $info.op = [int] $Payload[0]
    $macHex = @()
    for ($k = 28; $k -lt 34; $k++) { $macHex += ("{0:x2}" -f [int] $Payload[$k]) }
    $info.mac = ($macHex -join ":")
    $info.ciaddr = Format-Ipv4Bytes $Payload 12
    $info.yiaddr = Format-Ipv4Bytes $Payload 16
    $info.msg_type = $null
    $info.hostname = ""
    $info.vendor_class = ""
    $info.requested_ip = ""
    $i = 240; $n = $Payload.Length
    while ($i -lt $n) {
        $code = [int] $Payload[$i]
        if ($code -eq 255) { break }
        if ($code -eq 0) { $i++; continue }
        if (($i + 1) -ge $n) { break }
        $ln = [int] $Payload[$i + 1]
        $vs = $i + 2
        if (($vs + $ln) -gt $n) { break }
        $val = @()
        if ($ln -gt 0) { for ($j = 0; $j -lt $ln; $j++) { $val += $Payload[$vs + $j] } }
        $i = $vs + $ln
        if ($code -eq 53 -and $ln -ge 1) { $info.msg_type = [int] $val[0] }
        elseif ($code -eq 12) { $info.hostname = ConvertFrom-DhcpText ([byte[]] $val) }
        elseif ($code -eq 60) { $info.vendor_class = ConvertFrom-DhcpText ([byte[]] $val) }
        elseif ($code -eq 50 -and $ln -eq 4) { $info.requested_ip = Format-Ipv4Bytes ([byte[]] $val) 0 }
    }
    return $info
}

function Decode-Nbns {
    param([byte[]] $Payload)
    if ($Payload.Length -lt 45) { return "" }
    if ([int] $Payload[12] -ne 0x20) { return "" }
    $out = ""
    for ($i = 0; $i -lt 32; $i += 2) {
        $hi = [int] $Payload[13 + $i] - 0x41
        $lo = [int] $Payload[13 + $i + 1] - 0x41
        if ($hi -lt 0 -or $lo -lt 0 -or $hi -gt 15 -or $lo -gt 15) { return "" }
        $out += [char](($hi * 16) + $lo)
    }
    $len = [math]::Min(15, $out.Length)
    return $out.Substring(0, $len).Trim()
}

function Decode-DnsName {
    param([byte[]] $Payload, [int] $Off)
    $parts = @()
    $guard = 0
    while ($Off -lt $Payload.Length -and $guard -lt 16) {
        $ln = [int] $Payload[$Off]
        if ($ln -eq 0) { break }
        if ($ln -band 0xC0) { break }
        $Off++
        if (($Off + $ln) -gt $Payload.Length) { break }
        $seg = ""
        for ($j = 0; $j -lt $ln; $j++) { $seg += [char][int] $Payload[$Off + $j] }
        $parts += $seg
        $Off += $ln
        $guard++
    }
    $name = (@($parts | Where-Object { $_ }) -join ".")
    if ($name -match '^[\x20-\x7e]*$') { return $name }
    return ""
}

function Decode-Mdns {
    param([byte[]] $Payload)
    if ($Payload.Length -lt 13) { return "" }
    $name = Decode-DnsName $Payload 12
    foreach ($suffix in @("._tcp.local", "._udp.local", ".local")) {
        if ($name.EndsWith($suffix)) { $name = $name.Substring(0, $name.Length - $suffix.Length); break }
    }
    if ($name.StartsWith("_")) { return "" }
    return $name
}

function Decode-Ssdp {
    param([byte[]] $Payload)
    $text = ""
    try { $text = [System.Text.Encoding]::GetEncoding("iso-8859-1").GetString($Payload) } catch { return "" }
    foreach ($line in ($text -split "`r`n")) {
        if ($line.Length -ge 7 -and $line.Substring(0, 7).ToLower() -eq "server:") {
            $idx = $line.IndexOf(":")
            $v = $line.Substring($idx + 1).Trim()
            if ($v.Length -gt 60) { $v = $v.Substring(0, 60) }
            return $v
        }
    }
    return ""
}

function Decode-UdpDiscovery {
    param([int] $Port, [byte[]] $Data, [string] $SrcIp)
    $proto = "UDP"; $hostname = ""; $detail = ""; $mac = ""; $ip = $SrcIp
    if ($Port -eq 67 -or $Port -eq 68) {
        $info = Get-DhcpInfo $Data
        if ($info) {
            $mt = "?"
            if ($info.msg_type -ne $null -and $script:DhcpMsgTypes.ContainsKey([int] $info.msg_type)) { $mt = $script:DhcpMsgTypes[[int] $info.msg_type] }
            $proto = "DHCP-" + $mt
            $mac = $info.mac
            $hostname = $info.hostname
            $best = ""
            foreach ($k in @($info.yiaddr, $info.requested_ip, $info.ciaddr)) {
                if ($k -and $k -ne "0.0.0.0") { $best = $k; break }
            }
            if ($best) { $ip = $best }
            if ($info.vendor_class) { $detail = 'vendor-class="' + $info.vendor_class + '"' }
        } else { $proto = "DHCP" }
    } elseif ($Port -eq 137) { $proto = "NBNS"; $hostname = Decode-Nbns $Data }
    elseif ($Port -eq 5353) { $proto = "mDNS"; $hostname = Decode-Mdns $Data }
    elseif ($Port -eq 5355) { $proto = "LLMNR"; $hostname = Decode-Mdns $Data }
    elseif ($Port -eq 1900) { $proto = "SSDP/UPnP"; $detail = Decode-Ssdp $Data }
    elseif ($Port -eq 3702) { $proto = "WS-Discovery"; $detail = Decode-Ssdp $Data }
    $o = New-Object PSObject
    $o | Add-Member NoteProperty Proto $proto
    $o | Add-Member NoteProperty Hostname $hostname
    $o | Add-Member NoteProperty Detail $detail
    $o | Add-Member NoteProperty Mac $mac
    $o | Add-Member NoteProperty Ip $ip
    return $o
}

function New-DiscoverySocket {
    param([int] $Port, $Group)
    $sock = $null
    try {
        $sock = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
        $sock.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
        if (-not $Group) { $sock.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::Broadcast, $true) }
        $sock.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, $Port)))
        if ($Group) {
            $mo = New-Object System.Net.Sockets.MulticastOption([System.Net.IPAddress]::Parse($Group), [System.Net.IPAddress]::Any)
            $sock.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP, [System.Net.Sockets.SocketOptionName]::AddMembership, $mo)
        }
        return $sock
    } catch {
        if ($sock) { try { $sock.Close() } catch { } }
        return $null
    }
}

function Add-PassiveHit {
    param($Store, $Dec)
    $mac = $Dec.Mac
    $ip = $Dec.Ip
    $key = $mac
    if (-not $key) { $key = "ip:" + $ip }
    $new = $false; $newIp = $false
    if (-not $Store.ContainsKey($key)) {
        $r = New-Object PSObject
        $r | Add-Member NoteProperty Mac $mac
        $r | Add-Member NoteProperty Ips @()
        $r | Add-Member NoteProperty Hostnames @()
        $r | Add-Member NoteProperty Protos @()
        $r | Add-Member NoteProperty Details @()
        $r | Add-Member NoteProperty Count 0
        $r | Add-Member NoteProperty FirstSeen (Get-Date)
        $r | Add-Member NoteProperty LastSeen (Get-Date)
        $Store[$key] = $r
        $new = $true
    }
    $rec = $Store[$key]
    if (-not $rec.Mac -and $mac) { $rec.Mac = $mac }
    if ($ip -and $ip -ne "0.0.0.0" -and ($rec.Ips -notcontains $ip)) {
        $rec.Ips += $ip
        if (-not $new) { $newIp = $true }
    }
    if ($Dec.Hostname -and ($rec.Hostnames -notcontains $Dec.Hostname)) { $rec.Hostnames += $Dec.Hostname }
    if ($Dec.Proto -and ($rec.Protos -notcontains $Dec.Proto)) { $rec.Protos += $Dec.Proto }
    if ($Dec.Detail -and ($rec.Details -notcontains $Dec.Detail)) { $rec.Details += $Dec.Detail }
    $rec.Count++
    $rec.LastSeen = Get-Date
    $o = New-Object PSObject
    $o | Add-Member NoteProperty IsNew $new
    $o | Add-Member NoteProperty IsNewIp $newIp
    return $o
}

function Invoke-PassiveListen {
    Write-Head "--- Broadcast / Multicast Listen (no admin) ---"
    Write-Body " Passive discovery with ordinary UDP sockets - no root/Administrator and no"
    Write-Body " capture driver (Npcap) needed. Harvests IP + hostname from the discovery"
    Write-Body " chatter every segment carries:"
    Write-Body "   DHCP           MAC, IP, hostname, vendor class (only source with a MAC)"
    Write-Body "   mDNS / LLMNR   Bonjour and Windows name resolution -> hostnames"
    Write-Body "   NBNS           NetBIOS names (needs a low-port bind; skipped if blocked)"
    Write-Body "   SSDP / WS-Disc UPnP and WS-Discovery announcements"
    Write-Body " MACs for non-DHCP hosts are filled from this host's ARP cache afterwards."
    Write-Body " For MAC + unicast IT/OT visibility use the Python AtomICS promiscuous listen"
    Write-Body " (needs Npcap). Joining a multicast group emits standard IGMP membership"
    Write-Body " reports - ordinary host traffic, not a scan."

    $durIn = (Read-Host "`nListen duration in seconds (blank = 300; Ctrl+C stops early)").Trim()
    $duration = 300
    if ($durIn) { $tmp = 0; if ([int]::TryParse($durIn, [ref] $tmp)) { $duration = [math]::Max(0, $tmp) } }
    if ($duration -eq 0) { $duration = 86400 }

    $socks = @{}
    $joined = @(); $bcast = @(); $skipped = @()
    foreach ($entry in $script:PassiveUdp) {
        $label = $entry[0]; $port = $entry[1]; $group = $entry[2]
        $s = New-DiscoverySocket $port $group
        if (-not $s) { $skipped += $label; continue }
        $socks[$s] = $port
        if ($group) { $joined += $label } else { $bcast += $label }
    }
    if ($socks.Count -eq 0) { Write-Bad "Could not bind any discovery port - nothing to listen on."; return }
    if ($joined.Count -gt 0) { Write-Ok ("Subscribed (multicast): " + ($joined -join ", ")) }
    if ($bcast.Count -gt 0) { Write-Ok ("Listening (broadcast): " + ($bcast -join ", ")) }
    if ($skipped.Count -gt 0) { Write-Info ("Skipped (needs privilege for a low port, or port in use): " + ($skipped -join ", ")) }
    Write-Body "    Only new hosts and new addresses print; repeats are counted quietly."
    Write-LogLine ("PASSIVE_LISTEN joined=" + ($joined -join ",") + " bcast=" + ($bcast -join ",") + " duration=" + $duration)

    $store = @{}
    $frames = 0
    $start = Get-Date
    $allSocks = @($socks.Keys)
    try {
        while ($true) {
            $elapsed = ((Get-Date) - $start).TotalSeconds
            if ($elapsed -ge $duration) { break }
            $readList = New-Object System.Collections.ArrayList
            foreach ($s in $allSocks) { [void] $readList.Add($s) }
            try { [System.Net.Sockets.Socket]::Select($readList, $null, $null, 1000000) } catch { break }
            foreach ($s in $readList) {
                $cnt = 0
                try {
                    $buf = New-Object byte[] 65535
                    $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                    $refEp = [System.Net.EndPoint] $remote
                    $cnt = $s.ReceiveFrom($buf, [ref] $refEp)
                } catch { continue }
                if ($cnt -le 0) { continue }
                $frames++
                $srcIp = ([System.Net.IPEndPoint] $refEp).Address.ToString()
                $data = New-Object byte[] $cnt
                [array]::Copy($buf, 0, $data, 0, $cnt)
                $port = [int] $socks[$s]
                $dec = Decode-UdpDiscovery $port ([byte[]] $data) $srcIp
                $res = Add-PassiveHit $store $dec
                if ($res.IsNew -or $res.IsNewIp) {
                    $macDisp = "(MAC unknown)"
                    if ($dec.Mac) { $macDisp = Format-MacVendor $dec.Mac }
                    $hn = ""
                    if ($dec.Hostname) { $hn = "  " + $dec.Hostname }
                    Write-Body (" [" + (Get-Date).ToString("HH:mm:ss") + "] NEW  " + $dec.Proto.PadRight(14) + "  " + $srcIp.PadRight(16) + $macDisp + $hn)
                    Write-LogLine ("PASSIVE_SEEN proto=" + $dec.Proto + " ip=" + $srcIp + " mac=" + $dec.Mac)
                }
            }
        }
    } catch {
        Write-Host ""
        Write-Warn2 "Listener stopped."
    } finally {
        foreach ($s in $allSocks) { try { $s.Close() } catch { } }
    }

    # Fill MAC-less (IP-only) records from the ARP cache.
    $arp = Get-ArpCache
    $filled = 0
    if ($arp -and $arp.Count -gt 0) {
        foreach ($key in @($store.Keys)) {
            if ($key.StartsWith("ip:")) {
                $ip = $key.Substring(3)
                if ($arp.ContainsKey($ip)) { $store[$key].Mac = $arp[$ip]; $filled++ }
            }
        }
    }
    if ($filled -gt 0) { Write-Info ("Filled in " + $filled + " MAC address(es) from this host's ARP cache.") }

    Show-PassiveSummary $store $frames ([int]((Get-Date) - $start).TotalSeconds)
    Merge-PassiveIntoAssets $store
    if ($store.Count -gt 0 -and ((Read-Host "`nSave these results to CSV? [y/N]") -match '^(y|yes)$')) { Export-PassiveCsv $store }
}

function Show-PassiveSummary {
    param($Store, [int] $Frames, [int] $Seconds)
    $ipCount = 0
    foreach ($r in $Store.Values) { $ipCount += $r.Ips.Count }
    Write-Head ("--- Passive Listen Results (" + $Store.Count + " host(s), " + $ipCount + " address(es), " + $Frames + " frame(s), " + $Seconds + "s) ---")
    if ($Store.Count -eq 0) {
        Write-Body "  (nothing heard)"
        Write-Body "  A quiet, statically-addressed segment with no broadcast chatter looks"
        Write-Body "  exactly like this. Try a longer listen, a SPAN/mirror port, or a window"
        Write-Body "  that includes a device reboot."
        Write-Body "--- end ---"
        return
    }
    foreach ($rec in ($Store.Values | Sort-Object { if ($_.Ips.Count) { Get-IpSortKey $_.Ips[0] } else { 0 } })) {
        $macDisp = "(unknown MAC)"
        if ($rec.Mac) { $macDisp = Format-MacVendor $rec.Mac }
        $ip = "-"; if ($rec.Ips.Count) { $ip = $rec.Ips[0] }
        $hn = "-"; if ($rec.Hostnames.Count) { $hn = $rec.Hostnames[0] }
        $ipExtra = ""
        if ($rec.Ips.Count -gt 1) { $ipExtra = "  (+" + ($rec.Ips.Count - 1) + " more: " + (($rec.Ips[1..($rec.Ips.Count - 1)]) -join ", ") + ")" }
        Write-Body ("  " + $macDisp)
        Write-Body ("      ip       : " + $ip + $ipExtra)
        Write-Body ("      hostname : " + $hn)
        Write-Body ("      protocols: " + ($rec.Protos -join ", "))
        if ($rec.Details.Count -gt 0) { Write-Body ("      detail   : " + ($rec.Details -join "  ")) }
        Write-Body ("      frames   : " + $rec.Count + "   (" + $rec.FirstSeen.ToString("HH:mm:ss") + " -> " + $rec.LastSeen.ToString("HH:mm:ss") + ")")
        Write-LogLine ("PASSIVE_RESULT mac=" + $rec.Mac + " ips=" + ($rec.Ips -join ";") + " protos=" + ($rec.Protos -join ";") + " count=" + $rec.Count)
    }
    Write-Body "--- end ---"
}

function Merge-PassiveIntoAssets {
    param($Store)
    $added = 0
    foreach ($rec in $Store.Values) {
        $mac = $rec.Mac
        $vendor = ""
        if ($mac) { $vendor = Get-OuiVendor $mac }
        $hostname = ""
        if ($rec.Hostnames.Count) { $hostname = $rec.Hostnames[0] }
        foreach ($ip in $rec.Ips) {
            if ($ip -eq "0.0.0.0" -or $ip -eq "255.255.255.255") { continue }
            $before = $script:AssetRegister.ContainsKey($ip)
            Update-Asset -IPAddr $ip -Mac $mac -Vendor $vendor -Hostname $hostname -Source "passive"
            foreach ($proto in $rec.Protos) { Update-Asset -IPAddr $ip -Protocol $proto }
            if (-not $before) { $added++ }
        }
    }
    if ($added -gt 0) {
        Write-Info ("Added " + $added + " host(s) from the passive listen to the Asset Register.")
        Write-LogLine ("ASSET_MERGE passive added=" + $added)
    }
}

function Export-PassiveCsv {
    param($Store)
    $path = "atomics_ps_passive_" + (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss") + ".csv"
    $rows = @()
    foreach ($rec in ($Store.Values | Sort-Object { if ($_.Ips.Count) { Get-IpSortKey $_.Ips[0] } else { 0 } })) {
        $o = New-Object PSObject
        $o | Add-Member NoteProperty mac $rec.Mac
        $o | Add-Member NoteProperty ip_addresses ($rec.Ips -join ";")
        $vv = ""; if ($rec.Mac) { $vv = Get-OuiVendor $rec.Mac }
        $o | Add-Member NoteProperty oui_vendor $vv
        $o | Add-Member NoteProperty hostnames ($rec.Hostnames -join ";")
        $o | Add-Member NoteProperty protocols ($rec.Protos -join ";")
        $o | Add-Member NoteProperty details ($rec.Details -join ";")
        $o | Add-Member NoteProperty frames $rec.Count
        $o | Add-Member NoteProperty first_seen $rec.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss")
        $o | Add-Member NoteProperty last_seen $rec.LastSeen.ToString("yyyy-MM-dd HH:mm:ss")
        $rows += $o
    }
    try { $rows | Export-Csv -Path $path -NoTypeInformation; Write-Ok ("Saved " + $Store.Count + " host(s) to " + $path) }
    catch { Write-Bad ("Could not write " + $path + ": " + $_.Exception.Message) }
}

# ------------------------------------------------------------
#  Network Discovery menu
# ------------------------------------------------------------
function Invoke-NetworkDiscovery {
    param([string] $DefaultIp)
    while ($true) {
        Write-MenuTitle "Network Discovery"
        Write-Host ""
        Show-LocalInterfaces "    "
        Write-Host ""
        $lock = ""
        if ($script:SafeMode) { $lock = "   [LOCKED - safe mode]" }
        Write-Host "  Passive - sends nothing, available in safe mode" -ForegroundColor DarkCyan
        Write-Body  "   1. Broadcast/multicast listen - no admin (IP + hostnames: DHCP/mDNS/LLMNR/NBNS/SSDP)"
        Write-Body  "   2. ARP cache read (hosts this machine has talked to)"
        Write-Host ""
        $activeHdr = "  Active - puts packets on the wire"
        if ($script:SafeMode) { $activeHdr = $activeHdr + " [locked in safe mode]" }
        Write-Host $activeHdr -ForegroundColor DarkCyan
        Write-Body  ("   3. ICMP ping sweep" + $lock)
        Write-Body  ("   4. TCP connect scan - single port" + $lock)
        Write-Body  ("   5. TCP connect scan - common IT ports" + $lock)
        Write-Body  ("   6. TCP connect scan - common OT ports" + $lock)
        Write-Body  ("   7. TCP connect scan - common IT + OT ports" + $lock)
        Write-Host ""
        Write-Body  "   8. Back to main menu"
        $choice = (Read-Host "`nSelect an option").Trim()

        if ($choice -eq "8") { break }
        if ($choice -eq "1") {
            try { Invoke-PassiveListen } catch { Write-Bad ("Operation failed: " + $_.Exception.Message); Write-LogLine ("DISCOVERY_ERROR " + $_.Exception.Message) }
            continue
        }
        if ($choice -eq "2") { Show-ArpCache; continue }
        if (@("3", "4", "5", "6", "7") -notcontains $choice) { Write-Body "Invalid option."; continue }

        if (Test-ScanBlocked "Network scan") { continue }

        $hosts = Request-Targets $DefaultIp
        if (-not $hosts) { continue }
        try {
            if ($choice -eq "3") { Invoke-IcmpSweep $hosts }
            elseif ($choice -eq "4") {
                $raw = (Read-Host "Port to scan").Trim()
                $port = 0
                if ([int]::TryParse($raw, [ref] $port) -and $port -gt 0 -and $port -lt 65536) { Invoke-TcpScan $hosts @($port) ("single port " + $port) }
                else { Write-Bad "Invalid port (1-65535)." }
            }
            elseif ($choice -eq "5") { Invoke-TcpScan $hosts ([int[]]($script:CommonItPorts.Keys)) "common IT ports" }
            elseif ($choice -eq "6") { Invoke-TcpScan $hosts ([int[]]($script:CommonOtPorts.Keys)) "common OT ports" }
            elseif ($choice -eq "7") {
                $combined = @()
                $combined += [int[]]($script:CommonItPorts.Keys)
                $combined += [int[]]($script:CommonOtPorts.Keys)
                Invoke-TcpScan $hosts $combined "common IT + OT ports"
            }
        } catch { Write-Bad ("Operation failed: " + $_.Exception.Message); Write-LogLine ("DISCOVERY_ERROR " + $_.Exception.Message) }
    }
}
# ============================================================
#  MODBUS/TCP MODULE
# ============================================================
# Hand-rolled MBAP framing over TcpClient. Modbus is big-endian on the wire;
# multi-byte fields are packed with Get-HiByte/Get-LoByte (no -shl on PS 2.0)
# and read back with Get-U16BE.
function Connect-Modbus {
    param([string] $IPAddr, [int] $Port = 502, [int] $TimeoutMs = 3000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($IPAddr, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not ($ok -and $client.Connected)) {
            try { $client.Close() } catch { }
            Write-Bad ("Failed to connect to Modbus service at " + $IPAddr + ":" + $Port)
            Write-LogLine ("FAILED_CONNECT " + $IPAddr + ":" + $Port)
            return $null
        }
        $client.EndConnect($iar)
    } catch {
        Write-Bad ("Connection error: " + $_.Exception.Message)
        return $null
    }
    $stream = $client.GetStream()
    $stream.ReadTimeout = $TimeoutMs
    Write-Ok ("Connected to Modbus service at " + $IPAddr + ":" + $Port)
    Write-LogLine ("CONNECTED " + $IPAddr + ":" + $Port)
    $conn = New-Object PSObject
    $conn | Add-Member NoteProperty Client $client
    $conn | Add-Member NoteProperty Stream $stream
    $conn | Add-Member NoteProperty UnitId 1
    return $conn
}

function Read-StreamExact {
    param($Stream, [int] $Count)
    $buf = New-Object byte[] $Count
    $got = 0
    try {
        while ($got -lt $Count) {
            $n = $Stream.Read($buf, $got, $Count - $got)
            if ($n -le 0) { return $null }
            $got += $n
        }
    } catch { return $null }
    return ,$buf
}

function Invoke-ModbusPdu {
    param($Conn, [byte[]] $Pdu)
    $stream = $Conn.Stream
    $unit = [int] $Conn.UnitId
    $txid = Get-Random -Minimum 0 -Maximum 65536
    $lenField = $Pdu.Length + 1
    $mbap = [byte[]]@((Get-HiByte $txid), (Get-LoByte $txid), 0, 0, (Get-HiByte $lenField), (Get-LoByte $lenField), ([byte] $unit))
    $frame = [byte[]]($mbap + $Pdu)
    try { $stream.Write($frame, 0, $frame.Length); $stream.Flush() }
    catch { Write-LogLine ("MODBUS_WRITE_ERR " + $_.Exception.Message); return $null }
    $hdr = Read-StreamExact $stream 7
    if (-not $hdr) { return $null }
    $respLen = Get-U16BE $hdr 4
    if ($respLen -lt 2) { return $null }
    $body = Read-StreamExact $stream $respLen
    if (-not $body) { return $null }
    $func = [int] $body[1]
    $resp = New-Object PSObject
    $resp | Add-Member NoteProperty Function ($func -band 0x7F)
    if ($func -band 0x80) {
        $exc = 0
        if ($body.Length -ge 3) { $exc = [int] $body[2] }
        $resp | Add-Member NoteProperty IsError $true
        $resp | Add-Member NoteProperty Exception $exc
        $resp | Add-Member NoteProperty Data ([byte[]]@())
    } else {
        $data = @()
        if ($body.Length -gt 2) { $data = $body[2..($body.Length - 1)] }
        $resp | Add-Member NoteProperty IsError $false
        $resp | Add-Member NoteProperty Exception 0
        $resp | Add-Member NoteProperty Data ([byte[]] $data)
    }
    return $resp
}

$script:ModbusExceptions = @{
    1 = "Illegal Function"; 2 = "Illegal Data Address"; 3 = "Illegal Data Value";
    4 = "Slave Device Failure"; 5 = "Acknowledge"; 6 = "Slave Device Busy";
    8 = "Memory Parity Error"; 10 = "Gateway Path Unavailable"; 11 = "Gateway Target Failed to Respond"
}

function Format-ModbusError {
    param($Resp)
    if (-not $Resp) { return "no response (timeout or connection dropped)" }
    if ($Resp.IsError) {
        $name = "unknown"
        if ($script:ModbusExceptions.ContainsKey([int] $Resp.Exception)) { $name = $script:ModbusExceptions[[int] $Resp.Exception] }
        return ("exception " + $Resp.Exception + " (" + $name + ")")
    }
    return $null
}

function Read-ModbusBits {
    param($Conn, [byte] $Fc, [int] $Start, [int] $Count)
    $pdu = [byte[]]@($Fc, (Get-HiByte $Start), (Get-LoByte $Start), (Get-HiByte $Count), (Get-LoByte $Count))
    $resp = Invoke-ModbusPdu $Conn $pdu
    if (-not $resp -or $resp.IsError) { return $null }
    $data = $resp.Data
    if ($data.Length -lt 1) { return $null }
    $bits = @()
    for ($i = 0; $i -lt $Count; $i++) {
        $byteIndex = 1 + [int][math]::Floor($i / 8)
        $bitIndex = $i % 8
        if ($byteIndex -ge $data.Length) { break }
        $val = 0
        if ($data[$byteIndex] -band $script:BitMasks[$bitIndex]) { $val = 1 }
        $bits += $val
    }
    return ,$bits
}
function Read-ModbusCoils    { param($Conn, [int] $Start, [int] $Count) return (Read-ModbusBits $Conn 0x01 $Start $Count) }
function Read-ModbusDiscrete { param($Conn, [int] $Start, [int] $Count) return (Read-ModbusBits $Conn 0x02 $Start $Count) }

function Read-ModbusRegisters {
    param($Conn, [int] $Start, [int] $Count, [byte] $Fc = 0x03)
    $pdu = [byte[]]@($Fc, (Get-HiByte $Start), (Get-LoByte $Start), (Get-HiByte $Count), (Get-LoByte $Count))
    $resp = Invoke-ModbusPdu $Conn $pdu
    if (-not $resp -or $resp.IsError) { return $null }
    $data = $resp.Data
    if ($data.Length -lt 1) { return $null }
    $byteCount = [int] $data[0]
    $regs = @()
    $i = 1
    while ($i + 1 -le $byteCount -and ($i + 1) -lt $data.Length) {
        $regs += (Get-U16BE $data $i)
        $i += 2
    }
    return ,$regs
}

function Write-ModbusCoil {
    param($Conn, [int] $Addr, [int] $Value)
    $vHi = 0x00; $vLo = 0x00
    if ($Value -ne 0) { $vHi = 0xFF }
    $pdu = [byte[]]@(0x05, (Get-HiByte $Addr), (Get-LoByte $Addr), $vHi, $vLo)
    return (Invoke-ModbusPdu $Conn $pdu)
}
function Write-ModbusRegister {
    param($Conn, [int] $Addr, [int] $Value)
    $pdu = [byte[]]@(0x06, (Get-HiByte $Addr), (Get-LoByte $Addr), (Get-HiByte $Value), (Get-LoByte $Value))
    return (Invoke-ModbusPdu $Conn $pdu)
}

function Read-ModbusDeviceId {
    param($Conn)
    $pdu = [byte[]]@(0x2B, 0x0E, 0x01, 0x00)
    $resp = Invoke-ModbusPdu $Conn $pdu
    if (-not $resp -or $resp.IsError) { return $null }
    $data = $resp.Data
    if ($data.Length -lt 6) { return $null }
    $num = [int] $data[5]
    $objects = @{}
    $i = 6
    for ($k = 0; $k -lt $num; $k++) {
        if ($i + 1 -ge $data.Length) { break }
        $objId = [int] $data[$i]
        $objLen = [int] $data[$i + 1]
        $i += 2
        if ($i + $objLen -gt $data.Length) { break }
        $valBytes = @()
        if ($objLen -gt 0) { $valBytes = $data[$i..($i + $objLen - 1)] }
        $i += $objLen
        $text = ""
        try { $text = [System.Text.Encoding]::ASCII.GetString([byte[]] $valBytes) } catch { }
        $objects[$objId] = $text
    }
    return $objects
}

# ---- interactive operations ----
function Invoke-ReadCoils {
    param($Conn)
    $start = [int] (Read-Host "Enter starting coil address")
    $count = [int] (Read-Host "Enter number of coils to read")
    Write-LogLine ("READ_COILS addr=" + $start + " count=" + $count)
    $bits = Read-ModbusCoils $Conn $start $count
    if ($bits -eq $null) { Write-Bad "Failed to read coils."; return }
    for ($i = 0; $i -lt $bits.Count; $i++) { Write-Body ("Coil[" + ($start + $i) + "] = " + $bits[$i]) }
}

function Invoke-ReadRegisters {
    param($Conn)
    $start = [int] (Read-Host "Enter starting register address")
    $count = [int] (Read-Host "Enter number of registers to read")
    Write-LogLine ("READ_REGISTERS addr=" + $start + " count=" + $count)
    $regs = Read-ModbusRegisters $Conn $start $count
    if ($regs -eq $null) { Write-Bad "Failed to read registers."; return }
    for ($i = 0; $i -lt $regs.Count; $i++) {
        $v = [int] $regs[$i]
        $signed = $v; if ($v -gt 32767) { $signed = $v - 65536 }
        Write-Body ("Register[" + ($start + $i) + "] = " + $v + "  (signed: " + $signed + ")")
    }
}

function Invoke-WriteCoil {
    param($Conn, [string] $TargetIp)
    if (Test-SafeBlocked "Write Coil") { return }
    $addr = [int] (Read-Host "Enter coil address")
    $value = [int] (Read-Host "Enter value (0 or 1)")
    $norm = 0; if ($value -ne 0) { $norm = 1 }
    [void](Confirm-Write ("Coil[" + $addr + "] = " + $norm))
    $resp = Write-ModbusCoil $Conn $addr $value
    $err = Format-ModbusError $resp
    if ($err) { Write-Bad ("Failed to write coil: " + $err) }
    else { Write-Ok ("Coil[" + $addr + "] set to " + $norm); Write-LogLine "WRITE_SUCCESS" }
}

function Invoke-WriteRegister {
    param($Conn, [string] $TargetIp)
    if (Test-SafeBlocked "Write Register") { return }
    $addr = [int] (Read-Host "Enter register address")
    $value = [int] (Read-Host "Enter value (0-65535)")
    if ($value -lt 0 -or $value -gt 65535) { Write-Bad "Value out of range (0-65535)."; return }
    [void](Confirm-Write ("Holding register[" + $addr + "] = " + $value))
    $resp = Write-ModbusRegister $Conn $addr $value
    $err = Format-ModbusError $resp
    if ($err) { Write-Bad ("Failed to write register: " + $err) }
    else { Write-Ok ("Register[" + $addr + "] set to " + $value); Write-LogLine "WRITE_SUCCESS" }
}

function Invoke-ReadDeviceId {
    param($Conn, [string] $TargetIp)
    Write-Head "[Device Identity - FC 43]"
    Write-LogLine "READ_DEVICE_IDENTITY"
    $objects = Read-ModbusDeviceId $Conn
    if ($objects -eq $null) { Write-Bad "Device did not respond to FC 43 (may be unsupported)."; return }
    $collected = @()
    $vendor = ""
    foreach ($pair in $script:DeviceIdMap) {
        $id = $pair[0]; $label = $pair[1]
        if ($objects.ContainsKey($id) -and $objects[$id]) {
            Write-Body (" " + $label.PadRight(20) + ": " + $objects[$id])
            Write-LogLine ("DEVID " + $label + "=" + $objects[$id])
            $collected += ($label + "=" + $objects[$id])
            if ($label -eq "VendorName") { $vendor = $objects[$id] }
        }
    }
    if ($TargetIp -and $collected.Count -gt 0) {
        $ph = @{}; $ph[502] = "Modbus TCP"
        Update-Asset -IPAddr $TargetIp -Vendor $vendor -Ports $ph -Protocol "Modbus" -Version ("Modbus FC43: " + ($collected -join "; ")) -Source "Modbus"
    }
}

function Invoke-SmartScan {
    param($Conn, [string] $ItemLabel, [int] $MaxBlock, [string] $Kind)
    $rangeIn = (Read-Host ("Enter scan range (default " + $script:ScanDefaultRange + ")")).Trim()
    $scanRange = $script:ScanDefaultRange
    if ($rangeIn) { try { $scanRange = [int] $rangeIn } catch { } }
    Write-Info ("Smart-scanning " + $scanRange + " " + $ItemLabel + "s (start block " + $MaxBlock + ", adaptive)...")
    Write-LogLine ("SMART_SCAN_" + $Kind + " range=" + $scanRange + " block=" + $MaxBlock)
    $responsive = 0; $rangeStart = -1; $rangeEnd = -1
    $addr = 0; $block = $MaxBlock
    while ($addr -lt $scanRange) {
        $count = [math]::Min($block, $scanRange - $addr)
        $ok = $false
        if ($Kind -eq "COIL") { $r = Read-ModbusCoils $Conn $addr $count; $ok = ($r -ne $null) }
        else { $r = Read-ModbusRegisters $Conn $addr $count; $ok = ($r -ne $null) }
        if ($ok) {
            $responsive += $count
            if ($rangeStart -lt 0) { $rangeStart = $addr }
            $rangeEnd = $addr + $count - 1
            $addr += $count
        } elseif ($count -eq 1) { break }
        else { $block = [int][math]::Floor($count / 2); if ($block -lt 1) { $block = 1 } }
    }
    Write-Head ("--- Smart Scan Results: " + $ItemLabel + "s ---")
    Write-Body (" Probed         : 0 to " + ($scanRange - 1))
    Write-Body (" Responsive     : " + $responsive)
    if ($rangeStart -ge 0) { Write-Body (" Response range : " + $rangeStart + "-" + $rangeEnd + "  (" + ($rangeEnd - $rangeStart + 1) + " " + $ItemLabel + "s)") }
    else { Write-Body " Response range : (none)" }
    Write-LogLine ("SMART_SCAN_" + $Kind + " done responsive=" + $responsive)
}

# ---- Recon overview (banner grab) ----
function Invoke-BannerGrab {
    param($Conn, [string] $TargetIp, [int] $TargetPort)
    $BAR = "=" * 60
    $SAMPLE = 16
    Write-Host ""
    Write-Body $BAR
    Write-Body " MODBUS RECON OVERVIEW"
    Write-Body $BAR
    Write-Body (" Target     : " + $TargetIp + ":" + $TargetPort)
    Write-Body (" Unit ID    : " + $Conn.UnitId)
    Write-Body (" Timestamp  : " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
    Write-LogLine ("BANNER_GRAB target=" + $TargetIp + ":" + $TargetPort)

    Write-Head "[Device Identity - FC 43]"
    $objects = Read-ModbusDeviceId $Conn
    if ($objects -eq $null) { Write-Body " (device did not respond to FC 43)" }
    else {
        $collected = @(); $vendor = ""
        foreach ($pair in $script:DeviceIdMap) {
            $id = $pair[0]; $label = $pair[1]
            if ($objects.ContainsKey($id) -and $objects[$id]) {
                Write-Body (" " + $label.PadRight(20) + ": " + $objects[$id])
                $collected += ($label + "=" + $objects[$id])
                if ($label -eq "VendorName") { $vendor = $objects[$id] }
            }
        }
        if ($TargetIp -and $collected.Count -gt 0) {
            $ph = @{}; $ph[$TargetPort] = "Modbus TCP"
            Update-Asset -IPAddr $TargetIp -Vendor $vendor -Ports $ph -Protocol "Modbus" -Version ("Modbus FC43: " + ($collected -join "; ")) -Source "Modbus"
        }
    }

    Write-Head ("[Coil Snapshot - first " + $SAMPLE + "]")
    $bits = Read-ModbusCoils $Conn 0 $SAMPLE
    if ($bits -eq $null) { Write-Body " (no coils responded at address 0)" }
    else { Write-Body (" " + (($bits | ForEach-Object { ([string] $_) }) -join " ")) }

    Write-Head ("[Holding Register Snapshot - first " + $SAMPLE + "]")
    $regs = Read-ModbusRegisters $Conn 0 $SAMPLE
    if ($regs -eq $null) { Write-Body " (no registers responded at address 0)" }
    else {
        for ($i = 0; $i -lt $regs.Count; $i++) {
            $v = [int] $regs[$i]; $s = $v; if ($v -gt 32767) { $s = $v - 65536 }
            Write-Body (" Register[" + ([string] $i).PadLeft(2) + "] = " + ([string] $v).PadLeft(5) + "  (signed: " + $s + ")")
        }
    }

    Write-Head ("[Discrete Input Snapshot - first " + $SAMPLE + "]")
    $di = Read-ModbusDiscrete $Conn 0 $SAMPLE
    if ($di -eq $null) { Write-Body " (no discrete inputs responded at address 0)" }
    else { Write-Body (" " + (($di | ForEach-Object { ([string] $_) }) -join " ")) }

    Write-Body $BAR
    Write-LogLine "BANNER_GRAB completed"
}

# ---- advanced (state-changing) actions ----
function Measure-ResponsiveCount {
    param($Conn, [string] $Kind)
    $count = 0
    for ($i = 0; $i -lt $script:MaxLength; $i++) {
        $r = $null
        if ($Kind -eq "COIL") { $r = Read-ModbusCoils $Conn $i 1 } else { $r = Read-ModbusRegisters $Conn $i 1 }
        if ($r -ne $null) { $count++ } else { break }
    }
    return $count
}

function Invoke-FlipCoils {
    param($Conn, [string] $TargetIp)
    if (Test-SafeBlocked "Flip Coils") { return }
    Write-Body "Surveying the responsive coil range first (reads only)..."
    $count = Measure-ResponsiveCount $Conn "COIL"
    if ($count -eq 0) { Write-Body "No responsive coils found - nothing to do."; return }
    [void](Confirm-Write ("INVERT every coil in range 0-" + ($count - 1) + " (" + $count + " coils) on this device"))
    $bits = Read-ModbusCoils $Conn 0 $count
    if ($bits -eq $null) { Write-Bad "Failed to read coils."; return }
    for ($i = 0; $i -lt $bits.Count; $i++) {
        $newv = 0; if ($bits[$i] -eq 0) { $newv = 1 }
        [void](Write-ModbusCoil $Conn $i $newv)
    }
    Write-Ok ("Flipped " + $count + " coils.")
    Write-LogLine ("FLIP_COILS completed count=" + $count)
}

function Invoke-ZeroCoils {
    param($Conn, [string] $TargetIp)
    if (Test-SafeBlocked "Zero All Coils") { return }
    Write-Body "Surveying the responsive coil range first (reads only)..."
    $count = Measure-ResponsiveCount $Conn "COIL"
    if ($count -eq 0) { Write-Body "No responsive coils found - nothing to do."; return }
    [void](Confirm-Write ("Set every coil in range 0-" + ($count - 1) + " (" + $count + " coils) to 0 on this device"))
    for ($i = 0; $i -lt $count; $i++) { [void](Write-ModbusCoil $Conn $i 0) }
    Write-Ok ("Zeroed " + $count + " coils.")
    Write-LogLine ("ZERO_COILS completed count=" + $count)
}

function Invoke-FuzzRegisters {
    param($Conn, [string] $TargetIp)
    if (Test-SafeBlocked "Fuzz Registers") { return }
    Write-Body "Surveying the responsive register range first (reads only)..."
    $count = Measure-ResponsiveCount $Conn "REG"
    if ($count -eq 0) { Write-Body "No responsive holding registers found - nothing to do."; return }
    Write-Host ""
    Write-Warn2 "Fuzzing writes RANDOM values to live holding registers. On a running"
    Write-Body  "    process this is indistinguishable from sabotage. Simulator/bench only."
    [void](Confirm-Write ("Write RANDOM values to holding registers 0-" + ($count - 1) + " (" + $count + " registers) on this device"))
    for ($i = 0; $i -lt $count; $i++) {
        $value = Get-Random -Minimum 0 -Maximum 65536
        $resp = Write-ModbusRegister $Conn $i $value
        if ($resp -and -not $resp.IsError) { Write-LogLine ("Register[" + $i + "] fuzzed value=" + $value) }
    }
    Write-Ok ("Fuzzed " + $count + " registers.")
    Write-LogLine ("FUZZ_REGISTERS completed count=" + $count)
}

function Invoke-HoldWrite {
    param($Conn, [string] $TargetIp)
    if (Test-SafeBlocked "Hold Write") { return }
    $tt = (Read-Host "Target type ([c]oil or [r]egister)").Trim().ToLower()
    if (-not $tt -or ($tt[0] -ne "c" -and $tt[0] -ne "r")) { Write-Bad "Invalid target type."; return }
    $isCoil = ($tt[0] -eq "c")
    $addr = [int] (Read-Host "Enter target address")
    if ($isCoil) { $value = [int] (Read-Host "Enter value (0 or 1)"); $disp = 0; if ($value -ne 0) { $disp = 1 } }
    else { $value = [int] (Read-Host "Enter value (0-65535)"); $disp = $value }
    $intIn = (Read-Host "Interval between writes in seconds (default 0.5)").Trim()
    $interval = 0.5; if ($intIn) { try { $interval = [double] $intIn } catch { } }
    $durIn = (Read-Host "Duration in seconds (blank or 0 = run until Ctrl+C)").Trim()
    $duration = 0.0; if ($durIn) { try { $duration = [double] $durIn } catch { } }
    $ttype = "Register"; if ($isCoil) { $ttype = "Coil" }
    $label = $ttype + "[" + $addr + "]=" + $disp
    $span = "until Ctrl+C"; if ($duration -gt 0) { $span = "for " + $duration + "s" }
    [void](Confirm-Write ("Repeatedly write " + $label + " every " + $interval + "s, " + $span + " (overrides the controller's own logic)"))
    Write-Host ""
    Write-Info ("Holding " + $label + " every " + $interval + "s. Press Ctrl+C to stop.")
    Write-LogLine ("HOLD_WRITE_START target=" + $label + " interval=" + $interval + " duration=" + $duration)
    $writes = 0; $errors = 0
    $start = Get-Date
    try {
        while ($true) {
            if ($isCoil) { $resp = Write-ModbusCoil $Conn $addr $value } else { $resp = Write-ModbusRegister $Conn $addr $value }
            if ($resp -and -not $resp.IsError) { $writes++ } else { $errors++ }
            $elapsed = ((Get-Date) - $start).TotalSeconds
            Write-Host ("`r[hold] " + $label + " | elapsed: " + [int] $elapsed + "s | writes: " + $writes + " | errors: " + $errors + "   ") -NoNewline -ForegroundColor White
            if ($duration -gt 0 -and $elapsed -ge $duration) { break }
            Start-Sleep -Milliseconds ([int]($interval * 1000))
        }
    } catch { } finally {
        $elapsed = ((Get-Date) - $start).TotalSeconds
        Write-Host ""
        Write-Body ("[hold] Stopped. Total writes: " + $writes + ", errors: " + $errors + ", elapsed: " + [int] $elapsed + "s")
        Write-LogLine ("HOLD_WRITE_END writes=" + $writes + " errors=" + $errors)
    }
}

function Show-LogFile {
    if (-not $script:LogFile) { Write-Info "Logging is not enabled (relaunch with -Log)."; return }
    if (-not (Test-Path -LiteralPath $script:LogFile)) { Write-Info "Log file not created yet."; return }
    Write-Head ("--- Log: " + $script:LogFile + " ---")
    try { Get-Content -Path $script:LogFile | ForEach-Object { Write-Body $_ } } catch { Write-Bad "Could not read log." }
}

function Invoke-ModbusModule {
    param([string] $DefaultIp)
    $ipAddr = $DefaultIp
    if (-not $ipAddr) { $ipAddr = (Read-Host "Enter target Modbus TCP IP").Trim() }
    if (-not $ipAddr) { Write-Bad "No IP provided."; return }
    if (-not (Test-ValidTarget $ipAddr)) { Write-Bad ("'" + $ipAddr + "' is not a valid IP address or resolvable hostname."); return }
    $conn = Connect-Modbus $ipAddr $script:ModbusDefaultPort
    if (-not $conn) { return }
    $ph = @{}; $ph[502] = "Modbus TCP"
    Update-Asset -IPAddr $ipAddr -Ports $ph -Protocol "Modbus TCP" -Source "Modbus"
    try {
        $lock = ""
        if ($script:SafeMode) { $lock = "   [LOCKED - safe mode]" }
        while ($true) {
            Write-MenuTitle "Modbus Utility Menu"
            Write-Body ("    Target: " + $ipAddr + ":" + $script:ModbusDefaultPort)
            Write-Body "1.  Read Coils"
            Write-Body ("2.  Write Coil" + $lock)
            Write-Body "3.  Read Registers"
            Write-Body ("4.  Write Register" + $lock)
            Write-Body "5.  Scan for Coils"
            Write-Body "6.  Scan for Registers"
            Write-Body "7.  Read Device Identity"
            Write-Body "8.  Recon Overview"
            Write-Body ("9.  Flip Coils" + $lock)
            Write-Body ("10. Zero All Coils" + $lock)
            Write-Body ("11. Fuzz Registers" + $lock)
            Write-Body ("12. Hold Write (loop until interrupted)" + $lock)
            Write-Body "13. View Log File"
            Write-Body "14. Back to main menu"
            $choice = (Read-Host "`nSelect an option").Trim()
            try {
                if ($choice -eq "1") { Invoke-ReadCoils $conn }
                elseif ($choice -eq "2") { Invoke-WriteCoil $conn $ipAddr }
                elseif ($choice -eq "3") { Invoke-ReadRegisters $conn }
                elseif ($choice -eq "4") { Invoke-WriteRegister $conn $ipAddr }
                elseif ($choice -eq "5") { Invoke-SmartScan $conn "coil" $script:ScanBlockCoils "COIL" }
                elseif ($choice -eq "6") { Invoke-SmartScan $conn "register" $script:ScanBlockRegs "REG" }
                elseif ($choice -eq "7") { Invoke-ReadDeviceId $conn $ipAddr }
                elseif ($choice -eq "8") { Invoke-BannerGrab $conn $ipAddr $script:ModbusDefaultPort }
                elseif ($choice -eq "9") { Invoke-FlipCoils $conn $ipAddr }
                elseif ($choice -eq "10") { Invoke-ZeroCoils $conn $ipAddr }
                elseif ($choice -eq "11") { Invoke-FuzzRegisters $conn $ipAddr }
                elseif ($choice -eq "12") { Invoke-HoldWrite $conn $ipAddr }
                elseif ($choice -eq "13") { Show-LogFile }
                elseif ($choice -eq "14") { break }
                else { Write-Body "Invalid option." }
            } catch { Write-Bad ("Operation failed: " + $_.Exception.Message); Write-LogLine ("MODBUS_ERROR " + $_.Exception.Message) }
        }
    } finally {
        try { $conn.Client.Close() } catch { }
        Write-LogLine "DISCONNECTED"
    }
}
# ============================================================
#  S7comm MODULE (Siemens, raw TPKT / COTP / S7 - no snap7)
# ============================================================
# ISO-on-TCP (TCP/102). The Python AtomICS uses python-snap7 (a native DLL);
# this edition speaks the wire protocol directly so nothing has to be installed:
#   TPKT (RFC 1006)  : 03 00 <len16>
#   COTP             : Connection Request/Confirm, or Data (DT: 02 F0 80)
#   S7 PDU           : protid 0x32, ROSCTR job(1)/ack_data(3)/userdata(7)
# Implements Setup Communication, Read SZL (0x0011 order code, 0x001C component
# id, 0x0232 protection, 0x0424 CPU state), List Blocks, Read/Write Var (DB and
# I/Q/M), and PLC STOP/START. Connection TSAPs follow the snap7 convention
# (src 0x0100; dst 0x01 + rack*0x20+slot) so it reaches real S7-300/400/1200/1500
# gear, and it is verified against Mike's s7_bottling_sim.py. Rack/slot:
#   S7-1200/1500 = rack 0 slot 1 ; S7-300 = rack 0 slot 2 ; S7-400 varies.
$script:S7DefaultPort = 102
$script:S7CommonSlots = @(@(0, 1), @(0, 2), @(0, 0), @(0, 3))
$script:S7AreaPE = 0x81   # process inputs (I)
$script:S7AreaPA = 0x82   # process outputs (Q)
$script:S7AreaMK = 0x83   # merker / flags (M)
$script:S7AreaDB = 0x84   # data block (DB)

function Send-Tpkt {
    param($Stream, [byte[]] $Payload)
    $total = $Payload.Length + 4
    $frame = [byte[]]@(0x03, 0x00, (Get-HiByte $total), (Get-LoByte $total)) + $Payload
    $Stream.Write($frame, 0, $frame.Length); $Stream.Flush()
}
function Recv-Tpkt {
    param($Stream)
    $hdr = Read-StreamExact $Stream 4
    if (-not $hdr) { return $null }
    if ($hdr[0] -ne 0x03) { return $null }
    $total = Get-U16BE $hdr 2
    if ($total -lt 4) { return $null }
    if ($total -eq 4) { return ,(New-Object byte[] 0) }
    return (Read-StreamExact $Stream ($total - 4))
}
function Send-S7 {
    param($Conn, [byte[]] $S7)
    $cotp = [byte[]]@(0x02, 0xF0, 0x80) + $S7
    Send-Tpkt $Conn.Stream $cotp
}
function Recv-S7 {
    param($Conn)
    $payload = Recv-Tpkt $Conn.Stream
    if (-not $payload -or $payload.Length -lt 2) { return $null }
    $li = [int] $payload[0]
    $s7start = 1 + $li
    if ($s7start -ge $payload.Length) { return $null }
    return ,($payload[$s7start..($payload.Length - 1)])
}
function Parse-S7 {
    param([byte[]] $S7)
    if (-not $S7 -or $S7.Length -lt 10 -or $S7[0] -ne 0x32) { return $null }
    $rosctr = [int] $S7[1]
    $paramlen = Get-U16BE $S7 6
    $datalen = Get-U16BE $S7 8
    $hdrlen = 10
    $errclass = 0; $errcode = 0
    if ($rosctr -eq 0x03) {
        $hdrlen = 12
        if ($S7.Length -ge 12) { $errclass = [int] $S7[10]; $errcode = [int] $S7[11] }
    }
    $param = @(); $data = @()
    if ($paramlen -gt 0 -and ($hdrlen + $paramlen) -le $S7.Length) { $param = $S7[$hdrlen..($hdrlen + $paramlen - 1)] }
    $ds = $hdrlen + $paramlen
    if ($datalen -gt 0 -and ($ds + $datalen) -le $S7.Length) { $data = $S7[$ds..($ds + $datalen - 1)] }
    $o = New-Object PSObject
    $o | Add-Member NoteProperty Rosctr $rosctr
    $o | Add-Member NoteProperty ParamBytes ([byte[]] $param)
    $o | Add-Member NoteProperty DataBytes ([byte[]] $data)
    $o | Add-Member NoteProperty ErrClass $errclass
    $o | Add-Member NoteProperty ErrCode $errcode
    return $o
}
function Get-NextPduRef {
    param($Conn)
    $v = $Conn.PduRef
    $Conn.PduRef = ($v + 1) -band 0xFFFF
    if ($Conn.PduRef -eq 0) { $Conn.PduRef = 1 }
    return $v
}

function Connect-S7 {
    param([string] $IPAddr, [int] $Rack, [int] $Slot, [int] $Port = 102, [int] $TimeoutMs = 4000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($IPAddr, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not ($ok -and $client.Connected)) { try { $client.Close() } catch { }; return $null }
        $client.EndConnect($iar)
    } catch { return $null }
    $stream = $client.GetStream(); $stream.ReadTimeout = $TimeoutMs
    $conn = New-Object PSObject
    $conn | Add-Member NoteProperty Client $client
    $conn | Add-Member NoteProperty Stream $stream
    $conn | Add-Member NoteProperty PduRef 1
    $conn | Add-Member NoteProperty PduSize 480
    # COTP Connection Request. dst TSAP low byte = rack*0x20 + slot.
    $dstLo = (($Rack * 32) + $Slot) -band 0xFF
    $cr = [byte[]]@(0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
                    0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, $dstLo)
    try {
        Send-Tpkt $stream $cr
        $resp = Recv-Tpkt $stream
    } catch { try { $client.Close() } catch { }; return $null }
    if (-not $resp -or $resp.Length -lt 2 -or $resp[1] -ne 0xD0) { try { $client.Close() } catch { }; return $null }
    # Setup communication (negotiate PDU size).
    $pref = Get-NextPduRef $conn
    $setup = [byte[]]@(0x32, 0x01, 0x00, 0x00, (Get-HiByte $pref), (Get-LoByte $pref), 0x00, 0x08, 0x00, 0x00,
                       0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0)
    try {
        Send-S7 $conn $setup
        $r = Recv-S7 $conn
    } catch { try { $client.Close() } catch { }; return $null }
    $p = Parse-S7 ([byte[]] $r)
    if ($p -and $p.ParamBytes.Length -ge 8) { $conn.PduSize = Get-U16BE $p.ParamBytes 6 }
    return $conn
}

function Invoke-S7AutoProbe {
    param([string] $IPAddr, [int] $Port)
    foreach ($rs in $script:S7CommonSlots) {
        $rack = $rs[0]; $slot = $rs[1]
        Write-Body ("    trying rack " + $rack + ", slot " + $slot + " ...")
        $c = Connect-S7 $IPAddr $rack $slot $Port
        if ($c) {
            $o = New-Object PSObject
            $o | Add-Member NoteProperty Conn $c
            $o | Add-Member NoteProperty Rack $rack
            $o | Add-Member NoteProperty Slot $slot
            return $o
        }
    }
    return $null
}

function Read-Szl {
    param($Conn, [int] $SzlId, [int] $SzlIndex)
    $pref = Get-NextPduRef $Conn
    $seq = $pref -band 0xFF
    $param = [byte[]]@(0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, $seq)
    $data = [byte[]]@(0xFF, 0x09, 0x00, 0x04, (Get-HiByte $SzlId), (Get-LoByte $SzlId), (Get-HiByte $SzlIndex), (Get-LoByte $SzlIndex))
    $hdr = [byte[]]@(0x32, 0x07, 0x00, 0x00, (Get-HiByte $pref), (Get-LoByte $pref),
                     (Get-HiByte $param.Length), (Get-LoByte $param.Length), (Get-HiByte $data.Length), (Get-LoByte $data.Length))
    try {
        Send-S7 $Conn ([byte[]]($hdr + $param + $data))
        $r = Recv-S7 $Conn
    } catch { return $null }
    $p = Parse-S7 ([byte[]] $r)
    if (-not $p) { return $null }
    return $p.DataBytes
}

# resp_data: FF 09 len16 | szlid16 index16 reclen16 reccnt16 | records...
function Parse-SzlRecords {
    param([byte[]] $D)
    if (-not $D -or $D.Length -lt 12) { return $null }
    $reclen = Get-U16BE $D 8
    $reccnt = Get-U16BE $D 10
    $recs = @()
    $off = 12
    for ($k = 0; $k -lt $reccnt; $k++) {
        if ($reclen -le 0 -or ($off + $reclen) -gt $D.Length) { break }
        $recs += ,($D[$off..($off + $reclen - 1)])
        $off += $reclen
    }
    $o = New-Object PSObject
    $o | Add-Member NoteProperty RecLen $reclen
    $o | Add-Member NoteProperty Records $recs
    return $o
}

function Get-S7String {
    param([byte[]] $B)
    $s = ""
    try { $s = [System.Text.Encoding]::ASCII.GetString($B) } catch { }
    return $s.Replace([string][char] 0, "").Trim()
}

function Invoke-S7CpuInfo {
    param($Conn, [string] $TargetIp)
    Write-Head "[S7 CPU Info]"
    $parsed = Parse-SzlRecords (Read-Szl $Conn 0x001C 0)
    if (-not $parsed) { Write-Body " (CPU info unavailable)"; return }
    $byIdx = @{}
    foreach ($rec in $parsed.Records) {
        if ($rec.Length -lt 3) { continue }
        $idx = Get-U16BE $rec 0
        $byIdx[$idx] = Get-S7String ($rec[2..($rec.Length - 1)])
    }
    $fields = @(@(0x06, "Module Type"), @(0x02, "Module Name"), @(0x01, "AS Name"), @(0x05, "Serial"), @(0x04, "Copyright"))
    $collected = @()
    foreach ($f in $fields) {
        $idx = $f[0]; $label = $f[1]
        $v = ""; if ($byIdx.ContainsKey($idx)) { $v = $byIdx[$idx] }
        Write-Body (" " + $label.PadRight(12) + ": " + $v)
        if ($v) { $collected += ($label + "=" + $v) }
    }
    if ($TargetIp -and $collected.Count -gt 0) {
        Update-Asset -IPAddr $TargetIp -Vendor "Siemens" -Version ("S7 CPU: " + ($collected -join "; ")) -Source "S7"
    }
}

function Invoke-S7OrderCode {
    param($Conn, [string] $TargetIp)
    Write-Head "[S7 Order Code]"
    $parsed = Parse-SzlRecords (Read-Szl $Conn 0x0011 0)
    if (-not $parsed) { Write-Body " (order code unavailable)"; return }
    $code = ""; $fw = ""
    foreach ($rec in $parsed.Records) {
        if ($rec.Length -lt 22) { continue }
        if ((Get-U16BE $rec 0) -eq 0x0001) {
            $code = Get-S7String ($rec[2..21])
            if ($rec.Length -ge 28) { $fw = "V" + [int] $rec[25] + "." + [int] $rec[26] + "." + [int] $rec[27] }
        }
    }
    Write-Body (" Order Code : " + $code)
    if ($fw) { Write-Body (" Firmware   : " + $fw) }
    if ($TargetIp -and $code) {
        $ver = "S7 order code: " + $code
        if ($fw) { $ver += "; firmware " + $fw }
        Update-Asset -IPAddr $TargetIp -Vendor "Siemens" -Version $ver -Source "S7"
    }
}

function Invoke-S7CpuState {
    param($Conn)
    Write-Head "[S7 CPU State]"
    $parsed = Parse-SzlRecords (Read-Szl $Conn 0x0424 0)
    $state = "UNKNOWN"
    if ($parsed -and $parsed.Records.Count -ge 1) {
        $rec = $parsed.Records[0]
        $b = -1
        if ($rec.Length -gt 3) { $b = [int] $rec[3] }
        if ($b -eq 0x08) { $state = "RUN" } elseif ($b -eq 0x04) { $state = "STOP" }
        elseif ($rec.Length -gt 5) {
            $b2 = [int] $rec[5]
            if ($b2 -eq 0x08) { $state = "RUN" } elseif ($b2 -eq 0x04) { $state = "STOP" }
        }
    }
    Write-Body (" CPU State  : " + $state)
    Write-LogLine ("S7_CPU_STATE " + $state)
}

function Invoke-S7Protection {
    param($Conn)
    Write-Head "[S7 Protection Level]"
    $d = Read-Szl $Conn 0x0232 0
    if (-not $d -or $d.Length -lt 18) { Write-Body " (protection read unavailable)"; return }
    $sch = Get-U16BE $d 8
    $bart = Get-U16BE $d 14
    $levels = @{ 1 = "1 - no protection (open)"; 2 = "2 - write protected"; 3 = "3 - read/write protected" }
    $lv = $sch
    if ($levels.ContainsKey($sch)) { $lv = $levels[$sch] }
    Write-Body (" Protection : " + $lv)
    Write-Body (" Mode (bart): " + $bart + "  (1=RUN 2=RUN-P 3=STOP 4=MRES)")
    Write-LogLine ("S7_PROTECTION sch=" + $sch)
}

function Invoke-S7ListBlocks {
    param($Conn)
    Write-Head "[S7 Block Inventory]"
    $pref = Get-NextPduRef $Conn
    $seq = $pref -band 0xFF
    $param = [byte[]]@(0x00, 0x01, 0x12, 0x04, 0x11, 0x43, 0x01, $seq)
    $hdr = [byte[]]@(0x32, 0x07, 0x00, 0x00, (Get-HiByte $pref), (Get-LoByte $pref),
                     (Get-HiByte $param.Length), (Get-LoByte $param.Length), 0x00, 0x00)
    try {
        Send-S7 $Conn ([byte[]]($hdr + $param))
        $r = Recv-S7 $Conn
    } catch { Write-Body " (block list unavailable)"; return }
    $p = Parse-S7 ([byte[]] $r)
    if (-not $p -or $p.DataBytes.Length -lt 8) { Write-Body " (block list unavailable)"; return }
    $d = $p.DataBytes
    $typeNames = @{ 0x38 = "OB"; 0x41 = "DB"; 0x42 = "SDB"; 0x43 = "FC"; 0x44 = "SFC"; 0x45 = "FB"; 0x46 = "SFB" }
    $off = 4
    $any = $false
    while (($off + 4) -le $d.Length) {
        if ($d[$off] -eq 0x30) {
            $t = [int] $d[$off + 1]; $cnt = Get-U16BE $d ($off + 2)
            $name = ("type 0x{0:x2}" -f $t)
            if ($typeNames.ContainsKey($t)) { $name = $typeNames[$t] }
            Write-Body (" " + $name.PadRight(5) + ": " + $cnt)
            $any = $true
        }
        $off += 4
    }
    if (-not $any) { Write-Body " (no block counts returned)" }
}

function Get-S7AddrBytes {
    param([int] $Addr)
    $a2 = [int][math]::Floor($Addr / 65536) -band 0xFF
    $a1 = [int][math]::Floor($Addr / 256) -band 0xFF
    $a0 = $Addr -band 0xFF
    return @($a2, $a1, $a0)
}

function Read-S7Area {
    param($Conn, [int] $Area, [int] $DbNum, [int] $Start, [int] $Size)
    $pref = Get-NextPduRef $Conn
    $ab = Get-S7AddrBytes ($Start * 8)
    $item = [byte[]]@(0x12, 0x0A, 0x10, 0x02, (Get-HiByte $Size), (Get-LoByte $Size),
                      (Get-HiByte $DbNum), (Get-LoByte $DbNum), $Area, $ab[0], $ab[1], $ab[2])
    $param = [byte[]]@(0x04, 0x01) + $item
    $hdr = [byte[]]@(0x32, 0x01, 0x00, 0x00, (Get-HiByte $pref), (Get-LoByte $pref),
                     (Get-HiByte $param.Length), (Get-LoByte $param.Length), 0x00, 0x00)
    try {
        Send-S7 $Conn ([byte[]]($hdr + $param))
        $r = Recv-S7 $Conn
    } catch { return $null }
    $p = Parse-S7 ([byte[]] $r)
    if (-not $p -or $p.DataBytes.Length -lt 4) { return $null }
    $d = $p.DataBytes
    if ($d[0] -ne 0xFF) { return $null }
    $transport = [int] $d[1]
    $lenf = Get-U16BE $d 2
    $nbytes = $lenf
    if ($transport -eq 0x03 -or $transport -eq 0x04 -or $transport -eq 0x06) { $nbytes = [int][math]::Floor(($lenf + 7) / 8) }
    if ((4 + $nbytes) -gt $d.Length) { $nbytes = $d.Length - 4 }
    if ($nbytes -le 0) { return ,(New-Object byte[] 0) }
    return ,($d[4..(4 + $nbytes - 1)])
}

function Write-S7AreaBytes {
    param($Conn, [int] $Area, [int] $DbNum, [int] $Start, [byte[]] $Value)
    $pref = Get-NextPduRef $Conn
    $ab = Get-S7AddrBytes ($Start * 8)
    $size = $Value.Length
    $item = [byte[]]@(0x12, 0x0A, 0x10, 0x02, (Get-HiByte $size), (Get-LoByte $size),
                      (Get-HiByte $DbNum), (Get-LoByte $DbNum), $Area, $ab[0], $ab[1], $ab[2])
    $param = [byte[]]@(0x05, 0x01) + $item
    $bits = $size * 8
    $ditem = [byte[]]@(0x00, 0x04, (Get-HiByte $bits), (Get-LoByte $bits)) + $Value
    $hdr = [byte[]]@(0x32, 0x01, 0x00, 0x00, (Get-HiByte $pref), (Get-LoByte $pref),
                     (Get-HiByte $param.Length), (Get-LoByte $param.Length), (Get-HiByte $ditem.Length), (Get-LoByte $ditem.Length))
    try {
        Send-S7 $Conn ([byte[]]($hdr + $param + $ditem))
        $r = Recv-S7 $Conn
    } catch { return $false }
    $p = Parse-S7 ([byte[]] $r)
    if (-not $p -or $p.DataBytes.Length -lt 1) { return $false }
    return ($p.DataBytes[0] -eq 0xFF)
}

function Write-S7Bit {
    param($Conn, [int] $Area, [int] $DbNum, [int] $ByteOff, [int] $Bit, [int] $Val)
    $pref = Get-NextPduRef $Conn
    $ab = Get-S7AddrBytes ($ByteOff * 8 + $Bit)
    $item = [byte[]]@(0x12, 0x0A, 0x10, 0x01, 0x00, 0x01, (Get-HiByte $DbNum), (Get-LoByte $DbNum), $Area, $ab[0], $ab[1], $ab[2])
    $param = [byte[]]@(0x05, 0x01) + $item
    $v = 0; if ($Val) { $v = 1 }
    $ditem = [byte[]]@(0x00, 0x03, 0x00, 0x01, $v)
    $hdr = [byte[]]@(0x32, 0x01, 0x00, 0x00, (Get-HiByte $pref), (Get-LoByte $pref),
                     (Get-HiByte $param.Length), (Get-LoByte $param.Length), (Get-HiByte $ditem.Length), (Get-LoByte $ditem.Length))
    try {
        Send-S7 $Conn ([byte[]]($hdr + $param + $ditem))
        $r = Recv-S7 $Conn
    } catch { return $false }
    $p = Parse-S7 ([byte[]] $r)
    if (-not $p -or $p.DataBytes.Length -lt 1) { return $false }
    return ($p.DataBytes[0] -eq 0xFF)
}

function Pack-S7Value {
    param([string] $DType)
    # returns @(bytes, display) or @($null,$null)
    try {
        if ($DType -eq "b") { $v = [int] (Read-Host "Value (byte 0-255)"); return @([byte[]]@($v -band 0xFF), ("B:" + ($v -band 0xFF))) }
        if ($DType -eq "w") { $v = [int] (Read-Host "Value (word 0-65535)"); return @([byte[]](ConvertTo-BytesBE ($v -band 0xFFFF) 2), ("W:" + ($v -band 0xFFFF))) }
        if ($DType -eq "d") { $v = [long] (Read-Host "Value (dword 0-4294967295)"); return @([byte[]](ConvertTo-BytesBE ($v -band 0xFFFFFFFF) 4), ("D:" + ($v -band 0xFFFFFFFF))) }
        if ($DType -eq "i") { $v = [int] (Read-Host "Value (int16 -32768..32767)"); if ($v -lt -32768) { $v = -32768 }; if ($v -gt 32767) { $v = 32767 }; $u = $v; if ($u -lt 0) { $u = $u + 65536 }; return @([byte[]](ConvertTo-BytesBE $u 2), ("INT:" + $v)) }
        if ($DType -eq "r") { $v = [double] (Read-Host "Value (real/float)"); return @([byte[]](ConvertTo-FloatBE $v), ("REAL:" + $v)) }
    } catch { Write-Bad "Invalid value."; return @($null, $null) }
    Write-Bad "Unknown type."
    return @($null, $null)
}

function Invoke-S7ReadDb {
    param($Conn)
    try {
        $db = [int] (Read-Host "DB number")
        $start = [int] ((Read-Host "Start byte [0]").Trim())
        $size = [int] ((Read-Host "Size in bytes [64]").Trim())
    } catch { }
    if (-not $size) { $size = 64 }
    if (-not $start) { $start = 0 }
    $data = Read-S7Area $Conn $script:S7AreaDB $db $start $size
    if ($data -eq $null) { Write-Bad " (DB read failed or not permitted)"; return }
    Write-Head ("[DB" + $db + " bytes " + $start + ".." + ($start + $data.Length - 1) + "]")
    Write-Body (Format-HexDump ([byte[]] $data) $start)
}

function Invoke-S7ReadArea {
    param($Conn)
    $ain = (Read-Host "Area ([i]nputs/PE, [q]outputs/PA, [m]erkers/MK) [m]").Trim().ToLower()
    if (-not $ain) { $ain = "m" }
    $area = $script:S7AreaMK; $aname = "MK"
    if ($ain[0] -eq "i") { $area = $script:S7AreaPE; $aname = "PE" }
    elseif ($ain[0] -eq "q" -or $ain[0] -eq "o") { $area = $script:S7AreaPA; $aname = "PA" }
    elseif ($ain[0] -eq "m") { $area = $script:S7AreaMK; $aname = "MK" }
    else { Write-Bad "Invalid area."; return }
    $start = 0; $size = 16
    try { $start = [int] ((Read-Host "Start byte [0]").Trim()); $size = [int] ((Read-Host "Size in bytes [16]").Trim()) } catch { }
    if (-not $size) { $size = 16 }
    $data = Read-S7Area $Conn $area 0 $start $size
    if ($data -eq $null) { Write-Bad " (area read failed or not permitted)"; return }
    Write-Head ("[" + $aname + " bytes " + $start + ".." + ($start + $data.Length - 1) + "]")
    Write-Body (Format-HexDump ([byte[]] $data) $start)
}

function Invoke-S7WriteDb {
    param($Conn, [string] $Ip)
    if (Test-SafeBlocked "S7 Write DB") { return }
    try { $db = [int] (Read-Host "DB number"); $start = [int] (Read-Host "Start byte") } catch { Write-Bad "Invalid number."; return }
    $dtype = (Read-Host "Type ([b]yte [w]ord [d]word [i]nt16 [r]eal b[t]=bit) [b]").Trim().ToLower()
    if (-not $dtype) { $dtype = "b" }
    Write-Warn2 "Writing a live DB changes the data the PLC program runs on."
    if ($dtype -eq "t") {
        try { $bit = [int] (Read-Host "Bit offset (0-7)"); $val = [int] (Read-Host "Value (0 or 1)") } catch { Write-Bad "Invalid number."; return }
        if ($bit -lt 0 -or $bit -gt 7) { Write-Bad "Bit offset must be 0-7."; return }
        [void](Confirm-Write ("S7 DB" + $db + ".DBX" + $start + "." + $bit + " = " + $val + " at " + $Ip))
        if (Write-S7Bit $Conn $script:S7AreaDB $db $start $bit $val) { Write-Ok ("DB" + $db + ".DBX" + $start + "." + $bit + " set to " + $val) } else { Write-Bad "bit write failed." }
        return
    }
    $pv = Pack-S7Value $dtype
    if ($pv[0] -eq $null) { return }
    [void](Confirm-Write ("S7 DB" + $db + " byte " + $start + " = " + $pv[1] + " (" + $pv[0].Length + " byte(s)) at " + $Ip))
    if (Write-S7AreaBytes $Conn $script:S7AreaDB $db $start ([byte[]] $pv[0])) { Write-Ok ("Wrote " + $pv[0].Length + " byte(s) to DB" + $db + " at byte " + $start + ".") }
    else { Write-Bad "DB write failed." }
}

function Invoke-S7WriteArea {
    param($Conn, [string] $Ip)
    if (Test-SafeBlocked "S7 Write Area") { return }
    $ain = (Read-Host "Area ([m]erkers/MK flags, [q] outputs/PA) [m]").Trim().ToLower()
    if (-not $ain) { $ain = "m" }
    $area = 0; $aname = ""
    if ($ain[0] -eq "m") { $area = $script:S7AreaMK; $aname = "MK" }
    elseif ($ain[0] -eq "q" -or $ain[0] -eq "o") { $area = $script:S7AreaPA; $aname = "PA" }
    else { Write-Bad "Invalid area. (Inputs/PE reflect field wiring and are not writable.)"; return }
    if ($aname -eq "PA") {
        Write-Warn2 "Writing Q FORCES a physical output (valve/motor/relay) regardless of the"
        Write-Body  "    PLC program. Simulator/bench only."
    }
    try { $start = [int] (Read-Host "Start byte") } catch { Write-Bad "Invalid number."; return }
    $dtype = (Read-Host "Type ([b]yte [w]ord [d]word [i]nt16 [r]eal b[t]=bit) [b]").Trim().ToLower()
    if (-not $dtype) { $dtype = "b" }
    if ($dtype -eq "t") {
        try { $bit = [int] (Read-Host "Bit offset (0-7)"); $val = [int] (Read-Host "Value (0 or 1)") } catch { Write-Bad "Invalid number."; return }
        if ($bit -lt 0 -or $bit -gt 7) { Write-Bad "Bit offset must be 0-7."; return }
        [void](Confirm-Write ($aname + " byte " + $start + "." + $bit + " = " + $val + " at " + $Ip))
        if (Write-S7Bit $Conn $area 0 $start $bit $val) { Write-Ok ($aname + " " + $start + "." + $bit + " set to " + $val) } else { Write-Bad "bit write failed." }
        return
    }
    $pv = Pack-S7Value $dtype
    if ($pv[0] -eq $null) { return }
    [void](Confirm-Write ("S7 " + $aname + " byte " + $start + " = " + $pv[1] + " (" + $pv[0].Length + " byte(s)) at " + $Ip))
    if (Write-S7AreaBytes $Conn $area 0 $start ([byte[]] $pv[0])) { Write-Ok ("Wrote " + $pv[0].Length + " byte(s) to " + $aname + " at byte " + $start + ".") }
    else { Write-Bad "area write failed." }
}

function Invoke-S7Stop {
    param($Conn, [string] $Ip)
    if (Test-SafeBlocked "S7 STOP CPU") { return }
    Write-Head "[S7 STOP CPU]"
    Write-Warn2 ("This STOPs the CPU at " + $Ip + ". On a live PLC it HALTS the control program")
    Write-Body  "    and the process it drives. Confirm you are authorized and that stopping"
    Write-Body  "    this CPU is safe before continuing."
    $typed = (Read-Host ("  Type the target IP (" + $Ip + ") to confirm STOP, anything else cancels")).Trim()
    if ($typed -ne $Ip) { Write-Body "  STOP cancelled."; Write-LogLine "S7_STOP_CANCELLED"; return }
    Write-Body ("  [write] S7 STOP CPU at " + $Ip)
    Write-LogLine ("WRITE_EXECUTED S7_STOP ip=" + $Ip)
    $pref = Get-NextPduRef $Conn
    $pi = [System.Text.Encoding]::ASCII.GetBytes("P_PROGRAM")
    $param = [byte[]]@(0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09) + $pi
    $hdr = [byte[]]@(0x32, 0x01, 0x00, 0x00, (Get-HiByte $pref), (Get-LoByte $pref),
                     (Get-HiByte $param.Length), (Get-LoByte $param.Length), 0x00, 0x00)
    try {
        Send-S7 $Conn ([byte[]]($hdr + $param))
        $r = Recv-S7 $Conn
        $p = Parse-S7 ([byte[]] $r)
        if ($p -and $p.ErrClass -eq 0) { Write-Ok "STOP command sent. Use CPU state to confirm RUN->STOP." }
        else { Write-Bad "STOP response indicated an error (or no reply)." }
    } catch { Write-Bad ("STOP failed: " + $_.Exception.Message) }
}

function Invoke-S7Start {
    param($Conn, [string] $Ip)
    if (Test-SafeBlocked "S7 START CPU") { return }
    $mode = (Read-Host "Start type ([h]ot = resume, [c]old = full restart) [h]").Trim().ToLower()
    $label = "hot"; if ($mode.StartsWith("c")) { $label = "cold" }
    Write-Warn2 ("START re-energises the process controlled by " + $Ip + ". Confirm it is safe.")
    [void](Confirm-Write ("S7 START CPU (" + $label + ") at " + $Ip))
    # PLC Control start service (P_PROGRAM). Both hot and cold issue the start
    # service here; the requested mode is recorded in the audit line.
    $pref = Get-NextPduRef $Conn
    $pi = [System.Text.Encoding]::ASCII.GetBytes("P_PROGRAM")
    $param = [byte[]]@(0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFD, 0x00, 0x00, 0x09) + $pi
    $hdr = [byte[]]@(0x32, 0x01, 0x00, 0x00, (Get-HiByte $pref), (Get-LoByte $pref),
                     (Get-HiByte $param.Length), (Get-LoByte $param.Length), 0x00, 0x00)
    try {
        Send-S7 $Conn ([byte[]]($hdr + $param))
        $r = Recv-S7 $Conn
        $p = Parse-S7 ([byte[]] $r)
        if ($p -and $p.ErrClass -eq 0) { Write-Ok "START command sent. Use CPU state to confirm STOP->RUN." }
        else { Write-Bad "START response indicated an error (or no reply)." }
    } catch { Write-Bad ("START failed: " + $_.Exception.Message) }
}

function Invoke-S7Recon {
    param($Conn, [string] $Ip, [int] $Rack, [int] $Slot)
    $BAR = "=" * 60
    Write-Host ""
    Write-Body $BAR
    Write-Body " S7comm RECON OVERVIEW"
    Write-Body $BAR
    Write-Body (" Target     : " + $Ip + ":" + $script:S7DefaultPort + "  (rack " + $Rack + ", slot " + $Slot + ")")
    Write-Body (" Timestamp  : " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
    Invoke-S7CpuInfo $Conn $Ip
    Invoke-S7OrderCode $Conn $Ip
    Invoke-S7CpuState $Conn
    Invoke-S7Protection $Conn
    Invoke-S7ListBlocks $Conn
    Write-Body $BAR
}

function Invoke-S7Module {
    param([string] $DefaultIp)
    $ip = $DefaultIp
    if (-not $ip) { $ip = (Read-Host "Enter target S7 PLC IP").Trim() }
    if (-not $ip) { Write-Bad "No IP provided."; return }
    if (-not (Test-ValidTarget $ip)) { Write-Bad ("'" + $ip + "' is not a valid IP address or resolvable hostname."); return }
    $portIn = (Read-Host ("S7 port [" + $script:S7DefaultPort + "]")).Trim()
    $port = $script:S7DefaultPort
    if ($portIn) { try { $port = [int] $portIn } catch { } }

    $auto = (Read-Host "Auto-probe common rack/slot combos? [Y/n]").Trim().ToLower()
    $conn = $null; $rack = 0; $slot = 1
    if ($auto -eq "" -or $auto -eq "y" -or $auto -eq "yes") {
        Write-Body "Auto-probing rack/slot..."
        $probe = Invoke-S7AutoProbe $ip $port
        if ($probe) { $conn = $probe.Conn; $rack = $probe.Rack; $slot = $probe.Slot }
    } else {
        try { $rack = [int] ((Read-Host "Rack [0]").Trim()); $slot = [int] ((Read-Host "Slot (1=S7-1200/1500, 2=S7-300) [1]").Trim()) } catch { }
        if (-not $slot) { $slot = 1 }
        $conn = Connect-S7 $ip $rack $slot $port
    }
    if (-not $conn) { Write-Bad ("Could not establish an S7 connection to " + $ip + ":" + $port + "."); return }
    Write-Ok ("Connected to S7 at " + $ip + ":" + $port + " (rack " + $rack + ", slot " + $slot + ")")
    if ($script:SafeMode) { Write-Warn2 "SAFE mode: S7 writes (DB / M / Q) and STOP/START are blocked. Relaunch with -Active to enable them." }
    $ph = @{}; $ph[$port] = "S7comm / ISO-TSAP (Siemens)"
    Update-Asset -IPAddr $ip -Ports $ph -Protocol "S7comm" -Vendor "Siemens" -Source "S7"
    try {
        $lock = ""
        if ($script:SafeMode) { $lock = "   [LOCKED - safe mode]" }
        while ($true) {
            Write-MenuTitle "S7comm (Siemens) Menu"
            Write-Body ("    Target: " + $ip + ":" + $port + "  rack " + $rack + " slot " + $slot)
            Write-Body "1. Recon overview (identity, order code, state, protection, blocks)"
            Write-Body "2. CPU info (module type, serial, AS name)"
            Write-Body "3. Order code / firmware"
            Write-Body "4. CPU state (RUN/STOP)"
            Write-Body "5. Protection level"
            Write-Body "6. Block inventory (OB/FB/FC/DB counts)"
            Write-Body "7. Read a Data Block (DB)"
            Write-Body "8. Read I/Q/M area"
            Write-Body ("9. Write a Data Block (DB)" + $lock)
            Write-Body ("10. Write M (flags) / Q (outputs)" + $lock)
            Write-Body ("11. STOP CPU (RUN->STOP) - halts the controlled process" + $lock)
            Write-Body ("12. START CPU (STOP->RUN)" + $lock)
            Write-Body "13. Back to main menu"
            $choice = (Read-Host "`nSelect an option").Trim()
            try {
                if ($choice -eq "1") { Invoke-S7Recon $conn $ip $rack $slot }
                elseif ($choice -eq "2") { Invoke-S7CpuInfo $conn $ip }
                elseif ($choice -eq "3") { Invoke-S7OrderCode $conn $ip }
                elseif ($choice -eq "4") { Invoke-S7CpuState $conn }
                elseif ($choice -eq "5") { Invoke-S7Protection $conn }
                elseif ($choice -eq "6") { Invoke-S7ListBlocks $conn }
                elseif ($choice -eq "7") { Invoke-S7ReadDb $conn }
                elseif ($choice -eq "8") { Invoke-S7ReadArea $conn }
                elseif ($choice -eq "9") { Invoke-S7WriteDb $conn $ip }
                elseif ($choice -eq "10") { Invoke-S7WriteArea $conn $ip }
                elseif ($choice -eq "11") { Invoke-S7Stop $conn $ip }
                elseif ($choice -eq "12") { Invoke-S7Start $conn $ip }
                elseif ($choice -eq "13") { break }
                else { Write-Body "Invalid option." }
            } catch { Write-Bad ("Operation failed: " + $_.Exception.Message); Write-LogLine ("S7_ERROR " + $_.Exception.Message) }
        }
    } finally {
        try { $conn.Client.Close() } catch { }
        Write-LogLine "S7_DISCONNECTED"
    }
}
# Little-endian helpers (EtherNet/IP encapsulation + CIP are little-endian).
function ConvertTo-BytesLE {
    param([long] $Value, [int] $Width)
    $out = New-Object byte[] $Width
    for ($i = 0; $i -lt $Width; $i++) { $out[$i] = [byte]($Value -band 0xFF); $Value = [math]::Floor($Value / 256) }
    return ,$out
}
function Get-U16LE { param([byte[]] $B, [int] $Off) return ([int] $B[$Off] + [int] $B[$Off + 1] * 256) }
function Get-U32LE {
    param([byte[]] $B, [int] $Off)
    return ([long] $B[$Off] + [long] $B[$Off + 1] * 256 + [long] $B[$Off + 2] * 65536 + [long] $B[$Off + 3] * 16777216)
}

# ============================================================
#  EtherNet/IP + CIP MODULE (raw sockets, TCP/UDP 44818)
# ============================================================
# Builds the 24-byte encapsulation header and ListIdentity / ListServices /
# ListInterfaces / RegisterSession directly. Read-only: no CIP write, no
# Forward_Open. Encapsulation + CIP are little-endian; the sockaddr inside the
# identity reply is big-endian. Reference: ODVA CIP Networks Library Vol.2.
$script:EnipDefaultPort = 44818
$script:EnipCmdListServices   = 0x0004
$script:EnipCmdListIdentity   = 0x0063
$script:EnipCmdListInterfaces = 0x0064
$script:EnipCmdRegister       = 0x0065
$script:EnipCmdUnRegister     = 0x0066
$script:EnipItemCipIdentity   = 0x000C
$script:EnipItemServices      = 0x0100
$script:EnipStatus = @{
    0x0000 = "success"; 0x0001 = "invalid/unsupported command"; 0x0002 = "insufficient memory";
    0x0003 = "malformed data in request"; 0x0064 = "invalid session handle";
    0x0065 = "invalid message length"; 0x0069 = "unsupported protocol revision"
}
$script:EnipDeviceTypes = @{
    0x00 = "Generic Device"; 0x02 = "AC Drive"; 0x03 = "Motor Overload"; 0x04 = "Limit Switch";
    0x05 = "Inductive Proximity Switch"; 0x06 = "Photoelectric Sensor"; 0x07 = "General Purpose Discrete I/O";
    0x09 = "Resolver"; 0x0C = "Communications Adapter"; 0x0E = "Programmable Logic Controller";
    0x10 = "Position Controller"; 0x13 = "DC Drive"; 0x15 = "Contactor"; 0x16 = "Motor Starter";
    0x17 = "Soft Start"; 0x18 = "Human-Machine Interface"; 0x1A = "Mass Flow Controller";
    0x1B = "Pneumatic Valve"; 0x1C = "Vacuum Pressure Gauge"; 0x1D = "Process Control Valve";
    0x22 = "Encoder"; 0x23 = "Safety Discrete I/O Device"; 0x24 = "Fluid Flow Controller";
    0x25 = "CIP Motion Drive"; 0x28 = "CIP Modbus Device"; 0x29 = "CIP Modbus Translator";
    0x2A = "Safety Analog I/O Device"; 0x2C = "Managed Ethernet Switch"
}
$script:EnipVendors = @{ 1 = "Rockwell Automation / Allen-Bradley" }

function Build-EnipHeader {
    param([int] $Command, [byte[]] $Data = $null, [long] $Session = 0, [long] $Status = 0)
    if (-not $Data) { $Data = New-Object byte[] 0 }
    $h = [byte[]](ConvertTo-BytesLE $Command 2)
    $h += [byte[]](ConvertTo-BytesLE $Data.Length 2)
    $h += [byte[]](ConvertTo-BytesLE $Session 4)
    $h += [byte[]](ConvertTo-BytesLE $Status 4)
    $h += (New-Object byte[] 8)                 # sender context
    $h += [byte[]](ConvertTo-BytesLE 0 4)       # options
    if ($Data.Length -gt 0) { $h += $Data }
    return ,([byte[]] $h)
}
function Parse-EnipHeader {
    param([byte[]] $Raw)
    if (-not $Raw -or $Raw.Length -lt 24) { return $null }
    $o = New-Object PSObject
    $o | Add-Member NoteProperty Command (Get-U16LE $Raw 0)
    $o | Add-Member NoteProperty Length (Get-U16LE $Raw 2)
    $o | Add-Member NoteProperty Session (Get-U32LE $Raw 4)
    $o | Add-Member NoteProperty Status (Get-U32LE $Raw 8)
    $data = New-Object byte[] 0
    $ln = $o.Length
    if ($ln -gt 0 -and (24 + $ln) -le $Raw.Length) { $data = $Raw[24..(24 + $ln - 1)] }
    $o | Add-Member NoteProperty Data ([byte[]] $data)
    return $o
}

function Send-EnipTcp {
    param([string] $Ip, [int] $Port, [int] $Command, [byte[]] $Data = $null, [long] $Session = 0, [int] $TimeoutMs = 3000)
    $pkt = Build-EnipHeader $Command $Data $Session
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($Ip, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not ($ok -and $client.Connected)) { try { $client.Close() } catch { }; return $null }
        $client.EndConnect($iar)
        $st = $client.GetStream(); $st.ReadTimeout = $TimeoutMs
        $st.Write($pkt, 0, $pkt.Length); $st.Flush()
        $hdr = Read-StreamExact $st 24
        if (-not $hdr) { try { $client.Close() } catch { }; return $null }
        $len = Get-U16LE $hdr 2
        $data = New-Object byte[] 0
        if ($len -gt 0) { $data = Read-StreamExact $st $len; if (-not $data) { $data = New-Object byte[] 0 } }
        try { $client.Close() } catch { }
        return (Parse-EnipHeader ([byte[]]($hdr + $data)))
    } catch { try { $client.Close() } catch { }; return $null }
}

function Parse-EnipIdentityItem {
    param([byte[]] $Item)
    $o = New-Object PSObject
    $o | Add-Member NoteProperty VendorId $null
    $o | Add-Member NoteProperty DeviceType $null
    $o | Add-Member NoteProperty ProductCode $null
    $o | Add-Member NoteProperty Revision "?"
    $o | Add-Member NoteProperty Serial 0
    $o | Add-Member NoteProperty ProductName ""
    $o | Add-Member NoteProperty State $null
    if ($Item.Length -lt 33) { return $o }
    $p = 18
    $o.VendorId = Get-U16LE $Item $p; $p += 2
    $o.DeviceType = Get-U16LE $Item $p; $p += 2
    $o.ProductCode = Get-U16LE $Item $p; $p += 2
    $o.Revision = ("" + [int] $Item[$p] + "." + [int] $Item[$p + 1]); $p += 2
    $p += 2                                  # status word
    $o.Serial = Get-U32LE $Item $p; $p += 4
    $nameLen = [int] $Item[$p]; $p += 1
    if (($p + $nameLen) -le $Item.Length -and $nameLen -gt 0) {
        try { $o.ProductName = ([System.Text.Encoding]::ASCII.GetString($Item[$p..($p + $nameLen - 1)])).Trim() } catch { }
    }
    $p += $nameLen
    if ($p -lt $Item.Length) { $o.State = [int] $Item[$p] }
    return $o
}
function Parse-EnipIdentityReply {
    param($Reply)
    if (-not $Reply -or $Reply.Data.Length -lt 2) { return $null }
    $d = $Reply.Data
    $count = Get-U16LE $d 0
    $p = 2
    for ($k = 0; $k -lt $count; $k++) {
        if (($p + 4) -gt $d.Length) { break }
        $itype = Get-U16LE $d $p
        $ilen = Get-U16LE $d ($p + 2)
        $p += 4
        $item = New-Object byte[] 0
        if ($ilen -gt 0 -and ($p + $ilen) -le $d.Length) { $item = $d[$p..($p + $ilen - 1)] }
        $p += $ilen
        if ($itype -eq $script:EnipItemCipIdentity) { return (Parse-EnipIdentityItem ([byte[]] $item)) }
    }
    return $null
}
function Show-EnipIdentity {
    param($Info, [string] $Ip, [int] $Port)
    $vid = $Info.VendorId
    $vname = ""
    if ($vid -ne $null -and $script:EnipVendors.ContainsKey([int] $vid)) { $vname = $script:EnipVendors[[int] $vid] }
    $dtype = $Info.DeviceType
    $dname = ""
    if ($dtype -ne $null -and $script:EnipDeviceTypes.ContainsKey([int] $dtype)) { $dname = $script:EnipDeviceTypes[[int] $dtype] }
    $states = @{ 0 = "Nonexistent"; 1 = "Device Self Testing"; 2 = "Standby"; 3 = "Operational"; 4 = "Major Recoverable Fault"; 5 = "Major Unrecoverable Fault" }
    Write-Body (" Product Name : " + $Info.ProductName)
    $vline = "" + $vid; if ($vname) { $vline += " (" + $vname + ")" }
    Write-Body (" Vendor ID    : " + $vline)
    $dline = "" + $dtype; if ($dname) { $dline += " (" + $dname + ")" }
    Write-Body (" Device Type  : " + $dline)
    Write-Body (" Product Code : " + $Info.ProductCode)
    Write-Body (" Revision     : " + $Info.Revision)
    Write-Body (" Serial       : 0x" + ("{0:x8}" -f [long] $Info.Serial))
    if ($Info.State -ne $null) {
        $sn = "vendor-specific"; if ($states.ContainsKey([int] $Info.State)) { $sn = $states[[int] $Info.State] }
        Write-Body (" State        : " + $Info.State + " (" + $sn + ")")
    }
    $vp = @()
    if ($Info.ProductName) { $vp += ("Product=" + $Info.ProductName) }
    if ($vid -ne $null) { $vp += ("Vendor=" + $vline) }
    if ($dtype -ne $null) { $vp += ("DeviceType=" + $dline) }
    if ($Info.ProductCode -ne $null) { $vp += ("ProductCode=" + $Info.ProductCode) }
    if ($Info.Revision) { $vp += ("Rev=" + $Info.Revision) }
    $ph = @{}; $ph[$Port] = "EtherNet/IP (explicit / CIP)"
    Update-Asset -IPAddr $Ip -Ports $ph -Protocol "EtherNet/IP" -Vendor $vname -Version ("EtherNet/IP ListIdentity: " + ($vp -join "; ")) -Source "EtherNet/IP"
}

function Invoke-EnipListIdentity {
    param([string] $Ip, [int] $Port)
    Write-Head ("[EtherNet/IP ListIdentity] " + $Ip + ":" + $Port)
    $reply = Send-EnipTcp $Ip $Port $script:EnipCmdListIdentity
    if (-not $reply) { Write-Body " (no reply - port closed/filtered or not EtherNet/IP)"; return $null }
    $info = Parse-EnipIdentityReply $reply
    if (-not $info) { Write-Body " (reply carried no CIP Identity item)"; return $null }
    Show-EnipIdentity $info $Ip $Port
    return $info
}
function Invoke-EnipListServices {
    param([string] $Ip, [int] $Port)
    Write-Head ("[EtherNet/IP ListServices] " + $Ip + ":" + $Port)
    $reply = Send-EnipTcp $Ip $Port $script:EnipCmdListServices
    if (-not $reply -or $reply.Data.Length -lt 2) { Write-Body " (no reply)"; return }
    $d = $reply.Data
    $count = Get-U16LE $d 0
    $p = 2
    for ($k = 0; $k -lt $count; $k++) {
        if (($p + 4) -gt $d.Length) { break }
        $itype = Get-U16LE $d $p; $ilen = Get-U16LE $d ($p + 2); $p += 4
        $item = New-Object byte[] 0
        if ($ilen -gt 0 -and ($p + $ilen) -le $d.Length) { $item = $d[$p..($p + $ilen - 1)] }
        $p += $ilen
        if ($itype -eq $script:EnipItemServices -and $item.Length -ge 20) {
            $ver = Get-U16LE $item 0; $caps = Get-U16LE $item 2
            $name = ""
            try { $name = ([System.Text.Encoding]::ASCII.GetString($item[4..19])).Replace([char] 0, "").Trim() } catch { }
            Write-Body ("   Service   : " + $name)
            Write-Body ("   Version   : " + $ver)
            $tcp = "no"; if ($caps -band 0x0020) { $tcp = "yes" }
            $udp = "no"; if ($caps -band 0x0100) { $udp = "yes" }
            Write-Body ("   CIP/TCP   : " + $tcp)
            Write-Body ("   CIP/UDP   : " + $udp)
            $ph = @{}; $ph[$Port] = "EtherNet/IP (explicit / CIP)"
            Update-Asset -IPAddr $Ip -Ports $ph -Protocol "EtherNet/IP" -Source "EtherNet/IP"
        } else { Write-Body ("   (item type 0x" + ("{0:x4}" -f $itype) + ", " + $ilen + " bytes)") }
    }
}
function Invoke-EnipListInterfaces {
    param([string] $Ip, [int] $Port)
    Write-Head ("[EtherNet/IP ListInterfaces] " + $Ip + ":" + $Port)
    $reply = Send-EnipTcp $Ip $Port $script:EnipCmdListInterfaces
    if (-not $reply -or $reply.Data.Length -lt 2) { Write-Body " (no reply)"; return }
    $count = Get-U16LE $reply.Data 0
    Write-Body ("   Interface items: " + $count)
    if ($count -eq 0) { Write-Body "   (none reported - normal for many devices)" }
}
function Invoke-EnipRegisterSession {
    param([string] $Ip, [int] $Port)
    Write-Head ("[EtherNet/IP RegisterSession] " + $Ip + ":" + $Port)
    $data = [byte[]](ConvertTo-BytesLE 1 2); $data += [byte[]](ConvertTo-BytesLE 0 2)
    $reply = Send-EnipTcp $Ip $Port $script:EnipCmdRegister $data
    if (-not $reply) { Write-Body " (no reply)"; return }
    if ($reply.Status -ne 0 -or $reply.Session -eq 0) { Write-Body " (registration failed)"; return }
    Write-Ok ("Session opened: handle 0x" + ("{0:x8}" -f [long] $reply.Session) + " - device supports explicit messaging.")
    $ph = @{}; $ph[$Port] = "EtherNet/IP (explicit / CIP)"
    Update-Asset -IPAddr $Ip -Ports $ph -Protocol "EtherNet/IP" -Source "EtherNet/IP"
    # Close the session again so none is left open.
    [void](Send-EnipTcp $Ip $Port $script:EnipCmdUnRegister (New-Object byte[] 0) $reply.Session)
    Write-Body " (session closed)"
}
function Invoke-EnipDiscover {
    param([int] $Port, [string] $Target, [int] $TimeoutMs = 3000)
    $dest = $Target; if (-not $dest) { $dest = "255.255.255.255" }
    Write-Head ("Sending EtherNet/IP ListIdentity to " + $dest + ":" + $Port + " (listening " + ([int]($TimeoutMs / 1000)) + "s)...")
    $pkt = Build-EnipHeader $script:EnipCmdListIdentity
    $found = @{}
    $s = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
    try {
        $s.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::Broadcast, $true)
        $s.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)))
        [void] $s.SendTo($pkt, (New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($dest), $Port)))
        $end = (Get-Date).AddMilliseconds($TimeoutMs)
        while ((Get-Date) -lt $end) {
            $rl = New-Object System.Collections.ArrayList
            [void] $rl.Add($s)
            [System.Net.Sockets.Socket]::Select($rl, $null, $null, 500000)
            if ($rl.Count -eq 0) { continue }
            $buf = New-Object byte[] 2048
            $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $refEp = [System.Net.EndPoint] $remote
            $n = $s.ReceiveFrom($buf, [ref] $refEp)
            if ($n -le 0) { continue }
            $srcIp = ([System.Net.IPEndPoint] $refEp).Address.ToString()
            $reply = Parse-EnipHeader ([byte[]]($buf[0..($n - 1)]))
            $info = Parse-EnipIdentityReply $reply
            if ($info) { $found[$srcIp] = $info }
        }
    } catch { Write-Bad ("Discovery failed: " + $_.Exception.Message) }
    finally { try { $s.Close() } catch { } }
    Write-Head ("--- EtherNet/IP Discovery Results (" + $found.Count + " device(s)) ---")
    if ($found.Count -eq 0) { Write-Body "  (no replies - UDP 44818 filtered or no EtherNet/IP devices present)" }
    foreach ($ip in ($found.Keys | Sort-Object { Get-IpSortKey $_ })) {
        $info = $found[$ip]
        Write-Body ("  " + $ip + "   " + $info.ProductName)
        Show-EnipIdentity $info $ip $Port
    }
    Write-Body "--- end ---"
}
function Invoke-EnipRecon {
    param([string] $Ip, [int] $Port)
    $BAR = "=" * 60
    Write-Host ""; Write-Body $BAR; Write-Body " EtherNet/IP RECON OVERVIEW"; Write-Body $BAR
    Write-Body (" Target     : " + $Ip + ":" + $Port)
    Write-Body (" Timestamp  : " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
    [void](Invoke-EnipListIdentity $Ip $Port)
    Invoke-EnipListServices $Ip $Port
    Write-Body $BAR
}
function Invoke-EnipModule {
    param([string] $DefaultIp)
    $ip = $DefaultIp
    if (-not $ip) { $ip = (Read-Host "Enter target EtherNet/IP device IP (blank for UDP discovery)").Trim() }
    if ($ip -and -not (Test-ValidTarget $ip)) { Write-Bad ("'" + $ip + "' is not a valid IP address or resolvable hostname."); return }
    $portIn = (Read-Host ("EtherNet/IP port [" + $script:EnipDefaultPort + "]")).Trim()
    $port = $script:EnipDefaultPort
    if ($portIn) { try { $port = [int] $portIn } catch { } }
    if ($script:SafeMode) { Write-Info "Read-Only Mode (EtherNet/IP module identifies/enumerates only)" }
    while ($true) {
        Write-MenuTitle "EtherNet/IP (CIP) Menu"
        $tgt = $ip; if (-not $tgt) { $tgt = "(none - use discovery)" }
        Write-Body ("    Target: " + $tgt + ":" + $port)
        Write-Body "1. Recon overview (ListIdentity + ListServices)"
        Write-Body "2. ListIdentity (vendor / product / revision / serial / state)"
        Write-Body "3. ListServices (CIP-over-TCP/UDP support)"
        Write-Body "4. ListInterfaces"
        Write-Body "5. Register session (confirm explicit messaging)"
        Write-Body "6. UDP discovery (ListIdentity broadcast - like BACnet Who-Is)"
        Write-Body "7. Change target IP"
        Write-Body "8. Back to main menu"
        $choice = (Read-Host "`nSelect an option").Trim()
        try {
            if (@("1", "2", "3", "4", "5") -contains $choice -and -not $ip) { Write-Warn2 "No target IP set. Use option 7, or option 6 for discovery."; continue }
            if ($choice -eq "1") { Invoke-EnipRecon $ip $port }
            elseif ($choice -eq "2") { [void](Invoke-EnipListIdentity $ip $port) }
            elseif ($choice -eq "3") { Invoke-EnipListServices $ip $port }
            elseif ($choice -eq "4") { Invoke-EnipListInterfaces $ip $port }
            elseif ($choice -eq "5") { Invoke-EnipRegisterSession $ip $port }
            elseif ($choice -eq "6") { $t = (Read-Host "Broadcast/target for discovery [255.255.255.255]").Trim(); Invoke-EnipDiscover $port $t }
            elseif ($choice -eq "7") { $ip = (Read-Host "Target EtherNet/IP device IP").Trim(); Write-Info ("Target set to " + $ip) }
            elseif ($choice -eq "8") { break }
            else { Write-Body "Invalid option." }
        } catch { Write-Bad ("Operation failed: " + $_.Exception.Message); Write-LogLine ("ENIP_ERROR " + $_.Exception.Message) }
    }
}

# ============================================================
#  DNP3 MODULE (raw sockets, TCP/20000)
# ============================================================
# Builds the DNP3 (IEEE 1815) link frame with its header + per-block CRC, the
# transport header and the application READ request, then parses the reply far
# enough for recon: link status, IIN flags, best-effort object summary. Reads
# only (integrity/class polls, targeted object reads); no control/operate.
$script:Dnp3DefaultPort = 20000
$script:Dnp3Iin1 = @("Broadcast msg rx", "Class 1 events", "Class 2 events", "Class 3 events", "Need time", "Local control", "Device trouble", "Device restart")
$script:Dnp3Iin2 = @("Function not supported", "Object unknown", "Parameter error", "Buffer overflow", "Already executing", "Config corrupt", "Reserved(6)", "Reserved(7)")
$script:Dnp3GroupNames = @{
    1 = "Binary Input"; 2 = "Binary Input Event"; 3 = "Double-bit Input"; 10 = "Binary Output";
    12 = "Binary Output Command"; 20 = "Counter"; 21 = "Frozen Counter"; 22 = "Counter Event";
    30 = "Analog Input"; 32 = "Analog Input Event"; 40 = "Analog Output Status"; 41 = "Analog Output Command";
    50 = "Time and Date"; 60 = "Class Data"; 70 = "File Transfer"; 80 = "Internal Indications"; 110 = "Octet String"
}

function Get-Dnp3Crc {
    param([byte[]] $Data)
    [int] $crc = 0
    foreach ($b in $Data) {
        [int] $crc = $crc -bxor ([int] $b)
        for ($i = 0; $i -lt 8; $i++) {
            if (($crc -band 1) -ne 0) { [int] $crc = ([int][math]::Floor($crc / 2)) -bxor 0xA6BC }
            else { [int] $crc = [int][math]::Floor($crc / 2) }
        }
    }
    [int] $crc = ($crc -bxor 0xFFFF) -band 0xFFFF
    [int] $lo = $crc -band 0xFF
    [int] $hi = ([int][math]::Floor($crc / 256)) -band 0xFF
    return ,([byte[]]@($lo, $hi))
}
function Add-Dnp3BlockCrcs {
    param([byte[]] $User)
    $out = @()
    for ($i = 0; $i -lt $User.Length; $i += 16) {
        $end = [math]::Min($i + 16, $User.Length)
        $block = $User[$i..($end - 1)]
        $out += [byte[]] $block
        $out += [byte[]](Get-Dnp3Crc ([byte[]] $block))
    }
    return ,([byte[]] $out)
}
function Build-Dnp3Frame {
    param([int] $Dest, [int] $Src, [int] $Ctrl, [byte[]] $User = $null)
    if (-not $User) { $User = New-Object byte[] 0 }
    $length = 5 + $User.Length
    $header = [byte[]]@(0x05, 0x64, ($length -band 0xFF), $Ctrl, ($Dest -band 0xFF), (([int][math]::Floor($Dest / 256)) -band 0xFF), ($Src -band 0xFF), (([int][math]::Floor($Src / 256)) -band 0xFF))
    $frame = [byte[]]($header + [byte[]](Get-Dnp3Crc $header))
    if ($User.Length -gt 0) { $frame += [byte[]](Add-Dnp3BlockCrcs $User) }
    return ,([byte[]] $frame)
}
function Build-Dnp3AppRead {
    param($Objects, [int] $Seq)
    $appCtrl = 0xC0 -bor ($Seq -band 0x0F)
    $frag = [byte[]]@($appCtrl, 0x01)
    foreach ($o in $Objects) { $frag += [byte[]]@($o[0], $o[1], $o[2]) }
    $transport = [byte[]]@(0xC0 -bor ($Seq -band 0x3F))
    return ,([byte[]]($transport + $frag))
}
function Recv-Dnp3 {
    param($Stream, [int] $FirstTimeoutMs = 4000, [int] $GapMs = 400)
    $chunks = New-Object System.Collections.ArrayList
    $buf = New-Object byte[] 4096
    $Stream.ReadTimeout = $FirstTimeoutMs
    try { $n = $Stream.Read($buf, 0, 4096); if ($n -le 0) { return (New-Object byte[] 0) }; [void] $chunks.Add($buf[0..($n - 1)]) } catch { return (New-Object byte[] 0) }
    $Stream.ReadTimeout = $GapMs
    while ($true) {
        try { $n = $Stream.Read($buf, 0, 4096); if ($n -le 0) { break }; [void] $chunks.Add($buf[0..($n - 1)]) } catch { break }
    }
    $total = 0; foreach ($c in $chunks) { $total += $c.Length }
    $out = New-Object byte[] $total
    $pos = 0
    foreach ($c in $chunks) { [array]::Copy([byte[]] $c, 0, $out, $pos, $c.Length); $pos += $c.Length }
    return ,$out
}
function Parse-Dnp3Frames {
    param([byte[]] $Raw)
    $frames = @()
    $i = 0
    while (($i + 10) -le $Raw.Length) {
        if ($Raw[$i] -ne 0x05 -or $Raw[$i + 1] -ne 0x64) { $i++; continue }
        $length = [int] $Raw[$i + 2]
        $ctrl = [int] $Raw[$i + 3]
        $dest = Get-U16LE $Raw ($i + 4)
        $src = Get-U16LE $Raw ($i + 6)
        $userLen = $length - 5; if ($userLen -lt 0) { $userLen = 0 }
        $nblocks = [int][math]::Floor(($userLen + 15) / 16)
        $frameLen = 10 + $userLen + $nblocks * 2
        $region = New-Object byte[] 0
        $regEnd = [math]::Min($i + $frameLen, $Raw.Length)
        if (($i + 10) -lt $regEnd) { $region = $Raw[($i + 10)..($regEnd - 1)] }
        $userBytes = New-Object System.Collections.ArrayList
        $userRemaining = $userLen
        $bi = 0
        while ($userRemaining -gt 0 -and $bi -lt $region.Length) {
            $d = [math]::Min(16, $userRemaining)
            for ($j = 0; $j -lt $d -and ($bi + $j) -lt $region.Length; $j++) { [void] $userBytes.Add($region[$bi + $j]) }
            $bi += $d + 2
            $userRemaining -= $d
        }
        $u = New-Object byte[] $userBytes.Count
        for ($k = 0; $k -lt $userBytes.Count; $k++) { $u[$k] = [byte] $userBytes[$k] }
        $f = New-Object PSObject
        $f | Add-Member NoteProperty Ctrl $ctrl
        $f | Add-Member NoteProperty Dest $dest
        $f | Add-Member NoteProperty Src $src
        $f | Add-Member NoteProperty User ([byte[]] $u)
        $frames += $f
        if ($frameLen -gt 0) { $i += $frameLen } else { $i++ }
    }
    return ,$frames
}
function Decode-Dnp3Iin {
    param([int] $Iin1, [int] $Iin2)
    $flags = @()
    for ($bit = 0; $bit -lt 8; $bit++) { if ($Iin1 -band $script:BitMasks[$bit]) { $flags += $script:Dnp3Iin1[$bit] } }
    for ($bit = 0; $bit -lt 8; $bit++) { if ($Iin2 -band $script:BitMasks[$bit]) { $flags += $script:Dnp3Iin2[$bit] } }
    return $flags
}
function Join-Dnp3App {
    param($Frames)
    $app = @()
    foreach ($f in $Frames) { if ($f.User.Length -gt 1) { $app += [byte[]]($f.User[1..($f.User.Length - 1)]) } }
    return ,([byte[]] $app)
}
function Send-Dnp3Request {
    param([string] $Ip, [int] $Port, [int] $Dest, [int] $Src, $Objects, [string] $Label)
    $seq = Get-Random -Minimum 0 -Maximum 16
    $user = Build-Dnp3AppRead $Objects $seq
    $frame = Build-Dnp3Frame $Dest $Src 0xC4 $user
    $client = New-Object System.Net.Sockets.TcpClient
    $raw = New-Object byte[] 0
    try {
        $iar = $client.BeginConnect($Ip, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne(4000, $false)
        if (-not ($ok -and $client.Connected)) { try { $client.Close() } catch { }; Write-Bad ("DNP3 " + $Label + " failed: connect"); return $null }
        $client.EndConnect($iar)
        $st = $client.GetStream()
        $st.Write($frame, 0, $frame.Length); $st.Flush()
        $raw = Recv-Dnp3 $st
        $client.Close()
    } catch { try { $client.Close() } catch { }; Write-Bad ("DNP3 " + $Label + " failed: " + $_.Exception.Message); return $null }
    if (-not $raw -or $raw.Length -eq 0) { Write-Bad ("No DNP3 response to " + $Label + "."); return $null }
    $o = New-Object PSObject
    $o | Add-Member NoteProperty Raw ([byte[]] $raw)
    $o | Add-Member NoteProperty Frames (Parse-Dnp3Frames ([byte[]] $raw))
    return $o
}
function Invoke-Dnp3LinkStatus {
    param([string] $Ip, [int] $Port, [int] $Dest, [int] $Src)
    $frame = Build-Dnp3Frame $Dest $Src 0xC9
    Write-Head ("[DNP3 Link Status] " + $Ip + ":" + $Port + "  outstation=" + $Dest + " master=" + $Src)
    $client = New-Object System.Net.Sockets.TcpClient
    $raw = New-Object byte[] 0
    try {
        $iar = $client.BeginConnect($Ip, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne(4000, $false)
        if (-not ($ok -and $client.Connected)) { try { $client.Close() } catch { }; Write-Body " (link status failed: connect)"; return }
        $client.EndConnect($iar)
        $st = $client.GetStream()
        $st.Write($frame, 0, $frame.Length); $st.Flush()
        $raw = Recv-Dnp3 $st
        $client.Close()
    } catch { try { $client.Close() } catch { }; Write-Body (" (link status failed: " + $_.Exception.Message + ")"); return }
    if (-not $raw -or $raw.Length -eq 0) { Write-Body " (no reply - port open but no DNP3 link response)"; return }
    $frames = Parse-Dnp3Frames ([byte[]] $raw)
    if ($frames.Count -eq 0) { Write-Body (" (reply not a valid DNP3 frame; raw " + $raw.Length + " bytes)"); return }
    foreach ($f in $frames) {
        $func = $f.Ctrl -band 0x0F
        Write-Body (" Reply: outstation=" + $f.Src + " -> master=" + $f.Dest + "  link-func=" + $func)
        if ($func -eq 0x0B) { Write-Body "        (0x0B = Link Status)" }
        elseif ($func -eq 0x00) { Write-Body "        (0x00 = ACK / reset confirm)" }
    }
    Write-Ok ($Ip + " answered DNP3 on the link layer - confirmed outstation.")
    $ph = @{}; $ph[$Port] = "DNP3"
    Update-Asset -IPAddr $Ip -Ports $ph -Protocol "DNP3" -Version ("DNP3: confirmed outstation (addr " + $Dest + ")") -Source "DNP3"
}
function Show-Dnp3Response {
    param([byte[]] $Raw, $Frames, [string] $Label)
    if ($Frames.Count -eq 0) { Write-Body (" (no parseable DNP3 frames; raw " + $Raw.Length + " bytes)"); return }
    $app = Join-Dnp3App $Frames
    if ($app.Length -lt 4) { Write-Body " (response too short to contain an application header)"; return }
    $func = [int] $app[1]; $iin1 = [int] $app[2]; $iin2 = [int] $app[3]
    Write-Head ("--- DNP3 Response: " + $Label + " ---")
    $ftag = ""; if ($func -eq 0x81) { $ftag = "  (response)" } elseif ($func -eq 0x82) { $ftag = "  (unsolicited)" }
    Write-Body (" App control : 0x" + ("{0:x2}" -f [int] $app[0]) + "   Function: 0x" + ("{0:x2}" -f $func) + $ftag)
    $flags = Decode-Dnp3Iin $iin1 $iin2
    Write-Body (" IIN         : 0x" + ("{0:x2}" -f $iin1) + ("{0:x2}" -f $iin2))
    if ($flags.Count -gt 0) { foreach ($fl in $flags) { Write-Body ("    - " + $fl) } } else { Write-Body "    (no IIN flags set)" }
    $obj = New-Object byte[] 0
    if ($app.Length -gt 4) { $obj = $app[4..($app.Length - 1)] }
    if ($obj.Length -gt 0) { Write-Body (" Object data : " + $obj.Length + " bytes"); Show-Dnp3Objects ([byte[]] $obj) }
    else { Write-Body " Object data : (none returned)" }
    Write-Body "--- end ---"
}
function Show-Dnp3Objects {
    param([byte[]] $Obj)
    $i = 0
    $printed = $false
    while (($i + 3) -le $Obj.Length) {
        $grp = [int] $Obj[$i]; $var = [int] $Obj[$i + 1]; $qual = [int] $Obj[$i + 2]; $i += 3
        $name = ("Group " + $grp); if ($script:Dnp3GroupNames.ContainsKey($grp)) { $name = $script:Dnp3GroupNames[$grp] }
        $qf = $qual -band 0x0F
        $count = $null; $rng = ""
        if ($qf -eq 0x00 -and ($i + 2) -le $Obj.Length) { $start = [int] $Obj[$i]; $stop = [int] $Obj[$i + 1]; $i += 2; $count = $stop - $start + 1; $rng = " points " + $start + "-" + $stop }
        elseif ($qf -eq 0x01 -and ($i + 4) -le $Obj.Length) { $start = Get-U16LE $Obj $i; $stop = Get-U16LE $Obj ($i + 2); $i += 4; $count = $stop - $start + 1; $rng = " points " + $start + "-" + $stop }
        elseif ($qf -eq 0x07 -and ($i + 1) -le $Obj.Length) { $count = [int] $Obj[$i]; $i += 1; $rng = " count " + $count }
        elseif ($qf -eq 0x08 -and ($i + 2) -le $Obj.Length) { $count = Get-U16LE $Obj $i; $i += 2; $rng = " count " + $count }
        Write-Body ("    g" + $grp + " v" + $var + " (" + $name + ") qual=0x" + ("{0:x2}" -f $qual) + $rng)
        $printed = $true
        if ($count -eq $null) { break }
        $per = @{ 1 = 0; 10 = 0; 20 = 4; 30 = 4; 32 = 4; 40 = 4 }
        if ($per.ContainsKey($grp) -and $per[$grp] -gt 0) { $i += $per[$grp] * $count } else { break }
    }
    if (-not $printed) { Write-Body (Format-HexDump $Obj) }
}
function Invoke-Dnp3Module {
    param([string] $DefaultIp)
    $ip = $DefaultIp
    if (-not $ip) { $ip = (Read-Host "Enter target DNP3 outstation IP").Trim() }
    if (-not $ip) { Write-Bad "No IP provided."; return }
    if (-not (Test-ValidTarget $ip)) { Write-Bad ("'" + $ip + "' is not a valid IP address or resolvable hostname."); return }
    $portIn = (Read-Host ("DNP3 port [" + $script:Dnp3DefaultPort + "]")).Trim()
    $port = $script:Dnp3DefaultPort; if ($portIn) { try { $port = [int] $portIn } catch { } }
    $dest = 1024; $src = 1
    try { $dest = [int] ((Read-Host "Outstation (destination) DNP3 address [1024]").Trim()); $src = [int] ((Read-Host "Master (source) DNP3 address [1]").Trim()) } catch { }
    if (-not $dest) { $dest = 1024 }; if (-not $src) { $src = 1 }
    Write-Info ("DNP3 target " + $ip + ":" + $port + "  outstation=" + $dest + " master=" + $src)
    Invoke-Dnp3LinkStatus $ip $port $dest $src
    while ($true) {
        Write-MenuTitle "DNP3 (IEEE 1815) Menu"
        Write-Body ("    Target: " + $ip + ":" + $port + "  outstation=" + $dest + " master=" + $src)
        Write-Body "1. Request link status (confirm outstation)"
        Write-Body "2. Integrity poll (Class 1/2/3/0)"
        Write-Body "3. Class 0 poll (static data)"
        Write-Body "4. Read a specific object group/variation"
        Write-Body "5. Change addresses"
        Write-Body "6. Back to main menu"
        $choice = (Read-Host "`nSelect an option").Trim()
        try {
            if ($choice -eq "1") { Invoke-Dnp3LinkStatus $ip $port $dest $src }
            elseif ($choice -eq "2") {
                $objs = @(@(60, 2, 0x06), @(60, 3, 0x06), @(60, 4, 0x06), @(60, 1, 0x06))
                $res = Send-Dnp3Request $ip $port $dest $src $objs "integrity poll"
                if ($res) { Show-Dnp3Response $res.Raw $res.Frames "integrity poll (Class 1/2/3/0)" }
            }
            elseif ($choice -eq "3") {
                $res = Send-Dnp3Request $ip $port $dest $src @(@(60, 1, 0x06)) "Class 0 poll"
                if ($res) { Show-Dnp3Response $res.Raw $res.Frames "Class 0 poll" }
            }
            elseif ($choice -eq "4") {
                $grp = [int] (Read-Host "Object group (e.g. 1=BI, 30=AI, 20=Counter)")
                $var = [int] ((Read-Host "Variation (0 = any)").Trim())
                $res = Send-Dnp3Request $ip $port $dest $src @(@($grp, $var, 0x06)) ("read g" + $grp + " v" + $var)
                if ($res) { Show-Dnp3Response $res.Raw $res.Frames ("read g" + $grp + " v" + $var) }
            }
            elseif ($choice -eq "5") {
                $dest = [int] ((Read-Host "Outstation (destination) address [1024]").Trim()); if (-not $dest) { $dest = 1024 }
                $src = [int] ((Read-Host "Master (source) address [1]").Trim()); if (-not $src) { $src = 1 }
                Write-Info "Addresses updated."
            }
            elseif ($choice -eq "6") { break }
            else { Write-Body "Invalid option." }
        } catch { Write-Bad ("Operation failed: " + $_.Exception.Message); Write-LogLine ("DNP3_ERROR " + $_.Exception.Message) }
    }
}
# ============================================================
#  BACnet/IP MODULE (raw sockets, UDP/47808)
# ============================================================
# Who-Is broadcast + I-Am parse, and ReadProperty for device-object properties.
# Discovery/read only. Reference: ASHRAE 135.
$script:BacnetDefaultPort = 47808
$script:BacnetVendors = @{
    0 = "ASHRAE"; 2 = "Andover Controls"; 3 = "Automated Logic (ALC)"; 5 = "Johnson Controls";
    8 = "Delta Controls"; 10 = "Schneider Electric (TAC)"; 24 = "Siemens"; 36 = "Alerton";
    42 = "Trane"; 50 = "Honeywell"; 58 = "KMC Controls"; 260 = "Distech Controls"; 385 = "Reliable Controls"
}

function New-BacnetSocket {
    param([int] $Port)
    $s = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
    $s.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::Broadcast, $true)
    try { $s.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true); $s.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0))) } catch { }
    return $s
}
function Build-BacnetWhois {
    $apdu = [byte[]]@(0x10, 0x08)
    $npdu = [byte[]]@(0x01, 0x00)
    $body = $npdu + $apdu
    $total = $body.Length + 4
    $bvlc = [byte[]]@(0x81, 0x0B, (Get-HiByte $total), (Get-LoByte $total))
    return ,([byte[]]($bvlc + $body))
}
function Parse-BacnetIam {
    param([byte[]] $Data, [string] $SrcIp, [int] $SrcPort)
    if ($Data.Length -lt 6 -or $Data[0] -ne 0x81) { return $null }
    $npduCtrl = [int] $Data[5]
    $idx = 6
    if ($npduCtrl -band 0x20) { $idx += 3; if ($idx -lt $Data.Length) { $idx += [int] $Data[$idx - 1] } }
    if ($npduCtrl -band 0x08) { $idx += 3; if ($idx -le $Data.Length) { $idx += [int] $Data[$idx - 1] } }
    if ($npduCtrl -band 0x20) { $idx += 1 }
    if (($idx + 2) -gt $Data.Length) { return $null }
    $apdu = $Data[$idx..($Data.Length - 1)]
    if ($apdu.Length -lt 2 -or $apdu[0] -ne 0x10 -or $apdu[1] -ne 0x00) { return $null }
    $p = 2
    $res = New-Object PSObject
    $res | Add-Member NoteProperty Address $SrcIp
    $res | Add-Member NoteProperty DeviceInstance $null
    $res | Add-Member NoteProperty MaxApdu "?"
    $res | Add-Member NoteProperty Segmentation "?"
    $res | Add-Member NoteProperty VendorId $null
    if ($apdu[$p] -eq 0xC4 -and ($p + 5) -le $apdu.Length) {
        $val = Get-U32BE $apdu ($p + 1)
        $res.DeviceInstance = [long]($val -band 0x3FFFFF)
        $p += 5
    }
    if ($p -lt $apdu.Length) {
        $tag = [int] $apdu[$p]; $ln = $tag -band 0x07
        if (($tag -band 0xF0) -eq 0x20 -and ($p + 1 + $ln) -le $apdu.Length) {
            $n = 0; for ($i = 0; $i -lt $ln; $i++) { $n = $n * 256 + [int] $apdu[$p + 1 + $i] }
            $res.MaxApdu = $n; $p += 1 + $ln
        }
    }
    if ($p -lt $apdu.Length -and $apdu[$p] -eq 0x91 -and ($p + 1) -lt $apdu.Length) {
        $seg = [int] $apdu[$p + 1]
        $segMap = @{ 0 = "both"; 1 = "transmit"; 2 = "receive"; 3 = "none" }
        if ($segMap.ContainsKey($seg)) { $res.Segmentation = $segMap[$seg] } else { $res.Segmentation = $seg }
        $p += 2
    }
    if ($p -lt $apdu.Length) {
        $tag = [int] $apdu[$p]; $ln = $tag -band 0x07
        if (($tag -band 0xF0) -eq 0x20 -and ($p + 1 + $ln) -le $apdu.Length) {
            $n = 0; for ($i = 0; $i -lt $ln; $i++) { $n = $n * 256 + [int] $apdu[$p + 1 + $i] }
            $res.VendorId = $n
        }
    }
    return $res
}
function Invoke-BacnetWhois {
    param([int] $Port, [string] $Target, [int] $TimeoutMs = 3000)
    $dest = $Target; if (-not $dest) { $dest = "255.255.255.255" }
    Write-Head ("Sending BACnet Who-Is to " + $dest + ":" + $Port + " (listening " + ([int]($TimeoutMs / 1000)) + "s)...")
    $pkt = Build-BacnetWhois
    $found = @{}
    $s = New-BacnetSocket $Port
    try {
        [void] $s.SendTo($pkt, (New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($dest), $Port)))
        $end = (Get-Date).AddMilliseconds($TimeoutMs)
        while ((Get-Date) -lt $end) {
            $rl = New-Object System.Collections.ArrayList; [void] $rl.Add($s)
            [System.Net.Sockets.Socket]::Select($rl, $null, $null, 500000)
            if ($rl.Count -eq 0) { continue }
            $buf = New-Object byte[] 1500
            $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $refEp = [System.Net.EndPoint] $remote
            $n = $s.ReceiveFrom($buf, [ref] $refEp)
            if ($n -le 0) { continue }
            $srcIp = ([System.Net.IPEndPoint] $refEp).Address.ToString()
            $info = Parse-BacnetIam ([byte[]]($buf[0..($n - 1)])) $srcIp $Port
            if ($info -and $info.DeviceInstance -ne $null) { $found[($srcIp + "#" + $info.DeviceInstance)] = $info }
        }
    } catch { Write-Bad ("Who-Is failed: " + $_.Exception.Message) }
    finally { try { $s.Close() } catch { } }
    Write-Head ("--- BACnet Who-Is Results (" + $found.Count + " device(s)) ---")
    if ($found.Count -eq 0) { Write-Body "  (no I-Am replies - UDP 47808 filtered or no BACnet devices present)" }
    foreach ($k in $found.Keys) {
        $info = $found[$k]
        $vid = $info.VendorId
        $vname = "unknown vendor"
        if ($vid -ne $null -and $script:BacnetVendors.ContainsKey([int] $vid)) { $vname = $script:BacnetVendors[[int] $vid] }
        Write-Body ("  Device " + $info.DeviceInstance + "  @ " + $info.Address)
        Write-Body ("      Vendor      : " + $vid + " (" + $vname + ")")
        Write-Body ("      Max APDU    : " + $info.MaxApdu)
        Write-Body ("      Segmentation: " + $info.Segmentation)
        $ph = @{}; $ph[$script:BacnetDefaultPort] = "BACnet/IP"
        $vn = ""; if ($vname -ne "unknown vendor") { $vn = $vname }
        Update-Asset -IPAddr $info.Address -Ports $ph -Protocol "BACnet/IP" -Vendor $vn -Version ("BACnet device instance " + $info.DeviceInstance + ", vendor " + $vid + " (" + $vname + ")") -Source "BACnet"
    }
    Write-Body "--- end ---"
}
function Build-BacnetReadProp {
    param([long] $DeviceInstance, [int] $PropId, [int] $Invoke = 1)
    $apdu = [byte[]]@(0x00, 0x05, ($Invoke -band 0xFF), 0x0C)
    $obj = (8 * 4194304) + ($DeviceInstance -band 0x3FFFFF)   # (8<<22) | instance
    $apdu += [byte[]]@(0x0C) + [byte[]](ConvertTo-BytesBE $obj 4)
    $apdu += [byte[]]@(0x19, ($PropId -band 0xFF))
    $npdu = [byte[]]@(0x01, 0x04)
    $body = $npdu + $apdu
    $total = $body.Length + 4
    $bvlc = [byte[]]@(0x81, 0x0A, (Get-HiByte $total), (Get-LoByte $total))
    return ,([byte[]]($bvlc + $body))
}
function Parse-BacnetReadProp {
    param([byte[]] $Data)
    if ($Data.Length -lt 6 -or $Data[0] -ne 0x81) { return $null }
    $p = 6
    if ($p -ge $Data.Length) { return $null }
    $apdu = $Data[$p..($Data.Length - 1)]
    if ($apdu.Length -lt 1 -or (($apdu[0] -band 0xF0) -ne 0x30)) { return $null }
    $oi = -1; $oc = -1
    for ($i = 0; $i -lt $apdu.Length; $i++) { if ($apdu[$i] -eq 0x3E) { $oi = $i; break } }
    for ($i = $apdu.Length - 1; $i -ge 0; $i--) { if ($apdu[$i] -eq 0x3F) { $oc = $i; break } }
    if ($oi -eq -1 -or $oc -le $oi) { return $null }
    $value = $apdu[($oi + 1)..($oc - 1)]
    if ($value.Length -lt 1) { return $null }
    $tag = [int] $value[0]
    $tnum = [int][math]::Floor(($tag -band 0xF0) / 16)
    $ln = $tag -band 0x07
    $vbytes = @()
    if ($ln -lt 5) { if (($ln) -gt 0 -and (1 + $ln) -le $value.Length) { $vbytes = $value[1..$ln] } }
    else { if ($value.Length -ge 2) { $el = [int] $value[1]; if ((2 + $el) -le $value.Length -and $el -gt 0) { $vbytes = $value[2..(1 + $el)] } } }
    $vbytes = [byte[]] $vbytes
    if ($tnum -eq 7) { if ($vbytes.Length -gt 1) { try { return ([System.Text.Encoding]::ASCII.GetString($vbytes[1..($vbytes.Length - 1)])).Replace([string][char] 0, "") } catch { return "" } }; return "" }
    if ($tnum -eq 2 -or $tnum -eq 9) { $n = 0; foreach ($b in $vbytes) { $n = $n * 256 + [int] $b }; return ("" + $n) }
    $hex = ""; foreach ($b in $vbytes) { $hex += ("{0:x2}" -f [int] $b) }
    return $hex
}
function Invoke-BacnetReadDevice {
    param([int] $Port)
    $ip = (Read-Host "Device IP").Trim()
    if (-not $ip) { Write-Bad "No IP provided."; return }
    if (-not (Test-ValidTarget $ip)) { Write-Bad ("'" + $ip + "' is not a valid IP address or resolvable hostname."); return }
    $inst = 0
    try { $inst = [int] (Read-Host "Device instance number") } catch { Write-Bad "Invalid instance."; return }
    $props = @(@(77, "Object Name"), @(121, "Vendor Name"), @(70, "Model Name"), @(44, "Firmware Rev"), @(12, "App SW Version"))
    Write-Head ("--- BACnet Device " + $inst + " @ " + $ip + " ---")
    $s = New-BacnetSocket $Port
    $collected = @(); $vendor = ""
    try {
        $i = 1
        foreach ($pr in $props) {
            $pid = $pr[0]; $label = $pr[1]
            try {
                $pkt = Build-BacnetReadProp $inst $pid $i
                [void] $s.SendTo($pkt, (New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($ip), $Port)))
                $rl = New-Object System.Collections.ArrayList; [void] $rl.Add($s)
                [System.Net.Sockets.Socket]::Select($rl, $null, $null, 2500000)
                if ($rl.Count -eq 0) { Write-Body (" " + $label.PadRight(14) + ": (timeout)"); $i++; continue }
                $buf = New-Object byte[] 1500
                $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $refEp = [System.Net.EndPoint] $remote
                $n = $s.ReceiveFrom($buf, [ref] $refEp)
                $val = $null
                if ($n -gt 0) { $val = Parse-BacnetReadProp ([byte[]]($buf[0..($n - 1)])) }
                $disp = "(no/unparsed reply)"; if ($val -ne $null) { $disp = $val }
                Write-Body (" " + $label.PadRight(14) + ": " + $disp)
                if ($val -ne $null -and ("" + $val) -ne "") { $collected += ($label + "=" + $val); if ($label -eq "Vendor Name") { $vendor = "" + $val } }
            } catch { Write-Body (" " + $label.PadRight(14) + ": (error: " + $_.Exception.Message + ")") }
            $i++
        }
        if ($collected.Count -gt 0) {
            $ph = @{}; $ph[$Port] = "BACnet/IP"
            Update-Asset -IPAddr $ip -Ports $ph -Protocol "BACnet/IP" -Vendor $vendor -Version ("BACnet device " + $inst + ": " + ($collected -join "; ")) -Source "BACnet"
        }
    } finally { try { $s.Close() } catch { } }
    Write-Body "--- end ---"
}
function Invoke-BacnetModule {
    param([string] $DefaultIp)
    $portIn = (Read-Host ("BACnet/IP port [" + $script:BacnetDefaultPort + "]")).Trim()
    $port = $script:BacnetDefaultPort; if ($portIn) { try { $port = [int] $portIn } catch { } }
    if ($script:SafeMode) { Write-Info "Read-Only Mode (BACnet module discovers/reads only)" }
    while ($true) {
        Write-MenuTitle "BACnet/IP Menu"
        Write-Body "1. Who-Is broadcast (discover all devices on the subnet)"
        Write-Body "2. Who-Is to a specific IP/subnet-broadcast"
        Write-Body "3. Read device properties (name/vendor/model/firmware)"
        Write-Body "4. Back to main menu"
        $choice = (Read-Host "`nSelect an option").Trim()
        try {
            if ($choice -eq "1") { Invoke-BacnetWhois $port "" }
            elseif ($choice -eq "2") { $t = (Read-Host "Target IP or broadcast (e.g. 10.0.0.255)").Trim(); Invoke-BacnetWhois $port $t }
            elseif ($choice -eq "3") { Invoke-BacnetReadDevice $port }
            elseif ($choice -eq "4") { break }
            else { Write-Body "Invalid option." }
        } catch { Write-Bad ("Operation failed: " + $_.Exception.Message); Write-LogLine ("BACNET_ERROR " + $_.Exception.Message) }
    }
}

# ============================================================
#  SNMP MODULE (raw BER, UDP/161, v1/v2c)
# ============================================================
$script:SnmpDefaultPort = 161
$script:SnmpSummaryOids = @(
    @("Description", "1.3.6.1.2.1.1.1.0"), @("Name", "1.3.6.1.2.1.1.5.0"),
    @("Location", "1.3.6.1.2.1.1.6.0"), @("Contact", "1.3.6.1.2.1.1.4.0"),
    @("Uptime", "1.3.6.1.2.1.1.3.0"), @("Object ID", "1.3.6.1.2.1.1.2.0")
)
$script:SnmpSysObjectId = "1.3.6.1.2.1.1.2.0"
$script:SnmpEnterpriseNames = @{
    2 = "IBM"; 4 = "Unix"; 9 = "Cisco Systems"; 11 = "Hewlett-Packard"; 42 = "Sun Microsystems";
    43 = "3Com"; 63 = "Apple"; 111 = "Oracle"; 311 = "Microsoft"; 318 = "APC (Schneider Electric)";
    674 = "Dell"; 789 = "NetApp"; 2011 = "Huawei"; 2636 = "Juniper Networks"; 3375 = "F5 Networks";
    4526 = "Netgear"; 8072 = "net-snmp (Net-SNMP agent)"; 14988 = "MikroTik"; 25506 = "H3C";
    30065 = "Arista Networks"; 248 = "Hirschmann (Belden)"; 3833 = "Schneider Electric"; 4329 = "Siemens"
}

function Ber-Len {
    param([int] $N)
    if ($N -lt 128) { return ,([byte[]]@($N)) }
    if ($N -lt 256) { return ,([byte[]]@(0x81, $N)) }
    return ,([byte[]]@(0x82, ([int][math]::Floor($N / 256) -band 0xFF), ($N -band 0xFF)))
}
function Ber-Tlv {
    param([int] $Tag, [byte[]] $Value)
    return ,([byte[]]([byte[]]@($Tag) + [byte[]](Ber-Len $Value.Length) + $Value))
}
function Ber-Int {
    param([long] $V)
    $bytes = @()
    if ($V -eq 0) { $bytes = @(0) }
    else {
        $n = $V
        while ($n -gt 0) { $bytes = ,([int]($n -band 0xFF)) + $bytes; $n = [math]::Floor($n / 256) }
        if (($bytes[0] -band 0x80) -ne 0) { $bytes = ,0 + $bytes }
    }
    return ,(Ber-Tlv 0x02 ([byte[]] $bytes))
}
function ConvertTo-Base128 {
    param([long] $V)
    if ($V -eq 0) { return ,([byte[]]@(0)) }
    $stack = @()
    $n = $V
    while ($n -gt 0) { $stack = ,([int]($n -band 0x7F)) + $stack; $n = [math]::Floor($n / 128) }
    for ($i = 0; $i -lt $stack.Count - 1; $i++) { $stack[$i] = $stack[$i] -bor 0x80 }
    return ,([byte[]] $stack)
}
function Ber-OidEncode {
    param([string] $Oid)
    $arcs = @($Oid.TrimStart(".").Split(".") | ForEach-Object { [long] $_ })
    $body = @()
    $body += [byte[]](ConvertTo-Base128 (40 * $arcs[0] + $arcs[1]))
    for ($i = 2; $i -lt $arcs.Count; $i++) { $body += [byte[]](ConvertTo-Base128 $arcs[$i]) }
    return ,(Ber-Tlv 0x06 ([byte[]] $body))
}
function Decode-Oid {
    param([byte[]] $B)
    if ($B.Length -lt 1) { return "" }
    $arcs = @()
    $first = [int] $B[0]
    $arcs += [int][math]::Floor($first / 40)
    $arcs += ($first % 40)
    $i = 1
    $cur = 0
    while ($i -lt $B.Length) {
        $cur = $cur * 128 + ([int] $B[$i] -band 0x7F)
        if (-not ([int] $B[$i] -band 0x80)) { $arcs += $cur; $cur = 0 }
        $i++
    }
    return ($arcs -join ".")
}
function Read-BerTlv {
    param([byte[]] $B, [int] $Off)
    if ($Off -ge $B.Length) { return $null }
    $tag = [int] $B[$Off]; $p = $Off + 1
    if ($p -gt $B.Length) { return $null }
    $l = [int] $B[$p]; $p++
    if ($l -band 0x80) {
        $nb = $l -band 0x7F; $l = 0
        for ($i = 0; $i -lt $nb; $i++) { if ($p -ge $B.Length) { return $null }; $l = $l * 256 + [int] $B[$p]; $p++ }
    }
    $o = New-Object PSObject
    $o | Add-Member NoteProperty Tag $tag
    $o | Add-Member NoteProperty ValueOff $p
    $o | Add-Member NoteProperty Length $l
    $o | Add-Member NoteProperty Next ($p + $l)
    return $o
}
function Decode-SnmpValue {
    param([byte[]] $B, $Tlv)
    $tag = $Tlv.Tag; $off = $Tlv.ValueOff; $len = $Tlv.Length
    $v = @()
    if ($len -gt 0 -and ($off + $len) -le $B.Length) { $v = $B[$off..($off + $len - 1)] }
    $v = [byte[]] $v
    if ($tag -eq 0x02 -or $tag -eq 0x41 -or $tag -eq 0x42 -or $tag -eq 0x43 -or $tag -eq 0x46) {
        $n = 0; foreach ($bb in $v) { $n = $n * 256 + [int] $bb }
        if ($tag -eq 0x43) { return ("" + $n + " ticks (" + [math]::Round($n / 100.0, 2) + "s)") }
        return ("" + $n)
    }
    if ($tag -eq 0x04) {
        $txt = ""; try { $txt = [System.Text.Encoding]::ASCII.GetString($v) } catch { }
        if ($txt -match '^[\x09\x0a\x0d\x20-\x7e]*$') { return $txt.Replace([string][char] 0, "") }
        $hex = ""; foreach ($bb in $v) { $hex += ("{0:x2} " -f [int] $bb) }; return $hex.Trim()
    }
    if ($tag -eq 0x06) { return (Decode-Oid $v) }
    if ($tag -eq 0x40) { if ($v.Length -eq 4) { return ("" + [int] $v[0] + "." + [int] $v[1] + "." + [int] $v[2] + "." + [int] $v[3]) } }
    if ($tag -eq 0x05) { return "" }
    if ($tag -ge 0x80 -and $tag -le 0x82) { return "(no such object)" }
    $hex = ""; foreach ($bb in $v) { $hex += ("{0:x2} " -f [int] $bb) }; return $hex.Trim()
}
function Build-SnmpRequest {
    param([int] $Version, [string] $Community, [string] $Oid, [long] $ReqId, [int] $PduTag = 0xA0)
    $verT = Ber-Int $Version
    $commT = Ber-Tlv 0x04 ([System.Text.Encoding]::ASCII.GetBytes($Community))
    $vb = Ber-Tlv 0x30 ([byte[]]([byte[]](Ber-OidEncode $Oid) + [byte[]]@(0x05, 0x00)))
    $vblist = Ber-Tlv 0x30 ([byte[]] $vb)
    $pduBody = [byte[]]([byte[]](Ber-Int $ReqId) + [byte[]](Ber-Int 0) + [byte[]](Ber-Int 0) + [byte[]] $vblist)
    $pdu = Ber-Tlv $PduTag ([byte[]] $pduBody)
    $msg = Ber-Tlv 0x30 ([byte[]]([byte[]] $verT + [byte[]] $commT + [byte[]] $pdu))
    return ,([byte[]] $msg)
}
# Returns PSObject {Ok, Oid, Value} or {Ok=$false, Value=error}
function Invoke-SnmpQuery {
    param([string] $Ip, [int] $Port, [int] $Version, [string] $Community, [string] $Oid, [int] $PduTag = 0xA0, [int] $TimeoutMs = 2500)
    $reqId = Get-Random -Minimum 1 -Maximum 2000000000
    $pkt = Build-SnmpRequest $Version $Community $Oid $reqId $PduTag
    $s = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
    $o = New-Object PSObject
    $o | Add-Member NoteProperty Ok $false
    $o | Add-Member NoteProperty Oid ""
    $o | Add-Member NoteProperty Value ""
    try {
        $s.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)))
        [void] $s.SendTo($pkt, (New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($Ip), $Port)))
        $rl = New-Object System.Collections.ArrayList; [void] $rl.Add($s)
        [System.Net.Sockets.Socket]::Select($rl, $null, $null, ($TimeoutMs * 1000))
        if ($rl.Count -eq 0) { $o.Value = "timeout"; return $o }
        $buf = New-Object byte[] 65535
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $refEp = [System.Net.EndPoint] $remote
        $n = $s.ReceiveFrom($buf, [ref] $refEp)
        if ($n -le 0) { $o.Value = "no data"; return $o }
        $resp = $buf[0..($n - 1)]
    } catch { $o.Value = $_.Exception.Message; return $o }
    finally { try { $s.Close() } catch { } }
    # Decode: SEQ { version, community, PDU { reqid, errstat, erridx, vblist { vb { oid, value } } } }
    $seq = Read-BerTlv ([byte[]] $resp) 0
    if (-not $seq) { $o.Value = "malformed"; return $o }
    $p = $seq.ValueOff
    $verTlv = Read-BerTlv ([byte[]] $resp) $p; if (-not $verTlv) { $o.Value = "malformed"; return $o }; $p = $verTlv.Next
    $commTlv = Read-BerTlv ([byte[]] $resp) $p; if (-not $commTlv) { $o.Value = "malformed"; return $o }; $p = $commTlv.Next
    $pduTlv = Read-BerTlv ([byte[]] $resp) $p; if (-not $pduTlv) { $o.Value = "malformed"; return $o }
    $pp = $pduTlv.ValueOff
    $ridTlv = Read-BerTlv ([byte[]] $resp) $pp; if (-not $ridTlv) { $o.Value = "malformed"; return $o }; $pp = $ridTlv.Next
    $esTlv = Read-BerTlv ([byte[]] $resp) $pp; if (-not $esTlv) { $o.Value = "malformed"; return $o }
    $errStat = 0; if ($esTlv.Length -gt 0 -and ($esTlv.ValueOff + $esTlv.Length) -le $resp.Length) { foreach ($bb in $resp[$esTlv.ValueOff..($esTlv.ValueOff + $esTlv.Length - 1)]) { $errStat = $errStat * 256 + [int] $bb } }
    $pp = $esTlv.Next
    $eiTlv = Read-BerTlv ([byte[]] $resp) $pp; if (-not $eiTlv) { $o.Value = "malformed"; return $o }; $pp = $eiTlv.Next
    if ($errStat -ne 0) { $o.Value = "SNMP error-status " + $errStat; return $o }
    $vblistTlv = Read-BerTlv ([byte[]] $resp) $pp; if (-not $vblistTlv) { $o.Value = "malformed"; return $o }
    $vbTlv = Read-BerTlv ([byte[]] $resp) $vblistTlv.ValueOff; if (-not $vbTlv) { $o.Value = "malformed"; return $o }
    $oidTlv = Read-BerTlv ([byte[]] $resp) $vbTlv.ValueOff; if (-not $oidTlv) { $o.Value = "malformed"; return $o }
    $oidBytes = @(); if ($oidTlv.Length -gt 0) { $oidBytes = $resp[$oidTlv.ValueOff..($oidTlv.ValueOff + $oidTlv.Length - 1)] }
    $valTlv = Read-BerTlv ([byte[]] $resp) $oidTlv.Next; if (-not $valTlv) { $o.Value = "malformed"; return $o }
    $o.Ok = $true
    $o.Oid = Decode-Oid ([byte[]] $oidBytes)
    $o.Value = Decode-SnmpValue ([byte[]] $resp) $valTlv
    if ($valTlv.Tag -ge 0x80 -and $valTlv.Tag -le 0x82) { $o.Ok = $false; $o.Value = "end of MIB / no such object" }
    return $o
}
function Get-SnmpEnterprise {
    param([string] $Objid)
    $parts = @($Objid.TrimStart(".").Split("."))
    if ($parts.Count -gt 6 -and $parts[0] -eq "1" -and $parts[1] -eq "3" -and $parts[2] -eq "6" -and $parts[3] -eq "1" -and $parts[4] -eq "4" -and $parts[5] -eq "1") {
        $pen = 0
        if ([int]::TryParse($parts[6], [ref] $pen)) {
            if ($script:SnmpEnterpriseNames.ContainsKey($pen)) { return ($script:SnmpEnterpriseNames[$pen] + " (" + $pen + ")") }
            return ("" + $pen + " (unknown vendor - see IANA PEN registry)")
        }
    }
    return $Objid
}
function Get-SnmpVendorName {
    param([string] $Objid)
    $parts = @($Objid.TrimStart(".").Split("."))
    if ($parts.Count -gt 6 -and $parts[0] -eq "1" -and $parts[1] -eq "3" -and $parts[2] -eq "6" -and $parts[3] -eq "1" -and $parts[4] -eq "4" -and $parts[5] -eq "1") {
        $pen = 0
        if ([int]::TryParse($parts[6], [ref] $pen) -and $script:SnmpEnterpriseNames.ContainsKey($pen)) { return $script:SnmpEnterpriseNames[$pen] }
    }
    return $null
}
function Invoke-SnmpSummary {
    param([string] $Ip, [int] $Port, [int] $Version, [string] $Community, [string] $VerLabel)
    Write-Head ("--- SNMP Summary: " + $Ip + ":" + $Port + " ---")
    Write-Body (" SNMP Version : v" + $VerLabel + "  (queried with RO '" + $Community + "')")
    $collected = @{}
    foreach ($pair in $script:SnmpSummaryOids) {
        $label = $pair[0]; $oid = $pair[1]
        $r = Invoke-SnmpQuery $Ip $Port $Version $Community $oid 0xA0
        if (-not $r.Ok) { Write-Body (" " + $label.PadRight(13) + ": (no response - " + $r.Value + ")"); continue }
        $collected[$label] = $r.Value
        if ($oid -eq $script:SnmpSysObjectId) {
            $disp = Get-SnmpEnterprise $r.Value
            $collected["Enterprise"] = $disp
            Write-Body (" " + "Enterprise".PadRight(13) + ": " + $disp)
            Write-Body (" " + "Object ID".PadRight(13) + ": " + $r.Value)
        } else { Write-Body (" " + $label.PadRight(13) + ": " + $r.Value) }
    }
    Write-Body "--- end ---"
    return $collected
}
function Invoke-SnmpWalk {
    param([string] $Ip, [int] $Port, [int] $Version, [string] $Community, [string] $Base, [int] $MaxRows = 0)
    $rows = @()
    $cur = $Base
    $basePrefix = $Base.TrimStart(".") + "."
    while ($true) {
        $r = Invoke-SnmpQuery $Ip $Port $Version $Community $cur 0xA1
        if (-not $r.Ok -or -not $r.Oid) { break }
        $oid = $r.Oid
        if (-not (($oid + ".").StartsWith($basePrefix) -or $oid -eq $Base.TrimStart("."))) { break }
        $rows += ,@($oid, $r.Value)
        $cur = $oid
        if ($MaxRows -gt 0 -and $rows.Count -ge $MaxRows) { break }
        if ($rows.Count -ge 5000) { break }
    }
    return ,$rows
}
function Show-SnmpRows {
    param($Rows, [string] $Ip, [bool] $ToScreen, [bool] $ToFile, [string] $Title)
    if ($ToScreen) {
        Write-Head ("--- SNMP " + $Title + " (" + $Rows.Count + " rows) ---")
        foreach ($r in $Rows) { Write-Body ($r[0] + " = " + $r[1]) }
        Write-Body "--- end ---"
    }
    if ($ToFile) {
        $path = "atomics_ps_snmp_" + ($Ip.Replace(".", "_")) + "_" + (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss") + ".txt"
        $lines = @("# AtomICS SNMP results - " + $Title, "# Target: " + $Ip, "# Rows: " + $Rows.Count, "")
        foreach ($r in $Rows) { $lines += ($r[0] + " = " + $r[1]) }
        try { Set-Content -Path $path -Value $lines; Write-Ok ("Saved " + $Rows.Count + " rows to " + $path) } catch { Write-Bad ("Could not write " + $path) }
    }
}
function Invoke-SnmpModule {
    param([string] $DefaultIp)
    $ip = $DefaultIp
    if (-not $ip) { $ip = (Read-Host "Enter target IP for SNMP").Trim() }
    if (-not $ip) { Write-Bad "No IP provided."; return }
    if (-not (Test-ValidTarget $ip)) { Write-Bad ("'" + $ip + "' is not a valid IP address or resolvable hostname."); return }
    $portIn = (Read-Host ("SNMP port [" + $script:SnmpDefaultPort + "]")).Trim()
    $port = $script:SnmpDefaultPort; if ($portIn) { try { $port = [int] $portIn } catch { } }
    $ver = (Read-Host "SNMP version - 1 or 2c [2c]").Trim().ToLower(); if (-not $ver) { $ver = "2c" }
    $version = 1; if ($ver.StartsWith("1")) { $version = 0 }
    $ro = (Read-Host "Read-only community [public]").Trim(); if (-not $ro) { $ro = "public" }
    $verLabel = "2c"; if ($version -eq 0) { $verLabel = "1" }
    Write-Info ("Queries use the RO community '" + $ro + "' over SNMP v" + $verLabel + ".")
    Write-Body ("Verifying reachability (GET sysDescr)...")
    $r = Invoke-SnmpQuery $ip $port $version $ro "1.3.6.1.2.1.1.1.0" 0xA0
    if ($r.Ok) {
        Write-Ok ("Connected. sysDescr = " + $r.Value)
        $ph = @{}; $ph[$port] = "SNMP"
        Update-Asset -IPAddr $ip -Ports $ph -Protocol "SNMP" -Version ("SNMP sysDescr: " + $r.Value) -Source "SNMP"
    } else {
        Write-Bad ("No SNMP reply (" + $r.Value + "). Wrong community/version, or UDP 161 filtered.")
        if ((Read-Host "Continue anyway? [y/N]") -notmatch '^(y|yes)$') { return }
    }
    while ($true) {
        Write-MenuTitle "SNMP Menu"
        Write-Body ("    Target: " + $ip + ":" + $port + "  v" + $verLabel + "  RO='" + $ro + "'")
        Write-Body "1. Summary info (version, description, enterprise, uptime)"
        Write-Body "2. Full SNMP dump to screen (option to save)"
        Write-Body "3. Query a number of rows (limited walk)"
        Write-Body "4. Get a single OID"
        Write-Body "5. Change community / version"
        Write-Body "6. Back to main menu"
        $choice = (Read-Host "`nSelect an option").Trim()
        try {
            if ($choice -eq "1") { [void](Invoke-SnmpSummary $ip $port $version $ro $verLabel) }
            elseif ($choice -eq "2") {
                $base = (Read-Host "Base OID for full dump [1.3.6.1]").Trim(); if (-not $base) { $base = "1.3.6.1" }
                Write-Info ("Walking " + $base + " - this can take a while...")
                $rows = Invoke-SnmpWalk $ip $port $version $ro $base 0
                $save = ((Read-Host ("Save these " + $rows.Count + " rows to a file too? [y/N]")) -match '^(y|yes)$')
                Show-SnmpRows $rows $ip $true $save ("full dump " + $base)
            }
            elseif ($choice -eq "3") {
                $base = (Read-Host "Base OID [1.3.6.1.2.1]").Trim(); if (-not $base) { $base = "1.3.6.1.2.1" }
                $nrows = [int] (Read-Host "Number of rows to retrieve")
                $rows = Invoke-SnmpWalk $ip $port $version $ro $base $nrows
                Show-SnmpRows $rows $ip $true $false ("walk " + $base + " (max " + $nrows + ")")
            }
            elseif ($choice -eq "4") {
                $oid = (Read-Host "OID (e.g. 1.3.6.1.2.1.1.5.0 = sysName)").Trim()
                $rr = Invoke-SnmpQuery $ip $port $version $ro $oid 0xA0
                if ($rr.Ok) { Write-Body ($oid + " = " + $rr.Value) } else { Write-Bad $rr.Value }
            }
            elseif ($choice -eq "5") {
                $ver = (Read-Host "SNMP version - 1 or 2c [2c]").Trim().ToLower(); if (-not $ver) { $ver = "2c" }
                $version = 1; if ($ver.StartsWith("1")) { $version = 0 }
                $ro = (Read-Host "Read-only community [public]").Trim(); if (-not $ro) { $ro = "public" }
                $verLabel = "2c"; if ($version -eq 0) { $verLabel = "1" }
                Write-Info "Settings updated."
            }
            elseif ($choice -eq "6") { break }
            else { Write-Body "Invalid option." }
        } catch { Write-Bad ("Operation failed: " + $_.Exception.Message); Write-LogLine ("SNMP_ERROR " + $_.Exception.Message) }
    }
}
# ============================================================
#  IEC 60870-5-104 MODULE (raw sockets, TCP/2404)
# ============================================================
# APCI I/S/U framing with N(S)/N(R); STARTDT, General + Counter interrogation,
# and the common monitored types; control (active mode only) via single/double
# commands and setpoints with Select-Before-Operate or direct-operate. Control
# operates real substation points, so it is safe-mode-locked like every write.
# Reference: IEC 60870-5-104 / -101. Multi-byte info-object fields are LE.
$script:Iec104DefaultPort = 2404
$script:Iec104Types = @{
    1 = "M_SP_NA_1 single-point"; 3 = "M_DP_NA_1 double-point"; 5 = "M_ST_NA_1 step position";
    7 = "M_BO_NA_1 bitstring"; 9 = "M_ME_NA_1 measured normalized"; 11 = "M_ME_NB_1 measured scaled";
    13 = "M_ME_NC_1 measured short float"; 15 = "M_IT_NA_1 integrated totals";
    30 = "M_SP_TB_1 single-point w/time"; 31 = "M_DP_TB_1 double-point w/time"; 36 = "M_ME_TF_1 short float w/time";
    45 = "C_SC_NA_1 single command"; 46 = "C_DC_NA_1 double command"; 47 = "C_RC_NA_1 regulating step";
    48 = "C_SE_NA_1 setpoint normalized"; 49 = "C_SE_NB_1 setpoint scaled"; 50 = "C_SE_NC_1 setpoint short float";
    100 = "C_IC_NA_1 interrogation"; 101 = "C_CI_NA_1 counter interrogation"; 103 = "C_CS_NA_1 clock sync"
}
$script:Iec104Cot = @{
    1 = "periodic"; 2 = "background"; 3 = "spontaneous"; 4 = "initialized"; 5 = "request"; 6 = "activation";
    7 = "activation confirmation"; 8 = "deactivation"; 9 = "deactivation confirmation"; 10 = "activation termination";
    20 = "interrogated by station"; 37 = "interrogated by counter"; 44 = "unknown type id"; 45 = "unknown cause";
    46 = "unknown common address"; 47 = "unknown IOA"
}
$script:Iec104ElemLen = @{ 1 = 1; 3 = 1; 5 = 2; 7 = 5; 9 = 3; 11 = 3; 13 = 5; 15 = 5; 30 = 8; 31 = 8; 36 = 12 }

function Get-S16LE { param([byte[]] $B, [int] $Off) $v = Get-U16LE $B $Off; if ($v -gt 32767) { $v = $v - 65536 }; return $v }
function Get-S32LE { param([byte[]] $B, [int] $Off) $v = Get-U32LE $B $Off; if ($v -gt 2147483647) { $v = $v - 4294967296 }; return $v }
function ConvertFrom-FloatLE { param([byte[]] $B, [int] $Off) return [System.BitConverter]::ToSingle([byte[]]@($B[$Off], $B[$Off + 1], $B[$Off + 2], $B[$Off + 3]), 0) }
function ConvertTo-FloatLE { param([double] $V) return ,([System.BitConverter]::GetBytes([single] $V)) }

function Build-Iec104Asdu {
    param([int] $Tid, [int] $Cot, [int] $Ca, [int] $Ioa, [byte[]] $Elements, [int] $Vsq = 0x01, [int] $Orig = 0, [int] $Test = 0, [int] $Pn = 0)
    $cotByte = ($Cot -band 0x3F) -bor (($Pn -band 1) * 64) -bor (($Test -band 1) * 128)
    $out = [byte[]]@($Tid, $Vsq, $cotByte, $Orig, ($Ca -band 0xFF), (([int][math]::Floor($Ca / 256)) -band 0xFF),
                     ($Ioa -band 0xFF), (([int][math]::Floor($Ioa / 256)) -band 0xFF), (([int][math]::Floor($Ioa / 65536)) -band 0xFF))
    if ($Elements -and $Elements.Length -gt 0) { $out += $Elements }
    return ,$out
}
function Decode-Iec104Elem {
    param([int] $Tid, [byte[]] $Raw)
    try {
        if ($Tid -eq 1 -or $Tid -eq 30) { $siq = [int] $Raw[0]; $inv = ""; if ($siq -band 0x80) { $inv = " [invalid]" }; return ("SP=" + ($siq -band 1) + $inv) }
        if ($Tid -eq 3 -or $Tid -eq 31) { $names = @{ 0 = "intermediate"; 1 = "OFF"; 2 = "ON"; 3 = "indeterminate" }; $d = [int] $Raw[0] -band 0x03; $inv = ""; if ([int] $Raw[0] -band 0x80) { $inv = " [invalid]" }; return ("DP=" + $names[$d] + $inv) }
        if ($Tid -eq 5) { $v = [int] $Raw[0] -band 0x7F; if ($v -band 0x40) { $v = $v - 128 }; return ("step=" + $v) }
        if ($Tid -eq 7) { return ("bits=0x" + ("{0:x8}" -f (Get-U32LE $Raw 0))) }
        if ($Tid -eq 9) { return ("norm=" + [math]::Round((Get-S16LE $Raw 0) / 32768.0, 4)) }
        if ($Tid -eq 11) { return ("scaled=" + (Get-S16LE $Raw 0)) }
        if ($Tid -eq 13 -or $Tid -eq 36) { return ("float=" + [math]::Round((ConvertFrom-FloatLE $Raw 0), 4)) }
        if ($Tid -eq 15) { return ("counter=" + (Get-S32LE $Raw 0)) }
    } catch { }
    $hex = ""; foreach ($b in $Raw) { $hex += ("{0:x2}" -f [int] $b) }
    return ("0x" + $hex)
}
function Parse-Iec104Asdu {
    param([byte[]] $Asdu)
    if ($Asdu.Length -lt 6) { return $null }
    $tid = [int] $Asdu[0]; $vsq = [int] $Asdu[1]
    $sq = ([int][math]::Floor($vsq / 128)) -band 1
    $n = $vsq -band 0x7F
    $cot = [int] $Asdu[2] -band 0x3F
    $test = ([int][math]::Floor($Asdu[2] / 128)) -band 1
    $pn = ([int][math]::Floor($Asdu[2] / 64)) -band 1
    $ca = Get-U16LE $Asdu 4
    $body = New-Object byte[] 0
    if ($Asdu.Length -gt 6) { $body = $Asdu[6..($Asdu.Length - 1)] }
    $body = [byte[]] $body
    $elen = $null; if ($script:Iec104ElemLen.ContainsKey($tid)) { $elen = $script:Iec104ElemLen[$tid] }
    $objs = @()
    if ($sq -eq 0) {
        $off = 0
        for ($k = 0; $k -lt $n; $k++) {
            if (($off + 3) -gt $body.Length) { break }
            $ioa = [int] $body[$off] + [int] $body[$off + 1] * 256 + [int] $body[$off + 2] * 65536
            $off += 3
            if ($elen -eq $null) { $hex = ""; for ($z = $off; $z -lt $body.Length; $z++) { $hex += ("{0:x2}" -f [int] $body[$z]) }; $objs += ,@($ioa, ("0x" + $hex)); break }
            if (($off + $elen) -gt $body.Length) { break }
            $objs += ,@($ioa, (Decode-Iec104Elem $tid ([byte[]]($body[$off..($off + $elen - 1)]))))
            $off += $elen
        }
    } else {
        if ($body.Length -ge 3) {
            $base = [int] $body[0] + [int] $body[1] * 256 + [int] $body[2] * 65536
            $off = 3
            for ($k = 0; $k -lt $n; $k++) {
                if ($elen -eq $null -or ($off + $elen) -gt $body.Length) { break }
                $objs += ,@(($base + $k), (Decode-Iec104Elem $tid ([byte[]]($body[$off..($off + $elen - 1)]))))
                $off += $elen
            }
        }
    }
    $o = New-Object PSObject
    $o | Add-Member NoteProperty Tid $tid
    $o | Add-Member NoteProperty Cot $cot
    $o | Add-Member NoteProperty Test $test
    $o | Add-Member NoteProperty Pn $pn
    $o | Add-Member NoteProperty Ca $ca
    $o | Add-Member NoteProperty N $n
    $o | Add-Member NoteProperty Sq $sq
    $o | Add-Member NoteProperty Objs $objs
    return $o
}

function Connect-Iec104 {
    param([string] $Ip, [int] $Port, [int] $Ca, [int] $TimeoutMs = 4000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($Ip, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not ($ok -and $client.Connected)) { try { $client.Close() } catch { }; return $null }
        $client.EndConnect($iar)
    } catch { return $null }
    $stream = $client.GetStream(); $stream.ReadTimeout = $TimeoutMs
    $conn = New-Object PSObject
    $conn | Add-Member NoteProperty Client $client
    $conn | Add-Member NoteProperty Stream $stream
    $conn | Add-Member NoteProperty Ns 0
    $conn | Add-Member NoteProperty Nr 0
    $conn | Add-Member NoteProperty Ca $Ca
    return $conn
}
function Get-Iec104Apdu {
    param($Conn)
    $hdr = Read-StreamExact $Conn.Stream 2
    if (-not $hdr -or $hdr[0] -ne 0x68) { return $null }
    $len = [int] $hdr[1]
    $body = Read-StreamExact $Conn.Stream $len
    if (-not $body -or $body.Length -lt 4) { return $null }
    $c0 = [int] $body[0]
    $o = New-Object PSObject
    if (($c0 -band 0x01) -eq 0) {
        $Conn.Nr = ($Conn.Nr + 1) -band 0x7FFF
        $o | Add-Member NoteProperty Fmt "I"
        $asdu = New-Object byte[] 0; if ($body.Length -gt 4) { $asdu = $body[4..($body.Length - 1)] }
        $o | Add-Member NoteProperty Asdu ([byte[]] $asdu)
    } elseif (($c0 -band 0x03) -eq 0x01) {
        $o | Add-Member NoteProperty Fmt "S"; $o | Add-Member NoteProperty Asdu (New-Object byte[] 0)
    } else {
        $o | Add-Member NoteProperty Fmt "U"; $o | Add-Member NoteProperty Asdu (New-Object byte[] 0)
    }
    return $o
}
function Send-Iec104I {
    param($Conn, [byte[]] $Asdu)
    $ns = $Conn.Ns; $nr = $Conn.Nr
    $ctrl = [byte[]]@((($ns * 2) -band 0xFF), (([int][math]::Floor($ns / 128)) -band 0xFF), (($nr * 2) -band 0xFF), (([int][math]::Floor($nr / 128)) -band 0xFF))
    $pkt = [byte[]]@(0x68, ($ctrl.Length + $Asdu.Length)) + $ctrl + $Asdu
    $Conn.Stream.Write($pkt, 0, $pkt.Length); $Conn.Stream.Flush()
    $Conn.Ns = ($ns + 1) -band 0x7FFF
}
function Send-Iec104S {
    param($Conn)
    $nr = $Conn.Nr
    $pkt = [byte[]]@(0x68, 0x04, 0x01, 0x00, (($nr * 2) -band 0xFF), (([int][math]::Floor($nr / 128)) -band 0xFF))
    $Conn.Stream.Write($pkt, 0, $pkt.Length); $Conn.Stream.Flush()
}
function Start-Iec104 {
    param($Conn)
    $u = [byte[]]@(0x68, 0x04, 0x07, 0x00, 0x00, 0x00)
    try { $Conn.Stream.Write($u, 0, $u.Length); $Conn.Stream.Flush() } catch { return $false }
    $apdu = Get-Iec104Apdu $Conn
    return ($apdu -ne $null -and $apdu.Fmt -eq "U")
}
function Stop-Iec104 {
    param($Conn)
    try { $u = [byte[]]@(0x68, 0x04, 0x13, 0x00, 0x00, 0x00); $Conn.Stream.Write($u, 0, $u.Length); $Conn.Stream.Flush() } catch { }
}
function Get-Iec104Asdus {
    param($Conn, [int] $Max = 300)
    $out = @()
    for ($k = 0; $k -lt $Max; $k++) {
        $apdu = Get-Iec104Apdu $Conn
        if ($apdu -eq $null) { break }
        if ($apdu.Fmt -ne "I") { continue }
        $out += ,$apdu.Asdu
        $p = Parse-Iec104Asdu $apdu.Asdu
        if ($p -and $p.Cot -eq 10) { break }
    }
    if ($out.Count -gt 0) { try { Send-Iec104S $Conn } catch { } }
    return ,$out
}
function Show-Iec104Asdus {
    param($Asdus, [string] $Ip)
    $points = 0
    foreach ($raw in $Asdus) {
        $p = Parse-Iec104Asdu ([byte[]] $raw)
        if (-not $p) { continue }
        $tname = ("type " + $p.Tid); if ($script:Iec104Types.ContainsKey($p.Tid)) { $tname = $script:Iec104Types[$p.Tid] }
        $cname = ("" + $p.Cot); if ($script:Iec104Cot.ContainsKey($p.Cot)) { $cname = $script:Iec104Cot[$p.Cot] }
        Write-Body ("  " + $tname + "  [cot=" + $cname + ", CA=" + $p.Ca + ", " + $p.N + " obj]")
        foreach ($pair in $p.Objs) { $points++; Write-Body ("      IOA " + $pair[0] + ": " + $pair[1]) }
    }
    if ($points -gt 0) { Update-Asset -IPAddr $Ip -Protocol "IEC 104" -Version ("IEC104: " + $points + " point(s) enumerated") -Source "IEC104" }
    return $points
}
function Invoke-Iec104Interrogation {
    param($Conn, [string] $Ip)
    Write-Head "[IEC104 General Interrogation]"
    Send-Iec104I $Conn (Build-Iec104Asdu 100 6 $Conn.Ca 0 ([byte[]]@(20)))
    $asdus = Get-Iec104Asdus $Conn
    if ($asdus.Count -eq 0) { Write-Body "  (no response)"; return }
    $n = Show-Iec104Asdus $asdus $Ip
    Write-Body ("  -- " + $n + " monitored point(s) --")
}
function Invoke-Iec104CounterInterrogation {
    param($Conn, [string] $Ip)
    Write-Head "[IEC104 Counter Interrogation]"
    Send-Iec104I $Conn (Build-Iec104Asdu 101 6 $Conn.Ca 0 ([byte[]]@(0x05)))
    $asdus = Get-Iec104Asdus $Conn
    if ($asdus.Count -eq 0) { Write-Body "  (no response)"; return }
    $n = Show-Iec104Asdus $asdus $Ip
    Write-Body ("  -- " + $n + " counter value(s) --")
}
# Returns PSObject {Ok (nullable bool), Msg}
function Send-Iec104Cmd {
    param($Conn, [int] $Tid, [int] $Ioa, [byte[]] $Element, [string] $Label)
    Send-Iec104I $Conn (Build-Iec104Asdu $Tid 6 $Conn.Ca $Ioa $Element)
    $o = New-Object PSObject
    $o | Add-Member NoteProperty Ok $null
    $o | Add-Member NoteProperty Msg "no confirmation received"
    foreach ($raw in (Get-Iec104Asdus $Conn 20)) {
        $p = Parse-Iec104Asdu ([byte[]] $raw)
        if (-not $p -or $p.Tid -ne $Tid) { continue }
        if ($p.Cot -eq 7) {
            if ($p.Pn -eq 0) { $o.Ok = $true; $o.Msg = "ActCon positive" } else { $o.Ok = $false; $o.Msg = "ActCon NEGATIVE (rejected)" }
            return $o
        }
        if ($p.Cot -eq 10) { $o.Ok = $true; $o.Msg = "ActTerm"; return $o }
        if (@(44, 45, 46, 47) -contains $p.Cot) { $o.Ok = $false; $o.Msg = $script:Iec104Cot[$p.Cot]; return $o }
    }
    return $o
}
function Invoke-Iec104RunCommand {
    param($Conn, [string] $Ip, [int] $Tid, [int] $Ioa, [byte[]] $ElemSelect, [byte[]] $ElemExecute, [string] $Label)
    if (Test-SafeBlocked ("IEC 104 " + $Label)) { return }
    $m = (Read-Host "Mode ([s]elect-before-operate, [d]irect-operate) [s]").Trim().ToLower()
    if (-not $m) { $m = "s" }
    $direct = $m.StartsWith("d")
    Write-Warn2 ($Label + " operates a real control point (breaker/isolator/regulator)")
    Write-Body  "    on the outstation. Simulator/bench or authorized gear only."
    $modeLabel = "SBO"; if ($direct) { $modeLabel = "direct" }
    [void](Confirm-Write ("IEC104 " + $Label + " IOA=" + $Ioa + " (" + $modeLabel + ") at " + $Ip))
    if (-not $direct) {
        $r = Send-Iec104Cmd $Conn $Tid $Ioa $ElemSelect ($Label + " select")
        Write-Body ("  select : " + $r.Msg)
        if ($r.Ok -ne $true) { Write-Bad "  Select not confirmed - execute aborted."; return }
    }
    $r2 = Send-Iec104Cmd $Conn $Tid $Ioa $ElemExecute ($Label + " execute")
    Write-Body ("  execute: " + $r2.Msg)
    Write-LogLine ("IEC104_" + $Label + "_EXECUTE ioa=" + $Ioa + " result=" + $r2.Msg)
}
function Invoke-Iec104SingleCommand {
    param($Conn, [string] $Ip)
    if (Test-SafeBlocked "IEC 104 single command (C_SC)") { return }
    try { $ioa = [int] (Read-Host "Information object address (IOA)") } catch { Write-Bad "Invalid IOA."; return }
    $scs = 0; if ((Read-Host "Command ([c]lose/on, [o]pen/off)").Trim().ToLower().StartsWith("c")) { $scs = 1 }
    $sel = [byte[]]@((($scs -band 1) -bor 0x80))
    $exe = [byte[]]@(($scs -band 1))
    $lbl = "C_SC->OPEN/OFF"; if ($scs) { $lbl = "C_SC->CLOSE/ON" }
    Invoke-Iec104RunCommand $Conn $Ip 45 $ioa $sel $exe $lbl
}
function Invoke-Iec104DoubleCommand {
    param($Conn, [string] $Ip)
    if (Test-SafeBlocked "IEC 104 double command (C_DC)") { return }
    try { $ioa = [int] (Read-Host "Information object address (IOA)") } catch { Write-Bad "Invalid IOA."; return }
    $dcs = 1; if ((Read-Host "Command ([c]lose/on, [o]pen/off)").Trim().ToLower().StartsWith("c")) { $dcs = 2 }
    $sel = [byte[]]@((($dcs -band 0x03) -bor 0x80))
    $exe = [byte[]]@(($dcs -band 0x03))
    $lbl = "C_DC->OPEN/OFF"; if ($dcs -eq 2) { $lbl = "C_DC->CLOSE/ON" }
    Invoke-Iec104RunCommand $Conn $Ip 46 $ioa $sel $exe $lbl
}
function Invoke-Iec104Setpoint {
    param($Conn, [string] $Ip)
    if (Test-SafeBlocked "IEC 104 setpoint (C_SE)") { return }
    try { $ioa = [int] (Read-Host "Information object address (IOA)") } catch { Write-Bad "Invalid IOA."; return }
    $kind = (Read-Host "Setpoint type ([f]loat/C_SE_NC, [s]caled int/C_SE_NB) [f]").Trim().ToLower(); if (-not $kind) { $kind = "f" }
    $payload = $null; $tid = 50; $val = 0
    try {
        if ($kind.StartsWith("s")) {
            $val = [int] (Read-Host "Scaled value (-32768..32767)")
            if ($val -lt -32768) { $val = -32768 }; if ($val -gt 32767) { $val = 32767 }
            $u = $val; if ($u -lt 0) { $u = $u + 65536 }
            $payload = [byte[]](ConvertTo-BytesLE $u 2); $tid = 49
        } else {
            $val = [double] (Read-Host "Float value")
            $payload = [byte[]](ConvertTo-FloatLE $val); $tid = 50
        }
    } catch { Write-Bad "Invalid value."; return }
    $sel = [byte[]]($payload + [byte[]]@(0x80))
    $exe = [byte[]]($payload + [byte[]]@(0x00))
    Invoke-Iec104RunCommand $Conn $Ip $tid $ioa $sel $exe ("C_SE=" + $val)
}
function Invoke-Iec104Module {
    param([string] $DefaultIp)
    $ip = $DefaultIp
    if (-not $ip) { $ip = (Read-Host "Enter target IEC 104 IP").Trim() }
    if (-not $ip) { Write-Bad "No IP provided."; return }
    if (-not (Test-ValidTarget $ip)) { Write-Bad ("'" + $ip + "' is not a valid IP address or resolvable hostname."); return }
    $portIn = (Read-Host ("IEC 104 port [" + $script:Iec104DefaultPort + "]")).Trim()
    $port = $script:Iec104DefaultPort; if ($portIn) { try { $port = [int] $portIn } catch { } }
    $ca = 1
    try { $ca = [int] ((Read-Host "Common ASDU address [1]").Trim()) } catch { }
    if (-not $ca) { $ca = 1 }
    if ($script:SafeMode) { Write-Warn2 "SAFE mode: IEC 104 control commands (C_SC / C_DC / C_SE) are blocked. Relaunch with -Active to enable them." }
    $conn = Connect-Iec104 $ip $port $ca
    if (-not $conn) { Write-Bad ("Could not connect to " + $ip + ":" + $port + "."); return }
    if (-not (Start-Iec104 $conn)) { Write-Bad "STARTDT not confirmed - port open but no IEC 104 response."; try { $conn.Client.Close() } catch { }; return }
    Write-Ok ("IEC 104 data transfer started with " + $ip + ":" + $port + " (CA=" + $ca + ")")
    $ph = @{}; $ph[$port] = "IEC 60870-5-104"
    Update-Asset -IPAddr $ip -Ports $ph -Protocol "IEC 104" -Source "IEC104"
    try {
        $lock = ""; if ($script:SafeMode) { $lock = "   [LOCKED - safe mode]" }
        while ($true) {
            Write-MenuTitle "IEC 60870-5-104 Menu"
            Write-Body ("    Target: " + $ip + ":" + $port + "  CA=" + $ca)
            Write-Body "1. General interrogation (enumerate monitored points)"
            Write-Body "2. Counter interrogation (integrated totals)"
            Write-Body ("3. Single command C_SC (open/close a point)" + $lock)
            Write-Body ("4. Double command C_DC (open/close a point)" + $lock)
            Write-Body ("5. Setpoint command C_SE (analog)" + $lock)
            Write-Body "6. Change common address"
            Write-Body "7. Back to main menu"
            $choice = (Read-Host "`nSelect an option").Trim()
            try {
                if ($choice -eq "1") { Invoke-Iec104Interrogation $conn $ip }
                elseif ($choice -eq "2") { Invoke-Iec104CounterInterrogation $conn $ip }
                elseif ($choice -eq "3") { Invoke-Iec104SingleCommand $conn $ip }
                elseif ($choice -eq "4") { Invoke-Iec104DoubleCommand $conn $ip }
                elseif ($choice -eq "5") { Invoke-Iec104Setpoint $conn $ip }
                elseif ($choice -eq "6") { $ca = [int] ((Read-Host "Common ASDU address [1]").Trim()); if (-not $ca) { $ca = 1 }; $conn.Ca = $ca; Write-Info ("Common address set to " + $ca) }
                elseif ($choice -eq "7") { break }
                else { Write-Body "Invalid option." }
            } catch { Write-Bad ("Operation failed: " + $_.Exception.Message); Write-LogLine ("IEC104_ERROR " + $_.Exception.Message) }
        }
    } finally {
        Stop-Iec104 $conn
        try { $conn.Client.Close() } catch { }
        Write-LogLine "IEC104_DISCONNECTED"
    }
}
# ============================================================
#  AUTO-FINGERPRINT (read-only, single host)
# ============================================================
function Test-ValidTarget {
    param([string] $Target)
    $Target = ("" + $Target).Trim()
    if (-not $Target) { return $false }
    $addr = $null
    if ([System.Net.IPAddress]::TryParse($Target, [ref] $addr) -and $Target -match '^\d+\.\d+\.\d+\.\d+$') { return $true }
    try { [void][System.Net.Dns]::GetHostEntry($Target); return $true } catch { return $false }
}

function Invoke-AutoFpModbus {
    param([string] $Ip)
    $conn = Connect-Modbus $Ip 502
    if (-not $conn) { return }
    try {
        $ph = @{}; $ph[502] = "Modbus TCP"
        Update-Asset -IPAddr $Ip -Ports $ph -Protocol "Modbus TCP" -Source "AutoFP"
        Invoke-ReadDeviceId $conn $Ip
    } finally { try { $conn.Client.Close() } catch { } }
}
function Invoke-AutoFpS7 {
    param([string] $Ip)
    $probe = Invoke-S7AutoProbe $Ip $script:S7DefaultPort
    if (-not $probe) { Write-Body "    [i] 102 open but no rack/slot combo connected."; return }
    try {
        $ph = @{}; $ph[$script:S7DefaultPort] = "S7comm / ISO-TSAP (Siemens)"
        Update-Asset -IPAddr $Ip -Ports $ph -Protocol "S7comm" -Vendor "Siemens" -Source "AutoFP"
        Invoke-S7CpuInfo $probe.Conn $Ip
        Invoke-S7OrderCode $probe.Conn $Ip
    } finally { try { $probe.Conn.Client.Close() } catch { } }
}
function Invoke-AutoFpIec104 {
    param([string] $Ip)
    $conn = Connect-Iec104 $Ip $script:Iec104DefaultPort 1
    if (-not $conn) { Write-Body "    [i] IEC 104 probe: could not connect."; return }
    try {
        if (Start-Iec104 $conn) { Update-Asset -IPAddr $Ip -Protocol "IEC 104" -Source "AutoFP"; Write-Ok "IEC 104 STARTDT confirmed (CA=1 assumed)." }
        else { Write-Body "    [i] 2404 open but no IEC 104 STARTDT reply." }
    } finally { Stop-Iec104 $conn; try { $conn.Client.Close() } catch { } }
}
function Invoke-AutoFpSnmp {
    param([string] $Ip)
    $r = Invoke-SnmpQuery $Ip $script:SnmpDefaultPort 1 "public" "1.3.6.1.2.1.1.1.0" 0xA0
    if (-not $r.Ok) { Write-Body "    [-] No SNMP reply with community 'public' (v2c)."; return }
    $ph = @{}; $ph[161] = "SNMP"
    Update-Asset -IPAddr $Ip -Ports $ph -Protocol "SNMP" -Source "AutoFP"
    Write-Warn2 "SNMP answers default community 'public' (v2c) - read access, no auth."
    $fields = Invoke-SnmpSummary $Ip $script:SnmpDefaultPort 1 "public" "2c"
    $descr = ""; if ($fields.ContainsKey("Description")) { $descr = $fields["Description"] }
    $name = ""; if ($fields.ContainsKey("Name")) { $name = $fields["Name"] }
    $objid = ""; if ($fields.ContainsKey("Object ID")) { $objid = $fields["Object ID"] }
    $vendor = ""; if ($objid) { $v = Get-SnmpVendorName $objid; if ($v) { $vendor = $v } }
    $verLine = ""
    if ($descr) { $verLine = "SNMP sysDescr: " + $descr } elseif ($fields.ContainsKey("Enterprise")) { $verLine = "SNMP enterprise: " + $fields["Enterprise"] }
    Update-Asset -IPAddr $Ip -Source "AutoFP" -Hostname $name -Vendor $vendor -Version $verLine
    $folded = @()
    if ($vendor) { $folded += ("vendor=" + $vendor) }
    if ($name) { $folded += ("sysName=" + $name) }
    if ($folded.Count -gt 0) { Write-Ok ("SNMP identity -> Asset Register: " + ($folded -join ", ")) }
}
function Invoke-AutoFingerprint {
    param([string] $DefaultIp)
    $ip = $DefaultIp
    if (-not $ip) { $ip = (Read-Host "Target IP to fingerprint").Trim() }
    if (-not $ip) { Write-Bad "No IP provided."; return }
    if (-not (Test-ValidTarget $ip)) { Write-Bad ("'" + $ip + "' is not a valid IP address or resolvable hostname."); return }
    $BAR = "=" * 60
    Write-Host ""; Write-Body $BAR
    Write-Body (" AUTO-FINGERPRINT  " + $ip + "   (read-only)")
    Write-Body $BAR
    Write-Body " Probing OT service ports (one connection at a time)..."
    Write-LogLine ("AUTOFP start ip=" + $ip)
    $open = @()
    foreach ($entry in $script:AutoFpTcp) {
        $port = $entry[0]; $label = $entry[1]
        if (Test-TcpPort $ip $port 1000) {
            Write-Ok ($port + "/tcp open   - " + $label)
            $ph = @{}; $ph[$port] = $label
            Update-Asset -IPAddr $ip -Ports $ph -Source "AutoFP"
            $open += $port
        } else { Write-Body ("  [-] " + $port + "/tcp closed/filtered") }
    }
    if ($open -contains 502) { Write-Head "--- Modbus (TCP/502) ---"; Invoke-AutoFpModbus $ip }
    if ($open -contains 102) { Write-Head "--- S7comm (TCP/102) ---"; Invoke-AutoFpS7 $ip }
    if ($open -contains 44818) { Write-Head "--- EtherNet/IP (TCP/44818) ---"; Invoke-EnipRecon $ip $script:EnipDefaultPort }
    if ($open -contains 20000) { Write-Head "--- DNP3 (TCP/20000) ---"; Invoke-Dnp3LinkStatus $ip $script:Dnp3DefaultPort 1024 1 }
    if ($open -contains 2404) { Write-Head "--- IEC 60870-5-104 (TCP/2404) ---"; Invoke-AutoFpIec104 $ip }
    Write-Head "--- UDP probes (SNMP/161, BACnet/47808) ---"
    Invoke-AutoFpSnmp $ip
    try { Invoke-BacnetWhois $script:BacnetDefaultPort $ip } catch { Write-Body ("    [i] BACnet probe failed: " + $_.Exception.Message) }
    Write-Host ""; Write-Body $BAR
    Write-Body " Auto-fingerprint complete. Open the Asset Register (main menu) for the"
    Write-Body " merged result; export it to CSV/JSON to keep it."
    Write-Body $BAR
    Write-LogLine ("AUTOFP done ip=" + $ip + " open=" + ($open -join ","))
}

# ============================================================
#  HELP
# ============================================================
function Show-HelpScreen {
    Write-MenuTitle "Help"
    $mode = "ACTIVE (writes enabled)"; if ($script:SafeMode) { $mode = "SAFE (read-only)" }
    $lines = @(
        "",
        "This is the no-install PowerShell edition of AtomICS (the Python",
        "OT/ICS Recon & Assessment Console). It runs on a locked-down Windows",
        "host with nothing installed. It is read-only by default; any write or",
        "state-changing action requires launching with -Active.",
        "",
        "Current mode: " + $mode,
        "",
        "--- Main menu ---",
        "",
        "1. Network Discovery",
        "     Find live hosts on the local segment. The broadcast/multicast",
        "     listen and the ARP cache read send nothing and stay available in",
        "     safe mode. Active techniques (ICMP, TCP-connect scans) put packets",
        "     on the wire and need -Active.",
        "",
        "2. Protocol Modules",
        "     Speak directly to controllers over Modbus, S7comm (Siemens),",
        "     EtherNet/IP (CIP), DNP3, BACnet/IP, SNMP, and IEC 60870-5-104.",
        "     Each leads with read-only recon. Writes/control are opt-in and",
        "     labeled: Modbus writes, the S7 DB/M/Q writes and STOP/START, and",
        "     the IEC 104 C_SC/C_DC/C_SE commands.",
        "",
        "3. Auto-Fingerprint",
        "     Point it at one IP: it connect-scans the OT ports, then runs each",
        "     matching module's read-only recon and folds the result into the",
        "     Asset Register. Never writes - safe in any mode.",
        "",
        "4. Asset Register",
        "     The in-memory inventory of hosts, open ports, and services",
        "     collected this session. View it, or export to CSV / JSON. Not",
        "     saved to disk until you export it.",
        "",
        "5. Help      6. Exit",
        "",
        "--- Safety ---",
        "",
        "Legacy controllers can fault from traffic IT gear shrugs off. AtomICS",
        "uses conservative timeouts and one connection at a time. Run it against",
        "the simulators (plc_sim, the S7/DNP3/EtherNet-IP sims, MOTH) first.",
        "",
        "--- Command line ---",
        "",
        "  -Active      enable write / state-changing operations",
        "  -ReadOnly    hard override: keep writes blocked even with -Active",
        "  -Log         write a session log beside the script",
        "  -UpdateOui   download a MAC-vendor (OUI) database, then exit",
        "  -Help        show this help and exit",
        "",
        "--- About ---",
        "",
        "AtomICS was vibe-coded by Mike Holcomb (UtilSec, LLC).",
        "More OT/ICS security resources: https://www.utilsec.com",
        ""
    )
    foreach ($ln in $lines) { Write-Body $ln }
    foreach ($dl in $script:Disclaimer) { Write-Body ("  " + $dl) }
    Write-Host ""
}

# ============================================================
#  MENUS
# ============================================================
function Invoke-ProtocolModules {
    param([string] $DefaultIp)
    while ($true) {
        Write-MenuTitle "Protocol Modules"
        Write-Body "1. Modbus"
        Write-Body "2. S7 (Siemens)"
        Write-Body "3. EtherNet/IP (CIP)"
        Write-Body "4. DNP3"
        Write-Body "5. BACnet"
        Write-Body "6. SNMP"
        Write-Body "7. IEC 60870-5-104"
        Write-Body "8. Back to main menu"
        $c = (Read-Host "`nSelect an option").Trim()
        if ($c -eq "1") { Invoke-ModbusModule $DefaultIp }
        elseif ($c -eq "2") { Invoke-S7Module $DefaultIp }
        elseif ($c -eq "3") { Invoke-EnipModule $DefaultIp }
        elseif ($c -eq "4") { Invoke-Dnp3Module $DefaultIp }
        elseif ($c -eq "5") { Invoke-BacnetModule $DefaultIp }
        elseif ($c -eq "6") { Invoke-SnmpModule $DefaultIp }
        elseif ($c -eq "7") { Invoke-Iec104Module $DefaultIp }
        elseif ($c -eq "8") { break }
        else { Write-Body "Invalid option." }
    }
}

function Invoke-MainMenu {
    param([string] $DefaultIp)
    while ($true) {
        Write-MenuTitle "Main Menu"
        Write-Host ""
        Write-Body "1. Network Discovery"
        Write-Body "2. Protocol Modules"
        Write-Body "3. Auto-Fingerprint"
        Write-Body ("4. Asset Register (" + (Get-AssetSummary) + ")")
        Write-Body "5. Help"
        Write-Body "6. Exit"
        $c = (Read-Host "`nSelect an option").Trim()
        if ($c -eq "1") { Invoke-NetworkDiscovery $DefaultIp }
        elseif ($c -eq "2") { Invoke-ProtocolModules $DefaultIp }
        elseif ($c -eq "3") { Invoke-AutoFingerprint $DefaultIp }
        elseif ($c -eq "4") { Invoke-AssetRegister }
        elseif ($c -eq "5") { Show-HelpScreen }
        elseif ($c -eq "6") { Write-LogLine "SESSION_END"; break }
        else { Write-Body "Invalid option." }
    }
}

# ============================================================
#  ENTRY POINT
# ============================================================
if ($Help) { Show-HelpScreen; return }

if ($UpdateOui) { Update-OuiDatabase; return }

if ($Log) {
    $script:LogFile = "atomics_ps_log_" + (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss") + ".log"
    Write-LogLine "LOGGING_ENABLED"
}

Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host (" AtomICS - OT/ICS Recon & Assessment Console - PowerShell Edition (" + $script:Version + ")") -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
if ($script:SafeMode) {
    foreach ($line in $script:Disclaimer) { Write-Host (" " + $line) -ForegroundColor White }
    if ($Active -and $ReadOnly) { Write-Host " (-Active was overridden by -ReadOnly; writes stay blocked)" -ForegroundColor Green }
} else {
    Write-Host " !! MODE: ACTIVE - writes and state-changing actions are ENABLED !!" -ForegroundColor Yellow
    Write-Host "    This session can change live device state. Writes execute immediately," -ForegroundColor Yellow
    Write-Host "    each logged as a [write] line - no per-write prompt." -ForegroundColor Yellow
}
Write-Host ("=" * 60) -ForegroundColor Cyan
Show-LocalInterfaces "  "
Import-OuiDatabaseAtStartup
Write-Host ("=" * 60) -ForegroundColor Cyan

try {
    Invoke-MainMenu $IP
} catch {
    Write-Bad ("Fatal: " + $_.Exception.Message)
}
Write-Host "Goodbye."
