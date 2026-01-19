# Windows DFIR Toolkit

An enterprise-grade, forensic-safe Windows Incident Response toolkit
designed for live response and offline forensic analysis.

This toolkit helps DFIR analysts collect high-value forensic artifacts
related to execution, persistence, network activity, privilege abuse,
and defense evasion.

--------------------------------------------------------------------

## Features
- Read-only and forensic-safe scripts
- JSON output for automation and SIEM ingestion
- SHA256 hashing for evidence integrity
- Covers major Windows attack surfaces
- MITRE ATT&CK aligned

---------------------------------------------------------------------

## Output Location
All artifacts are saved to:

C:\IR_Collection\

Each artifact includes a corresponding SHA256 hash file.

---------------------------------------------------------------------

## Folder Structure

scripts/
├── network
│ ├── ARP_Entries.ps1
│ ├── Network_Connections.ps1
│ └── DNS_Cache.ps1
├── execution
│ └── Running_Processes.ps1
├── persistence
│ ├── Scheduled_Tasks.ps1
│ ├── Windows_Services.ps1
│ ├── Registry_RunKeys.ps1
│ ├── Startup_Folder.ps1
│ └── WMI_Persistence.ps1
├── privilege
│ └── Local_Users_Groups.ps1
├── defense_evasion
│ └── Firewall_Rules.ps1
└── correlation
└── Autoruns_Master_Summary.ps1

------------------------------------------------------------------

## Usage

Run scripts individually based on investigation needs:

```powershell
.\Running_Processes.ps1
.\Network_Connections.ps1
.\Registry_RunKeys.ps1

-- Administrator privileges are recommended for full visibility.

------------------------------------------------------------------

Author: Subash J