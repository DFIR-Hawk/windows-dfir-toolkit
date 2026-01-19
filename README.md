# Windows DFIR Toolkit

An enterprise-grade, forensic-safe Windows Incident Response (DFIR) toolkit
designed to assist security teams during live response and post-incident
investigations.

This toolkit focuses on collecting high-value forensic artifacts related to
process execution, persistence mechanisms, network activity, privilege abuse,
and defense evasion, while maintaining forensic integrity.

----------------------------------------------------------------------------------------------------

## Purpose

The primary goal of this toolkit is to:
- Support **live incident response**
- Enable **offline forensic analysis**
- Provide **structured evidence** suitable for SOC, DFIR, and threat-hunting teams
- Maintain **forensic safety** (read-only operations)

----------------------------------------------------------------------------------------------------

## Key Features

- Forensic-safe (read-only, no system modification)
- Structured **JSON output** for automation and SIEM ingestion
- **SHA256 hashing** for evidence integrity verification
- Covers major Windows attack surfaces
- Modular and easy to extend
- MITRE ATT&CK aligned
- Prefetch artifact collection for execution evidence (offline parsing recommended)

----------------------------------------------------------------------------------------------------

## Output Location

All artifacts are collected and stored in: C:\IR_Collection\

Each script generates:
- A JSON evidence file
- A corresponding SHA256 hash file
- An execution log (where applicable)
  
----------------------------------------------------------------------------------------------------

## Toolkit Structure

Windows-dfir-toolkit/
├── scripts/
│   ├── host/
│   │   └── System_Info.ps1
│   │
│   ├── execution/
│   │   ├── Running_Processes.ps1
│   │   └── Collect_Prefetch.ps1
│   │
│   ├── persistence/
│   │   ├── Scheduled_Tasks.ps1
│   │   ├── Windows_Services.ps1
│   │   ├── Registry_RunKeys.ps1
│   │   ├── Startup_Folder.ps1
│   │   └── WMI_Persistence.ps1
│   │
│   ├── privilege/
│   │   └── Local_Users_Groups.ps1
│   │
│   ├── defense_evasion/
│   │   └── Firewall_Rules.ps1
│   │
│   ├── network/
│   │   ├── Network_Connections.ps1
│   │   ├── ARP_Entries.ps1
│   │   └── DNS_Cache.ps1
│   │
│   └── correlation/
│       └── Autoruns_Master_Summary.ps1
│
├── README.md
├── LICENSE


----------------------------------------------------------------------------------------------------

## Usage

Run individual scripts based on investigation requirements.

Example:

```powershell
.\Running_Processes.ps1
.\Network_Connections.ps1
.\Registry_RunKeys.ps1

Administrator privileges are recommended for full visibility.

Forensic Safety:
- All scripts are read-only
- No registry modification, file deletion, or process termination
- Safe to execute during live incident response

## Artifact Handling & Scope

- This toolkit focuses on **forensic-safe artifact collection** during
live incident response.
- Artifacts such as **Prefetch files** are collected intact and are
intended to be **parsed offline** using dedicated forensic tools.
- Live parsing on compromised hosts is intentionally avoided to
preserve evidence integrity.


MITRE ATT&CK Coverage:
The toolkit covers multiple MITRE ATT&CK techniques including:
1. Execution
2. Persistence
3. Privilege Escalation
4. Defense Evasion
5. Command and Control
6. Each script documents relevant ATT&CK mappings internally.

Author: Subash J
DFIR | Incident Response | Threat Hunting

⚠️ Disclaimer
This toolkit is intended for authorized security investigations only.
The author is not responsible for misuse or unauthorized deployment.

----------------------------------------------------------------------------------------------------
