<#
.SYNOPSIS
    Collects Windows service information for persistence detection.

.DESCRIPTION
    Enumerates Windows services and extracts binary paths, run-as
    accounts, start types, and service states to identify malicious
    persistence and privilege abuse.

.IR_PHASE
    Persistence / Investigation

.MITRE_ATTCK
    T1543.003 - Windows Service
    T1036 - Masquerading
    T1059 - Command-Line / PowerShell
    T1106 - Native API

.FORENSIC_SAFETY
    Read-only, forensic-safe

.OUTPUT
    JSON evidence file + SHA256 hash
    Execution log

.AUTHOR
    Subash J

.VERSION
    1.0
#>

# =========================
# Privilege Awareness
# =========================
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# =========================
# Environment Information
# =========================
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = "C:\IR_Collection"
$LogFile   = "$BasePath\Services_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param ($Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Windows service collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "Administrator privileges recommended for full service visibility."
}

# =========================
# Service Collection
# =========================
Write-Host "[*] Collecting Windows services..." -ForegroundColor Cyan
Write-Log "Enumerating Windows services"

$Services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue

$ServiceData = foreach ($Service in $Services) {

    [PSCustomObject]@{
        Hostname        = $Hostname
        CollectionTime  = (Get-Date).ToString("o")
        ServiceName     = $Service.Name
        DisplayName     = $Service.DisplayName
        Description     = $Service.Description
        State           = $Service.State
        StartMode       = $Service.StartMode
        RunAsAccount    = $Service.StartName
        BinaryPath      = $Service.PathName
    }
}

# =========================
# Unified Evidence Schema
# =========================
$Evidence = [PSCustomObject]@{
    ArtifactType = "WindowsServices"
    Hostname     = $Hostname
    CollectedAt  = (Get-Date).ToString("o")
    ToolVersion  = "1.0"
    ServiceCount = $ServiceData.Count
    Data         = $ServiceData
}

$JsonFile = "$BasePath\Windows_Services_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence | ConvertTo-Json -Depth 5 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Service data exported to JSON"

# =========================
# Evidence Integrity
# =========================
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256

$HashInfo = [PSCustomObject]@{
    FileName  = $JsonFile
    Algorithm = $Hash.Algorithm
    Hash      = $Hash.Hash
    Generated = (Get-Date).ToString("o")
}

$HashInfo | ConvertTo-Json |
    Out-File -FilePath $HashFile -Encoding UTF8

Write-Log "SHA256 hash generated"

Write-Host "[+] Windows service collection completed" -ForegroundColor Green
Write-Host "[+] JSON Output : $JsonFile" -ForegroundColor Green
Write-Host "[+] Hash Output : $HashFile" -ForegroundColor Green
Write-Host "[+] Execution Log : $LogFile" -ForegroundColor Green

Write-Log "Script execution completed"
