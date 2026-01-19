<#
.SYNOPSIS
    Collects active network connections and listening ports.

.DESCRIPTION
    Enumerates active TCP connections and correlates them with
    process information to identify malicious network activity,
    C2 communication, and unauthorized listeners.

.IR_PHASE
    Identification / Live Response

.MITRE_ATTCK
    T1041 - Exfiltration Over C2 Channel
    T1071 - Application Layer Protocol
    T1571 - Non-Standard Port
    T1105 - Ingress Tool Transfer
    T1021 - Remote Services

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
$LogFile   = "$BasePath\Network_Connections_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param ($Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Network connection collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "Administrator privileges recommended for full process correlation."
}

# =========================
# Network Connection Collection
# =========================
Write-Host "[*] Collecting network connections..." -ForegroundColor Cyan
Write-Log "Enumerating TCP connections"

$Connections = Get-NetTCPConnection -ErrorAction SilentlyContinue

$ConnectionData = foreach ($Conn in $Connections) {

    $ProcessName = "Unknown"

    try {
        $ProcessName = (Get-Process -Id $Conn.OwningProcess -ErrorAction Stop).ProcessName
    } catch {
        $ProcessName = "Access Denied"
    }

    [PSCustomObject]@{
        Hostname        = $Hostname
        CollectionTime  = (Get-Date).ToString("o")
        ProcessName     = $ProcessName
        PID             = $Conn.OwningProcess
        LocalAddress    = $Conn.LocalAddress
        LocalPort       = $Conn.LocalPort
        RemoteAddress   = $Conn.RemoteAddress
        RemotePort      = $Conn.RemotePort
        State           = $Conn.State
    }
}

# =========================
# Unified Evidence Schema
# =========================
$Evidence = [PSCustomObject]@{
    ArtifactType   = "NetworkConnections"
    Hostname       = $Hostname
    CollectedAt    = (Get-Date).ToString("o")
    ToolVersion    = "1.0"
    ConnectionCount= $ConnectionData.Count
    Data           = $ConnectionData
}

$JsonFile = "$BasePath\Network_Connections_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence | ConvertTo-Json -Depth 5 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Network connection data exported to JSON"

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

Write-Host "[+] Network connection collection completed" -ForegroundColor Green
Write-Host "[+] JSON Output : $JsonFile" -ForegroundColor Green
Write-Host "[+] Hash Output : $HashFile" -ForegroundColor Green
Write-Host "[+] Execution Log : $LogFile" -ForegroundColor Green

Write-Log "Script execution completed"
