<#
.SYNOPSIS
    Collects running process details and validates digital signatures.

.DESCRIPTION
    Enumerates running processes, captures executable metadata,
    digital signature status, and file hash to assist DFIR
    investigations in identifying suspicious or malicious activity.

.IR_PHASE
    Identification / Live Response

.MITRE_ATTCK
    T1055 - Process Injection
    T1036 - Masquerading
    T1106 - Native API Abuse

.FORENSIC_SAFETY
    Read-only, forensic-safe

.OUTPUT
    JSON evidence file + SHA256 hash
    Execution log file

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
$LogFile   = "$BasePath\Running_Processes_Execution.log"

# Create directories
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

# Logging function
function Write-Log {
    param ($Message)
    $Entry = "$(Get-Date -Format o) :: $Message"
    Add-Content -Path $LogFile -Value $Entry
}

Write-Log "Script execution started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "Script is NOT running as Administrator. Some processes may not be accessible."
    Write-Log "WARNING: Script not running as Administrator"
}

# =========================
# Output Files
# =========================
$JsonFile = "$BasePath\Running_Processes_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

Write-Host "[*] Collecting running processes..." -ForegroundColor Cyan
Write-Log "Collecting running processes"

$ProcessData = @()

foreach ($Process in Get-Process) {
    try {
        $ExePath = $Process.MainModule.FileName

        if (Test-Path $ExePath) {
            $Signature = Get-AuthenticodeSignature -FilePath $ExePath
            $FileHash  = (Get-FileHash -Path $ExePath -Algorithm SHA256).Hash
            $SigStatus = $Signature.Status
        } else {
            $SigStatus = "Executable Not Found"
            $FileHash  = $null
        }
    } catch {
        $ExePath   = "Access Denied"
        $SigStatus = "Unknown"
        $FileHash  = $null
    }

    $ProcessData += [PSCustomObject]@{
        Hostname        = $Hostname
        CollectionTime  = (Get-Date).ToString("o")
        ProcessName     = $Process.ProcessName
        PID             = $Process.Id
        ExecutablePath  = $ExePath
        SHA256          = $FileHash
        SignatureStatus = $SigStatus
    }
}

# =========================
# Unified Evidence Schema
# =========================
$Evidence = [PSCustomObject]@{
    ArtifactType = "RunningProcesses"
    Hostname     = $Hostname
    CollectedAt  = (Get-Date).ToString("o")
    ToolVersion  = "1.0"
    Data         = $ProcessData
}

# Export JSON
$Evidence | ConvertTo-Json -Depth 5 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Process data exported to JSON"

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

Write-Host "[+] Running process collection completed" -ForegroundColor Green
Write-Host "[+] JSON Output : $JsonFile" -ForegroundColor Green
Write-Host "[+] Hash Output : $HashFile" -ForegroundColor Green
Write-Host "[+] Execution Log : $LogFile" -ForegroundColor Green

Write-Log "Script execution completed"
