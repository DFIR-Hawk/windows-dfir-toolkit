<#
.SYNOPSIS
    Collects Windows Registry Run Keys for persistence detection.

.DESCRIPTION
    Enumerates common Windows Registry auto-start locations used
    for persistence and extracts command values for DFIR analysis.

.IR_PHASE
    Persistence / Investigation

.MITRE_ATTCK
    T1547.001 - Registry Run Keys / Startup Folder
    T1059 - Command-Line / PowerShell
    T1036 - Masquerading

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
$LogFile   = "$BasePath\Registry_RunKeys_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param ($Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Registry Run Keys collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "Administrator privileges recommended for full registry visibility."
}

# =========================
# Registry Run Key Paths
# =========================
$RunKeyPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)

Write-Host "[*] Collecting Registry Run Keys..." -ForegroundColor Cyan
Write-Log "Enumerating registry run key paths"

$RunKeyData = @()

foreach ($Path in $RunKeyPaths) {
    try {
        if (Test-Path $Path) {
            $Values = Get-ItemProperty -Path $Path
            foreach ($Property in $Values.PSObject.Properties) {
                if ($Property.Name -notmatch "^PS") {
                    $RunKeyData += [PSCustomObject]@{
                        Hostname       = $Hostname
                        CollectionTime = (Get-Date).ToString("o")
                        RegistryPath   = $Path
                        ValueName      = $Property.Name
                        Command        = $Property.Value
                    }
                }
            }
        }
    } catch {
        Write-Log "Failed to access $Path"
    }
}

# =========================
# Unified Evidence Schema
# =========================
$Evidence = [PSCustomObject]@{
    ArtifactType = "RegistryRunKeys"
    Hostname     = $Hostname
    CollectedAt  = (Get-Date).ToString("o")
    ToolVersion  = "1.0"
    EntryCount   = $RunKeyData.Count
    Data         = $RunKeyData
}

$JsonFile = "$BasePath\Registry_RunKeys_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence | ConvertTo-Json -Depth 5 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Registry run keys exported to JSON"

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

Write-Host "[+] Registry Run Key collection completed" -ForegroundColor Green
Write-Host "[+] JSON Output : $JsonFile" -ForegroundColor Green
Write-Host "[+] Hash Output : $HashFile" -ForegroundColor Green
Write-Host "[+] Execution Log : $LogFile" -ForegroundColor Green

Write-Log "Script execution completed"
