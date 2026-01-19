<#
.SYNOPSIS
    Collects startup folder executables and shortcuts for persistence detection.

.DESCRIPTION
    Enumerates user and system startup folders and extracts file details,
    including shortcut targets, to identify malicious persistence.

.IR_PHASE
    Persistence / Investigation

.MITRE_ATTCK
    T1547.001 - Startup Folder
    T1036 - Masquerading
    T1059 - Command-Line / PowerShell

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
$LogFile   = "$BasePath\StartupFolder_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param ($Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Startup folder collection started"
Write-Log "Administrator privileges: $IsAdmin"

# =========================
# Startup Folder Paths
# =========================
$StartupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

Write-Host "[*] Collecting Startup Folder items..." -ForegroundColor Cyan
Write-Log "Enumerating startup folder paths"

$StartupData = @()

foreach ($Path in $StartupPaths) {
    if (Test-Path $Path) {
        Get-ChildItem -Path $Path -Force | ForEach-Object {

            $TargetPath = $null

            # Resolve shortcut target
            if ($_.Extension -eq ".lnk") {
                try {
                    $WshShell = New-Object -ComObject WScript.Shell
                    $Shortcut = $WshShell.CreateShortcut($_.FullName)
                    $TargetPath = $Shortcut.TargetPath
                } catch {
                    $TargetPath = "Unable to resolve shortcut"
                }
            }

            $StartupData += [PSCustomObject]@{
                Hostname        = $Hostname
                CollectionTime  = (Get-Date).ToString("o")
                StartupPath     = $Path
                FileName        = $_.Name
                FullPath        = $_.FullName
                TargetPath      = $TargetPath
                FileExtension   = $_.Extension
                LastWriteTime   = $_.LastWriteTimeUtc.ToString("o")
            }
        }
    }
}

# =========================
# Unified Evidence Schema
# =========================
$Evidence = [PSCustomObject]@{
    ArtifactType = "StartupFolder"
    Hostname     = $Hostname
    CollectedAt  = (Get-Date).ToString("o")
    ToolVersion  = "1.0"
    EntryCount   = $StartupData.Count
    Data         = $StartupData
}

$JsonFile = "$BasePath\Startup_Folder_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence | ConvertTo-Json -Depth 6 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Startup folder data exported to JSON"

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

Write-Host "[+] Startup folder collection completed" -ForegroundColor Green
Write-Host "[+] JSON Output : $JsonFile" -ForegroundColor Green
Write-Host "[+] Hash Output : $HashFile" -ForegroundColor Green
Write-Host "[+] Execution Log : $LogFile" -ForegroundColor Green

Write-Log "Script execution completed"
