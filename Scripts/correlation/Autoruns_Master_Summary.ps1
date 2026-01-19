<#
.SYNOPSIS
    Generates a unified Autoruns-style persistence summary.

.DESCRIPTION
    Aggregates persistence artifacts collected from multiple DFIR
    scripts (Run Keys, Services, Scheduled Tasks, Startup Folder,
    WMI Subscriptions) into a single, structured persistence view.

.IR_PHASE
    Persistence / Triage / Investigation

.MITRE_ATTCK
    T1547 - Boot or Logon Autostart Execution
    T1546 - Event Triggered Execution
    T1053 - Scheduled Task
    T1543 - Windows Service

.FORENSIC_SAFETY
    Read-only, offline, forensic-safe

.OUTPUT
    JSON persistence summary + SHA256 hash

.AUTHOR
    Subash J

.VERSION
    1.0
#>

# =========================
# Environment Information
# =========================
$BasePath = "C:\IR_Collection"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME

$OutputFile = "$BasePath\Autoruns_Persistence_Summary_${Hostname}_${Timestamp}.json"
$HashFile   = "$OutputFile.hash.json"

Write-Host "[*] Building Autoruns-style persistence summary..." -ForegroundColor Cyan

# =========================
# Load JSON Artifacts
# =========================
function Load-Artifact {
    param ($Pattern)
    Get-ChildItem -Path $BasePath -Filter $Pattern -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                Get-Content $_.FullName -Raw | ConvertFrom-Json
            } catch {
                $null
            }
        }
}

$RunKeys     = Load-Artifact "Registry_RunKeys_*.json"
$Tasks       = Load-Artifact "Scheduled_Tasks_*.json"
$Services    = Load-Artifact "Windows_Services_*.json"
$Startup     = Load-Artifact "Startup_Folder_*.json"
$WMI         = Load-Artifact "WMI_Persistence_*.json"

# =========================
# Normalize Persistence Data
# =========================
$Persistence = @()

foreach ($Item in $RunKeys.Data) {
    $Persistence += [PSCustomObject]@{
        Source     = "RegistryRunKey"
        Name       = $Item.ValueName
        Location   = $Item.RegistryPath
        Command    = $Item.Command
    }
}

foreach ($Item in $Tasks.Data) {
    $Persistence += [PSCustomObject]@{
        Source     = "ScheduledTask"
        Name       = $Item.TaskName
        Location   = $Item.TaskPath
        Command    = "$($Item.Command) $($Item.Arguments)"
    }
}

foreach ($Item in $Services.Data) {
    $Persistence += [PSCustomObject]@{
        Source     = "Service"
        Name       = $Item.ServiceName
        Location   = $Item.BinaryPath
        Command    = $Item.BinaryPath
    }
}

foreach ($Item in $Startup.Data) {
    $Persistence += [PSCustomObject]@{
        Source     = "StartupFolder"
        Name       = $Item.FileName
        Location   = $Item.StartupPath
        Command    = $Item.TargetPath
    }
}

foreach ($Item in $WMI.Data) {
    $Persistence += [PSCustomObject]@{
        Source     = "WMIEventSubscription"
        Name       = $Item.ConsumerName
        Location   = $Item.EventNamespace
        Command    = $Item.CommandLine
    }
}

# =========================
# Unified Persistence Schema
# =========================
$Summary = [PSCustomObject]@{
    ArtifactType   = "AutorunsPersistenceSummary"
    Hostname       = $Hostname
    GeneratedAt    = (Get-Date).ToString("o")
    EntryCount     = $Persistence.Count
    Data           = $Persistence
}

# Export JSON
$Summary | ConvertTo-Json -Depth 6 |
    Out-File -FilePath $OutputFile -Encoding UTF8

# =========================
# Evidence Integrity
# =========================
$Hash = Get-FileHash -Path $OutputFile -Algorithm SHA256

$HashInfo = [PSCustomObject]@{
    FileName  = $OutputFile
    Algorithm = $Hash.Algorithm
    Hash      = $Hash.Hash
    Generated = (Get-Date).ToString("o")
}

$HashInfo | ConvertTo-Json |
    Out-File -FilePath $HashFile -Encoding UTF8

Write-Host "[+] Autoruns persistence summary created" -ForegroundColor Green
Write-Host "[+] JSON Output : $OutputFile" -ForegroundColor Green
Write-Host "[+] Hash Output : $HashFile" -ForegroundColor Green
