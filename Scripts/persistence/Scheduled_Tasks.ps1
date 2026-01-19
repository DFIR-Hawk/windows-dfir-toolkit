<#
.SYNOPSIS
    Collects scheduled tasks to identify persistence mechanisms.

.DESCRIPTION
    Enumerates Windows scheduled tasks and extracts execution
    commands, triggers, and run context to detect malicious
    persistence techniques.

.IR_PHASE
    Persistence / Investigation

.MITRE_ATTCK
    T1053.005 - Scheduled Task
    T1059 - Command-Line / PowerShell
    T1106 - Native API
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
$LogFile   = "$BasePath\ScheduledTasks_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param ($Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Scheduled task collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "Administrator privileges recommended for full scheduled task visibility."
}

# =========================
# Task Collection
# =========================
Write-Host "[*] Collecting scheduled tasks..." -ForegroundColor Cyan
Write-Log "Enumerating scheduled tasks"

$Tasks = Get-ScheduledTask -ErrorAction SilentlyContinue

$TaskData = foreach ($Task in $Tasks) {

    foreach ($Action in $Task.Actions) {
        [PSCustomObject]@{
            Hostname       = $Hostname
            CollectionTime = (Get-Date).ToString("o")
            TaskName       = $Task.TaskName
            TaskPath       = $Task.TaskPath
            State          = $Task.State
            RunAsUser      = $Task.Principal.UserId
            LogonType      = $Task.Principal.LogonType
            Command        = $Action.Execute
            Arguments      = $Action.Arguments
            TriggerType    = ($Task.Triggers | ForEach-Object { $_.TriggerType }) -join ", "
        }
    }
}

# =========================
# Unified Evidence Schema
# =========================
$Evidence = [PSCustomObject]@{
    ArtifactType = "ScheduledTasks"
    Hostname     = $Hostname
    CollectedAt  = (Get-Date).ToString("o")
    ToolVersion  = "1.0"
    TaskCount    = $TaskData.Count
    Data         = $TaskData
}

$JsonFile = "$BasePath\Scheduled_Tasks_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence | ConvertTo-Json -Depth 6 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Scheduled tasks exported to JSON"

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

Write-Host "[+] Scheduled task collection completed" -ForegroundColor Green
Write-Host "[+] JSON Output : $JsonFile" -ForegroundColor Green
Write-Host "[+] Hash Output : $HashFile" -ForegroundColor Green
Write-Host "[+] Execution Log : $LogFile" -ForegroundColor Green

Write-Log "Script execution completed"
