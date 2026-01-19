<#
.SYNOPSIS
    Collects WMI permanent event subscriptions for persistence detection.

.DESCRIPTION
    Enumerates WMI Event Filters, CommandLineEventConsumers,
    and FilterToConsumerBindings to identify stealthy fileless
    persistence mechanisms.

.IR_PHASE
    Persistence / Advanced Investigation

.MITRE_ATTCK
    T1546.003 - WMI Event Subscription
    T1059 - Command-Line / PowerShell
    T1106 - Native API
    T1027 - Obfuscated Files or Information

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
$LogFile   = "$BasePath\WMI_Persistence_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param ($Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "WMI persistence collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "Administrator privileges required to enumerate WMI subscriptions."
}

# =========================
# WMI Persistence Collection
# =========================
Write-Host "[*] Collecting WMI Event Subscriptions..." -ForegroundColor Cyan
Write-Log "Enumerating WMI Event Filters, Consumers, and Bindings"

$Filters   = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
$Consumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
$Bindings  = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue

$Data = foreach ($Binding in $Bindings) {

    $Filter   = $Filters | Where-Object { $_.__PATH -eq $Binding.Filter }
    $Consumer = $Consumers | Where-Object { $_.__PATH -eq $Binding.Consumer }

    [PSCustomObject]@{
        Hostname        = $Hostname
        CollectionTime  = (Get-Date).ToString("o")
        FilterName      = $Filter.Name
        FilterQuery     = $Filter.Query
        EventNamespace  = $Filter.EventNamespace
        ConsumerName    = $Consumer.Name
        CommandLine     = $Consumer.CommandLineTemplate
        Executable      = $Consumer.ExecutablePath
    }
}

# =========================
# Unified Evidence Schema
# =========================
$Evidence = [PSCustomObject]@{
    ArtifactType = "WMIPersistence"
    Hostname     = $Hostname
    CollectedAt  = (Get-Date).ToString("o")
    ToolVersion  = "1.0"
    EntryCount   = $Data.Count
    Data         = $Data
}

$JsonFile = "$BasePath\WMI_Persistence_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence | ConvertTo-Json -Depth 6 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "WMI persistence data exported to JSON"

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

Write-Host "[+] WMI persistence collection completed" -ForegroundColor Green
Write-Host "[+] JSON Output : $JsonFile" -ForegroundColor Green
Write-Host "[+] Hash Output : $HashFile" -ForegroundColor Green
Write-Host "[+] Execution Log : $LogFile" -ForegroundColor Green

Write-Log "Script execution completed"
