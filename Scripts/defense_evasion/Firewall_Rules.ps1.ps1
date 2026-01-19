<#
.SYNOPSIS
    Collects Windows Firewall rules for DFIR investigations.

.DESCRIPTION
    Enumerates inbound and outbound firewall rules to identify
    defense evasion, C2 enablement, and unauthorized network access.

.IR_PHASE
    Defense Evasion / Live Response

.MITRE_ATTCK
    T1562.004 - Disable or Modify Firewall
    T1105 - Ingress Tool Transfer
    T1071 - Application Layer Protocol
    T1046 - Network Service Scanning

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
$LogFile   = "$BasePath\Firewall_Rules_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param ($Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Firewall rule collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "Administrator privileges recommended for full firewall rule visibility."
}

# =========================
# Firewall Rule Collection
# =========================
Write-Host "[*] Collecting firewall rules..." -ForegroundColor Cyan
Write-Log "Enumerating firewall rules"

$Rules = Get-NetFirewallRule -ErrorAction SilentlyContinue

$RuleData = foreach ($Rule in $Rules) {

    $PortFilter  = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue
    $AppFilter   = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue
    $AddrFilter  = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        Hostname        = $Hostname
        CollectionTime  = (Get-Date).ToString("o")
        RuleName        = $Rule.DisplayName
        Direction       = $Rule.Direction
        Action          = $Rule.Action
        Enabled         = $Rule.Enabled
        Profile         = $Rule.Profile
        Program         = $AppFilter.Program
        LocalPort       = $PortFilter.LocalPort
        RemotePort      = $PortFilter.RemotePort
        LocalAddress    = $AddrFilter.LocalAddress
        RemoteAddress   = $AddrFilter.RemoteAddress
    }
}

# =========================
# Unified Evidence Schema
# =========================
$Evidence = [PSCustomObject]@{
    ArtifactType = "FirewallRules"
    Hostname     = $Hostname
    CollectedAt  = (Get-Date).ToString("o")
    ToolVersion  = "1.0"
    RuleCount    = $RuleData.Count
    Data         = $RuleData
}

$JsonFile = "$BasePath\Firewall_Rules_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence | ConvertTo-Json -Depth 6 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Firewall rules exported to JSON"

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

Write-Host "[+] Firewall rule collection completed" -ForegroundColor Green
Write-Host "[+] JSON Output : $JsonFile" -ForegroundColor Green
Write-Host "[+] Hash Output : $HashFile" -ForegroundColor Green
Write-Host "[+] Execution Log : $LogFile" -ForegroundColor Green

Write-Log "Script execution completed"
