<#
.SYNOPSIS
    Collects local users and group memberships for DFIR investigations.

.DESCRIPTION
    Enumerates local user accounts and local group memberships to
    identify unauthorized accounts, privilege escalation, and
    persistence via valid accounts.

.IR_PHASE
    Privilege Escalation / Persistence / Investigation

.MITRE_ATTCK
    T1136.001 - Create Account: Local Account
    T1078 - Valid Accounts
    T1068 - Privilege Escalation
    T1021.001 - Remote Services: RDP

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
$LogFile   = "$BasePath\Local_Users_Groups_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param ($Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Local users and groups collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "Administrator privileges recommended for full user and group visibility."
}

# =========================
# Local User Collection
# =========================
Write-Host "[*] Collecting local users..." -ForegroundColor Cyan
Write-Log "Enumerating local users"

$Users = Get-LocalUser -ErrorAction SilentlyContinue

$UserData = foreach ($User in $Users) {
    [PSCustomObject]@{
        Hostname           = $Hostname
        CollectionTime     = (Get-Date).ToString("o")
        UserName           = $User.Name
        FullName           = $User.FullName
        Enabled            = $User.Enabled
        PasswordRequired   = $User.PasswordRequired
        PasswordExpires    = $User.PasswordExpires
        LastLogon          = $User.LastLogon
        SID                = $User.SID.Value
    }
}

# =========================
# Local Group Collection
# =========================
Write-Host "[*] Collecting local groups..." -ForegroundColor Cyan
Write-Log "Enumerating local groups"

$Groups = Get-LocalGroup -ErrorAction SilentlyContinue

$GroupData = foreach ($Group in $Groups) {

    $Members = @()
    try {
        $Members = (Get-LocalGroupMember -Group $Group.Name -ErrorAction Stop |
            Select-Object -ExpandProperty Name)
    } catch {
        $Members = "Unable to enumerate members"
    }

    [PSCustomObject]@{
        Hostname       = $Hostname
        CollectionTime = (Get-Date).ToString("o")
        GroupName      = $Group.Name
        Description    = $Group.Description
        Members        = $Members
    }
}

# =========================
# Unified Evidence Schema
# =========================
$Evidence = [PSCustomObject]@{
    ArtifactType = "LocalUsersAndGroups"
    Hostname     = $Hostname
    CollectedAt  = (Get-Date).ToString("o")
    ToolVersion  = "1.0"
    UserCount    = $UserData.Count
    GroupCount   = $GroupData.Count
    Users        = $UserData
    Groups       = $GroupData
}

$JsonFile = "$BasePath\Local_Users_Groups_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence | ConvertTo-Json -Depth 6 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Local users and groups exported to JSON"

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

Write-Host "[+] Local users and groups collection completed" -ForegroundColor Green
Write-Host "[+] JSON Output : $JsonFile" -ForegroundColor Green
Write-Host "[+] Hash Output : $HashFile" -ForegroundColor Green
Write-Host "[+] Execution Log : $LogFile" -ForegroundColor Green

Write-Log "Script execution completed"
