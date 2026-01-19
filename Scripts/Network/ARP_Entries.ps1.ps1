<#
.SYNOPSIS
    Collects IPv4 ARP cache entries for DFIR investigations.

.DESCRIPTION
    Retrieves ARP neighbor information using native PowerShell cmdlets
    and maps network interfaces to identify suspicious devices, rogue
    gateways, and potential ARP spoofing or MITM activity.

.IR_PHASE
    Identification / Live Response

.FORENSIC_SAFETY
    Read-only, forensic-safe (does not modify system state)

.OUTPUT
    JSON evidence file + SHA256 hash file stored in C:\IR_Collection\

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

if (-not $IsAdmin) {
    Write-Warning "Script is NOT running as Administrator. Output may be incomplete."
}

# =========================
# Environment Information
# =========================
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = "C:\IR_Collection"

# Create evidence directory if it doesn't exist
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

$JsonFile = "$BasePath\ARP_Entries_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

Write-Host "[*] Collecting ARP cache entries..." -ForegroundColor Cyan

try {
    # Retrieve network adapters for interface mapping
    $Adapters = Get-NetAdapter -ErrorAction Stop | Select-Object ifIndex, Name

    # Retrieve IPv4 ARP entries
    $ArpEntries = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop

    $Results = foreach ($Entry in $ArpEntries) {

        $AdapterName = ($Adapters | Where-Object { $_.ifIndex -eq $Entry.InterfaceIndex }).Name

        [PSCustomObject]@{
            Hostname        = $Hostname
            CollectionTime  = (Get-Date).ToString("o")   # ISO 8601
            IPAddress       = $Entry.IPAddress
            MACAddress      = $Entry.LinkLayerAddress
            Interface       = $AdapterName
            InterfaceIndex  = $Entry.InterfaceIndex
            State           = $Entry.State
            CacheType       = if ($Entry.IsPermanent -eq $true) { "Static" } else { "Dynamic" }
            IsRouter        = $Entry.IsRouter
        }
    }

    # Export JSON evidence
    $Results | ConvertTo-Json -Depth 4 |
        Out-File -FilePath $JsonFile -Encoding UTF8

    # =========================
    # Evidence Integrity (SHA256)
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

    Write-Host "[+] ARP data successfully collected" -ForegroundColor Green
    Write-Host "[+] JSON Output : $JsonFile" -ForegroundColor Green
    Write-Host "[+] Hash Output : $HashFile" -ForegroundColor Green

} catch {
    Write-Error "[!] Failed to collect ARP entries."
    Write-Error $_
}
