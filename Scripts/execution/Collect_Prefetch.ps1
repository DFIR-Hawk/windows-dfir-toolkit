# ==========================================
# Windows DFIR - Prefetch Collection
# Version : 1.0
# Author  : Subash J
# Purpose : Execution evidence collection
# ==========================================

# Admin check
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Run as Administrator"
    exit
}

$Hostname  = $env:COMPUTERNAME
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BaseDir   = "C:\IR_Collection"
$OutDir    = "$BaseDir\Prefetch_$Hostname`_$Timestamp"

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$PrefetchPath = "C:\Windows\Prefetch"

if (Test-Path $PrefetchPath) {
    Copy-Item "$PrefetchPath\*.pf" -Destination $OutDir -Force -ErrorAction SilentlyContinue
}

# Hashing
Get-ChildItem $OutDir -Filter *.pf | ForEach-Object {
    Get-FileHash $_.FullName -Algorithm SHA256
} | Out-File "$OutDir\hashes.txt"

Write-Host "[+] Prefetch collected at $OutDir"
