$ErrorActionPreference = "SilentlyContinue"
Clear-Host

function Red($msg)    { Write-Host $msg -ForegroundColor Red }
function Green($msg)  { Write-Host $msg -ForegroundColor Green }
function Yellow($msg) { Write-Host $msg -ForegroundColor Yellow }
function Cyan($msg)   { Write-Host $msg -ForegroundColor Cyan }

Write-Host "=== System Integrity Check ===" -ForegroundColor Cyan
Write-Host ""

# Windows Defender
Write-Host "--- Windows Defender ---" -ForegroundColor Cyan
$mp = Get-MpComputerStatus
Green "Real-Time Protection : $($mp.RealTimeProtectionEnabled)"
Green "Antivirus Enabled    : $($mp.AntivirusEnabled)"
Green "Behavior Monitor     : $($mp.BehaviorMonitorEnabled)"
Green "IOAV Protection      : $($mp.IOAVProtectionEnabled)"
Green "Tamper Protection    : $($mp.IsTamperProtected)"
Green "Antispyware          : $($mp.AntispywareEnabled)"

# Defender Exclusions
Write-Host ""
Write-Host "--- Defender Exclusions ---" -ForegroundColor Cyan
$pref = Get-MpPreference

if ($pref.ExclusionPath) {
    Red "Excluded Paths:"
    $pref.ExclusionPath | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
} else {
    Green "No excluded paths"
}

if ($pref.ExclusionProcess) {
    Red "Excluded Processes:"
    $pref.ExclusionProcess | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
} else {
    Green "No excluded processes"
}

# Memory Integrity
Write-Host ""
Write-Host "--- Memory Integrity ---" -ForegroundColor Cyan
$hvci = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
if ($hvci.Enabled -eq 1) { Green "Memory Integrity: ENABLED" } else { Red "Memory Integrity: DISABLED" }

# Device Guard
Write-Host ""
Write-Host "--- Device Guard ---" -ForegroundColor Cyan
Get-CimInstance Win32_DeviceGuard | ForEach-Object {
    Green "VBS Status              : $($_.VirtualizationBasedSecurityStatus)"
    Green "Code Integrity Policy   : $($_.CodeIntegrityPolicyEnforcementStatus)"
}

# Malwarebytes
Write-Host ""
Write-Host "--- Malwarebytes ---" -ForegroundColor Cyan
$mbPath = "HKLM:\SOFTWARE\Malwarebytes"
if (Test-Path $mbPath) {
    $mb = Get-ChildItem $mbPath -Recurse
    if ($mb) {
        Red "Malwarebytes entries found:"
        $mb | ForEach-Object { Write-Host "  $($_.Name)" -ForegroundColor Red }
    } else {
        Green "No Malwarebytes registry entries"
    }
} else {
    Yellow "Malwarebytes not installed"
}

# Downloads Scan
Write-Host ""
Write-Host "--- Recent Executables in Downloads ---" -ForegroundColor Cyan
$downloads = "$env:USERPROFILE\Downloads"
Get-ChildItem $downloads -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -match "\.(exe|dll|sys|bat|ps1)$" } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 20 |
    ForEach-Object {
        Yellow "  $($_.Name)  [$($_.LastWriteTime)]"
    }

# Open Task Manager
Write-Host ""
Write-Host "Opening Task Manager..." -ForegroundColor Cyan
Start-Process taskmgr.exe
