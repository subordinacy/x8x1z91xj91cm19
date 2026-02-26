$ErrorActionPreference = "SilentlyContinue"
Clear-Host

function Red($msg){Write-Host $msg -ForegroundColor Red}
function Green($msg){Write-Host $msg -ForegroundColor Green}
function Yellow($msg){Write-Host $msg -ForegroundColor Yellow}
function Cyan($msg){Write-Host $msg -ForegroundColor Cyan}

Write-Host "=== REAL-TIME SYSTEM INTEGRITY MONITOR ===" -ForegroundColor Cyan
Write-Host "Press CTRL+C to exit.`n" -ForegroundColor Yellow

Write-Host "`n=== WINDOWS DEFENDER STATUS ===" -ForegroundColor Cyan
$mp = Get-MpComputerStatus
Green "RealTimeProtection: $($mp.RealTimeProtectionEnabled)"
Green "AntivirusEnabled: $($mp.AntivirusEnabled)"
Green "BehaviorMonitor: $($mp.BehaviorMonitorEnabled)"
Green "IOAVProtection: $($mp.IOAVProtectionEnabled)"
Green "TamperProtection: $($mp.IsTamperProtected)"
Green "AntispywareEnabled: $($mp.AntispywareEnabled)"

Write-Host "`n=== DEFENDER EXCLUSIONS ===" -ForegroundColor Cyan
$pref = Get-MpPreference
if($pref.ExclusionPath){
    Red "Defender Exclusion Paths:"
    $pref.ExclusionPath | ForEach-Object{Write-Host $_ -ForegroundColor Red}
}else{Green "No exclusion paths found"}

if($pref.ExclusionProcess){
    Red "Defender Exclusion Processes:"
    $pref.ExclusionProcess | ForEach-Object{Write-Host $_ -ForegroundColor Red}
}else{Green "No exclusion processes found"}

Write-Host "`n=== MEMORY INTEGRITY STATUS ===" -ForegroundColor Cyan
$hvci = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
if($hvci.Enabled -eq 1){Green "Memory Integrity: ENABLED"}else{Red "Memory Integrity: DISABLED"}

Write-Host "`n=== DEVICE GUARD STATUS ===" -ForegroundColor Cyan
Get-CimInstance Win32_DeviceGuard | ForEach-Object{
    Green "VBS Status: $($_.VirtualizationBasedSecurityStatus)"
    Green "Code Integrity Policy: $($_.CodeIntegrityPolicyEnforcementStatus)"
}

Write-Host "`n=== MALWAREBYTES EXCLUSIONS ===" -ForegroundColor Cyan
$mbPath = "HKLM:\SOFTWARE\Malwarebytes"
if(Test-Path $mbPath){
    $mb = Get-ChildItem $mbPath -Recurse
    if($mb){
        Red "Malwarebytes entries detected:"
        $mb | ForEach-Object{Write-Host $_.Name -ForegroundColor Red}
    }else{Green "No Malwarebytes registry entries found"}
}else{Yellow "Malwarebytes not detected"}

Write-Host "`n=== FAST DOWNLOADS SCAN ===" -ForegroundColor Cyan
$downloads = "$env:USERPROFILE\Downloads"
Get-ChildItem $downloads -Recurse -ErrorAction SilentlyContinue |
Where-Object {$_.Extension -match ".exe|.dll|.sys|.bat|.ps1"} |
Sort-Object LastWriteTime -Descending |
Select-Object -First 20 |
ForEach-Object{
    Write-Host "$($_.Name) - $($_.LastWriteTime)" -ForegroundColor Yellow
}

Write-Host "`n=== INITIAL PROCESS SNAPSHOT ===" -ForegroundColor Cyan
$known = @{}
Get-Process | ForEach-Object{
    $known[$_.Id] = $_.ProcessName
}

while($true){
    Start-Sleep -Seconds 2
    $current = Get-Process
    foreach($proc in $current){
        if(-not $known.ContainsKey($proc.Id)){
            Red "`nNEW PROCESS DETECTED"
            Write-Host "Name: $($proc.ProcessName)" -ForegroundColor Red
            Write-Host "PID: $($proc.Id)" -ForegroundColor Red
            Write-Host "Path: $($proc.Path)" -ForegroundColor Red
            Write-Host "StartTime: $($proc.StartTime)" -ForegroundColor Red
            $known[$proc.Id] = $proc.ProcessName
        }
    }
}
