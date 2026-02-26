$ErrorActionPreference = "SilentlyContinue"

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$logPath = "$env:USERPROFILE\Desktop\Integrity_Report_$timestamp.txt"

function Write-Log {
    param([string]$text)
    Add-Content -Path $logPath -Value $text
}

Write-Log "=== SYSTEM INTEGRITY REPORT ==="
Write-Log "Generated: $(Get-Date)"
Write-Log ""

Write-Log "=== WINDOWS DEFENDER STATUS ==="
$defender = Get-MpComputerStatus
Write-Log "RealTimeProtectionEnabled: $($defender.RealTimeProtectionEnabled)"
Write-Log "AntivirusEnabled: $($defender.AntivirusEnabled)"
Write-Log "BehaviorMonitorEnabled: $($defender.BehaviorMonitorEnabled)"
Write-Log "IOAVProtectionEnabled: $($defender.IOAVProtectionEnabled)"
Write-Log ""

Write-Log "=== DEFENDER EXCLUSIONS ==="
$exclusions = Get-MpPreference
Write-Log "ExclusionPaths:"
$exclusions.ExclusionPath | ForEach-Object { Write-Log $_ }
Write-Log "ExclusionProcesses:"
$exclusions.ExclusionProcess | ForEach-Object { Write-Log $_ }
Write-Log ""

Write-Log "=== MEMORY INTEGRITY (HVCI) STATUS ==="
$hvci = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
Write-Log "MemoryIntegrityEnabled: $($hvci.Enabled)"
Write-Log ""

Write-Log "=== CORE DEVICE GUARD STATUS ==="
Get-CimInstance -ClassName Win32_DeviceGuard | ForEach-Object {
    Write-Log "VirtualizationBasedSecurityStatus: $($_.VirtualizationBasedSecurityStatus)"
    Write-Log "CodeIntegrityPolicyEnforcementStatus: $($_.CodeIntegrityPolicyEnforcementStatus)"
}
Write-Log ""

Write-Log "=== RECENT PREFETCH FILES (Last 50) ==="
$prefetchPath = "C:\Windows\Prefetch"
Get-ChildItem $prefetchPath -ErrorAction SilentlyContinue |
Sort-Object LastWriteTime -Descending |
Select-Object -First 50 |
ForEach-Object {
    Write-Log "$($_.Name) - $($_.LastWriteTime)"
}
Write-Log ""

Write-Log "=== RECENTLY EXECUTED PROGRAMS (UserAssist) ==="
$userAssistPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
Get-ChildItem $userAssistPath | ForEach-Object {
    Get-ItemProperty $_.PsPath | ForEach-Object {
        $_.PSObject.Properties | Where-Object { $_.Name -match "Count" } | ForEach-Object {
            Write-Log "$($_.Name): $($_.Value)"
        }
    }
}
Write-Log ""

Write-Log "=== RUNNING PROCESSES ==="
Get-Process | Sort-Object CPU -Descending | ForEach-Object {
    Write-Log "$($_.ProcessName) - ID: $($_.Id)"
}
Write-Log ""

Write-Log "=== UNSIGNED DRIVERS ==="
Get-WmiObject Win32_PnPSignedDriver |
Where-Object { $_.IsSigned -eq $false } |
ForEach-Object {
    Write-Log "$($_.DeviceName) - $($_.DriverVersion)"
}
Write-Log ""

Write-Log "=== SCRIPT COMPLETE ==="
Write-Output "Integrity report saved to: $logPath"
