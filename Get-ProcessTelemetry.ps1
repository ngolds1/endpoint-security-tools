<#
.SYNOPSIS
    Queries active process telemetry to identify unusual command-line execution and LOLBin activity.
.DESCRIPTION
    Inspects process tree ancestry and alerts on administrative shells launched from temporary user directories or browser parents.
#>

[CmdletBinding()]
param ()

Write-Host "=== Process Telemetry & LOLBin Execution Audit ===" -ForegroundColor Cyan

$TargetShells = @("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")

# Retrieve running processes with CIM and process via pipeline
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath | ForEach-Object {
    $proc =$_

    # Check for shells running out of Temp directories
    if ($proc.ExecutablePath -like "*\AppData\Local\Temp\*" -and $proc.Name -in$TargetShells) {
        Write-Host "[ALERT] Shell executing from Temp Directory!" -ForegroundColor Red
        Write-Host "        PID: $($proc.ProcessId) | Path: $($proc.ExecutablePath)" -ForegroundColor Yellow
        Write-Host "        Cmd: $($proc.CommandLine)`n"
    }

    # Check for encoded command line execution
    if ($proc.CommandLine -like "*-EncodedCommand*" -or $proc.CommandLine -like "*-enc *") {
        Write-Host "[WARN] Encoded PowerShell execution detected!" -ForegroundColor Red
        Write-Host "       PID: $($proc.ProcessId) | Cmd: $($proc.CommandLine)`n" -ForegroundColor Yellow
    }
}