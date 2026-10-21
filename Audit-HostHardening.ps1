<#
.SYNOPSIS
    Audits core Windows host hardening controls and telemetry configurations.
.DESCRIPTION
    Checks LSA RunAsPPL protection, PowerShell script block logging status,
    and UAC execution policies for baseline compliance.
#>

[CmdletBinding()]
param ()

Write-Host "=== Host Security Baseline Audit ===" -ForegroundColor Cyan

# 1. Check LSA Protection (RunAsPPL)
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lsaPpl = (Get-ItemProperty -Path $lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL

if ($lsaPpl -ge 1) {
    Write-Host "[PASS] LSA Protection (RunAsPPL) is ENABLED (Value: $lsaPpl)" -ForegroundColor Green
} else {
    Write-Host "[WARN] LSA Protection (RunAsPPL) is DISABLED or NOT CONFIGURED" -ForegroundColor Red
}

# 2. Check PowerShell Script Block Logging
$psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$sbLogging = (Get-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging

if ($sbLogging -eq 1) {
    Write-Host "[PASS] PowerShell Script Block Logging is ENABLED" -ForegroundColor Green
} else {
    Write-Host "[WARN] PowerShell Script Block Logging is NOT ENABLED in Registry" -ForegroundColor Yellow
}

# 3. Check UAC Consent Prompt Behavior
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$uacLevel = (Get-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin

Write-Host "[INFO] UAC Admin Consent Level: $uacLevel" -ForegroundColor Cyan