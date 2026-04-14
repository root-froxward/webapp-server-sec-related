#Requires -RunAsAdministrator

param(
    [switch]$Audit
)

$ErrorActionPreference = "Continue"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = "C:\CIS-Backup\cis-audit-report-$Timestamp.txt"
$Pass = 0
$Fail = 0
$Warn = 0

if (-not (Test-Path "C:\CIS-Backup")) { New-Item -Path "C:\CIS-Backup" -ItemType Directory -Force | Out-Null }

function Write-Result {
    param([string]$Status, [string]$Control, [string]$Detail)
    $line = "[$Status] $Control - $Detail"
    Write-Host $line
    Add-Content -Path $ReportFile -Value $line
    switch ($Status) {
        "PASS" { $script:Pass++ }
        "FAIL" { $script:Fail++ }
        "WARN" { $script:Warn++ }
    }
}

$header = @"
=============================================
  CIS Benchmark Compliance Audit Report
  Date: $(Get-Date)
  Host: $env:COMPUTERNAME
=============================================
"@

Write-Host $header
Set-Content -Path $ReportFile -Value $header

Write-Host "`n--- Firewall (CIS 9.x) ---"
Add-Content -Path $ReportFile -Value "`n--- Firewall (CIS 9.x) ---"

foreach ($profile in @("Domain", "Private", "Public")) {
    $fw = Get-NetFirewallProfile -Name $profile
    if ($fw.Enabled) {
        Write-Result "PASS" "CIS 9.1.1" "$profile profile: enabled"
    } else {
        Write-Result "FAIL" "CIS 9.1.1" "$profile profile: disabled"
    }
    if ($fw.DefaultInboundAction -eq "Block") {
        Write-Result "PASS" "CIS 9.x" "$profile inbound: Block"
    } else {
        Write-Result "FAIL" "CIS 9.x" "$profile inbound: $($fw.DefaultInboundAction) (expected Block)"
    }
    if ($fw.LogBlocked) {
        Write-Result "PASS" "CIS 9.x" "$profile log blocked: enabled"
    } else {
        Write-Result "FAIL" "CIS 9.x" "$profile log blocked: disabled"
    }
}

Write-Host "`n--- Account Policies (CIS 1.1.x, 1.2.x) ---"
Add-Content -Path $ReportFile -Value "`n--- Account Policies (CIS 1.1.x, 1.2.x) ---"

$tempCfg = "$env:TEMP\secpol_audit_$Timestamp.inf"
secedit /export /cfg $tempCfg | Out-Null
$secpol = Get-Content $tempCfg

function Get-SecPolValue {
    param([string]$Key)
    $line = $secpol | Where-Object { $_ -match "^\s*$Key\s*=" }
    if ($line) { return ($line -split "=")[1].Trim() }
    return $null
}

$checks = @(
    @{ Key="MinimumPasswordLength"; Expected="14"; Control="CIS 1.1.2"; Op="ge" },
    @{ Key="PasswordComplexity"; Expected="1"; Control="CIS 1.1.5"; Op="eq" },
    @{ Key="PasswordHistorySize"; Expected="24"; Control="CIS 1.1.1"; Op="ge" },
    @{ Key="MaximumPasswordAge"; Expected="365"; Control="CIS 1.1.3"; Op="le" },
    @{ Key="MinimumPasswordAge"; Expected="1"; Control="CIS 1.1.4"; Op="ge" },
    @{ Key="LockoutBadCount"; Expected="5"; Control="CIS 1.2.1"; Op="le" },
    @{ Key="ClearTextPassword"; Expected="0"; Control="CIS 1.1.6"; Op="eq" }
)

foreach ($check in $checks) {
    $actual = Get-SecPolValue -Key $check.Key
    if ($null -eq $actual) {
        Write-Result "WARN" $check.Control "$($check.Key): not configured"
        continue
    }
    $pass = switch ($check.Op) {
        "eq" { [int]$actual -eq [int]$check.Expected }
        "ge" { [int]$actual -ge [int]$check.Expected }
        "le" { [int]$actual -le [int]$check.Expected }
    }
    if ($pass) {
        Write-Result "PASS" $check.Control "$($check.Key) = $actual"
    } else {
        Write-Result "FAIL" $check.Control "$($check.Key) = $actual (expected $($check.Op) $($check.Expected))"
    }
}

Remove-Item $tempCfg -Force -ErrorAction SilentlyContinue

$guestAccount = Get-LocalUser | Where-Object { $_.SID -like "*-501" }
if ($guestAccount -and -not $guestAccount.Enabled) {
    Write-Result "PASS" "CIS 1.1.7" "Guest account is disabled"
} else {
    Write-Result "FAIL" "CIS 1.1.7" "Guest account is enabled"
}

Write-Host "`n--- Audit Policy (CIS 17.x) ---"
Add-Content -Path $ReportFile -Value "`n--- Audit Policy (CIS 17.x) ---"

$requiredAudits = @(
    "Credential Validation",
    "Security Group Management",
    "User Account Management",
    "Process Creation",
    "Account Lockout",
    "Logon",
    "Logoff",
    "Special Logon",
    "Audit Policy Change",
    "Sensitive Privilege Use",
    "System Integrity"
)

foreach ($sub in $requiredAudits) {
    $result = auditpol /get /subcategory:"$sub" 2>$null
    if ($result -match "Success and Failure|Success") {
        Write-Result "PASS" "CIS 17.x" "$sub audit: configured"
    } else {
        Write-Result "FAIL" "CIS 17.x" "$sub audit: not configured"
    }
}

$cmdLineKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$cmdLineVal = (Get-ItemProperty -Path $cmdLineKey -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
if ($cmdLineVal -eq 1) {
    Write-Result "PASS" "CIS 17.x" "Command line auditing: enabled"
} else {
    Write-Result "FAIL" "CIS 17.x" "Command line auditing: disabled"
}

$psLogging = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$psVal = (Get-ItemProperty -Path $psLogging -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
if ($psVal -eq 1) {
    Write-Result "PASS" "CIS 17.x" "PowerShell script block logging: enabled"
} else {
    Write-Result "FAIL" "CIS 17.x" "PowerShell script block logging: disabled"
}

$footer = @"

=============================================
  RESULTS: $Pass PASS / $Fail FAIL / $Warn WARN
  Total checks: $($Pass + $Fail + $Warn)
  Report saved: $ReportFile
=============================================
"@

Write-Host $footer
Add-Content -Path $ReportFile -Value $footer
