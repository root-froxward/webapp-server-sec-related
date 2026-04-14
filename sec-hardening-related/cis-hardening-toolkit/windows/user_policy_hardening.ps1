#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$BackupDir = "C:\CIS-Backup\user-policy"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "C:\CIS-Backup\cis-hardening-userpolicy-$Timestamp.log"

if (-not (Test-Path $BackupDir)) { New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null }

function Write-Log {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry
    Add-Content -Path $LogFile -Value $entry
}

Write-Log "Starting user/password policy hardening based on CIS Benchmark 1.1.x, 1.2.x"

secedit /export /cfg "$BackupDir\secpol_$Timestamp.inf" | Out-Null
Write-Log "BACKUP: current security policy exported"

$secTemplate = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 365
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
ClearTextPassword = 0
[Version]
signature="`$CHICAGO`$"
Revision=1
"@

$templatePath = "$BackupDir\cis_secpol_$Timestamp.inf"
$dbPath = "$BackupDir\cis_secpol_$Timestamp.sdb"

Set-Content -Path $templatePath -Value $secTemplate -Encoding Unicode
Write-Log "CREATED: security template"

secedit /configure /db $dbPath /cfg $templatePath /areas SECURITYPOLICY | Out-Null
Write-Log "APPLIED: password and account lockout policies"

Write-Log "SET: MinimumPasswordAge = 1"
Write-Log "SET: MaximumPasswordAge = 365"
Write-Log "SET: MinimumPasswordLength = 14"
Write-Log "SET: PasswordComplexity = 1"
Write-Log "SET: PasswordHistorySize = 24"
Write-Log "SET: LockoutBadCount = 5"
Write-Log "SET: ResetLockoutCount = 15 minutes"
Write-Log "SET: LockoutDuration = 15 minutes"

$guestAccount = Get-LocalUser | Where-Object { $_.SID -like "*-501" }
if ($guestAccount -and $guestAccount.Enabled) {
    Disable-LocalUser -Name $guestAccount.Name
    Write-Log "DISABLED: Guest account ($($guestAccount.Name))"
} else {
    Write-Log "OK: Guest account already disabled"
}

$adminAccount = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
if ($adminAccount.Name -eq "Administrator") {
    Write-Log "WARN: Default Administrator account has not been renamed (CIS 1.1.6)"
} else {
    Write-Log "OK: Administrator account renamed to $($adminAccount.Name)"
}

$inactiveThreshold = (Get-Date).AddDays(-90)
Get-LocalUser | Where-Object { $_.Enabled -and $_.LastLogon -and $_.LastLogon -lt $inactiveThreshold } | ForEach-Object {
    Write-Log "WARN: Inactive user (90+ days): $($_.Name) — last logon: $($_.LastLogon)"
}

Write-Log "User/password policy hardening complete. Log: $LogFile"
