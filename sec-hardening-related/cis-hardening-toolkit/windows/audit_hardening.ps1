#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$BackupDir = "C:\CIS-Backup\audit"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "C:\CIS-Backup\cis-hardening-audit-$Timestamp.log"

if (-not (Test-Path $BackupDir)) { New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null }

function Write-Log {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry
    Add-Content -Path $LogFile -Value $entry
}

Write-Log "Starting audit policy hardening based on CIS Benchmark 17.x"

auditpol /backup /file:"$BackupDir\auditpol_$Timestamp.csv" | Out-Null
Write-Log "BACKUP: current audit policy exported"

$auditPolicies = @(
    @{ Subcategory="Credential Validation"; Success="enable"; Failure="enable" },
    @{ Subcategory="Application Group Management"; Success="enable"; Failure="enable" },
    @{ Subcategory="Computer Account Management"; Success="enable"; Failure="enable" },
    @{ Subcategory="Other Account Management Events"; Success="enable"; Failure="enable" },
    @{ Subcategory="Security Group Management"; Success="enable"; Failure="enable" },
    @{ Subcategory="User Account Management"; Success="enable"; Failure="enable" },
    @{ Subcategory="Process Creation"; Success="enable"; Failure="disable" },
    @{ Subcategory="Account Lockout"; Success="enable"; Failure="enable" },
    @{ Subcategory="Group Membership"; Success="enable"; Failure="disable" },
    @{ Subcategory="Logoff"; Success="enable"; Failure="disable" },
    @{ Subcategory="Logon"; Success="enable"; Failure="enable" },
    @{ Subcategory="Other Logon/Logoff Events"; Success="enable"; Failure="enable" },
    @{ Subcategory="Special Logon"; Success="enable"; Failure="disable" },
    @{ Subcategory="Detailed File Share"; Success="enable"; Failure="disable" },
    @{ Subcategory="File Share"; Success="enable"; Failure="enable" },
    @{ Subcategory="Other Object Access Events"; Success="enable"; Failure="enable" },
    @{ Subcategory="Removable Storage"; Success="enable"; Failure="enable" },
    @{ Subcategory="Audit Policy Change"; Success="enable"; Failure="enable" },
    @{ Subcategory="Authentication Policy Change"; Success="enable"; Failure="disable" },
    @{ Subcategory="Authorization Policy Change"; Success="enable"; Failure="disable" },
    @{ Subcategory="Sensitive Privilege Use"; Success="enable"; Failure="enable" },
    @{ Subcategory="IPsec Driver"; Success="enable"; Failure="enable" },
    @{ Subcategory="Other System Events"; Success="enable"; Failure="enable" },
    @{ Subcategory="Security State Change"; Success="enable"; Failure="disable" },
    @{ Subcategory="Security System Extension"; Success="enable"; Failure="enable" },
    @{ Subcategory="System Integrity"; Success="enable"; Failure="enable" }
)

foreach ($policy in $auditPolicies) {
    $sub = $policy.Subcategory
    auditpol /set /subcategory:"$sub" /success:$($policy.Success) /failure:$($policy.Failure) 2>$null
    Write-Log "SET: $sub — success:$($policy.Success) failure:$($policy.Failure)"
}

$logNames = @("Application", "Security", "System", "Setup")
foreach ($logName in $logNames) {
    $log = Get-WinEvent -ListLog $logName
    if ($log.MaximumSizeInBytes -lt 209715200) {
        Limit-EventLog -LogName $logName -MaximumSize 200MB
        Write-Log "SET: $logName event log max size to 200MB"
    } else {
        Write-Log "OK: $logName event log size already >= 200MB"
    }
    Limit-EventLog -LogName $logName -OverflowAction OverwriteAsNeeded
    Write-Log "SET: $logName overflow action to OverwriteAsNeeded"
}

$commandLineAudit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $commandLineAudit)) {
    New-Item -Path $commandLineAudit -Force | Out-Null
}
Set-ItemProperty -Path $commandLineAudit -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
Write-Log "SET: Command line auditing in process creation events enabled"

$powerShellLogging = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $powerShellLogging)) {
    New-Item -Path $powerShellLogging -Force | Out-Null
}
Set-ItemProperty -Path $powerShellLogging -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Write-Log "SET: PowerShell script block logging enabled"

$moduleLogging = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $moduleLogging)) {
    New-Item -Path $moduleLogging -Force | Out-Null
}
Set-ItemProperty -Path $moduleLogging -Name "EnableModuleLogging" -Value 1 -Type DWord

$moduleNames = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
if (-not (Test-Path $moduleNames)) {
    New-Item -Path $moduleNames -Force | Out-Null
}
Set-ItemProperty -Path $moduleNames -Name "*" -Value "*" -Type String
Write-Log "SET: PowerShell module logging enabled for all modules"

Write-Log "Audit policy hardening complete. Log: $LogFile"
