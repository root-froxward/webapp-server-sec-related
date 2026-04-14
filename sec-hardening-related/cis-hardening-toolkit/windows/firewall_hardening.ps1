#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$BackupDir = "C:\CIS-Backup\firewall"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "C:\CIS-Backup\cis-hardening-firewall-$Timestamp.log"

if (-not (Test-Path $BackupDir)) { New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null }

function Write-Log {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry
    Add-Content -Path $LogFile -Value $entry
}

Write-Log "Starting firewall hardening based on CIS Benchmark 9.x"

netsh advfirewall export "$BackupDir\firewall_policy_$Timestamp.wfw" | Out-Null
Write-Log "BACKUP: current firewall policy exported"

Set-NetFirewallProfile -Profile Domain -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 16384 -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\domainfw.log"
Write-Log "SET: Domain profile — enabled, inbound block, logging on"

Set-NetFirewallProfile -Profile Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 16384 -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\privatefw.log"
Write-Log "SET: Private profile — enabled, inbound block, logging on"

Set-NetFirewallProfile -Profile Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 16384 -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\publicfw.log"
Write-Log "SET: Public profile — enabled, inbound/outbound block, logging on"

$rules = @(
    @{ Name="CIS-Allow-DNS-Out"; Direction="Outbound"; Protocol="UDP"; RemotePort=53; Action="Allow"; Profile="Any" },
    @{ Name="CIS-Allow-HTTP-Out"; Direction="Outbound"; Protocol="TCP"; RemotePort=80; Action="Allow"; Profile="Any" },
    @{ Name="CIS-Allow-HTTPS-Out"; Direction="Outbound"; Protocol="TCP"; RemotePort=443; Action="Allow"; Profile="Any" },
    @{ Name="CIS-Allow-NTP-Out"; Direction="Outbound"; Protocol="UDP"; RemotePort=123; Action="Allow"; Profile="Any" },
    @{ Name="CIS-Allow-RDP-In"; Direction="Inbound"; Protocol="TCP"; LocalPort=3389; Action="Allow"; Profile="Domain,Private" }
)

foreach ($rule in $rules) {
    $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
    if ($existing) { Remove-NetFirewallRule -DisplayName $rule.Name }

    $params = @{
        DisplayName = $rule.Name
        Direction = $rule.Direction
        Protocol = $rule.Protocol
        Action = $rule.Action
        Profile = $rule.Profile
        Enabled = "True"
    }

    if ($rule.ContainsKey("RemotePort")) { $params.RemotePort = $rule.RemotePort }
    if ($rule.ContainsKey("LocalPort")) { $params.LocalPort = $rule.LocalPort }

    New-NetFirewallRule @params | Out-Null
    Write-Log "RULE: $($rule.Name) — $($rule.Direction) $($rule.Protocol)/$($rule.RemotePort)$($rule.LocalPort) $($rule.Action)"
}

Write-Log "Firewall hardening complete. Log: $LogFile"
