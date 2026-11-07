#Requires -Version 5.1
<#
.SYNOPSIS
    OPNGate guided deployment from Windows using Git for Windows.
.EXAMPLE
    .\Deploy.ps1
.EXAMPLE
    .\Deploy.ps1 -Action Check -NonInteractive
#>
[CmdletBinding()]
param(
    [ValidateSet('Deploy','Menu','Configure','Install','Update','Rollback','Check','Status')]
    [string]$Action = 'Deploy',
    [string]$ConfigPath,
    [string]$BashPath,
    [string]$ReleaseId,
    [switch]$NonInteractive,
    [switch]$NoPause
)
$ErrorActionPreference = 'Stop'
$deploymentRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ConfigPath) { $ConfigPath = Join-Path $deploymentRoot 'deploy\deploy.conf' }

function ConvertTo-PosixPath([string]$Value) {
    $full = [IO.Path]::GetFullPath($Value)
    if ($full -notmatch '^([A-Za-z]):[\\/](.*)$') { throw 'Use a local Windows drive path; UNC paths are not supported.' }
    return '/' + $Matches[1].ToLowerInvariant() + '/' + $Matches[2].Replace('\','/')
}

function Read-Setting([string]$Label, [string]$Default, [string]$Pattern) {
    while ($true) {
        $prompt = if ($Default) { "$Label [$Default]" } else { $Label }
        $value = Read-Host $prompt
        if (-not $value) { $value = $Default }
        if ($value -and $value -match $Pattern) { return $value }
        Write-Host 'Enter a valid value.' -ForegroundColor Yellow
    }
}

function New-DeploymentConfig {
    if (Test-Path -LiteralPath $ConfigPath) {
        Write-Host 'Using your existing private deployment configuration.'
        return
    }
    if ($NonInteractive) { throw "Missing $ConfigPath. Run Configure interactively first." }
    Write-Host "`nFirst-time setup: values stay in your ignored deploy.conf file." -ForegroundColor Cyan
    Write-Host 'Prepare root SSH key login, verify host fingerprints, and install Docker Compose and Python 3.9+ on both Linux hosts first.'
    Write-Host 'The firewall remains responsible for routing. Configure proxied DNS and port forwarding before installing the edge.'
    $ip = '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    $domain = Read-Setting 'Parent DNS domain' '' '^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$'
    $subdomain = Read-Setting 'Console subdomain' 'opngate' '^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    $firewall = Read-Setting 'OPNsense management IPv4 address' '' $ip
    $firewallLan = Read-Setting 'OPNsense IPv4 address on the services LAN' '' $ip
    $edge = Read-Setting 'Edge Linux host IPv4 address (Pi 5)' '' $ip
    $services = Read-Setting 'Services Linux host IPv4 address (Pi 4)' '' $ip
    $admin = Read-Setting 'This admin PC IPv4 address as seen by the Linux hosts' '' $ip
    foreach ($value in @($firewall,$firewallLan,$edge,$services,$admin)) {
        $parsed = $null
        if (-not [Net.IPAddress]::TryParse($value,[ref]$parsed)) { throw "Invalid IPv4 address: $value" }
    }
    $lan = Read-Setting 'Services LAN CIDR, e.g. 192.168.10.0/24' '' '^[0-9.]+/(?:[0-9]|[12][0-9]|3[0-2])$'
    $lanIf = Read-Setting 'Linux LAN interface name on both hosts' 'eth0' '^[a-zA-Z0-9_.:-]+$'
    $inside = Read-Setting 'OPNsense logical inside interfaces for pause/block rules' 'lan' '^[a-zA-Z0-9_,.-]+$'
    $wan = Read-Setting 'OPNsense logical WAN interface' 'wan' '^[a-zA-Z0-9_.-]+$'
    $zone = Read-Setting 'Fallback IANA time zone' 'UTC' '^[a-zA-Z0-9_+/-]+$'
    $user = Read-Setting 'First operator username' 'admin' '^[a-zA-Z0-9_.-]{1,64}$'
    $key = Read-Setting 'Existing SSH private key path' (Join-Path $env:USERPROFILE '.ssh\id_ed25519') '^.+$'
    if (-not (Test-Path -LiteralPath $key -PathType Leaf)) { throw 'SSH key does not exist. Create and install your key before deployment.' }
    $upstreams = Read-Host 'Application upstreams allowed by the Linux host firewall (space-separated IP:port; blank for none)'
    if ($upstreams -and $upstreams -notmatch '^(?:[0-9.]+:[0-9]+)(?: [0-9.]+:[0-9]+)*$') { throw 'Upstreams must be space-separated IPv4:port pairs.' }
    $values = [ordered]@{
        DOMAIN=$domain.ToLowerInvariant(); PORTAL_SUBDOMAIN=$subdomain.ToLowerInvariant(); PORTAL_TITLE='OPNGate'; LEGACY_PORTAL_ORIGIN=''; TZ=$zone
        SSH_KEY=(ConvertTo-PosixPath $key); REMOTE_DIR='/opt/gateway'
        FIREWALL="root@$firewall"; FIREWALL_LAN_IP=$firewallLan
        EDGE="root@$edge"; EDGE_IP=$edge; SERVICES="root@$services"; SERVICES_IP=$services
        INSTALL_HOSTFW='yes'; LAN_IF=$lanIf; LAN_NET=$lan; ADMIN_IP=$admin; UPSTREAMS=$upstreams
        PAUSE_INTERFACES=$inside; WAN_INTERFACE=$wan; WAF_MODE='DetectionOnly'; HOME_IP=''; ADMIN_USER=$user; INSTALL_DOCKER='no'
    }
    $lines = @('# Private OPNGate configuration. Never commit this file.')
    foreach ($entry in $values.GetEnumerator()) {
        $quoted = "'" + ([string]$entry.Value).Replace("'", "'\''") + "'"
        $lines += $entry.Key + '=' + $quoted
    }
    $directory = Split-Path -Parent $ConfigPath
    if (-not (Test-Path -LiteralPath $directory)) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
    [IO.File]::WriteAllText($ConfigPath, ($lines -join "`n") + "`n", (New-Object Text.UTF8Encoding($false)))
    Write-Host 'Saved deploy.conf. No remote changes have been made.' -ForegroundColor Green
}

try {
    if ($Action -eq 'Menu') {
        if ($NonInteractive) { throw 'Choose an explicit -Action for non-interactive use.' }
        Write-Host "`nOPNGate deployment" -ForegroundColor Cyan
        Write-Host '1  Deploy (detect a new or existing stack)'
        Write-Host '2  Configure only'
        Write-Host '3  Check prerequisites and connections'
        Write-Host '4  Install a new three-host stack'
        Write-Host '5  Update the application on an existing stack'
        Write-Host '6  Check running services'
        Write-Host '7  Roll back an application update'
        $choice = Read-Host 'Choose 1-7'
        $menu = @{'1'='Deploy';'2'='Configure';'3'='Check';'4'='Install';'5'='Update';'6'='Status';'7'='Rollback'}
        if (-not $menu.ContainsKey($choice)) { throw 'No action selected.' }
        $Action = $menu[$choice]
    }
    $ConfigPath = [IO.Path]::GetFullPath($ConfigPath)
    New-DeploymentConfig
    if ($Action -eq 'Configure') { exit 0 }
    if (-not $BashPath) {
        $candidates = @("$env:ProgramFiles\Git\bin\bash.exe", "${env:ProgramFiles(x86)}\Git\bin\bash.exe", "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe")
        $BashPath = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    }
    if (-not $BashPath -or -not (Test-Path -LiteralPath $BashPath -PathType Leaf)) { throw 'Install Git for Windows, or pass -BashPath to its bash.exe.' }
    $gitRoot = Split-Path -Parent (Split-Path -Parent $BashPath)
    $env:PATH = "$gitRoot\usr\bin;$gitRoot\mingw64\bin;$env:PATH"
    $previousConf = $env:DEPLOY_CONF
    $env:DEPLOY_CONF = ConvertTo-PosixPath $ConfigPath
    if ($Action -eq 'Rollback') {
        if (-not $ReleaseId -and -not $NonInteractive) { $ReleaseId = Read-Host 'Release ID printed by the deployment' }
        if ($ReleaseId -notmatch '^opngate-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$') { throw 'Rollback requires a valid -ReleaseId from the deployment output.' }
    }
    $commands = @{'Deploy'='deploy';'Install'='all';'Update'='update';'Rollback'='rollback';'Check'='check';'Status'='status'}
    $deploymentArguments = @($commands[$Action])
    if ($Action -eq 'Rollback') { $deploymentArguments += $ReleaseId }
    try {
        & $BashPath --noprofile --norc (ConvertTo-PosixPath (Join-Path $deploymentRoot 'deploy\deploy.sh')) @deploymentArguments
        if ($LASTEXITCODE -ne 0) { throw "Deployment stopped with exit code $LASTEXITCODE. Fix the reported step before retrying." }
    } finally { $env:DEPLOY_CONF = $previousConf }
} catch {
    Write-Error $_
    exit 1
} finally {
    if (-not $NoPause -and -not $NonInteractive) { Read-Host 'Press Enter to close' | Out-Null }
}
