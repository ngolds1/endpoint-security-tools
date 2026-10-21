<#
.SYNOPSIS
    Summarizes blocked outbound connections from local Windows Filtering Platform (WFP) audit events.

.DESCRIPTION
    Reads Security log event 5157 (and optionally 5152), keeps outbound events, and summarizes them
    by application and by application -> destination pair.

    Requires an elevated session and "Filtering Platform Connection" failure auditing
    ("Filtering Platform Packet Drop" failure auditing for -IncludePacketDrops).

.PARAMETER Hours
    Look-back window in hours. Default 24.

.PARAMETER StartTime
    Absolute start of the window. Overrides -Hours.

.PARAMETER MaxEvents
    Maximum events to read, newest first. 0 = no limit.

.PARAMETER IncludePacketDrops
    Include event 5152 (packet drops). High volume.

.PARAMETER IncludeLoopback
    Keep events with a loopback destination.

.PARAMETER ResolveFilters
    Name the blocking filter by matching FilterRTID against the current WFP state. RTIDs are runtime
    IDs, so events from before the last reboot or from removed filters cannot be matched.

.PARAMETER Top
    Rows per on-screen table. Default 20.

.PARAMETER ExportPath
    Folder for CSV output (details and summaries).

.PARAMETER PassThru
    Emit per-event detail objects to the pipeline.

.EXAMPLE
    .\Get-WfpBlockedOutbound.ps1 -Hours 4 -ResolveFilters -ExportPath C:\Temp\WFP
#>
[CmdletBinding(DefaultParameterSetName = 'Relative')]
param(
    [Parameter(ParameterSetName = 'Relative')]
    [ValidateRange(1, 8760)]
    [int]$Hours = 24,

    [Parameter(ParameterSetName = 'Absolute', Mandatory)]
    [datetime]$StartTime,

    [ValidateRange(0, [int]::MaxValue)]
    [int]$MaxEvents = 0,

    [switch]$IncludePacketDrops,
    [switch]$IncludeLoopback,
    [switch]$ResolveFilters,

    [ValidateRange(1, 1000)]
    [int]$Top = 20,

    [string]$ExportPath,
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from an elevated session; reading the Security log requires administrator rights.'
}

if ($PSCmdlet.ParameterSetName -eq 'Relative') {
    $StartTime = (Get-Date).AddHours(-$Hours)
}

# Warn if the required audit subcategory is not logging failures (GUIDs are locale-independent).
$auditGuid = '{0CCE9226-69AE-11D9-BED3-505054503030}'   # Filtering Platform Connection
try {
    $audit = @(auditpol.exe /get /subcategory:"$auditGuid" /r 2>$null | Where-Object { $_ } | ConvertFrom-Csv)
    if ($audit.Count -gt 0 -and [string]$audit[0].'Inclusion Setting' -notmatch 'Failure') {
        Write-Warning ("Filtering Platform Connection failure auditing appears disabled; 5157 events will not be logged. " +
            "Enable with: auditpol /set /subcategory:`"$auditGuid`" /failure:enable")
    }
}
catch {
    Write-Verbose "Could not read audit policy: $($_.Exception.Message)"
}

# Map \Device\HarddiskVolumeN prefixes to drive letters.
$deviceMap = @{}
try {
    if (-not ('WfpAudit.NativeMethods' -as [type])) {
        Add-Type -Namespace WfpAudit -Name NativeMethods -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);
'@
    }
    foreach ($drive in [IO.DriveInfo]::GetDrives()) {
        $letter = $drive.Name.TrimEnd('\')
        $sb = New-Object System.Text.StringBuilder 1024
        if ([WfpAudit.NativeMethods]::QueryDosDevice($letter, $sb, $sb.Capacity) -gt 0) {
            $deviceMap[$sb.ToString()] = $letter
        }
    }
}
catch {
    Write-Warning "Device path mapping unavailable; paths stay in \Device\HarddiskVolumeN form. ($($_.Exception.Message))"
}

$pathCache = @{}
function Convert-DevicePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    if ($pathCache.ContainsKey($Path)) { return $pathCache[$Path] }
    $result = $Path
    foreach ($device in $deviceMap.Keys) {
        if ($Path.StartsWith($device + '\', [StringComparison]::OrdinalIgnoreCase)) {
            $result = $deviceMap[$device] + $Path.Substring($device.Length)
            break
        }
    }
    $pathCache[$Path] = $result
    return $result
}

$filterMap = @{}
if ($ResolveFilters) {
    $tmp = Join-Path $env:TEMP ('wfpfilters_{0}.xml' -f [guid]::NewGuid())
    try {
        $null = netsh.exe wfp show filters file="$tmp" 2>&1
        if (-not (Test-Path -LiteralPath $tmp)) { throw 'netsh produced no output file.' }
        [xml]$filterXml = Get-Content -LiteralPath $tmp -Raw
        foreach ($item in $filterXml.SelectNodes('//item[filterId]')) {
            $nameNode = $item.SelectSingleNode('displayData/name')
            $provNode = $item.SelectSingleNode('providerKey')
            $filterMap[$item.SelectSingleNode('filterId').InnerText] = @{
                Name     = if ($nameNode) { $nameNode.InnerText } else { $null }
                Provider = if ($provNode) { $provNode.InnerText } else { $null }
            }
        }
    }
    catch {
        Write-Warning "Could not resolve WFP filters: $($_.Exception.Message)"
    }
    finally {
        Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    }
}

# Query outbound (%%14593) block events; direction is filtered in the query for performance.
$eventIds = @(5157)
if ($IncludePacketDrops) { $eventIds += 5152 }
$idClause = ($eventIds | ForEach-Object { "EventID=$_" }) -join ' or '
$since    = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$query    = @{
    LogName     = 'Security'
    FilterXPath = "*[System[($idClause) and TimeCreated[@SystemTime>='$since']]] and *[EventData[Data[@Name='Direction']='%%14593']]"
}
if ($MaxEvents -gt 0) { $query.MaxEvents = $MaxEvents }

try {
    $events = @(Get-WinEvent @query)
}
catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
    $events = @()
}

$protocolNames = @{ '1' = 'ICMP'; '6' = 'TCP'; '17' = 'UDP'; '58' = 'ICMPv6' }

$records = @(foreach ($e in $events) {
    $data = @{}
    foreach ($node in ([xml]$e.ToXml()).Event.EventData.Data) {
        $data[$node.GetAttribute('Name')] = $node.InnerText
    }

    $dest = [string]$data['DestAddress']
    if (-not $IncludeLoopback -and ($dest -like '127.*' -or $dest -eq '::1' -or $dest -like '::ffff:127.*')) { continue }

    $app      = Convert-DevicePath ([string]$data['Application'])
    $proto    = [string]$data['Protocol']
    $filterId = [string]$data['FilterRTID']
    $filter   = if ($filterMap.ContainsKey($filterId)) { $filterMap[$filterId] } else { $null }

    [pscustomobject]@{
        TimeCreated    = $e.TimeCreated
        EventId        = $e.Id
        ProcessId      = [int]$data['ProcessID']
        ProcessName    = if ($app) { [IO.Path]::GetFileName($app) } else { $null }
        Application    = $app
        SourceAddress  = [string]$data['SourceAddress']
        SourcePort     = [int]$data['SourcePort']
        DestAddress    = $dest
        DestPort       = [int]$data['DestPort']
        Protocol       = if ($protocolNames.ContainsKey($proto)) { $protocolNames[$proto] } else { $proto }
        FilterRTID     = $filterId
        FilterName     = if ($filter) { $filter.Name } elseif ($ResolveFilters) { '(not in current WFP state)' } else { $null }
        FilterProvider = if ($filter) { $filter.Provider } else { $null }
    }
})

if ($records.Count -eq 0) {
    Write-Host "No blocked outbound WFP events found since $StartTime."
    return
}

function Join-Top($Values, [int]$Count = 5) {
    $groups = @($Values | Where-Object { "$_" } | Group-Object | Sort-Object Count -Descending)
    $text = ($groups | Select-Object -First $Count | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', '
    if ($groups.Count -gt $Count) { $text += ", +$($groups.Count - $Count) more" }
    $text
}

$byApplication = @($records | Group-Object Application | ForEach-Object {
    $g = $_.Group
    [pscustomobject]@{
        ProcessName        = $g[0].ProcessName
        Blocked            = $_.Count
        UniqueDestinations = @($g | ForEach-Object { "$($_.DestAddress):$($_.DestPort)/$($_.Protocol)" } | Sort-Object -Unique).Count
        TopDestPorts       = Join-Top ($g | ForEach-Object { "$($_.DestPort)/$($_.Protocol)" })
        FirstSeen          = ($g.TimeCreated | Measure-Object -Minimum).Minimum
        LastSeen           = ($g.TimeCreated | Measure-Object -Maximum).Maximum
        Application        = $_.Name
    }
} | Sort-Object Blocked -Descending)

$byAppDestination = @($records | Group-Object Application, DestAddress, DestPort, Protocol | ForEach-Object {
    $g = $_.Group
    [pscustomobject]@{
        ProcessName = $g[0].ProcessName
        DestAddress = $g[0].DestAddress
        DestPort    = $g[0].DestPort
        Protocol    = $g[0].Protocol
        Blocked     = $_.Count
        FirstSeen   = ($g.TimeCreated | Measure-Object -Minimum).Minimum
        LastSeen    = ($g.TimeCreated | Measure-Object -Maximum).Maximum
        FilterName  = $g[0].FilterName
        Application = $g[0].Application
    }
} | Sort-Object Blocked -Descending)

$capped = if ($MaxEvents -gt 0 -and $events.Count -ge $MaxEvents) { " (capped at $MaxEvents)" } else { '' }
Write-Host ("{0}: {1} blocked outbound events, {2} applications, {3} -> {4}{5}" -f
    $env:COMPUTERNAME, $records.Count, $byApplication.Count, $StartTime, (Get-Date), $capped)

$byApplication | Select-Object -First $Top ProcessName, Blocked, UniqueDestinations, TopDestPorts, LastSeen |
    Format-Table -AutoSize -Wrap | Out-Host

$pairColumns = @('ProcessName', 'DestAddress', 'DestPort', 'Protocol', 'Blocked', 'LastSeen')
if ($ResolveFilters) { $pairColumns += 'FilterName' }
$byAppDestination | Select-Object -First $Top $pairColumns | Format-Table -AutoSize -Wrap | Out-Host

if ($ExportPath) {
    $null = New-Item -ItemType Directory -Path $ExportPath -Force
    $prefix = Join-Path $ExportPath ('WFP_BlockedOutbound_{0}_{1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $records          | Export-Csv -LiteralPath "${prefix}_Details.csv"          -NoTypeInformation -Encoding UTF8
    $byApplication    | Export-Csv -LiteralPath "${prefix}_ByApplication.csv"    -NoTypeInformation -Encoding UTF8
    $byAppDestination | Export-Csv -LiteralPath "${prefix}_ByAppDestination.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "CSV output written to $ExportPath"
}

if ($PassThru) { $records }