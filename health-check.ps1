[CmdletBinding()]
param(
  [switch]$UsingOU,
  [string]$OrganizationUnitDN,
  [string[]]$DomainControllers,
  [switch]$IncludeHardware,
  [string]$OutputPath = ".\ADHealthReport.html",
  [switch]$Csv,
  [switch]$EmailOnErrorOnly,

  # SMTP
  [string]$SmtpServer,
  [int]$SmtpPort = 587,
  [switch]$SmtpUseSsl,
  [string]$From,
  [string[]]$To,
  [string]$Subject = "Active Directory Health Report",
  [pscredential]$Credential,

  # Graph
  [switch]$UseGraph,
  [string]$GraphSenderUpn
)

# ===================== Utilities =====================
function Test-Tool {
  param([string]$Name)
  return Get-Command $Name -ErrorAction SilentlyContinue
}

function Get-DomainDN {
  try { (Get-ADDomain).DistinguishedName } catch { throw "Unable to get domain DN. Is RSAT ActiveDirectory installed?" }
}

function Get-DCList {
  param([switch]$UsingOU,[string]$OrganizationUnitDN,[string[]]$DomainControllers)
  if ($UsingOU) {
    if (-not $OrganizationUnitDN) { $OrganizationUnitDN = "OU=Domain Controllers,$(Get-DomainDN)" }
    $dcs = Get-ADComputer -SearchBase $OrganizationUnitDN -LDAPFilter '(objectClass=computer)' -Properties dnsHostName |
           Where-Object { $_.dnsHostName } | Select-Object -ExpandProperty dnsHostName
    if (-not $dcs) { throw "No DCs found in OU $OrganizationUnitDN" }
    return $dcs
  }
  if ($DomainControllers -and $DomainControllers.Count) { return $DomainControllers }
  (Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
}

function Invoke-External {
  param([string]$FileName,[string[]]$Arguments)
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $FileName
  $psi.Arguments = ($Arguments -join ' ')
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute = $false
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()
  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  [pscustomobject]@{
    Output   = $stdout
    Error    = $stderr
    ExitCode = $p.ExitCode
  }
}

function Invoke-DcDiag {
  param([string]$Server,[string[]]$ExtraArgs)
  $args = @("/s:$Server", "/c", "/v")
  if ($ExtraArgs) { $args += $ExtraArgs }
  Invoke-External -FileName 'dcdiag.exe' -Arguments $args
}

function Invoke-DcDiagTest {
  param(
    [string]$Server,
    [string]$TestName
  )
  $res = Invoke-External -FileName 'dcdiag.exe' -Arguments @("/s:$Server", "/test:$TestName", "/v")
  $text = $res.Output + "`n" + $res.Error
  $isFail = $false

  if ($res.ExitCode -ne 0) { $isFail = $true }
  elseif ($text -match '(?i)\b(fail|failed|error|erro)\b' -and $text -notmatch '(?i)\b0 failed\b') { $isFail = $true }

  [pscustomobject]@{
    Test   = $TestName
    Status = if ($isFail) { 'FAIL' } else { 'OK' }
    Output = $text
  }
}

function Invoke-RepAdmin {
  param([string]$Server,[string[]]$Args)
  $args = if ($Args) { $Args } else { @('/showrepl', $Server, '/verbose', '/all', '/intersite') }
  Invoke-External -FileName 'repadmin.exe' -Arguments $args
}

function Get-ReplSummary {
  $res = Invoke-External -FileName 'repadmin.exe' -Arguments @('/replsummary')
  return $res.Output
}

function Try-GetWmi {
  param([string]$Class,[string]$ComputerName,[string]$Filter)
  try {
    if ($Filter) {
      Get-WmiObject -Class $Class -ComputerName $ComputerName -Filter $Filter -ErrorAction Stop
    } else {
      Get-WmiObject -Class $Class -ComputerName $ComputerName -ErrorAction Stop
    }
  } catch { $null }
}

function Get-CPUUsage {
  param([string]$Server)
  
  try {
    Write-Verbose "Measuring CPU usage for $Server (10 seconds)..."
    
    # First sample
    $cpu1 = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -ComputerName $Server -Filter "Name='_Total'" -ErrorAction Stop
    if (-not $cpu1) {
      $cpu1 = Try-GetWmi -Class Win32_PerfFormattedData_PerfOS_Processor -ComputerName $Server -Filter "Name='_Total'"
    }
    
    Start-Sleep -Seconds 10
    
    # Second sample
    $cpu2 = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -ComputerName $Server -Filter "Name='_Total'" -ErrorAction Stop
    if (-not $cpu2) {
      $cpu2 = Try-GetWmi -Class Win32_PerfFormattedData_PerfOS_Processor -ComputerName $Server -Filter "Name='_Total'"
    }
    
    if ($cpu2) {
      return [Math]::Round($cpu2.PercentProcessorTime, 1)
    }
    
    return $null
  } catch {
    Write-Verbose "Failed to get CPU for $Server : $_"
    return $null
  }
}

function Get-HardwareInfo {
  param([string]$Server)

  $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Server -ErrorAction SilentlyContinue
  $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $Server -ErrorAction SilentlyContinue

  if (-not $os) { $os = Try-GetWmi -Class Win32_OperatingSystem -ComputerName $Server }
  if (-not $disks) { 
    $disks = @()
    $drives = @('C:', 'D:', 'E:')
    foreach ($d in $drives) {
      $disk = Try-GetWmi -Class Win32_LogicalDisk -ComputerName $Server -Filter "DeviceID='$d'"
      if ($disk) { $disks += $disk }
    }
  }

  # Get CPU usage (10 second measurement)
  $cpuUsage = Get-CPUUsage -Server $Server

  $memTotalGB = if ($os) { [Math]::Round($os.TotalVisibleMemorySize/1MB,1) } else { $null }
  $memFreeGB  = if ($os) { [Math]::Round($os.FreePhysicalMemory/1MB,1) } else { $null }
  $memUsedGB  = if ($memTotalGB -and $memFreeGB) { [Math]::Round($memTotalGB - $memFreeGB, 1) } else { $null }
  $memUsedPct = if ($memTotalGB -gt 0) { [Math]::Round(($memUsedGB/$memTotalGB)*100,1) } else { $null }
  $uptime     = if ($os) { [Math]::Round((New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)).TotalHours,1) } else { $null }

  $diskInfo = @()
  foreach ($disk in $disks) {
    $freeGB = [Math]::Round($disk.FreeSpace/1GB,1)
    $sizeGB = [Math]::Round($disk.Size/1GB,1)
    $usedGB = [Math]::Round($sizeGB - $freeGB, 1)
    $usedPct = if ($sizeGB -gt 0) { [Math]::Round(($usedGB/$sizeGB)*100,1) } else { 0 }
    
    $diskInfo += [pscustomobject]@{
      Drive = $disk.DeviceID
      SizeGB = $sizeGB
      UsedGB = $usedGB
      FreeGB = $freeGB
      UsedPct = $usedPct
    }
  }

  [pscustomobject]@{
    UptimeHours = $uptime
    CPUUsagePct = $cpuUsage
    MemTotalGB  = $memTotalGB
    MemUsedGB   = $memUsedGB
    MemFreeGB   = $memFreeGB
    MemUsedPct  = $memUsedPct
    Disks       = $diskInfo
  }
}

function Test-Services {
  param([string]$Server,[string[]]$Names=@('DNS','NTDS','Netlogon'))
  $map = @{
    'DNS'      = 'DNS'
    'NTDS'     = 'NTDS'
    'Netlogon' = 'Netlogon'
  }
  $result = @{}
  foreach ($n in $Names) {
    $svcName = $map[$n]
    $svc = Get-Service -ComputerName $Server -Name $svcName -ErrorAction SilentlyContinue
    $result[$n] = if ($svc) { $svc.Status -eq 'Running' } else { $false }
  }
  [pscustomobject]$result
}

function New-Status { param([bool]$Ok) if ($Ok) { 'OK' } else { 'FAIL' } }

function Badge {
  param([string]$val)
  switch ($val) {
    'OK'   { '<span class="badge ok">OK</span>' }
    'FAIL' { '<span class="badge fail">FAIL</span>' }
    default { '<span class="badge na">N/A</span>' }
  }
}

function Show-NA {
  param([object]$v,[string]$suffix="")
  if ($null -eq $v -or ($v -is [string] -and [string]::IsNullOrWhiteSpace($v))) { "N/A" }
  else { if ($suffix) { "$v$suffix" } else { "$v" } }
}

# ===================== Tools check =====================
if (-not (Get-Module -ListAvailable ActiveDirectory)) { throw "ActiveDirectory module not found. Install RSAT." }
if (-not (Test-Tool 'dcdiag.exe')) { throw "dcdiag.exe not found. Install RSAT/DC tools." }
if (-not (Test-Tool 'repadmin.exe')) { throw "repadmin.exe not found. Install RSAT/DC tools." }

Import-Module ActiveDirectory -ErrorAction Stop

# ===================== Discover DCs =====================
$allDCs = Get-DCList -UsingOU:$UsingOU -OrganizationUnitDN $OrganizationUnitDN -DomainControllers $DomainControllers

# ===================== Collect per DC =====================
$results = @()
$detailBlobs = @()

$dcdiagTests = @(
  'Connectivity',
  'Advertising',
  'NetLogons',
  'Services',
  'Replications',
  'Topology',
  'SysVolCheck',
  'KnowsOfRoleHolders',
  'RidManager'
)

foreach ($dc in $allDCs) {
  Write-Verbose "Collecting $dc ..."

  $pingOk = Test-Connection -ComputerName $dc -Count 1 -Quiet -ErrorAction SilentlyContinue
  $svc    = Test-Services -Server $dc

  $testResults = @{}
  $testOutputs = @{}
  foreach ($t in $dcdiagTests) {
    $tres = Invoke-DcDiagTest -Server $dc -TestName $t
    $testResults[$t] = $tres.Status
    $testOutputs[$t] = $tres.Output
  }

  $fsmStatus = if ($testResults['KnowsOfRoleHolders'] -eq 'FAIL' -or $testResults['RidManager'] -eq 'FAIL') { 'FAIL' } else { 'OK' }

  $rep  = Invoke-RepAdmin -Server $dc
  $repFail = ($rep.Output -match '(?i)\b(fail|failed|error|erro)\b')
  $repStatus = if ($repFail) { 'FAIL' } else { 'OK' }

  $hw = Get-HardwareInfo -Server $dc

  $obj = [pscustomobject]@{
    DC                   = $dc
    Ping                 = New-Status $pingOk
    DNS_Service          = New-Status $svc.DNS
    NTDS_Service         = New-Status $svc.NTDS
    NetLogon_Service     = New-Status $svc.Netlogon
    Connectivity         = $testResults['Connectivity']
    Advertising          = $testResults['Advertising']
    NetLogons            = $testResults['NetLogons']
    ServicesTest         = $testResults['Services']
    ReplicationsTest     = $testResults['Replications']
    Topology             = $testResults['Topology']
    SysVol               = $testResults['SysVolCheck']
    FSMO                 = $fsmStatus
    Replication_RepAdmin = $repStatus
    Hardware             = $hw
  }
  $results += $obj

  $detailBlobs += [pscustomobject]@{
    DC            = $dc
    TestOutputs   = $testOutputs
    RepAdminText  = $rep.Output
  }
}

# ===================== Replication Summary =====================
$replSummary = Get-ReplSummary

# ===================== Forest/Domain & FSMO holders =====================
$forest = Get-ADForest
$domain = Get-ADDomain
$fsmo = [pscustomobject]@{
  SchemaMaster          = $forest.SchemaMaster
  DomainNamingMaster    = $forest.DomainNamingMaster
  PDCEmulator           = $domain.PDCEmulator
  RIDMaster             = $domain.RIDMaster
  InfrastructureMaster  = $domain.InfrastructureMaster
}

# ===================== Metrics/Summary =====================
$total = $results.Count

# Count all FAIL statuses across all health columns for each DC
$healthColumns = @(
  'Ping','DNS_Service','NTDS_Service','NetLogon_Service',
  'Connectivity','Advertising','NetLogons','ServicesTest',
  'ReplicationsTest','Topology','SysVol','FSMO','Replication_RepAdmin'
)

$failCount = 0
foreach ($dc in $results) {
  foreach ($col in $healthColumns) {
    if ($dc.$col -eq 'FAIL') {
      $failCount++
    }
  }
}

# ===================== CSV export (optional) =====================
if ($Csv) {
  $csvPath = [IO.Path]::ChangeExtension((Resolve-Path $OutputPath),'.csv')
  $results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath
}

# ===================== HTML =====================
$css = @"
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Roboto, Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: #e2e8f0; padding: 20px; }
  .container { max-width: 1400px; margin: 0 auto; }
  .card { background: rgba(17, 24, 39, 0.95); border: 1px solid #1f2937; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 10px 40px rgba(0,0,0,.4); backdrop-filter: blur(10px); }
  h1 { color: #f9fafb; margin: 0 0 8px 0; font-size: 32px; font-weight: 700; }
  h2 { color: #e5e7eb; margin: 0 0 20px 0; font-size: 22px; font-weight: 600; border-bottom: 2px solid #374151; padding-bottom: 10px; }
  h3 { color: #cbd5e1; font-size: 16px; margin: 20px 0 10px 0; }
  .muted { color: #94a3b8; font-size: 14px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-top: 20px; }
  .tile { background: linear-gradient(135deg, #1e293b 0%, #0b1220 100%); border: 1px solid #334155; border-radius: 10px; padding: 20px; text-align: center; transition: transform 0.2s, box-shadow 0.2s; }
  .tile:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,.3); }
  .tile-alert { background: linear-gradient(135deg, #7f1d1d 0%, #450a0a 100%); border: 2px solid #ef4444; box-shadow: 0 0 20px rgba(239, 68, 68, 0.3); animation: pulse 2s infinite; }
  .tile .k { font-size: 13px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
  .tile .v { font-size: 32px; font-weight: 700; color: #fff; }
  
  @keyframes pulse {
    0%, 100% { box-shadow: 0 0 20px rgba(239, 68, 68, 0.3); }
    50% { box-shadow: 0 0 30px rgba(239, 68, 68, 0.6); }
  }
  
  .dc-card { background: #0b1220; border: 1px solid #1f2937; border-radius: 10px; padding: 20px; margin-bottom: 16px; transition: all 0.2s; }
  .dc-card:hover { border-color: #3b82f6; box-shadow: 0 4px 16px rgba(59, 130, 246, 0.1); }
  .dc-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid #1f2937; }
  .dc-name { font-size: 18px; font-weight: 600; color: #f9fafb; }
  .dc-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .dc-item { background: #151f30; padding: 12px; border-radius: 6px; border-left: 3px solid #374151; cursor: pointer; transition: all 0.2s; }
  .dc-item:hover { background: #1a2332; border-left-color: #3b82f6; transform: translateX(2px); }
  .dc-item-static { background: #151f30; padding: 12px; border-radius: 6px; border-left: 3px solid #374151; cursor: default; transition: all 0.2s; }
  .dc-item-static:hover { background: #151f30; border-left-color: #374151; transform: none; }
  .dc-item-label { font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
  .dc-item-value { display: flex; align-items: center; gap: 8px; }
  
  /* COMPACT HARDWARE SECTION */
  .hw-section { background: #0d1829; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; margin-top: 16px; }
  .hw-compact { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }
  .hw-metric { flex: 1; min-width: 180px; }
  .hw-metric-label { font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; display: flex; justify-content: space-between; }
  .hw-metric-value { font-size: 13px; font-weight: 600; color: #e5e7eb; }
  .hw-bar-mini { background: #1e293b; border-radius: 4px; height: 8px; overflow: hidden; position: relative; margin-top: 4px; }
  .hw-bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s ease; }
  .hw-bar-good { background: linear-gradient(90deg, #10b981 0%, #059669 100%); }
  .hw-bar-warning { background: linear-gradient(90deg, #f59e0b 0%, #d97706 100%); }
  .hw-bar-critical { background: linear-gradient(90deg, #ef4444 0%, #dc2626 100%); }
  
  .badge { display: inline-flex; align-items: center; padding: 4px 12px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .ok { background: rgba(6, 78, 59, 0.3); color: #6ee7b7; border: 1px solid #10b981; }
  .fail { background: rgba(127, 29, 29, 0.3); color: #fca5a5; border: 1px solid #ef4444; }
  .na { background: rgba(55, 65, 81, 0.3); color: #e5e7eb; border: 1px solid #6b7280; }
  
  .icon { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  .icon-ok { background: #10b981; box-shadow: 0 0 8px rgba(16, 185, 129, 0.5); }
  .icon-fail { background: #ef4444; box-shadow: 0 0 8px rgba(239, 68, 68, 0.5); }
  
  /* ENHANCED REPLICATION TABLE */
  .repl-table-wrapper { overflow-x: auto; margin-top: 16px; border-radius: 8px; border: 1px solid #1f2937; }
  .repl-table { width: 100%; border-collapse: collapse; }
  .repl-table thead { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); position: sticky; top: 0; z-index: 10; }
  .repl-table th { padding: 16px 12px; text-align: left; color: #cbd5e1; font-size: 12px; text-transform: uppercase; letter-spacing: 0.8px; font-weight: 700; border-bottom: 2px solid #374151; white-space: nowrap; }
  .repl-table tbody tr { transition: all 0.2s; border-bottom: 1px solid #1f2937; }
  .repl-table tbody tr:hover { background: rgba(59, 130, 246, 0.05); }
  .repl-table tbody tr:last-child { border-bottom: none; }
  .repl-table td { padding: 14px 12px; color: #e2e8f0; font-size: 13px; }
  .repl-table td:first-child { font-weight: 600; color: #f9fafb; }
  .repl-status-good { color: #6ee7b7; font-weight: 600; }
  .repl-status-warn { color: #fbbf24; font-weight: 600; }
  .repl-status-error { color: #fca5a5; font-weight: 600; }
  .repl-badge { display: inline-block; padding: 4px 10px; border-radius: 8px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
  .repl-badge-success { background: rgba(6, 78, 59, 0.3); color: #6ee7b7; border: 1px solid #10b981; }
  .repl-badge-warning { background: rgba(146, 64, 14, 0.3); color: #fbbf24; border: 1px solid #f59e0b; }
  .repl-badge-error { background: rgba(127, 29, 29, 0.3); color: #fca5a5; border: 1px solid #ef4444; }
  
  details { background: #0b1220; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; margin-bottom: 12px; transition: all 0.2s; }
  details:hover { border-color: #374151; }
  details[open] { background: #0d1829; }
  summary { cursor: pointer; font-weight: 600; color: #e5e7eb; user-select: none; padding: 4px 0; }
  summary:hover { color: #60a5fa; }
  pre { white-space: pre-wrap; color: #cbd5e1; background: #030712; padding: 16px; border-radius: 6px; font-size: 12px; line-height: 1.6; overflow-x: auto; border: 1px solid #1f2937; max-height: 400px; overflow-y: auto; }
  
  ul { list-style: none; padding: 0; }
  ul li { padding: 8px 0; color: #cbd5e1; border-bottom: 1px solid #1f2937; }
  ul li:last-child { border-bottom: none; }
  ul li b { color: #e5e7eb; font-weight: 600; min-width: 180px; display: inline-block; }
  
  .footer { font-size: 12px; color: #64748b; margin-top: 32px; text-align: center; padding: 20px; border-top: 1px solid #1f2937; }
  a { color: #60a5fa; text-decoration: none; transition: color 0.2s; }
  a:hover { color: #93c5fd; }
  
  .detail-section { display: none; margin-top: 16px; padding: 16px; background: #030712; border-radius: 8px; border: 1px solid #1f2937; }
  .detail-section.active { display: block; animation: fadeIn 0.3s ease; }
  
  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
  }
  
  @media (max-width: 768px) {
    .dc-grid { grid-template-columns: 1fr; }
    .grid { grid-template-columns: 1fr; }
    .hw-compact { flex-direction: column; }
    .hw-metric { min-width: 100%; }
  }
</style>
"@

function Badge($val){
  $icon = if ($val -eq 'OK') { '<span class="icon icon-ok"></span>' }
          elseif ($val -eq 'FAIL') { '<span class="icon icon-fail"></span>' }
          else { '' }
  
  if ($val -eq 'OK') { "$icon <span class='badge ok'>OK</span>" }
  elseif ($val -eq 'FAIL') { "$icon <span class='badge fail'>FAIL</span>" }
  else { "<span class='badge na'>N/A</span>" }
}

$dcCards = $results | ForEach-Object {
  $dcName = $_.DC
  $dcSafe = $dcName -replace '[^a-zA-Z0-9]', '_'
  
  $statusItems = @(
    @{Label='Ping'; Value=$_.Ping; Key='Ping'; HasDetail=$false},
    @{Label='DNS Service'; Value=$_.DNS_Service; Key='DNS_Service'; HasDetail=$false},
    @{Label='NTDS Service'; Value=$_.NTDS_Service; Key='NTDS_Service'; HasDetail=$false},
    @{Label='NetLogon'; Value=$_.NetLogon_Service; Key='NetLogon_Service'; HasDetail=$false},
    @{Label='Connectivity'; Value=$_.Connectivity; Key='Connectivity'; HasDetail=$true},
    @{Label='Advertising'; Value=$_.Advertising; Key='Advertising'; HasDetail=$true},
    @{Label='NetLogons'; Value=$_.NetLogons; Key='NetLogons'; HasDetail=$true},
    @{Label='Services'; Value=$_.ServicesTest; Key='Services'; HasDetail=$true},
    @{Label='Replications'; Value=$_.ReplicationsTest; Key='Replications'; HasDetail=$true},
    @{Label='RepAdmin'; Value=$_.Replication_RepAdmin; Key='RepAdmin'; HasDetail=$false},
    @{Label='FSMO'; Value=$_.FSMO; Key='FSMO'; HasDetail=$false},
    @{Label='SysVol'; Value=$_.SysVol; Key='SysVolCheck'; HasDetail=$true},
    @{Label='Topology'; Value=$_.Topology; Key='Topology'; HasDetail=$true}
  )
  
  $itemsHtml = $statusItems | ForEach-Object {
    $badgeHtml = Badge $_.Value
    $itemKey = $_.Key
    $itemClass = if ($_.HasDetail) { 'dc-item' } else { 'dc-item-static' }
    $onclickAttr = if ($_.HasDetail) { "onclick=`"toggleDetail('${dcSafe}_$itemKey')`"" } else { '' }
    
    @"
    <div class="$itemClass" $onclickAttr>
      <div class="dc-item-label">$($_.Label)</div>
      <div class="dc-item-value">$badgeHtml</div>
    </div>
"@
  } | Out-String

  # COMPACT Hardware info with CPU
  $hw = $_.Hardware
  $hwHtml = ""
  
  if ($hw) {
    $metricsHtml = ""
    
    # Uptime
    $uptimeVal = Show-NA $hw.UptimeHours
    $metricsHtml += @"
<div class="hw-metric">
  <div class="hw-metric-label"><span>Uptime</span></div>
  <div class="hw-metric-value">$uptimeVal hours</div>
</div>
"@
    
    # CPU
    $cpuVal = Show-NA $hw.CPUUsagePct
    $cpuPct = if ($hw.CPUUsagePct) { $hw.CPUUsagePct } else { 0 }
    $cpuClass = if ($cpuPct -lt 70) { 'hw-bar-good' } elseif ($cpuPct -lt 85) { 'hw-bar-warning' } else { 'hw-bar-critical' }
    $metricsHtml += @"
<div class="hw-metric">
  <div class="hw-metric-label"><span>CPU</span><span>$cpuVal%</span></div>
  <div class="hw-bar-mini">
    <div class="hw-bar-fill $cpuClass" style="width: $cpuPct%"></div>
  </div>
</div>
"@
    
    # Memory
    $memUsedPct = if ($hw.MemUsedPct) { $hw.MemUsedPct } else { 0 }
    $memClass = if ($memUsedPct -lt 70) { 'hw-bar-good' } elseif ($memUsedPct -lt 85) { 'hw-bar-warning' } else { 'hw-bar-critical' }
    $memLabel = "$(Show-NA $hw.MemUsedGB) / $(Show-NA $hw.MemTotalGB) GB"
    $metricsHtml += @"
<div class="hw-metric">
  <div class="hw-metric-label"><span>Memory</span><span>$memLabel</span></div>
  <div class="hw-bar-mini">
    <div class="hw-bar-fill $memClass" style="width: $memUsedPct%"></div>
  </div>
</div>
"@

    # Disks (compact)
    if ($hw.Disks -and $hw.Disks.Count -gt 0) {
      foreach ($disk in $hw.Disks) {
        $diskClass = if ($disk.UsedPct -lt 70) { 'hw-bar-good' } elseif ($disk.UsedPct -lt 85) { 'hw-bar-warning' } else { 'hw-bar-critical' }
        $diskLabel = "$($disk.UsedGB) / $($disk.SizeGB) GB"
        $metricsHtml += @"
<div class="hw-metric">
  <div class="hw-metric-label"><span>Disk $($disk.Drive)</span><span>$diskLabel</span></div>
  <div class="hw-bar-mini">
    <div class="hw-bar-fill $diskClass" style="width: $($disk.UsedPct)%"></div>
  </div>
</div>
"@
      }
    }

    $hwHtml = @"
<div class="hw-section">
  <h3 style="margin-top:0; margin-bottom: 12px;">Hardware & Resources</h3>
  <div class="hw-compact">
    $metricsHtml
  </div>
</div>
"@
  }

  @"
<div class="dc-card">
  <div class="dc-header">
    <div class="dc-name">$dcName</div>
  </div>
  <div class="dc-grid">
    $itemsHtml
  </div>
  $hwHtml
</div>
"@
} | Out-String

# Details sections
$detailsScript = "<script>"
$detailBlobs | ForEach-Object {
  $dcName = $_.DC
  $dcSafe = $dcName -replace '[^a-zA-Z0-9]', '_'
  
  foreach ($test in $_.TestOutputs.GetEnumerator()) {
    $testKey = $test.Key
    $testOutput = [System.Web.HttpUtility]::HtmlEncode($test.Value)
    
    $detailsScript += @"

var detail_${dcSafe}_${testKey} = ``$testOutput``;
"@
  }
}

$detailsScript += @"

function toggleDetail(key) {
  var container = document.getElementById('detail-container');
  var content = document.getElementById('detail-content');
  var title = document.getElementById('detail-title');
  
  var detailVar = 'detail_' + key;
  if (typeof window[detailVar] !== 'undefined') {
    title.textContent = key.replace(/_/g, ' > ');
    content.textContent = window[detailVar];
    container.classList.add('active');
    container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

function closeDetail() {
  document.getElementById('detail-container').classList.remove('active');
}
</script>
"@

# ENHANCED Replication Summary Table
$replTableHtml = ""
if ($replSummary) {
  $replLines = $replSummary -split "`n"
  $replData = @()
  
  # Parse repadmin output more robustly
  $inDataSection = $false
  foreach ($line in $replLines) {
    if ($line -match '^\s*Source DSA\s+') { $inDataSection = $true; continue }
    if (-not $inDataSection) { continue }
    if ($line -match '^\s*$') { continue }
    
    # Match DC replication data
    if ($line -match '^\s*(\S+)\s+(\d+)\s*/\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)') {
      $replData += [pscustomobject]@{
        DC = $matches[1]
        LargestDelta = [int]$matches[2]
        Total = [int]$matches[3]
        Fails = [int]$matches[4]
        TotalFails = [int]$matches[5]
        LastSuccess = $matches[6]
        LastFailure = $matches[7]
      }
    }
  }
  
  if ($replData.Count -gt 0) {
    $replRows = $replData | ForEach-Object {
      # Status badge based on failures
      $statusBadge = if ([int]$_.TotalFails -eq 0 -and [int]$_.Fails -eq 0) {
        '<span class="repl-badge repl-badge-success">✓ OK</span>'
      } elseif ([int]$_.TotalFails -gt 0) {
        '<span class="repl-badge repl-badge-error">✗ ERROR</span>'
      } else {
        '<span class="repl-badge repl-badge-warning">⚠ WARNING</span>'
      }
      
      # Color coding for delta
      $deltaClass = if ([int]$_.LargestDelta -lt 60) { 'repl-status-good' }
                    elseif ([int]$_.LargestDelta -lt 180) { 'repl-status-warn' }
                    else { 'repl-status-error' }
      
      $failsClass = if ([int]$_.TotalFails -gt 0) { 'repl-status-error' } else { 'repl-status-good' }
      
      @"
<tr>
  <td>$($_.DC)</td>
  <td class="$deltaClass">$($_.LargestDelta) min</td>
  <td>$($_.Total)</td>
  <td>$($_.Fails)</td>
  <td class="$failsClass">$($_.TotalFails)</td>
  <td>$($_.LastSuccess)</td>
  <td>$($_.LastFailure)</td>
  <td>$statusBadge</td>
</tr>
"@
    } | Out-String
    
    $replTableHtml = @"
<div class="repl-table-wrapper">
  <table class="repl-table">
    <thead>
      <tr>
        <th>Domain Controller</th>
        <th>Largest Delta</th>
        <th>Total Links</th>
        <th>Current Fails</th>
        <th>Total Fails</th>
        <th>Last Success</th>
        <th>Last Failure</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
      $replRows
    </tbody>
  </table>
</div>
"@
  } else {
    $replTableHtml = "<div class='muted' style='margin-top: 16px;'>No replication data available or unable to parse output.</div><pre>$([System.Web.HttpUtility]::HtmlEncode($replSummary))</pre>"
  }
}

$fsmoHtml = @"
<ul>
  <li><b>Schema Master:</b> $($fsmo.SchemaMaster)</li>
  <li><b>Domain Naming Master:</b> $($fsmo.DomainNamingMaster)</li>
  <li><b>PDC Emulator:</b> $($fsmo.PDCEmulator)</li>
  <li><b>RID Master:</b> $($fsmo.RIDMaster)</li>
  <li><b>Infrastructure Master:</b> $($fsmo.InfrastructureMaster)</li>
</ul>
"@

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Active Directory Health Report</title>
$css
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>Active Directory — Health Report</h1>
      <div class="muted">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") — Domain: $($domain.DNSRoot)</div>
      <div class="grid">
        <div class="tile">
          <div class="k">Domain Controllers</div>
          <div class="v">$total</div>
        </div>
        <div class="tile $(if($failCount -gt 0){'tile-alert'})">
          <div class="k">Total Failures</div>
          <div class="v" style="color: $(if($failCount -gt 0){'#fca5a5'}else{'#10b981'})">$failCount</div>
        </div>
        <div class="tile">
          <div class="k">Forest</div>
          <div class="v" style="font-size: 20px;">$($forest.Name)</div>
        </div>
        <div class="tile">
          <div class="k">Domain</div>
          <div class="v" style="font-size: 20px;">$($domain.DNSRoot)</div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>Domain Controllers Status</h2>
      <div class="muted" style="margin-bottom: 16px;">Click on any status item to view detailed diagnostics</div>
      $dcCards
      
      <div id="detail-container" class="detail-section">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <h3 style="margin: 0;" id="detail-title">Details</h3>
          <button onclick="closeDetail()" style="background: #374151; border: none; color: #e5e7eb; padding: 6px 12px; border-radius: 6px; cursor: pointer;">Close</button>
        </div>
        <pre id="detail-content"></pre>
      </div>
    </div>

    <div class="card">
      <h2>Replication Summary</h2>
      <div class="muted" style="margin-bottom: 8px;">Active Directory replication status across all domain controllers</div>
      $replTableHtml
    </div>

    <div class="card">
      <h2>FSMO Role Holders</h2>
      $fsmoHtml
    </div>

    <div class="footer">
      Report generated by Invoke-ADHealthReport-Improved.ps1 | CPU measurements taken over 10-second intervals
    </div>
  </div>
  
  $detailsScript
</body>
</html>
"@

# ===================== Save HTML =====================
$fullPath = (Resolve-Path (New-Item -Path $OutputPath -ItemType File -Force)).Path
[IO.File]::WriteAllText($fullPath, $html, [Text.UTF8Encoding]::new($false))

# ===================== Email sending =====================
function Send-ReportViaSmtp {
  param([string]$Server,[int]$Port,[switch]$UseSsl,[string]$From,[string[]]$To,[string]$Subject,[pscredential]$Cred,[string]$BodyHtml,[string]$Attachment)
  if (-not $Server) { throw "SmtpServer was not provided." }
  if (-not $From -or -not $To) { throw "From/To were not provided." }
  Send-MailMessage -SmtpServer $Server -Port $Port -UseSsl:$UseSsl `
    -From $From -To $To -Subject $Subject -Body $BodyHtml -BodyAsHtml `
    -Credential $Cred -Attachments $Attachment -ErrorAction Stop
}

function Send-ReportViaGraph {
  param([string]$SenderUpn,[string[]]$To,[string]$Subject,[string]$BodyHtml,[string]$Attachment)
  if (-not (Get-Module -ListAvailable Microsoft.Graph)) { throw "Microsoft.Graph module not found. Install with: Install-Module Microsoft.Graph" }
  if (-not $SenderUpn) { throw "GraphSenderUpn was not provided." }
  Import-Module Microsoft.Graph -ErrorAction Stop
  if (-not (Get-MgContext)) { Connect-MgGraph -Scopes "Mail.Send" | Out-Null }

  $bytes = [System.IO.File]::ReadAllBytes($Attachment)
  $b64 = [System.Convert]::ToBase64String($bytes)
  $message = @{
    message = @{
      subject = $Subject
      body = @{ contentType = "HTML"; content = $BodyHtml }
      toRecipients = @($To | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
      attachments = @(@{
          "@odata.type" = "#microsoft.graph.fileAttachment"
          name = [IO.Path]::GetFileName($Attachment)
          contentBytes = $b64
          contentType = "text/html"
      })
    }
    saveToSentItems = $true
  }
  Send-MgUserMail -UserId $SenderUpn -BodyParameter $message
}

$shouldSend = $true
if ($EmailOnErrorOnly -and $failCount -eq 0) { $shouldSend = $false }

if ($shouldSend -and ($To -and $To.Count -gt 0)) {
  if ($UseGraph) {
    Send-ReportViaGraph -SenderUpn $GraphSenderUpn -To $To -Subject $Subject -BodyHtml $html -Attachment $fullPath
  } elseif ($SmtpServer) {
    Send-ReportViaSmtp -Server $SmtpServer -Port $SmtpPort -UseSsl:$SmtpUseSsl -From $From -To $To -Subject $Subject -Cred $Credential -BodyHtml $html -Attachment $fullPath
  }
}

# ===================== Final output =====================
Write-Host "Report saved at: $fullPath" -ForegroundColor Green
if ($Csv -and (Test-Path $csvPath)) { Write-Host "CSV saved at: $csvPath" -ForegroundColor Green }
if ($shouldSend -and ($To -and $To.Count -gt 0)) {
  Write-Host "Email sent successfully." -ForegroundColor Green
} elseif (-not $shouldSend -and $EmailOnErrorOnly) {
  Write-Host "No failures detected — email suppressed (EmailOnErrorOnly)." -ForegroundColor Yellow
}
