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
# Load System.Web for HTML encoding
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

function ConvertTo-HtmlEncoded {
  param([string]$Text)
  if ([string]::IsNullOrEmpty($Text)) { return "" }
  
  # Try System.Web.HttpUtility first
  if ([System.Web.HttpUtility] -as [Type]) {
    return [System.Web.HttpUtility]::HtmlEncode($Text)
  }
  
  # Fallback to manual encoding
  $Text = $Text -replace '&', '&amp;'
  $Text = $Text -replace '<', '&lt;'
  $Text = $Text -replace '>', '&gt;'
  $Text = $Text -replace '"', '&quot;'
  $Text = $Text -replace "'", '&#39;'
  return $Text
}

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
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background: #0a0e1a; color: #e2e8f0; padding: 16px; font-size: 13px; line-height: 1.4; }
  .container { max-width: 1600px; margin: 0 auto; }
  
  /* COMPACT HEADER */
  .header { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border: 1px solid #334155; border-radius: 8px; padding: 16px 20px; margin-bottom: 16px; box-shadow: 0 4px 12px rgba(0,0,0,.3); }
  .header-top { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 12px; }
  .header-title { font-size: 22px; font-weight: 700; color: #f9fafb; margin: 0; }
  .header-meta { display: flex; gap: 20px; flex-wrap: wrap; align-items: center; }
  .meta-item { display: flex; align-items: center; gap: 6px; font-size: 11px; color: #94a3b8; }
  .meta-label { font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
  .meta-value { color: #cbd5e1; }
  
  /* COMPACT METRICS */
  .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; }
  .metric { background: rgba(30, 41, 59, 0.5); border: 1px solid #334155; border-radius: 6px; padding: 10px 14px; text-align: center; }
  .metric-label { font-size: 10px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; font-weight: 600; }
  .metric-value { font-size: 24px; font-weight: 700; color: #fff; }
  .metric-alert { background: linear-gradient(135deg, #7f1d1d 0%, #450a0a 100%); border-color: #ef4444; animation: pulse 2s infinite; }
  @keyframes pulse { 0%, 100% { box-shadow: 0 0 0 rgba(239, 68, 68, 0.4); } 50% { box-shadow: 0 0 12px rgba(239, 68, 68, 0.6); } }
  
  .card { background: rgba(17, 24, 39, 0.9); border: 1px solid #1f2937; border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 2px 8px rgba(0,0,0,.2); }
  .card-title { font-size: 16px; font-weight: 700; color: #e5e7eb; margin: 0 0 12px 0; padding-bottom: 8px; border-bottom: 1px solid #374151; }
  .card-subtitle { font-size: 11px; color: #94a3b8; margin-bottom: 12px; }
  
  /* ULTRA COMPACT DC CARDS */
  .dc-card { background: #0f1419; border: 1px solid #1f2937; border-radius: 6px; padding: 12px; margin-bottom: 10px; transition: all 0.15s; }
  .dc-card:hover { border-color: #3b82f6; }
  .dc-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid #1f2937; }
  .dc-name { font-size: 15px; font-weight: 700; color: #f9fafb; }
  
  /* DENSE STATUS GRID */
  .status-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(110px, 1fr)); gap: 6px; margin-bottom: 10px; }
  .status-item { background: #1a1f2e; padding: 6px 8px; border-radius: 4px; border-left: 2px solid #374151; cursor: pointer; transition: all 0.15s; }
  .status-item:hover { background: #242938; border-left-color: #3b82f6; }
  .status-item-static { background: #1a1f2e; padding: 6px 8px; border-radius: 4px; border-left: 2px solid #374151; cursor: default; }
  .status-label { font-size: 9px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.3px; margin-bottom: 3px; font-weight: 600; }
  .status-value { display: flex; align-items: center; gap: 4px; font-size: 11px; }
  
  /* MINI BADGES */
  .badge { display: inline-flex; align-items: center; padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; }
  .ok { background: rgba(6, 78, 59, 0.4); color: #6ee7b7; border: 1px solid #059669; }
  .fail { background: rgba(127, 29, 29, 0.4); color: #fca5a5; border: 1px solid #dc2626; }
  .na { background: rgba(55, 65, 81, 0.3); color: #9ca3af; border: 1px solid #4b5563; }
  .icon { width: 6px; height: 6px; border-radius: 50%; display: inline-block; }
  .icon-ok { background: #10b981; }
  .icon-fail { background: #ef4444; }
  
  /* SUPER COMPACT HARDWARE */
  .hw { background: #0d1117; border: 1px solid #1f2937; border-radius: 6px; padding: 10px; margin-top: 10px; }
  .hw-title { font-size: 11px; font-weight: 700; color: #cbd5e1; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
  .hw-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 8px; }
  .hw-item { }
  .hw-label { font-size: 9px; color: #9ca3af; margin-bottom: 3px; display: flex; justify-content: space-between; font-weight: 600; }
  .hw-bar { background: #1e293b; border-radius: 3px; height: 6px; overflow: hidden; position: relative; }
  .hw-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }
  .hw-good { background: linear-gradient(90deg, #10b981, #059669); }
  .hw-warn { background: linear-gradient(90deg, #f59e0b, #d97706); }
  .hw-crit { background: linear-gradient(90deg, #ef4444, #dc2626); }
  
  /* COMPACT REPLICATION TABLE */
  .table-wrap { overflow-x: auto; margin-top: 12px; border-radius: 6px; border: 1px solid #1f2937; }
  .table { width: 100%; border-collapse: collapse; font-size: 11px; }
  .table thead { background: linear-gradient(135deg, #1e293b, #0f172a); }
  .table th { padding: 8px 10px; text-align: left; color: #cbd5e1; font-size: 9px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; border-bottom: 1px solid #374151; white-space: nowrap; }
  .table thead tr:first-child th { padding: 10px; font-size: 10px; border-bottom: 2px solid #374151; }
  .table tbody tr { transition: background 0.15s; border-bottom: 1px solid #1f2937; }
  .table tbody tr:hover { background: rgba(59, 130, 246, 0.06); }
  .table td { padding: 8px 10px; color: #e2e8f0; border-right: 1px solid #1f2937; }
  .table td:first-child { font-weight: 600; color: #f9fafb; background: rgba(30, 41, 59, 0.3); }
  .table td:last-child { border-right: none; }
  .status-good { color: #6ee7b7; font-weight: 600; }
  .status-warn { color: #fbbf24; font-weight: 600; }
  .status-error { color: #fca5a5; font-weight: 600; }
  .badge-sm { padding: 3px 8px; font-size: 8px; border-radius: 4px; font-weight: 700; text-transform: uppercase; white-space: nowrap; display: inline-block; }
  .badge-success { background: rgba(6, 78, 59, 0.5); color: #6ee7b7; border: 1px solid #10b981; }
  .badge-warning { background: rgba(146, 64, 14, 0.5); color: #fbbf24; border: 1px solid #f59e0b; }
  .badge-error { background: rgba(127, 29, 29, 0.5); color: #fca5a5; border: 1px solid #ef4444; }
  
  /* COMPACT FSMO TABLE */
  .fsmo-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; }
  .fsmo-item { background: #0f1419; border: 1px solid #1f2937; border-radius: 6px; padding: 10px 12px; display: flex; justify-content: space-between; align-items: center; transition: all 0.15s; }
  .fsmo-item:hover { background: #1a1f2e; border-color: #374151; }
  .fsmo-role { font-size: 11px; color: #9ca3af; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; }
  .fsmo-holder { font-size: 13px; color: #e5e7eb; font-weight: 700; }
  .fsmo-icon { width: 24px; height: 24px; background: linear-gradient(135deg, #3b82f6, #1d4ed8); border-radius: 4px; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 700; color: #fff; margin-right: 10px; }
  
  /* DETAIL SECTION */
  .detail { display: none; margin-top: 12px; padding: 12px; background: #030712; border-radius: 6px; border: 1px solid #1f2937; }
  .detail.active { display: block; animation: fadeIn 0.2s; }
  .detail-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .detail-title { font-size: 12px; font-weight: 600; color: #e5e7eb; margin: 0; }
  .detail-close { background: #374151; border: none; color: #e5e7eb; padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 10px; font-weight: 600; }
  .detail-close:hover { background: #4b5563; }
  pre { white-space: pre-wrap; color: #cbd5e1; background: #0a0e14; padding: 10px; border-radius: 4px; font-size: 10px; line-height: 1.4; overflow-x: auto; border: 1px solid #1f2937; max-height: 300px; overflow-y: auto; margin: 0; }
  
  @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
  
  .footer { font-size: 10px; color: #64748b; margin-top: 20px; text-align: center; padding: 12px; border-top: 1px solid #1f2937; }
  
  @media (max-width: 768px) {
    .status-grid { grid-template-columns: 1fr 1fr; }
    .metrics { grid-template-columns: 1fr 1fr; }
    .hw-grid { grid-template-columns: 1fr; }
    .fsmo-grid { grid-template-columns: 1fr; }
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
    @{Label='DNS Svc'; Value=$_.DNS_Service; Key='DNS_Service'; HasDetail=$false},
    @{Label='NTDS Svc'; Value=$_.NTDS_Service; Key='NTDS_Service'; HasDetail=$false},
    @{Label='NetLogon'; Value=$_.NetLogon_Service; Key='NetLogon_Service'; HasDetail=$false},
    @{Label='Connect'; Value=$_.Connectivity; Key='Connectivity'; HasDetail=$true},
    @{Label='Advertise'; Value=$_.Advertising; Key='Advertising'; HasDetail=$true},
    @{Label='NetLogons'; Value=$_.NetLogons; Key='NetLogons'; HasDetail=$true},
    @{Label='Services'; Value=$_.ServicesTest; Key='Services'; HasDetail=$true},
    @{Label='Replication'; Value=$_.ReplicationsTest; Key='Replications'; HasDetail=$true},
    @{Label='RepAdmin'; Value=$_.Replication_RepAdmin; Key='RepAdmin'; HasDetail=$false},
    @{Label='FSMO'; Value=$_.FSMO; Key='FSMO'; HasDetail=$false},
    @{Label='SysVol'; Value=$_.SysVol; Key='SysVolCheck'; HasDetail=$true},
    @{Label='Topology'; Value=$_.Topology; Key='Topology'; HasDetail=$true}
  )
  
  $itemsHtml = $statusItems | ForEach-Object {
    $badgeHtml = Badge $_.Value
    $itemKey = $_.Key
    $itemClass = if ($_.HasDetail) { 'status-item' } else { 'status-item-static' }
    $onclickAttr = if ($_.HasDetail) { "onclick=`"toggleDetail('${dcSafe}_$itemKey')`"" } else { '' }
    
    @"
    <div class="$itemClass" $onclickAttr>
      <div class="status-label">$($_.Label)</div>
      <div class="status-value">$badgeHtml</div>
    </div>
"@
  } | Out-String

  # ULTRA COMPACT Hardware
  $hw = $_.Hardware
  $hwHtml = ""
  
  if ($hw) {
    $metricsHtml = ""
    
    # Uptime (text only, no bar)
    $uptimeVal = Show-NA $hw.UptimeHours
    $metricsHtml += "<div class='hw-item'><div class='hw-label'><span>Uptime</span><span>$uptimeVal hrs</span></div></div>"
    
    # CPU
    $cpuVal = Show-NA $hw.CPUUsagePct
    $cpuPct = if ($hw.CPUUsagePct) { $hw.CPUUsagePct } else { 0 }
    $cpuClass = if ($cpuPct -lt 70) { 'hw-good' } elseif ($cpuPct -lt 85) { 'hw-warn' } else { 'hw-crit' }
    $metricsHtml += "<div class='hw-item'><div class='hw-label'><span>CPU</span><span>$cpuVal%</span></div><div class='hw-bar'><div class='hw-fill $cpuClass' style='width: $cpuPct%'></div></div></div>"
    
    # Memory
    $memUsedPct = if ($hw.MemUsedPct) { $hw.MemUsedPct } else { 0 }
    $memClass = if ($memUsedPct -lt 70) { 'hw-good' } elseif ($memUsedPct -lt 85) { 'hw-warn' } else { 'hw-crit' }
    $memLabel = "$(Show-NA $hw.MemUsedGB)/$(Show-NA $hw.MemTotalGB)GB"
    $metricsHtml += "<div class='hw-item'><div class='hw-label'><span>RAM</span><span>$memLabel</span></div><div class='hw-bar'><div class='hw-fill $memClass' style='width: $memUsedPct%'></div></div></div>"

    # Disks (compact)
    if ($hw.Disks -and $hw.Disks.Count -gt 0) {
      foreach ($disk in $hw.Disks) {
        $diskClass = if ($disk.UsedPct -lt 70) { 'hw-good' } elseif ($disk.UsedPct -lt 85) { 'hw-warn' } else { 'hw-crit' }
        $diskLabel = "$($disk.UsedGB)/$($disk.SizeGB)GB"
        $metricsHtml += "<div class='hw-item'><div class='hw-label'><span>$($disk.Drive)</span><span>$diskLabel</span></div><div class='hw-bar'><div class='hw-fill $diskClass' style='width: $($disk.UsedPct)%'></div></div></div>"
      }
    }

    $hwHtml = "<div class='hw'><div class='hw-title'>Hardware & Resources</div><div class='hw-grid'>$metricsHtml</div></div>"
  }

  @"
<div class="dc-card">
  <div class="dc-header">
    <div class="dc-name">$dcName</div>
  </div>
  <div class="status-grid">
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
    $testOutput = ConvertTo-HtmlEncoded -Text $test.Value
    
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
  Write-Verbose "Parsing replication summary..."
  $replLines = $replSummary -split "`r?`n"
  $replData = @()
  
  # Parse repadmin /replsummary output
  # Looking for lines that contain DC names with replication stats
  $sourceSection = $false
  $destSection = $false
  
  foreach ($line in $replLines) {
    # Detect section headers
    if ($line -match 'Source DSA') { 
      $sourceSection = $true
      $destSection = $false
      Write-Verbose "Found Source DSA section"
      continue 
    }
    if ($line -match 'Destination DSA') { 
      $destSection = $true
      $sourceSection = $false
      Write-Verbose "Found Destination DSA section"
      continue 
    }
    
    # Skip empty lines and headers
    if ($line -match '^\s*$') { continue }
    if ($line -match '^[-=\s]+$') { continue }
    if ($line -match 'largest delta|fails/total|DSA') { continue }
    
    # Parse data lines - Try multiple formats
    # Format 1: SERVERNAME   :11s   0 / 5   0
    if ($line -match '^\s*(\S+)\s+:(\d+)s\s+(\d+)\s*/\s*(\d+)\s+(\d+)') {
      $dcName = $matches[1]
      $delta = $matches[2]
      $fails = $matches[3]
      $total = $matches[4]
      $errorCount = $matches[5]
      
      $type = if ($sourceSection) { 'Source' } elseif ($destSection) { 'Destination' } else { 'Unknown' }
      
      Write-Verbose "Parsed: $dcName - Type: $type, Delta: ${delta}s, Fails: $fails/$total, Errors: $errorCount"
      
      $replData += [pscustomobject]@{
        DC = $dcName
        Type = $type
        LargestDelta = [int]$delta
        Fails = [int]$fails
        Total = [int]$total
        Errors = [int]$errorCount
      }
    }
    # Format 2: SERVERNAME   11s   0 / 5   0 (without colon)
    elseif ($line -match '^\s*(\S+)\s+(\d+)s\s+(\d+)\s*/\s*(\d+)\s+(\d+)') {
      $dcName = $matches[1]
      $delta = $matches[2]
      $fails = $matches[3]
      $total = $matches[4]
      $errorCount = $matches[5]
      
      $type = if ($sourceSection) { 'Source' } elseif ($destSection) { 'Destination' } else { 'Unknown' }
      
      Write-Verbose "Parsed (alt format): $dcName - Type: $type, Delta: ${delta}s, Fails: $fails/$total, Errors: $errorCount"
      
      $replData += [pscustomobject]@{
        DC = $dcName
        Type = $type
        LargestDelta = [int]$delta
        Fails = [int]$fails
        Total = [int]$total
        Errors = [int]$errorCount
      }
    }
  }
  
  Write-Verbose "Total replication entries parsed: $($replData.Count)"
  
  if ($replData.Count -gt 0) {
    # Group by DC to combine Source and Destination data
    $replSummaryByDC = @{}
    
    foreach ($item in $replData) {
      if (-not $replSummaryByDC.ContainsKey($item.DC)) {
        $replSummaryByDC[$item.DC] = @{
          DC = $item.DC
          SourceDelta = 0
          SourceFails = 0
          SourceTotal = 0
          SourceErrors = 0
          DestDelta = 0
          DestFails = 0
          DestTotal = 0
          DestErrors = 0
        }
      }
      
      if ($item.Type -eq 'Source') {
        $replSummaryByDC[$item.DC].SourceDelta = $item.LargestDelta
        $replSummaryByDC[$item.DC].SourceFails = $item.Fails
        $replSummaryByDC[$item.DC].SourceTotal = $item.Total
        $replSummaryByDC[$item.DC].SourceErrors = $item.Errors
      } else {
        $replSummaryByDC[$item.DC].DestDelta = $item.LargestDelta
        $replSummaryByDC[$item.DC].DestFails = $item.Fails
        $replSummaryByDC[$item.DC].DestTotal = $item.Total
        $replSummaryByDC[$item.DC].DestErrors = $item.Errors
      }
    }
    
    $replRows = $replSummaryByDC.Values | ForEach-Object {
      $totalErrors = $_.SourceErrors + $_.DestErrors
      $totalFails = $_.SourceFails + $_.DestFails
      $maxDelta = [Math]::Max($_.SourceDelta, $_.DestDelta)
      
      # Status badge
      $statusBadge = if ($totalErrors -eq 0 -and $totalFails -eq 0) {
        '<span class="badge-sm badge-success">✓ HEALTHY</span>'
      } elseif ($totalErrors -gt 0) {
        '<span class="badge-sm badge-error">✗ ERROR</span>'
      } else {
        '<span class="badge-sm badge-warning">⚠ WARN</span>'
      }
      
      # Delta color
      $deltaClass = if ($maxDelta -lt 60) { 'status-good' }
                    elseif ($maxDelta -lt 300) { 'status-warn' }
                    else { 'status-error' }
      
      # Error color
      $errorClass = if ($totalErrors -gt 0) { 'status-error' } 
                    elseif ($totalFails -gt 0) { 'status-warn' }
                    else { 'status-good' }
      
      @"
<tr>
  <td><strong>$($_.DC)</strong></td>
  <td class="$deltaClass">$($_.SourceDelta)s</td>
  <td>$($_.SourceFails)/$($_.SourceTotal)</td>
  <td class="$errorClass">$($_.SourceErrors)</td>
  <td class="$deltaClass">$($_.DestDelta)s</td>
  <td>$($_.DestFails)/$($_.DestTotal)</td>
  <td class="$errorClass">$($_.DestErrors)</td>
  <td style="text-align: center;">$statusBadge</td>
</tr>
"@
    } | Out-String
    
    $replTableHtml = @"
<div class="table-wrap">
  <table class="table">
    <thead>
      <tr>
        <th rowspan="2">Domain Controller</th>
        <th colspan="3" style="text-align: center; border-right: 2px solid #374151;">Source DSA</th>
        <th colspan="3" style="text-align: center; border-right: 2px solid #374151;">Destination DSA</th>
        <th rowspan="2" style="text-align: center;">Status</th>
      </tr>
      <tr>
        <th style="border-right: 1px solid #1f2937;">Delta</th>
        <th style="border-right: 1px solid #1f2937;">Fails/Total</th>
        <th style="border-right: 2px solid #374151;">Errors</th>
        <th style="border-right: 1px solid #1f2937;">Delta</th>
        <th style="border-right: 1px solid #1f2937;">Fails/Total</th>
        <th style="border-right: 2px solid #374151;">Errors</th>
      </tr>
    </thead>
    <tbody>
      $replRows
    </tbody>
  </table>
</div>
"@
  } else {
    # Fallback: show raw output in a formatted pre tag
    $encodedSummary = ConvertTo-HtmlEncoded -Text $replSummary
    $replTableHtml = @"
<div class="muted" style="margin-bottom: 12px;">Unable to parse replication summary data. Raw output below:</div>
<div style="background: #0b1220; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; overflow-x: auto;">
  <pre style="margin: 0; max-height: none;">$encodedSummary</pre>
</div>
"@
  }
}

$fsmoHtml = @"
<div class="fsmo-grid">
  <div class="fsmo-item">
    <div style="display: flex; align-items: center;">
      <div class="fsmo-icon">SM</div>
      <div>
        <div class="fsmo-role">Schema Master</div>
        <div class="fsmo-holder">$($fsmo.SchemaMaster)</div>
      </div>
    </div>
  </div>
  <div class="fsmo-item">
    <div style="display: flex; align-items: center;">
      <div class="fsmo-icon">DN</div>
      <div>
        <div class="fsmo-role">Domain Naming</div>
        <div class="fsmo-holder">$($fsmo.DomainNamingMaster)</div>
      </div>
    </div>
  </div>
  <div class="fsmo-item">
    <div style="display: flex; align-items: center;">
      <div class="fsmo-icon">PDC</div>
      <div>
        <div class="fsmo-role">PDC Emulator</div>
        <div class="fsmo-holder">$($fsmo.PDCEmulator)</div>
      </div>
    </div>
  </div>
  <div class="fsmo-item">
    <div style="display: flex; align-items: center;">
      <div class="fsmo-icon">RID</div>
      <div>
        <div class="fsmo-role">RID Master</div>
        <div class="fsmo-holder">$($fsmo.RIDMaster)</div>
      </div>
    </div>
  </div>
  <div class="fsmo-item">
    <div style="display: flex; align-items: center;">
      <div class="fsmo-icon">INF</div>
      <div>
        <div class="fsmo-role">Infrastructure</div>
        <div class="fsmo-holder">$($fsmo.InfrastructureMaster)</div>
      </div>
    </div>
  </div>
</div>
"@

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>AD Health Report</title>
$css
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="header-top">
        <h1 class="header-title">Active Directory Health Report</h1>
        <div class="header-meta">
          <div class="meta-item">
            <span class="meta-label">Generated:</span>
            <span class="meta-value">$(Get-Date -Format "yyyy-MM-dd HH:mm")</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Domain:</span>
            <span class="meta-value">$($domain.DNSRoot)</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Forest:</span>
            <span class="meta-value">$($forest.Name)</span>
          </div>
        </div>
      </div>
      <div class="metrics">
        <div class="metric">
          <div class="metric-label">Domain Controllers</div>
          <div class="metric-value">$total</div>
        </div>
        <div class="metric $(if($failCount -gt 0){'metric-alert'})">
          <div class="metric-label">Total Failures</div>
          <div class="metric-value" style="color: $(if($failCount -gt 0){'#fca5a5'}else{'#6ee7b7'})">$failCount</div>
        </div>
        <div class="metric">
          <div class="metric-label">Forest Level</div>
          <div class="metric-value" style="font-size: 16px;">$($forest.ForestMode)</div>
        </div>
        <div class="metric">
          <div class="metric-label">Domain Level</div>
          <div class="metric-value" style="font-size: 16px;">$($domain.DomainMode)</div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2 class="card-title">Domain Controllers Status</h2>
      <div class="card-subtitle">Click status items with details to expand diagnostics</div>
      $dcCards
      
      <div id="detail-container" class="detail">
        <div class="detail-header">
          <h3 class="detail-title" id="detail-title">Details</h3>
          <button onclick="closeDetail()" class="detail-close">✕ Close</button>
        </div>
        <pre id="detail-content"></pre>
      </div>
    </div>

    <div class="card">
      <h2 class="card-title">Replication Summary</h2>
      <div class="card-subtitle">AD replication status across all domain controllers</div>
      $replTableHtml
    </div>

    <div class="card">
      <h2 class="card-title">FSMO Role Holders</h2>
      $fsmoHtml
    </div>

    <div class="footer">
      AD Health Report v2.5 | Generated by Invoke-ADHealthReport-Improved.ps1 | CPU measurements: 10s intervals
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
