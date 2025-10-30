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

$healthColumns = @(
  'Ping','DNS_Service','NTDS_Service','NetLogon_Service',
  'Connectivity','Advertising','NetLogons','ServicesTest',
  'ReplicationsTest','Topology','SysVol','FSMO','Replication_RepAdmin'
)
$failCount = ($results | Where-Object {
  foreach ($c in $healthColumns) { if ($_.$c -eq 'FAIL') { return $true } }
  return $false
}).Count

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
  .tile .k { font-size: 13px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
  .tile .v { font-size: 32px; font-weight: 700; color: #fff; }
  
  .dc-card { background: #0b1220; border: 1px solid #1f2937; border-radius: 10px; padding: 20px; margin-bottom: 16px; transition: all 0.2s; }
  .dc-card:hover { border-color: #3b82f6; box-shadow: 0 4px 16px rgba(59, 130, 246, 0.1); }
  .dc-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid #1f2937; }
  .dc-name { font-size: 18px; font-weight: 600; color: #f9fafb; }
  .dc-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .dc-item { background: #151f30; padding: 12px; border-radius: 6px; border-left: 3px solid #374151; cursor: pointer; transition: all 0.2s; }
  .dc-item:hover { background: #1a2332; border-left-color: #3b82f6; transform: translateX(2px); }
  .dc-item-label { font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
  .dc-item-value { display: flex; align-items: center; gap: 8px; }
  
  .hw-section { background: #0d1829; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; margin-top: 16px; }
  .hw-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; }
  .hw-item { }
  .hw-label { font-size: 12px; color: #9ca3af; margin-bottom: 8px; display: flex; justify-content: space-between; }
  .hw-bar-container { background: #1e293b; border-radius: 8px; height: 24px; overflow: hidden; position: relative; }
  .hw-bar { height: 100%; border-radius: 8px; transition: width 0.3s ease; display: flex; align-items: center; padding: 0 8px; font-size: 11px; font-weight: 600; }
  .hw-bar-good { background: linear-gradient(90deg, #10b981 0%, #059669 100%); }
  .hw-bar-warning { background: linear-gradient(90deg, #f59e0b 0%, #d97706 100%); }
  .hw-bar-critical { background: linear-gradient(90deg, #ef4444 0%, #dc2626 100%); }
  .disk-list { display: flex; flex-direction: column; gap: 12px; }
  
  .badge { display: inline-flex; align-items: center; padding: 4px 12px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .ok { background: rgba(6, 78, 59, 0.3); color: #6ee7b7; border: 1px solid #10b981; }
  .fail { background: rgba(127, 29, 29, 0.3); color: #fca5a5; border: 1px solid #ef4444; }
  .na { background: rgba(55, 65, 81, 0.3); color: #e5e7eb; border: 1px solid #6b7280; }
  
  .icon { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  .icon-ok { background: #10b981; box-shadow: 0 0 8px rgba(16, 185, 129, 0.5); }
  .icon-fail { background: #ef4444; box-shadow: 0 0 8px rgba(239, 68, 68, 0.5); }
  
  .repl-table { width: 100%; border-collapse: collapse; margin-top: 16px; }
  .repl-table th, .repl-table td { padding: 12px; text-align: left; border-bottom: 1px solid #1f2937; }
  .repl-table th { background: #0b1220; color: #cbd5e1; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  .repl-table td { color: #e2e8f0; }
  .repl-table tr:hover { background: #0d1829; }
  
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
  
  .status-summary { display: flex; gap: 8px; flex-wrap: wrap; }
  
  .detail-section { display: none; margin-top: 16px; padding: 16px; background: #030712; border-radius: 8px; border: 1px solid #1f2937; }
  .detail-section.active { display: block; animation: fadeIn 0.3s ease; }
  
  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
  }
  
  @media (max-width: 768px) {
    .dc-grid { grid-template-columns: 1fr; }
    .grid { grid-template-columns: 1fr; }
    .hw-grid { grid-template-columns: 1fr; }
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
    @{Label='Ping'; Value=$_.Ping; Key='Ping'},
    @{Label='DNS Service'; Value=$_.DNS_Service; Key='DNS_Service'},
    @{Label='NTDS Service'; Value=$_.NTDS_Service; Key='NTDS_Service'},
    @{Label='NetLogon'; Value=$_.NetLogon_Service; Key='NetLogon_Service'},
    @{Label='Connectivity'; Value=$_.Connectivity; Key='Connectivity'},
    @{Label='Advertising'; Value=$_.Advertising; Key='Advertising'},
    @{Label='NetLogons'; Value=$_.NetLogons; Key='NetLogons'},
    @{Label='Services'; Value=$_.ServicesTest; Key='Services'},
    @{Label='Replications'; Value=$_.ReplicationsTest; Key='Replications'},
    @{Label='RepAdmin'; Value=$_.Replication_RepAdmin; Key='RepAdmin'},
    @{Label='FSMO'; Value=$_.FSMO; Key='FSMO'},
    @{Label='SysVol'; Value=$_.SysVol; Key='SysVolCheck'},
    @{Label='Topology'; Value=$_.Topology; Key='Topology'}
  )
  
  $itemsHtml = $statusItems | ForEach-Object {
    $badgeHtml = Badge $_.Value
    $itemKey = $_.Key
    @"
    <div class="dc-item" onclick="toggleDetail('${dcSafe}_$itemKey')">
      <div class="dc-item-label">$($_.Label)</div>
      <div class="dc-item-value">$badgeHtml</div>
    </div>
"@
  } | Out-String

  # Hardware info
  $hw = $_.Hardware
  $hwHtml = ""
  
  if ($hw) {
    # Uptime
    $uptimeHtml = "<div><strong>Uptime:</strong> $(Show-NA $hw.UptimeHours ' hours')</div>"
    
    # Memory bar
    $memUsedPct = if ($hw.MemUsedPct) { $hw.MemUsedPct } else { 0 }
    $memClass = if ($memUsedPct -lt 70) { 'hw-bar-good' } elseif ($memUsedPct -lt 85) { 'hw-bar-warning' } else { 'hw-bar-critical' }
    $memHtml = @"
<div class="hw-item">
  <div class="hw-label">
    <span>Memory</span>
    <span>$(Show-NA $hw.MemUsedGB) / $(Show-NA $hw.MemTotalGB) GB</span>
  </div>
  <div class="hw-bar-container">
    <div class="hw-bar $memClass" style="width: $memUsedPct%">$memUsedPct%</div>
  </div>
</div>
"@

    # Disk bars
    $disksHtml = ""
    if ($hw.Disks -and $hw.Disks.Count -gt 0) {
      $disksHtml = '<div class="disk-list">'
      foreach ($disk in $hw.Disks) {
        $diskClass = if ($disk.UsedPct -lt 70) { 'hw-bar-good' } elseif ($disk.UsedPct -lt 85) { 'hw-bar-warning' } else { 'hw-bar-critical' }
        $disksHtml += @"
<div class="hw-item">
  <div class="hw-label">
    <span>Disk $($disk.Drive)</span>
    <span>$($disk.UsedGB) / $($disk.SizeGB) GB</span>
  </div>
  <div class="hw-bar-container">
    <div class="hw-bar $diskClass" style="width: $($disk.UsedPct)%">$($disk.UsedPct)%</div>
  </div>
</div>
"@
      }
      $disksHtml += '</div>'
    }

    $hwHtml = @"
<div class="hw-section">
  <h3 style="margin-top:0;">Hardware & Resources</h3>
  $uptimeHtml
  <div class="hw-grid" style="margin-top: 16px;">
    $memHtml
  </div>
  $disksHtml
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

# Details sections (collapsed by default, shown when clicking status items)
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

# Parse replication summary
