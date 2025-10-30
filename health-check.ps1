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
  
  if ([System.Web.HttpUtility] -as [Type]) {
    return [System.Web.HttpUtility]::HtmlEncode($Text)
  }
  
  $Text = $Text -replace '&', '&amp;'
  $Text = $Text -replace '<', '&lt;'
  $Text = $Text -replace '>', '&gt;'
  $Text = $Text -replace '"', '&quot;'
  $Text = $Text -replace "'", '&#39;'
  return $Text
}

function Get-ADLevelShort {
  param([string]$Level)
  if ($Level -match '(\d{4}R?\d?)') { return $matches[1] }
  return $Level
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

function Invoke-DcDiagTest {
  param([string]$Server,[string]$TestName)
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
    $cpu1 = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -ComputerName $Server -Filter "Name='_Total'" -ErrorAction Stop
    if (-not $cpu1) { $cpu1 = Try-GetWmi -Class Win32_PerfFormattedData_PerfOS_Processor -ComputerName $Server -Filter "Name='_Total'" }
    
    Start-Sleep -Seconds 10
    
    $cpu2 = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -ComputerName $Server -Filter "Name='_Total'" -ErrorAction Stop
    if (-not $cpu2) { $cpu2 = Try-GetWmi -Class Win32_PerfFormattedData_PerfOS_Processor -ComputerName $Server -Filter "Name='_Total'" }
    
    if ($cpu2) { return [Math]::Round($cpu2.PercentProcessorTime, 1) }
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
    foreach ($d in @('C:', 'D:', 'E:')) {
      $disk = Try-GetWmi -Class Win32_LogicalDisk -ComputerName $Server -Filter "DeviceID='$d'"
      if ($disk) { $disks += $disk }
    }
  }

  $cpuUsage = Get-CPUUsage -Server $Server
  $memTotalGB = if ($os) { [Math]::Round($os.TotalVisibleMemorySize/1MB,1) } else { $null }
  $memFreeGB  = if ($os) { [Math]::Round($os.FreePhysicalMemory/1MB,1) } else { $null }
  $memUsedGB  = if ($memTotalGB -and $memFreeGB) { [Math]::Round($memTotalGB - $memFreeGB, 1) } else { $null }
  $memUsedPct = if ($memTotalGB -gt 0) { [Math]::Round(($memUsedGB/$memTotalGB)*100,1) } else { $null }
  $memFreePct = if ($memUsedPct) { [Math]::Round(100 - $memUsedPct, 1) } else { $null }
  $uptime     = if ($os) { [Math]::Round((New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)).TotalHours,1) } else { $null }

  $diskInfo = @()
  foreach ($disk in $disks) {
    $freeGB = [Math]::Round($disk.FreeSpace/1GB,1)
    $sizeGB = [Math]::Round($disk.Size/1GB,1)
    $usedGB = [Math]::Round($sizeGB - $freeGB, 1)
    $usedPct = if ($sizeGB -gt 0) { [Math]::Round(($usedGB/$sizeGB)*100,1) } else { 0 }
    $freePct = if ($sizeGB -gt 0) { [Math]::Round(($freeGB/$sizeGB)*100,1) } else { 0 }
    
    $diskInfo += [pscustomobject]@{
      Drive = $disk.DeviceID; SizeGB = $sizeGB; UsedGB = $usedGB
      FreeGB = $freeGB; UsedPct = $usedPct; FreePct = $freePct
    }
  }

  [pscustomobject]@{
    UptimeHours = $uptime; CPUUsagePct = $cpuUsage
    MemTotalGB  = $memTotalGB; MemUsedGB  = $memUsedGB; MemFreeGB   = $memFreeGB
    MemUsedPct  = $memUsedPct; MemFreePct  = $memFreePct; Disks = $diskInfo
  }
}

function Test-Services {
  param([string]$Server,[string[]]$Names=@('DNS','NTDS','Netlogon','Kdc','DFSR','W32Time'))
  $map = @{
    'DNS'='DNS'; 'NTDS'='NTDS'; 'Netlogon'='Netlogon'
    'Kdc'='Kdc'; 'DFSR'='DFSR'; 'W32Time'='W32Time'
  }
  $result = @{}
  foreach ($n in $Names) {
    $svc = Get-Service -ComputerName $Server -Name $map[$n] -ErrorAction SilentlyContinue
    $result[$n] = if ($svc) { $svc.Status -eq 'Running' } else { $false }
  }
  [pscustomobject]$result
}

function Get-CriticalEvents {
  param([string]$Server,[int]$Hours=24)
  try {
    $startTime = (Get-Date).AddHours(-$Hours)
    $logs = @('System', 'Application', 'Directory Service')
    $criticalCount = 0; $errorCount = 0
    
    foreach ($log in $logs) {
      try {
        $events = Get-WinEvent -ComputerName $Server -FilterHashtable @{
          LogName = $log; Level = 1,2; StartTime = $startTime
        } -ErrorAction SilentlyContinue
        
        if ($events) {
          $criticalCount += ($events | Where-Object { $_.Level -eq 1 }).Count
          $errorCount += ($events | Where-Object { $_.Level -eq 2 }).Count
        }
      } catch { Write-Verbose "Could not read $log on $Server" }
    }
    
    return [pscustomobject]@{
      Critical = $criticalCount; Error = $errorCount; Total = $criticalCount + $errorCount
    }
  } catch {
    return [pscustomobject]@{ Critical = $null; Error = $null; Total = $null }
  }
}

function Get-ADBackupStatus {
  param([string]$Server)
  try {
    $res = Invoke-External -FileName 'repadmin.exe' -Arguments @('/showbackup', $Server)
    if ($res.Output -match 'dsaMain\s+:\s+(.+)') {
      try {
        $backupDate = [DateTime]::Parse($matches[1].Trim())
        $daysSince = [Math]::Round((New-TimeSpan -Start $backupDate -End (Get-Date)).TotalDays, 1)
        return [pscustomobject]@{
          LastBackup = $backupDate; DaysSince = $daysSince
          Status = if ($daysSince -lt 7) { 'OK' } elseif ($daysSince -lt 14) { 'WARN' } else { 'FAIL' }
        }
      } catch { }
    }
    return [pscustomobject]@{ LastBackup = $null; DaysSince = $null; Status = 'UNKNOWN' }
  } catch {
    return [pscustomobject]@{ LastBackup = $null; DaysSince = $null; Status = 'UNKNOWN' }
  }
}

function Get-TimeSync {
  param([string]$Server)
  try {
    $res = Invoke-External -FileName 'w32tm.exe' -Arguments @('/stripchart', "/computer:$Server", '/samples:1', '/dataonly')
    if ($res.Output -match '([\+\-]?\d+\.\d+)s') {
      $offset = [Math]::Abs([double]$matches[1])
      return [pscustomobject]@{
        OffsetSeconds = [Math]::Round($offset, 3)
        Status = if ($offset -lt 1) { 'OK' } elseif ($offset -lt 5) { 'WARN' } else { 'FAIL' }
      }
    }
    return [pscustomobject]@{ OffsetSeconds = $null; Status = 'UNKNOWN' }
  } catch {
    return [pscustomobject]@{ OffsetSeconds = $null; Status = 'UNKNOWN' }
  }
}

function New-Status { param([bool]$Ok) if ($Ok) { 'OK' } else { 'FAIL' } }

function Badge {
  param([string]$val)
  switch ($val) {
    'OK'   { '<span class="badge ok">OK</span>' }
    'FAIL' { '<span class="badge fail">FAIL</span>' }
    'WARN' { '<span class="badge warn">WARN</span>' }
    default { '<span class="badge na">N/A</span>' }
  }
}

function Show-NA {
  param([object]$v,[string]$suffix="")
  if ($null -eq $v -or ($v -is [string] -and [string]::IsNullOrWhiteSpace($v))) { "N/A" }
  else { if ($suffix) { "$v$suffix" } else { "$v" } }
}

# ===================== Tools check =====================
if (-not (Get-Module -ListAvailable ActiveDirectory)) { throw "ActiveDirectory module not found." }
if (-not (Test-Tool 'dcdiag.exe')) { throw "dcdiag.exe not found." }
if (-not (Test-Tool 'repadmin.exe')) { throw "repadmin.exe not found." }
Import-Module ActiveDirectory -ErrorAction Stop

# ===================== Discover DCs =====================
$allDCs = Get-DCList -UsingOU:$UsingOU -OrganizationUnitDN $OrganizationUnitDN -DomainControllers $DomainControllers

Write-Verbose "Collecting DC details..."
$dcDetails = @{}
foreach ($dcName in $allDCs) {
  try {
    $dcInfo = Get-ADDomainController -Identity $dcName -ErrorAction Stop
    $ipAddress = $dcInfo.IPv4Address
    if (-not $ipAddress) {
      try {
        $ipAddress = [System.Net.Dns]::GetHostAddresses($dcName) | 
                     Where-Object { $_.AddressFamily -eq 'InterNetwork' } | 
                     Select-Object -First 1 -ExpandProperty IPAddressToString
      } catch { $ipAddress = "N/A" }
    }
    $dcDetails[$dcName] = @{ IP = $ipAddress; IsGC = $dcInfo.IsGlobalCatalog }
  } catch {
    $dcDetails[$dcName] = @{ IP = "N/A"; IsGC = $false }
  }
}

# ===================== Collect per DC =====================
$results = @()
$detailBlobs = @()
$dcdiagTests = @(
  'Connectivity','Advertising','DNS','NetLogons','Services',
  'Replications','Topology','SysVolCheck','KnowsOfRoleHolders','RidManager'
)

foreach ($dc in $allDCs) {
  Write-Verbose "Collecting $dc ..."
  $pingOk = Test-Connection -ComputerName $dc -Count 1 -Quiet -ErrorAction SilentlyContinue
  $svc = Test-Services -Server $dc

  $testResults = @{}; $testOutputs = @{}
  foreach ($t in $dcdiagTests) {
    $tres = Invoke-DcDiagTest -Server $dc -TestName $t
    $testResults[$t] = $tres.Status
    $testOutputs[$t] = $tres.Output
  }

  $fsmStatus = if ($testResults['KnowsOfRoleHolders'] -eq 'FAIL' -or $testResults['RidManager'] -eq 'FAIL') { 'FAIL' } else { 'OK' }
  $rep = Invoke-RepAdmin -Server $dc
  $repStatus = if ($rep.Output -match '(?i)\b(fail|failed|error|erro)\b') { 'FAIL' } else { 'OK' }
  
  $events = Get-CriticalEvents -Server $dc -Hours 24
  $backup = Get-ADBackupStatus -Server $dc
  $timeSync = Get-TimeSync -Server $dc
  $hw = Get-HardwareInfo -Server $dc

  $obj = [pscustomobject]@{
    DC=$dc; IP=$dcDetails[$dc].IP; IsGlobalCatalog=$dcDetails[$dc].IsGC
    Ping=New-Status $pingOk; DNS_Service=New-Status $svc.DNS; NTDS_Service=New-Status $svc.NTDS
    NetLogon_Service=New-Status $svc.Netlogon; Kdc_Service=New-Status $svc.Kdc
    DFSR_Service=New-Status $svc.DFSR; W32Time_Service=New-Status $svc.W32Time
    Connectivity=$testResults['Connectivity']; Advertising=$testResults['Advertising']
    DNSTest=$testResults['DNS']; NetLogons=$testResults['NetLogons']
    ServicesTest=$testResults['Services']; ReplicationsTest=$testResults['Replications']
    Topology=$testResults['Topology']; SysVol=$testResults['SysVolCheck']
    FSMO=$fsmStatus; Replication_RepAdmin=$repStatus
    CriticalEvents=$events.Total; BackupStatus=$backup.Status; BackupDays=$backup.DaysSince
    TimeSyncStatus=$timeSync.Status; TimeSyncOffset=$timeSync.OffsetSeconds; Hardware=$hw
  }
  $results += $obj
  $detailBlobs += [pscustomobject]@{
    DC=$dc; TestOutputs=$testOutputs; RepAdminText=$rep.Output
  }
}

# ===================== Summary =====================
$replSummary = Get-ReplSummary
$forest = Get-ADForest
$domain = Get-ADDomain
$fsmo = [pscustomobject]@{
  SchemaMaster=$forest.SchemaMaster; DomainNamingMaster=$forest.DomainNamingMaster
  PDCEmulator=$domain.PDCEmulator; RIDMaster=$domain.RIDMaster
  InfrastructureMaster=$domain.InfrastructureMaster
}

$total = $results.Count
$healthColumns = @(
  'Ping','DNS_Service','NTDS_Service','NetLogon_Service','Kdc_Service','DFSR_Service','W32Time_Service',
  'Connectivity','Advertising','DNSTest','NetLogons','ServicesTest',
  'ReplicationsTest','Topology','SysVol','FSMO','Replication_RepAdmin'
)

$failCount = 0; $warnCount = 0
foreach ($dc in $results) {
  foreach ($col in $healthColumns) {
    if ($dc.$col -eq 'FAIL') { $failCount++ }
    elseif ($dc.$col -eq 'WARN') { $warnCount++ }
  }
  if ($dc.BackupStatus -eq 'FAIL') { $failCount++ }
  elseif ($dc.BackupStatus -eq 'WARN') { $warnCount++ }
  if ($dc.TimeSyncStatus -eq 'FAIL') { $failCount++ }
  elseif ($dc.TimeSyncStatus -eq 'WARN') { $warnCount++ }
}

# ===================== CSV =====================
if ($Csv) {
  $csvPath = [IO.Path]::ChangeExtension((Resolve-Path $OutputPath),'.csv')
  $results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath
}

# Replication Summary Table
$replTableHtml = ""
if ($replSummary) {
  Write-Verbose "Parsing replication summary..."
  $replLines = $replSummary -split "`r?`n"
  $replData = @()
  $sourceSection = $false; $destSection = $false
  
  foreach ($line in $replLines) {
    if ($line -match 'Source DSA') { $sourceSection = $true; $destSection = $false; continue }
    if ($line -match 'Destination DSA') { $destSection = $true; $sourceSection = $false; continue }
    if ($line -match '^\s*$|^[-=\s]+$|largest delta|fails/total|DSA') { continue }
    
    if ($line -match '^\s*(\S+)\s+:?(\d+)s\s+(\d+)\s*/\s*(\d+)\s+(\d+)') {
      $replData += [pscustomobject]@{
        DC = $matches[1]; Type = if ($sourceSection) { 'Source' } else { 'Destination' }
        LargestDelta = [int]$matches[2]; Fails = [int]$matches[3]
        Total = [int]$matches[4]; Errors = [int]$matches[5]
      }
    }
  }
  
  if ($replData.Count -gt 0) {
    $replSummaryByDC = @{}
    foreach ($item in $replData) {
      if (-not $replSummaryByDC.ContainsKey($item.DC)) {
        $replSummaryByDC[$item.DC] = @{
          DC=$item.DC; SourceDelta=0; SourceFails=0; SourceTotal=0; SourceErrors=0
          DestDelta=0; DestFails=0; DestTotal=0; DestErrors=0
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
      
      $statusBadge = if ($totalErrors -eq 0 -and $totalFails -eq 0) {
        '<span class="badge-sm badge-success">✓ HEALTHY</span>'
      } elseif ($totalErrors -gt 0) {
        '<span class="badge-sm badge-error">✗ ERROR</span>'
      } else {
        '<span class="badge-sm badge-warning">⚠ WARN</span>'
      }
      
      $deltaClass = if ($maxDelta -lt 60) { 'status-good' } elseif ($maxDelta -lt 300) { 'status-warn' } else { 'status-error' }
      $errorClass = if ($totalErrors -gt 0) { 'status-error' } elseif ($totalFails -gt 0) { 'status-warn' } else { 'status-good' }
      
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
    $encodedSummary = ConvertTo-HtmlEncoded -Text $replSummary
    $replTableHtml = "<div style='background: #0b1220; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; overflow-x: auto;'><pre style='margin: 0; max-height: none;'>$encodedSummary</pre></div>"
  }
}

$fsmoHtml = @"
<div class="fsmo-grid">
  <div class="fsmo-item">
    <div style="display: flex; align-items: center;">
      <div class="fsmo-icon">SM</div>
      <div><div class="fsmo-role">Schema Master</div><div class="fsmo-holder">$($fsmo.SchemaMaster)</div></div>
    </div>
  </div>
  <div class="fsmo-item">
    <div style="display: flex; align-items: center;">
      <div class="fsmo-icon">DN</div>
      <div><div class="fsmo-role">Domain Naming</div><div class="fsmo-holder">$($fsmo.DomainNamingMaster)</div></div>
    </div>
  </div>
  <div class="fsmo-item">
    <div style="display: flex; align-items: center;">
      <div class="fsmo-icon">PDC</div>
      <div><div class="fsmo-role">PDC Emulator</div><div class="fsmo-holder">$($fsmo.PDCEmulator)</div></div>
    </div>
  </div>
  <div class="fsmo-item">
    <div style="display: flex; align-items: center;">
      <div class="fsmo-icon">RID</div>
      <div><div class="fsmo-role">RID Master</div><div class="fsmo-holder">$($fsmo.RIDMaster)</div></div>
    </div>
  </div>
  <div class="fsmo-item">
    <div style="display: flex; align-items: center;">
      <div class="fsmo-icon">INF</div>
      <div><div class="fsmo-role">Infrastructure</div><div class="fsmo-holder">$($fsmo.InfrastructureMaster)</div></div>
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
          <div class="metric-label">Critical Failures</div>
          <div class="metric-value" style="color: $(if($failCount -gt 0){'#fca5a5'}else{'#6ee7b7'})">$failCount</div>
        </div>
        <div class="metric $(if($warnCount -gt 0){'metric-warn'})">
          <div class="metric-label">Warnings</div>
          <div class="metric-value" style="color: $(if($warnCount -gt 0){'#fbbf24'}else{'#6ee7b7'})">$warnCount</div>
        </div>
        <div class="metric">
          <div class="metric-label">Forest Level</div>
          <div class="metric-value" style="font-size: 16px;">$(Get-ADLevelShort $forest.ForestMode)</div>
        </div>
        <div class="metric">
          <div class="metric-label">Domain Level</div>
          <div class="metric-value" style="font-size: 16px;">$(Get-ADLevelShort $domain.DomainMode)</div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2 class="card-title">Domain Controllers Status</h2>
      <div class="card-subtitle">Click status items with details to expand diagnostics • Hover over resource bars to see availability percentages</div>
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
      AD Health Report v3.0 Enhanced | ADHealthReport_Enhanced.ps1
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
  if (-not (Get-Module -ListAvailable Microsoft.Graph)) { throw "Microsoft.Graph module not found." }
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
          contentBytes = $b64; contentType = "text/html"
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
 )
  
  $itemsHtml = $statusItems | ForEach-Object {
    $badgeHtml = Badge $_.Value
    $itemClass = if ($_.HasDetail) { 'status-item' } else { 'status-item-static' }
    $onclickAttr = if ($_.HasDetail) { "onclick=`"toggleDetail('${dcSafe}_$($_.Key)')`"" } else { '' }
    
    @"
    <div class="$itemClass" $onclickAttr>
      <div class="status-label">$($_.Label)</div>
      <div class="status-value">$badgeHtml</div>
    </div>
"@
  } | Out-String

  $hw = $_.Hardware
  $hwHtml = ""
  
  if ($hw) {
    $metricsHtml = ""
    
    $uptimeVal = Show-NA $hw.UptimeHours
    $metricsHtml += "<div class='hw-item'><div class='hw-label'><span>Uptime</span><span>$uptimeVal hrs</span></div></div>"
    
    $cpuVal = Show-NA $hw.CPUUsagePct
    $cpuPct = if ($hw.CPUUsagePct) { $hw.CPUUsagePct } else { 0 }
    $cpuClass = if ($cpuPct -lt 70) { 'hw-good' } elseif ($cpuPct -lt 85) { 'hw-warn' } else { 'hw-crit' }
    $metricsHtml += "<div class='hw-item'><div class='hw-label'><span>CPU</span><span>$cpuVal%</span></div><div class='hw-bar' title='CPU Usage: $cpuVal% | Available: $([Math]::Round(100-$cpuPct,1))%'><div class='hw-fill $cpuClass' style='width: $cpuPct%'></div></div></div>"
    
    $memUsedPct = if ($hw.MemUsedPct) { $hw.MemUsedPct } else { 0 }
    $memFreePct = if ($hw.MemFreePct) { $hw.MemFreePct } else { 0 }
    $memClass = if ($memUsedPct -lt 70) { 'hw-good' } elseif ($memUsedPct -lt 85) { 'hw-warn' } else { 'hw-crit' }
    $memLabel = "$(Show-NA $hw.MemUsedGB)/$(Show-NA $hw.MemTotalGB)GB"
    $metricsHtml += "<div class='hw-item'><div class='hw-label'><span>RAM</span><span>$memLabel</span></div><div class='hw-bar' title='Memory Used: $memUsedPct% | Available: $memFreePct%'><div class='hw-fill $memClass' style='width: $memUsedPct%'></div></div></div>"

    if ($hw.Disks -and $hw.Disks.Count -gt 0) {
      foreach ($disk in $hw.Disks) {
        $diskClass = if ($disk.UsedPct -lt 70) { 'hw-good' } elseif ($disk.UsedPct -lt 85) { 'hw-warn' } else { 'hw-crit' }
        $diskLabel = "$($disk.UsedGB)/$($disk.SizeGB)GB"
        $metricsHtml += "<div class='hw-item'><div class='hw-label'><span>$($disk.Drive)</span><span>$diskLabel</span></div><div class='hw-bar' title='Disk $($disk.Drive) Used: $($disk.UsedPct)% | Available: $($disk.FreePct)%'><div class='hw-fill $diskClass' style='width: $($disk.UsedPct)%'></div></div></div>"
      }
    }

    $hwHtml = "<div class='hw'><div class='hw-title'>Hardware & Resources</div><div class='hw-grid'>$metricsHtml</div></div>"
  }

  @"
<div class="dc-card">
  <div class="dc-header">
    <div class="dc-info">
      <div class="dc-name">$dcName</div>
      <div class="dc-ip">[$dcIP]</div>
      $gcBadge
    </div>
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
  $dcSafe = $_.DC -replace '[^a-zA-Z0-9]', '_'
  foreach ($test in $_.TestOutputs.GetEnumerator()) {
    $testOutput = ConvertTo-HtmlEncoded -Text $test.Value
    $detailsScript += "`nvar detail_${dcSafe}_$($test.Key) = ``$testOutput``;"
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
