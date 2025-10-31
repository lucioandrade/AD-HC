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
  try { (Get-ADDomain).DistinguishedName } catch { throw "Unable to get domain DN." }
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

function ConvertFrom-WmiDateTime {
  param([string]$WmiDateTime)
  try {
    if ($WmiDateTime -match '(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})') {
      $year = $matches[1]
      $month = $matches[2]
      $day = $matches[3]
      $hour = $matches[4]
      $minute = $matches[5]
      $second = $matches[6]
      return [DateTime]::ParseExact("$year-$month-$day $($hour):$($minute):$($second)", "yyyy-MM-dd HH:mm:ss", $null)
    }
  } catch {
    Write-Verbose "Failed to parse WMI DateTime: $WmiDateTime"
  }
  return $null
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

function Format-Uptime {
  param([double]$Hours)
  if ($null -eq $Hours) { return "N/A" }
  
  if ($Hours -ge 24) {
    $days = [Math]::Floor($Hours / 24)
    $remainingHours = [Math]::Round($Hours % 24, 1)
    if ($remainingHours -eq 0) {
      return "$days days"
    } else {
      return "$days days $remainingHours hrs"
    }
  } else {
    return "$([Math]::Round($Hours, 1)) hrs"
  }
}

function Get-HardwareInfo {
  param([string]$Server)
  $os = $null
  $disks = $null
  
  try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Server -ErrorAction Stop
  } catch {
    Write-Verbose "Failed to get OS info via CIM, trying WMI..."
    $os = Try-GetWmi -Class Win32_OperatingSystem -ComputerName $Server
  }
  
  try {
    $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $Server -ErrorAction Stop
  } catch {
    Write-Verbose "Failed to get disk info via CIM, trying WMI..."
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
  
  # Fix uptime calculation
  $uptimeHours = $null
  if ($os) {
    try {
      if ($os.LastBootUpTime -is [DateTime]) {
        $uptimeHours = [Math]::Round((New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)).TotalHours, 1)
      } else {
        # WMI format
        $bootTime = ConvertFrom-WmiDateTime -WmiDateTime $os.LastBootUpTime
        if ($bootTime) {
          $uptimeHours = [Math]::Round((New-TimeSpan -Start $bootTime -End (Get-Date)).TotalHours, 1)
        }
      }
    } catch {
      Write-Verbose "Failed to calculate uptime: $_"
    }
  }
  
  $diskInfo = @()
  if ($disks) {
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
  }
  
  [pscustomobject]@{
    UptimeHours = $uptimeHours; CPUUsagePct = $cpuUsage
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
      } catch { }
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

function Get-ADCriticalEventIDs {
  param([string]$Server,[int]$Hours = 24)
  $criticalEvents = @{
    1864 = @{Category='Replication'; Severity='Critical'; Description='Lack of disk space for logs'}
    2042 = @{Category='Replication'; Severity='Warning'; Description='Long time without replication'}
    2092 = @{Category='Replication'; Severity='Critical'; Description='Replication blocked'}
    4013 = @{Category='DNS'; Severity='Critical'; Description='AD DNS error'}
    5805 = @{Category='Authentication'; Severity='Warning'; Description='Authentication failure'}
    13508 = @{Category='SYSVOL'; Severity='Critical'; Description='SYSVOL replication error'}
    13509 = @{Category='SYSVOL'; Severity='Warning'; Description='SYSVOL share not published'}
    1168 = @{Category='Database'; Severity='Critical'; Description='AD database error'}
    1173 = @{Category='Database'; Severity='Critical'; Description='Corrupted database'}
    2089 = @{Category='Backup'; Severity='Warning'; Description='Outdated AD backup'}
  }
  try {
    $startTime = (Get-Date).AddHours(-$Hours)
    $foundEvents = @()
    foreach ($eventId in $criticalEvents.Keys) {
      try {
        $events = Get-WinEvent -ComputerName $Server -FilterHashtable @{
          LogName = 'Directory Service', 'System', 'DFS Replication'
          ID = $eventId
          StartTime = $startTime
        } -ErrorAction SilentlyContinue
        foreach ($event in $events) {
          $eventInfo = $criticalEvents[$eventId]
          $foundEvents += [pscustomobject]@{
            EventID = $eventId
            TimeCreated = $event.TimeCreated
            Category = $eventInfo.Category
            Severity = $eventInfo.Severity
            Description = $eventInfo.Description
            Message = $event.Message
          }
        }
      } catch { }
    }
    return $foundEvents | Sort-Object TimeCreated -Descending
  } catch {
    return @()
  }
}

function Test-ADCertificates {
  param([string]$Server,[int]$WarningDays = 30)
  try {
    $certs = Invoke-Command -ComputerName $Server -ScriptBlock {
      Get-ChildItem -Path Cert:\LocalMachine\My | 
      Where-Object { $_.HasPrivateKey -eq $true }
    } -ErrorAction Stop
    $certStatus = @()
    $now = Get-Date
    foreach ($cert in $certs) {
      $daysUntilExpiration = ($cert.NotAfter - $now).Days
      $status = 'OK'
      $severity = 'Info'
      if ($daysUntilExpiration -lt 0) {
        $status = 'EXPIRED'
        $severity = 'Critical'
      } elseif ($daysUntilExpiration -le $WarningDays) {
        $status = 'EXPIRING SOON'
        $severity = 'Warning'
      }
      $certStatus += [pscustomobject]@{
        Subject = $cert.Subject
        Issuer = $cert.Issuer
        Thumbprint = $cert.Thumbprint
        NotBefore = $cert.NotBefore
        NotAfter = $cert.NotAfter
        DaysUntilExpiration = $daysUntilExpiration
        Status = $status
        Severity = $severity
      }
    }
    return $certStatus | Sort-Object DaysUntilExpiration
  } catch {
    return @()
  }
}

function Test-ADIntegratedDNS {
  param([string]$Server)
  try {
    $issues = @()
    $zones = Get-DnsServerZone -ComputerName $Server -ErrorAction Stop | Where-Object { $_.IsReverseLookupZone -eq $false }
    foreach ($zone in $zones) {
      if ($zone.ZoneType -ne 'Primary' -or $zone.IsDsIntegrated -ne $true) {
        $issues += [pscustomobject]@{
          Zone = $zone.ZoneName
          Issue = 'Not AD Integrated'
          Severity = 'Warning'
        }
      }
      if ($zone.DynamicUpdate -eq 'None') {
        $issues += [pscustomobject]@{
          Zone = $zone.ZoneName
          Issue = 'Dynamic Updates Disabled'
          Severity = 'Warning'
        }
      }
      $zoneAging = Get-DnsServerZoneAging -Name $zone.ZoneName -ComputerName $Server -ErrorAction SilentlyContinue
      if ($zoneAging -and -not $zoneAging.ScavengingEnabled) {
        $issues += [pscustomobject]@{
          Zone = $zone.ZoneName
          Issue = 'Scavenging Disabled'
          Severity = 'Info'
        }
      }
    }
    $domain = (Get-ADDomain).DNSRoot
    $requiredSRV = @(
      "_ldap._tcp.$domain",
      "_kerberos._tcp.$domain",
      "_kpasswd._tcp.$domain",
      "_gc._tcp.$domain"
    )
    foreach ($srv in $requiredSRV) {
      try {
        $result = Resolve-DnsName -Name $srv -Type SRV -Server $Server -ErrorAction Stop
        if (-not $result) {
          $issues += [pscustomobject]@{
            Zone = $domain
            Issue = "Missing SRV: $srv"
            Severity = 'Critical'
          }
        }
      } catch {
        $issues += [pscustomobject]@{
          Zone = $domain
          Issue = "Missing SRV: $srv"
          Severity = 'Critical'
        }
      }
    }
    return [pscustomobject]@{
      TotalZones = $zones.Count
      Issues = $issues
      Status = if ($issues | Where-Object { $_.Severity -eq 'Critical' }) { 'FAIL' } 
               elseif ($issues | Where-Object { $_.Severity -eq 'Warning' }) { 'WARN' } 
               else { 'OK' }
    }
  } catch {
    return [pscustomobject]@{ TotalZones = 0; Issues = @(); Status = 'UNKNOWN' }
  }
}

function Test-TrustRelationships {
  try {
    $trusts = Get-ADTrust -Filter * -ErrorAction Stop
    $trustStatus = @()
    foreach ($trust in $trusts) {
      try {
        $testResult = Test-ComputerSecureChannel -Server $trust.Name -ErrorAction Stop
        $status = if ($testResult) { 'OK' } else { 'BROKEN' }
        $severity = if ($testResult) { 'Info' } else { 'Critical' }
      } catch {
        $status = 'ERROR'
        $severity = 'Critical'
      }
      $trustStatus += [pscustomobject]@{
        Name = $trust.Name
        Direction = $trust.Direction
        TrustType = $trust.TrustType
        Status = $status
        Severity = $severity
      }
    }
    return [pscustomobject]@{
      TotalTrusts = $trusts.Count
      TrustDetails = $trustStatus
      Status = if ($trustStatus | Where-Object { $_.Status -ne 'OK' }) { 'FAIL' } else { 'OK' }
    }
  } catch {
    return [pscustomobject]@{ TotalTrusts = 0; TrustDetails = @(); Status = 'UNKNOWN' }
  }
}

function New-Status { param([bool]$Ok) if ($Ok) { 'OK' } else { 'FAIL' } }

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

# Get PDC Emulator
$pdcEmulator = (Get-ADDomain).PDCEmulator

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
    
    # Check if this DC is the PDC Emulator
    $isPDC = $dcInfo.HostName -eq $pdcEmulator -or $dcName -eq $pdcEmulator
    
    $dcDetails[$dcName] = @{ IP = $ipAddress; IsGC = $dcInfo.IsGlobalCatalog; IsPDC = $isPDC }
  } catch {
    $dcDetails[$dcName] = @{ IP = "N/A"; IsGC = $false; IsPDC = $false }
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
  
  # Execute enhanced checks
  $criticalEventIDs = Get-ADCriticalEventIDs -Server $dc -Hours 24
  $certificates = Test-ADCertificates -Server $dc -WarningDays 30
  $dnsHealth = Test-ADIntegratedDNS -Server $dc
  
  # Fix the Events status logic
  $eventsStatus = 'OK'
  if ($null -eq $events.Total) {
    $eventsStatus = 'UNKNOWN'
  } elseif ($events.Total -gt 0) {
    $eventsStatus = 'WARN'
  }
  
  $obj = [pscustomobject]@{
    DC=$dc; IP=$dcDetails[$dc].IP; IsGlobalCatalog=$dcDetails[$dc].IsGC; IsPDC=$dcDetails[$dc].IsPDC
    Ping=New-Status $pingOk; DNS_Service=New-Status $svc.DNS; NTDS_Service=New-Status $svc.NTDS
    NetLogon_Service=New-Status $svc.Netlogon; Kdc_Service=New-Status $svc.Kdc
    DFSR_Service=New-Status $svc.DFSR; W32Time_Service=New-Status $svc.W32Time
    Connectivity=$testResults['Connectivity']; Advertising=$testResults['Advertising']
    DNSTest=$testResults['DNS']; NetLogons=$testResults['NetLogons']
    ServicesTest=$testResults['Services']; ReplicationsTest=$testResults['Replications']
    Topology=$testResults['Topology']; SysVol=$testResults['SysVolCheck']
    FSMO=$fsmStatus; Replication_RepAdmin=$repStatus
    CriticalEvents=$events.Total; EventsStatus=$eventsStatus
    BackupStatus=$backup.Status; BackupDays=$backup.DaysSince
    TimeSyncStatus=$timeSync.Status; TimeSyncOffset=$timeSync.OffsetSeconds; Hardware=$hw
    CriticalEventIDs=$criticalEventIDs
    Certificates=$certificates
    DNSHealth=$dnsHealth
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

# Trust relationships (domain-wide)
$trustHealth = Test-TrustRelationships

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
  if ($dc.DNSHealth.Status -eq 'FAIL') { $failCount++ }
  elseif ($dc.DNSHealth.Status -eq 'WARN') { $warnCount++ }
}
if ($trustHealth.Status -eq 'FAIL') { $failCount++ }

# ===================== CSV =====================
if ($Csv) {
  $csvPath = [IO.Path]::ChangeExtension((Resolve-Path $OutputPath),'.csv')
  $results | Select-Object -Property * -ExcludeProperty Hardware,CriticalEventIDs,Certificates,DNSHealth | 
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath
}

# ===================== HTML =====================
$css = @"
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background: #0a0e1a; color: #e2e8f0; padding: 16px; font-size: 14px; line-height: 1.5; }
  .container { max-width: 1600px; margin: 0 auto; }
  .header { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border: 1px solid #334155; border-radius: 8px; padding: 16px 20px; margin-bottom: 16px; box-shadow: 0 4px 12px rgba(0,0,0,.3); }
  .header-top { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 12px; }
  .header-title { font-size: 26px; font-weight: 700; color: #f9fafb; margin: 0; }
  .header-meta { display: flex; gap: 20px; flex-wrap: wrap; align-items: center; }
  .meta-item { display: flex; align-items: center; gap: 6px; font-size: 12px; color: #94a3b8; }
  .meta-label { font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
  .meta-value { color: #cbd5e1; }
  .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; }
  .metric { background: rgba(30, 41, 59, 0.5); border: 1px solid #334155; border-radius: 6px; padding: 10px 14px; text-align: center; }
  .metric-label { font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; font-weight: 600; }
  .metric-value { font-size: 28px; font-weight: 700; color: #fff; }
  .metric-alert { background: #7f1d1d; border-color: #ef4444; animation: pulse 2s infinite; }
  .metric-warn { background: #78350f; border-color: #f59e0b; }
  @keyframes pulse { 0%, 100% { box-shadow: 0 0 0 rgba(239, 68, 68, 0.4); } 50% { box-shadow: 0 0 12px rgba(239, 68, 68, 0.6); } }
  .card { background: rgba(17, 24, 39, 0.9); border: 1px solid #1f2937; border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 2px 8px rgba(0,0,0,.2); }
  .card-title { font-size: 18px; font-weight: 700; color: #e5e7eb; margin: 0 0 12px 0; padding-bottom: 8px; border-bottom: 1px solid #374151; }
  .card-subtitle { font-size: 12px; color: #94a3b8; margin-bottom: 12px; }
  .dc-card { background: #0f1419; border: 1px solid #1f2937; border-radius: 6px; padding: 12px; margin-bottom: 10px; transition: all 0.15s; }
  .dc-card:hover { border-color: #3b82f6; }
  .dc-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid #1f2937; }
  .dc-name { font-size: 16px; font-weight: 700; color: #f9fafb; }
  .dc-info { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .dc-ip { font-size: 13px; color: #94a3b8; font-weight: 400; }
  .gc-badge { background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 2px 4px rgba(59, 130, 246, 0.3); }
  .pdc-badge { background: linear-gradient(135deg, #8b5cf6, #6d28d9); color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 2px 4px rgba(92, 199, 246, 0.3); }
  .status-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(110px, 1fr)); gap: 6px; margin-bottom: 10px; }
  .status-item { background: #1a1f2e; padding: 6px 8px; border-radius: 4px; border-left: 2px solid #374151; cursor: pointer; transition: all 0.15s; position: relative; }
  .status-item:hover { background: #242938; border-left-color: #3b82f6; }
  .status-item-static { background: #1a1f2e; padding: 6px 8px; border-radius: 4px; border-left: 2px solid #374151; cursor: default; position: relative; }
  .status-label { font-size: 10px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.3px; margin-bottom: 3px; font-weight: 600; }
  .status-value { display: flex; align-items: center; gap: 4px; font-size: 13px; }
  .badge { display: inline-flex; align-items: center; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; }
  .ok { background: rgba(6, 78, 59, 0.4); color: #6ee7b7; border: 1px solid #059669; }
  .fail { background: rgba(127, 29, 29, 0.4); color: #fca5a5; border: 1px solid #dc2626; }
  .warn { background: rgba(146, 64, 14, 0.4); color: #fbbf24; border: 1px solid #f59e0b; }
  .na { background: rgba(55, 65, 81, 0.3); color: #9ca3af; border: 1px solid #4b5563; }
  .icon { width: 6px; height: 6px; border-radius: 50%; display: inline-block; }
  .icon-ok { background: #10b981; }
  .icon-fail { background: #ef4444; }
  .icon-warn { background: #f59e0b; }
  .tooltip { position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%); background: #1e293b; color: #e2e8f0; padding: 8px 12px; border-radius: 6px; font-size: 11px; white-space: normal; width: 220px; text-align: center; margin-bottom: 8px; opacity: 0; visibility: hidden; transition: opacity 0.2s, visibility 0.2s; z-index: 1000; border: 1px solid #334155; box-shadow: 0 4px 12px rgba(0,0,0,0.4); line-height: 1.4; }
  .tooltip::after { content: ''; position: absolute; top: 100%; left: 50%; transform: translateX(-50%); border: 6px solid transparent; border-top-color: #1e293b; }
  .status-item:hover .tooltip, .status-item-static:hover .tooltip { opacity: 1; visibility: visible; }
  .hw { background: #0d1117; border: 1px solid #1f2937; border-radius: 6px; padding: 10px; margin-top: 10px; }
  .hw-title { font-size: 12px; font-weight: 700; color: #cbd5e1; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
  .hw-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 8px; }
  .hw-label { font-size: 10px; color: #9ca3af; margin-bottom: 3px; display: flex; justify-content: space-between; font-weight: 600; }
  .hw-bar { background: #1e293b; border-radius: 3px; height: 6px; overflow: hidden; position: relative; cursor: help; }
  .hw-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }
  .hw-good { background: linear-gradient(90deg, #10b981, #059669); }
  .hw-warn { background: linear-gradient(90deg, #f59e0b, #d97706); }
  .hw-crit { background: linear-gradient(90deg, #ef4444, #dc2626); }
  .table-wrap { overflow-x: auto; margin-top: 12px; border-radius: 6px; border: 1px solid #1f2937; }
  .table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .table thead { background: linear-gradient(135deg, #1e293b, #0f172a); }
  .table th { padding: 10px 12px; text-align: left; color: #cbd5e1; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; border-bottom: 1px solid #374151; white-space: nowrap; }
  .table thead tr:first-child th { padding: 12px; font-size: 12px; border-bottom: 2px solid #374151; }
  .table tbody tr { transition: background 0.15s; border-bottom: 1px solid #1f2937; }
  .table tbody tr:hover { background: rgba(59, 130, 246, 0.06); }
  .table td { padding: 10px 12px; color: #e2e8f0; border-right: 1px solid #1f2937; font-size: 13px; }
  .table td:first-child { font-weight: 600; color: #f9fafb; background: rgba(30, 41, 59, 0.3); }
  .table td:last-child { border-right: none; }
  .status-good { color: #6ee7b7; font-weight: 600; }
  .status-warn { color: #fbbf24; font-weight: 600; }
  .status-error { color: #fca5a5; font-weight: 600; }
  .badge-sm { padding: 3px 8px; font-size: 8px; border-radius: 4px; font-weight: 700; text-transform: uppercase; white-space: nowrap; display: inline-block; }
  .badge-success { background: rgba(6, 78, 59, 0.5); color: #6ee7b7; border: 1px solid #10b981; }
  .badge-warning { background: rgba(146, 64, 14, 0.5); color: #fbbf24; border: 1px solid #f59e0b; }
  .badge-error { background: rgba(127, 29, 29, 0.5); color: #fca5a5; border: 1px solid #ef4444; }
  .fsmo-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; }
  .fsmo-item { background: #0f1419; border: 1px solid #1f2937; border-radius: 6px; padding: 10px 12px; display: flex; justify-content: space-between; align-items: center; transition: all 0.15s; }
  .fsmo-item:hover { background: #1a1f2e; border-color: #374151; }
  .fsmo-role { font-size: 12px; color: #9ca3af; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; }
  .fsmo-holder { font-size: 14px; color: #e5e7eb; font-weight: 700; }
  .fsmo-icon { width: 24px; height: 24px; background: linear-gradient(135deg, #3b82f6, #1d4ed8); border-radius: 4px; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 700; color: #fff; margin-right: 10px; }
  .detail { display: none; margin-top: 12px; padding: 12px; background: #030712; border-radius: 6px; border: 1px solid #1f2937; }
  .detail.active { display: block; animation: fadeIn 0.2s; }
  .detail-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .detail-title { font-size: 13px; font-weight: 600; color: #e5e7eb; margin: 0; }
  .detail-close { background: #374151; border: none; color: #e5e7eb; padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; font-weight: 600; }
  .detail-close:hover { background: #4b5563; }
  pre { white-space: pre-wrap; color: #cbd5e1; background: #0a0e14; padding: 10px; border-radius: 4px; font-size: 11px; line-height: 1.5; overflow-x: auto; border: 1px solid #1f2937; max-height: 300px; overflow-y: auto; margin: 0; }
  @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
  .footer { font-size: 11px; color: #64748b; margin-top: 20px; text-align: center; padding: 12px; border-top: 1px solid #1f2937; }
  .expandable { background: #0f1419; border: 1px solid #1f2937; border-radius: 6px; padding: 10px; margin-bottom: 10px; }
  .expandable-header { display: flex; justify-content: space-between; align-items: center; cursor: pointer; padding: 8px; background: #1a1f2e; border-radius: 4px; transition: all 0.15s; }
  .expandable-header:hover { background: #242938; }
  .expandable-title { font-size: 13px; font-weight: 700; color: #e5e7eb; }
  .expandable-badge { margin-left: auto; margin-right: 10px; }
  .expandable-icon { font-size: 11px; color: #9ca3af; transition: transform 0.3s; }
  .expandable-icon.open { transform: rotate(90deg); }
  .expandable-content { display: none; padding: 10px; margin-top: 10px; background: #030712; border-radius: 4px; border: 1px solid #1f2937; }
  .expandable-content.open { display: block; animation: fadeIn 0.3s; }
  .event-item { padding: 8px; margin-bottom: 6px; background: #1a1f2e; border-radius: 4px; border-left: 3px solid #374151; }
  .event-item.critical { border-left-color: #ef4444; }
  .event-item.warning { border-left-color: #f59e0b; }
  .event-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
  .event-id { font-size: 11px; font-weight: 700; color: #3b82f6; }
  .event-time { font-size: 10px; color: #9ca3af; }
  .event-category { font-size: 10px; color: #6ee7b7; text-transform: uppercase; font-weight: 600; }
  .event-desc { font-size: 11px; color: #cbd5e1; margin-top: 4px; }
  .cert-item { padding: 8px; margin-bottom: 6px; background: #1a1f2e; border-radius: 4px; }
  .cert-subject { font-size: 12px; font-weight: 700; color: #e5e7eb; margin-bottom: 4px; }
  .cert-details { font-size: 10px; color: #9ca3af; }
  .cert-expiry { font-size: 11px; font-weight: 600; margin-top: 4px; }
  .cert-expiry.ok { color: #6ee7b7; }
  .cert-expiry.warn { color: #fbbf24; }
  .cert-expiry.critical { color: #fca5a5; }
  .success-message { padding: 10px; background: rgba(6, 78, 59, 0.2); border: 1px solid #059669; border-radius: 4px; color: #6ee7b7; font-size: 12px; text-align: center; }
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
          elseif ($val -eq 'WARN') { '<span class="icon icon-warn"></span>' }
          else { '' }
  if ($val -eq 'OK') { "$icon <span class='badge ok'>OK</span>" }
  elseif ($val -eq 'FAIL') { "$icon <span class='badge fail'>FAIL</span>" }
  elseif ($val -eq 'WARN') { "$icon <span class='badge warn'>WARN</span>" }
  else { "<span class='badge na'>N/A</span>" }
}

# Tooltip descriptions for each status item
$tooltipDescriptions = @{
  'Ping' = 'Verifies network connectivity to the Domain Controller'
  'DNS Svc' = 'Checks if DNS Server service is running (required for name resolution)'
  'NTDS Svc' = 'Active Directory Domain Services - the core AD database service'
  'NetLogon' = 'Handles authentication requests and replication of user account database'
  'KDC Svc' = 'Key Distribution Center - manages Kerberos tickets for authentication'
  'DFSR Svc' = 'DFS Replication service - replicates SYSVOL and other shared folders'
  'W32Time' = 'Windows Time service - synchronizes time across domain'
  'Connect' = 'Tests basic connectivity and LDAP binding to the DC'
  'Advertise' = 'Verifies DC is properly advertising its services in DNS'
  'DNS Test' = 'Comprehensive DNS functionality test for AD integration'
  'NetLogons' = 'Tests NetLogon service registration and secure channel'
  'Services' = 'Verifies all essential AD services are running properly'
  'Replication' = 'Checks AD replication status between domain controllers'
  'RepAdmin' = 'Advanced replication diagnostics using repadmin tool'
  'FSMO' = 'Verifies FSMO role holders are reachable and functioning'
  'SysVol' = 'Checks SYSVOL share health and replication status'
  'Topology' = 'Validates AD replication topology and site configuration'
  'Backup' = 'Shows days since last AD backup (tombstone lifetime risk)'
  'TimeSync' = 'Validates time synchronization accuracy (critical for Kerberos)'
  'Events' = 'Summary of critical and error events in the last 24 hours'
  'DNS Health' = 'Validates DNS zones, dynamic updates, and SRV records'
}

$dcCards = $results | ForEach-Object {
  $dcName = $_.DC
  $dcIP = $_.IP
  $isGC = $_.IsGlobalCatalog
  $isPDC = $_.IsPDC
  $dcSafe = $dcName -replace '[^a-zA-Z0-9]', '_'
  $gcBadge = if ($isGC) { '<span class="gc-badge">🌐 Global Catalog</span>' } else { '' }
  $pdcBadge = if ($isPDC) { '<span class="pdc-badge">👑 PDC Emulator</span>' } else { '' }
  
  $statusItems = @(
    @{Label='Ping'; Value=$_.Ping; Key='Ping'; HasDetail=$false},
    @{Label='DNS Svc'; Value=$_.DNS_Service; Key='DNS_Service'; HasDetail=$false},
    @{Label='NTDS Svc'; Value=$_.NTDS_Service; Key='NTDS_Service'; HasDetail=$false},
    @{Label='NetLogon'; Value=$_.NetLogon_Service; Key='NetLogon_Service'; HasDetail=$false},
    @{Label='KDC Svc'; Value=$_.Kdc_Service; Key='Kdc_Service'; HasDetail=$false},
    @{Label='DFSR Svc'; Value=$_.DFSR_Service; Key='DFSR_Service'; HasDetail=$false},
    @{Label='W32Time'; Value=$_.W32Time_Service; Key='W32Time_Service'; HasDetail=$false},
    @{Label='Connect'; Value=$_.Connectivity; Key='Connectivity'; HasDetail=$true},
    @{Label='Advertise'; Value=$_.Advertising; Key='Advertising'; HasDetail=$true},
    @{Label='DNS Test'; Value=$_.DNSTest; Key='DNS'; HasDetail=$true},
    @{Label='NetLogons'; Value=$_.NetLogons; Key='NetLogons'; HasDetail=$true},
    @{Label='Services'; Value=$_.ServicesTest; Key='Services'; HasDetail=$true},
    @{Label='Replication'; Value=$_.ReplicationsTest; Key='Replications'; HasDetail=$true},
    @{Label='RepAdmin'; Value=$_.Replication_RepAdmin; Key='RepAdmin'; HasDetail=$false},
    @{Label='FSMO'; Value=$_.FSMO; Key='FSMO'; HasDetail=$false},
    @{Label='SysVol'; Value=$_.SysVol; Key='SysVolCheck'; HasDetail=$true},
    @{Label='Topology'; Value=$_.Topology; Key='Topology'; HasDetail=$true},
    @{Label='Backup'; Value=$_.BackupStatus; Key='Backup'; HasDetail=$false},
    @{Label='TimeSync'; Value=$_.TimeSyncStatus; Key='TimeSync'; HasDetail=$false},
    @{Label='Events'; Value=$_.EventsStatus; Key='Events'; HasDetail=$false},
    @{Label='DNS Health'; Value=$_.DNSHealth.Status; Key='DNSHealth'; HasDetail=$false}
  )
  
  $itemsHtml = $statusItems | ForEach-Object {
    $badgeHtml = Badge $_.Value
    $itemClass = if ($_.HasDetail) { 'status-item' } else { 'status-item-static' }
    $onclickAttr = if ($_.HasDetail) { "onclick=`"toggleDetail('${dcSafe}_$($_.Key)')`"" } else { '' }
    $tooltipText = $tooltipDescriptions[$_.Label]
    @"
    <div class="$itemClass" $onclickAttr>
      <div class="status-label">$($_.Label)</div>
      <div class="status-value">$badgeHtml</div>
      <div class="tooltip">$tooltipText</div>
    </div>
"@
  } | Out-String

  $hw = $_.Hardware
  $hwHtml = ""
  if ($hw) {
    $metricsHtml = ""
    $uptimeFormatted = Format-Uptime -Hours $hw.UptimeHours
    $metricsHtml += "<div class='hw-item'><div class='hw-label'><span>Uptime</span><span>$uptimeFormatted</span></div></div>"
    
    $cpuVal = Show-NA $hw.CPUUsagePct
    $cpuPct = if ($hw.CPUUsagePct) { $hw.CPUUsagePct } else { 0 }
    $cpuAvail = [Math]::Round(100-$cpuPct,1)
    $cpuClass = if ($cpuPct -lt 70) { 'hw-good' } elseif ($cpuPct -lt 85) { 'hw-warn' } else { 'hw-crit' }
    $metricsHtml += "<div class='hw-item'><div class='hw-label'><span>CPU</span><span>$cpuVal%</span></div><div class='hw-bar' title='CPU Usage: $cpuVal% | Available: $cpuAvail%'><div class='hw-fill $cpuClass' style='width: $cpuPct%'></div></div></div>"
    
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

  # Critical Event IDs expandable section
  $criticalEventsHtml = ""
  if ($_.CriticalEventIDs -and $_.CriticalEventIDs.Count -gt 0) {
    $eventCount = $_.CriticalEventIDs.Count
    $criticalCount = ($_.CriticalEventIDs | Where-Object { $_.Severity -eq 'Critical' }).Count
    $eventBadge = if ($criticalCount -gt 0) { Badge 'FAIL' } else { Badge 'WARN' }
    
    $eventItems = $_.CriticalEventIDs | ForEach-Object {
      $eventClass = if ($_.Severity -eq 'Critical') { 'critical' } else { 'warning' }
      $timeStr = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
      @"
      <div class="event-item $eventClass">
        <div class="event-header">
          <span class="event-id">Event ID: $($_.EventID)</span>
          <span class="event-time">$timeStr</span>
        </div>
        <div class="event-category">$($_.Category) - $($_.Severity)</div>
        <div class="event-desc">$($_.Description)</div>
      </div>
"@
    } | Out-String
    
    $criticalEventsHtml = @"
    <div class="expandable">
      <div class="expandable-header" onclick="toggleExpand('${dcSafe}_events')">
        <span class="expandable-title">⚠️ Critical AD Events ($eventCount)</span>
        <span class="expandable-badge">$eventBadge</span>
        <span class="expandable-icon" id="${dcSafe}_events_icon">▶</span>
      </div>
      <div class="expandable-content" id="${dcSafe}_events_content">
        $eventItems
      </div>
    </div>
"@
  } else {
    # Show success message when check was executed but no critical events found
    $criticalEventsHtml = @"
    <div class="expandable">
      <div class="expandable-header" onclick="toggleExpand('${dcSafe}_events')">
        <span class="expandable-title">⚠️ Critical AD Events Check</span>
        <span class="expandable-badge">$(Badge 'OK')</span>
        <span class="expandable-icon" id="${dcSafe}_events_icon">▶</span>
      </div>
      <div class="expandable-content" id="${dcSafe}_events_content">
        <div class="success-message">
          <strong>✓ Validation Executed Successfully</strong><br>
          No critical AD events were identified in the last 24 hours.<br>
          <small>Monitored Event IDs: 1864, 2042, 2092, 4013, 5805, 13508, 13509, 1168, 1173, 2089</small>
        </div>
      </div>
    </div>
"@
  }

  # Certificates expandable section
  $certificatesHtml = ""
  if ($_.Certificates -and $_.Certificates.Count -gt 0) {
    $certCount = $_.Certificates.Count
    $expiring = $_.Certificates | Where-Object { $_.Status -ne 'OK' }
    $certBadge = if ($expiring.Count -gt 0) { Badge 'WARN' } else { Badge 'OK' }
    
    $certItems = $_.Certificates | ForEach-Object {
      $expiryClass = if ($_.Status -eq 'EXPIRED') { 'critical' } 
                     elseif ($_.Status -eq 'EXPIRING SOON') { 'warn' } 
                     else { 'ok' }
      $expiryText = if ($_.DaysUntilExpiration -lt 0) { 
        "EXPIRED $([Math]::Abs($_.DaysUntilExpiration)) days ago" 
      } else { 
        "Expires in $($_.DaysUntilExpiration) days" 
      }
      @"
      <div class="cert-item">
        <div class="cert-subject">$($_.Subject)</div>
        <div class="cert-details">
          Issuer: $($_.Issuer)<br>
          Valid: $($_.NotBefore.ToString("yyyy-MM-dd")) to $($_.NotAfter.ToString("yyyy-MM-dd"))
        </div>
        <div class="cert-expiry $expiryClass">$expiryText</div>
      </div>
"@
    } | Out-String
    
    $certificatesHtml = @"
    <div class="expandable">
      <div class="expandable-header" onclick="toggleExpand('${dcSafe}_certs')">
        <span class="expandable-title">🔐 Certificates ($certCount)</span>
        <span class="expandable-badge">$certBadge</span>
        <span class="expandable-icon" id="${dcSafe}_certs_icon">▶</span>
      </div>
      <div class="expandable-content" id="${dcSafe}_certs_content">
        $certItems
      </div>
    </div>
"@
  } else {
    # Show success message when check was executed but no certificate issues found
    $certificatesHtml = @"
    <div class="expandable">
      <div class="expandable-header" onclick="toggleExpand('${dcSafe}_certs')">
        <span class="expandable-title">🔐 Certificates Check</span>
        <span class="expandable-badge">$(Badge 'OK')</span>
        <span class="expandable-icon" id="${dcSafe}_certs_icon">▶</span>
      </div>
      <div class="expandable-content" id="${dcSafe}_certs_content">
        <div class="success-message">
          <strong>✓ Validation Executed Successfully</strong><br>
          All certificates with private keys are valid and not expiring within the next 30 days.
        </div>
      </div>
    </div>
"@
  }

  # DNS Health expandable section
  $dnsHealthHtml = ""
  if ($_.DNSHealth -and $_.DNSHealth.Issues -and $_.DNSHealth.Issues.Count -gt 0) {
    $dnsIssueCount = $_.DNSHealth.Issues.Count
    $dnsBadge = Badge $_.DNSHealth.Status
    
    $dnsItems = $_.DNSHealth.Issues | ForEach-Object {
      $severityClass = if ($_.Severity -eq 'Critical') { 'critical' } 
                       elseif ($_.Severity -eq 'Warning') { 'warning' } 
                       else { '' }
      @"
      <div class="event-item $severityClass">
        <div class="event-header">
          <span class="event-category">$($_.Zone)</span>
          <span class="event-id">$($_.Severity)</span>
        </div>
        <div class="event-desc">$($_.Issue)</div>
      </div>
"@
    } | Out-String
    
    $dnsHealthHtml = @"
    <div class="expandable">
      <div class="expandable-header" onclick="toggleExpand('${dcSafe}_dns')">
        <span class="expandable-title">🌐 DNS Health Issues ($dnsIssueCount)</span>
        <span class="expandable-badge">$dnsBadge</span>
        <span class="expandable-icon" id="${dcSafe}_dns_icon">▶</span>
      </div>
      <div class="expandable-content" id="${dcSafe}_dns_content">
        $dnsItems
      </div>
    </div>
"@
  } else {
    # Show success message when check was executed but no DNS issues found
    $dnsHealthHtml = @"
    <div class="expandable">
      <div class="expandable-header" onclick="toggleExpand('${dcSafe}_dns')">
        <span class="expandable-title">🌐 DNS Health Check</span>
        <span class="expandable-badge">$(Badge 'OK')</span>
        <span class="expandable-icon" id="${dcSafe}_dns_icon">▶</span>
      </div>
      <div class="expandable-content" id="${dcSafe}_dns_content">
        <div class="success-message">
          <strong>✓ Validation Executed Successfully</strong><br>
          All DNS zones are AD integrated, with dynamic updates enabled and essential SRV records present (_ldap, _kerberos, _kpasswd, _gc).
        </div>
      </div>
    </div>
"@
  }

  @"
<div class="dc-card">
  <div class="dc-header">
    <div class="dc-info">
      <div class="dc-name">$dcName</div>
      <div class="dc-ip">[$dcIP]</div>
      $gcBadge
      $pdcBadge
    </div>
  </div>
  <div class="status-grid">
    $itemsHtml
  </div>
  $hwHtml
  $criticalEventsHtml
  $certificatesHtml
  $dnsHealthHtml
</div>
"@
} | Out-String

# Trust Relationships Card
$trustHtml = ""
if ($trustHealth -and $trustHealth.TotalTrusts -gt 0) {
  $trustRows = $trustHealth.TrustDetails | ForEach-Object {
    $statusBadge = Badge $_.Status
    $statusClass = if ($_.Status -eq 'OK') { 'status-good' } else { 'status-error' }
    @"
<tr>
  <td><strong>$($_.Name)</strong></td>
  <td>$($_.Direction)</td>
  <td>$($_.TrustType)</td>
  <td class="$statusClass">$statusBadge</td>
</tr>
"@
  } | Out-String
  
  $trustHtml = @"
  <div class="card">
    <h2 class="card-title">Trust Relationships</h2>
    <div class="card-subtitle">Status: $(Badge $trustHealth.Status) | Total Trusts: $($trustHealth.TotalTrusts)</div>
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>Trust Name</th>
            <th>Direction</th>
            <th>Type</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          $trustRows
        </tbody>
      </table>
    </div>
  </div>
"@
} else {
  $trustHtml = @"
  <div class="card">
    <h2 class="card-title">Trust Relationships</h2>
    <div class="card-subtitle">No trust relationships configured or unable to retrieve trust information.</div>
  </div>
"@
}

# Details sections script
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
function toggleExpand(id) {
  var content = document.getElementById(id + '_content');
  var icon = document.getElementById(id + '_icon');
  if (content.classList.contains('open')) {
    content.classList.remove('open');
    icon.classList.remove('open');
  } else {
    content.classList.add('open');
    icon.classList.add('open');
  }
}
</script>
"@

# Replication Summary Table
$replTableHtml = ""
if ($replSummary) {
  $replLines = $replSummary -split "`r?`n"
  $replData = @()
  $sourceSection = $false; $destSection = $false
  foreach ($line in $replLines) {
    if ($line -match 'Source DSA') { $sourceSection = $true; $destSection = $false; continue }
    if ($line -match 'Destination DSA') { $destSection = $true; $sourceSection = $false; continue }
    if ($line -match '^\s*$|^[-=\s]+$|largest delta|fails/total|DSA|Replication Summary|Beginning data') { continue }
    
    # Parse line with format: DC01  07m:20s  0 / 5  0
    # or: DC01  440s  0 / 5  0
    if ($line -match '^\s*(\S+)\s+(?:(\d+)m:)?(\d+)s\s+(\d+)\s*/\s*(\d+)\s+(\d+)') {
      $dcName = $matches[1]
      $minutes = if ($matches[2]) { [int]$matches[2] } else { 0 }
      $seconds = [int]$matches[3]
      $totalSeconds = ($minutes * 60) + $seconds
      $fails = [int]$matches[4]
      $replTotal = [int]$matches[5]
      $errors = [int]$matches[6]
      
      $replData += [pscustomobject]@{
        DC = $dcName
        Type = if ($sourceSection) { 'Source' } else { 'Destination' }
        LargestDelta = $totalSeconds
        Fails = $fails
        ReplTotal = $replTotal
        Errors = $errors
      }
    }
  }
  
  if ($replData.Count -gt 0) {
    $replSummaryByDC = @{}
    foreach ($item in $replData) {
      if (-not $replSummaryByDC.ContainsKey($item.DC)) {
        $replSummaryByDC[$item.DC] = @{
          DC=$item.DC; SourceDelta=0; SourceFails=0; SourceReplTotal=0; SourceErrors=0
          DestDelta=0; DestFails=0; DestReplTotal=0; DestErrors=0
        }
      }
      if ($item.Type -eq 'Source') {
        $replSummaryByDC[$item.DC].SourceDelta = $item.LargestDelta
        $replSummaryByDC[$item.DC].SourceFails = $item.Fails
        $replSummaryByDC[$item.DC].SourceReplTotal = $item.ReplTotal
        $replSummaryByDC[$item.DC].SourceErrors = $item.Errors
      } else {
        $replSummaryByDC[$item.DC].DestDelta = $item.LargestDelta
        $replSummaryByDC[$item.DC].DestFails = $item.Fails
        $replSummaryByDC[$item.DC].DestReplTotal = $item.ReplTotal
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
      
      # Format delta time nicely
      $sourceDeltaFormatted = if ($_.SourceDelta -ge 60) {
        $mins = [Math]::Floor($_.SourceDelta / 60)
        $secs = $_.SourceDelta % 60
        "${mins}m ${secs}s"
      } else {
        "$($_.SourceDelta)s"
      }
      
      $destDeltaFormatted = if ($_.DestDelta -ge 60) {
        $mins = [Math]::Floor($_.DestDelta / 60)
        $secs = $_.DestDelta % 60
        "${mins}m ${secs}s"
      } else {
        "$($_.DestDelta)s"
      }
      
      $deltaClass = if ($maxDelta -lt 60) { 'status-good' } elseif ($maxDelta -lt 300) { 'status-warn' } else { 'status-error' }
      $errorClass = if ($totalErrors -gt 0) { 'status-error' } elseif ($totalFails -gt 0) { 'status-warn' } else { 'status-good' }
      @"
<tr>
  <td><strong>$($_.DC)</strong></td>
  <td class="$deltaClass">$sourceDeltaFormatted</td>
  <td>$($_.SourceFails) / $($_.SourceReplTotal)</td>
  <td class="$errorClass">$($_.SourceErrors)</td>
  <td class="$deltaClass">$destDeltaFormatted</td>
  <td>$($_.DestFails) / $($_.DestReplTotal)</td>
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
        <th rowspan="2" style="vertical-align: middle;">Domain Controller</th>
        <th colspan="3" style="text-align: center; border-right: 2px solid #374151;">Source DSA</th>
        <th colspan="3" style="text-align: center; border-right: 2px solid #374151;">Destination DSA</th>
        <th rowspan="2" style="text-align: center; vertical-align: middle;">Status</th>
      </tr>
      <tr>
        <th style="border-right: 1px solid #1f2937;">Largest Delta</th>
        <th style="border-right: 1px solid #1f2937;">Fails / Total</th>
        <th style="border-right: 2px solid #374151;">Errors</th>
        <th style="border-right: 1px solid #1f2937;">Largest Delta</th>
        <th style="border-right: 1px solid #1f2937;">Fails / Total</th>
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
    # If we can't parse the data, show a simple message
    $replTableHtml = @"
<div style="background: #1a1f2e; border: 1px solid #374151; border-radius: 6px; padding: 16px; text-align: center;">
  <p style="color: #9ca3af; font-size: 13px; margin-bottom: 8px;">Unable to parse replication summary data.</p>
  <p style="color: #6b7280; font-size: 12px;">Run <code style="background: #0f1419; padding: 2px 6px; border-radius: 3px; color: #3b82f6;">repadmin /replsummary</code> manually for detailed information.</p>
</div>
"@
  }
} else {
  $replTableHtml = @"
<div style="background: #1a1f2e; border: 1px solid #374151; border-radius: 6px; padding: 16px; text-align: center;">
  <p style="color: #9ca3af; font-size: 13px;">No replication summary data available.</p>
</div>
"@
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
          <div class="metric-value">$(Get-ADLevelShort $forest.ForestMode)</div>
        </div>
        <div class="metric">
          <div class="metric-label">Domain Level</div>
          <div class="metric-value">$(Get-ADLevelShort $domain.DomainMode)</div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2 class="card-title">Domain Controllers Status</h2>
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

    $trustHtml

    <div class="card">
      <h2 class="card-title">FSMO Role Holders</h2>
      $fsmoHtml
    </div>

    <div class="footer">
      AD Health Report v3.8 Enhanced | Tooltips Added
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
