[CmdletBinding()]
param(
  [switch]$UsingOU,
  [string]$OrganizationUnitDN,
  [string[]]$DomainControllers,
  [string]$OutputPath = ".\ADHealthReport.html",
  [switch]$Csv,
  [switch]$EmailOnErrorOnly,

  # SMTP
  [string]$SmtpServer,
  [int]$SmtpPort = 587,
  [switch]$SmtpUseSsl,
  [string]$From,
  [string[]]$To,
  [string]$Subject = "AD Health Check Report",
  [pscredential]$Credential,

  # Graph
  [switch]$UseGraph,
  [string]$GraphSenderUpn,
  
  # Thresholds
  [int]$CertWarningDays = 30,
  [int]$RidPoolWarningPercent = 20
)

# ===================== CONSTANTS =====================
$SCRIPT_VERSION = "2.4"
$CRITICAL_EVENT_IDS = @{
  1864 = 'Disk space critical for AD logs'
  2042 = 'Replication has not occurred for extended period'
  2092 = 'Replication is blocked'
  1168 = 'AD Database error detected'
  1173 = 'Database corruption detected'
  2089 = 'AD backup is critically outdated'
  13508 = 'SYSVOL replication error'
  13509 = 'SYSVOL share not accessible'
}

# DCDiag tests to run
$DCDIAG_TESTS = @(
  'Connectivity',
  'Advertising',
  'DFSREvent',
  'SysVolCheck',
  'KccEvent',
  'KnowsOfRoleHolders',
  'MachineAccount',
  'NCSecDesc',
  'NetLogons',
  'ObjectsReplicated',
  'Replications',
  'RidManager',
  'Services',
  'SystemLog',
  'VerifyReferences'
)

# ===================== UTILITIES =====================
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

function Write-Log {
  param([string]$Message, [string]$Level = "INFO")
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Verbose "[$timestamp] [$Level] $Message"
  Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $(
    switch ($Level) {
      'CRITICAL' { 'Red' }
      'WARNING' { 'Yellow' }
      default { 'Gray' }
    }
  )
}

function Test-Tool {
  param([string]$Name)
  $tool = Get-Command $Name -ErrorAction SilentlyContinue
  if (-not $tool) {
    Write-Warning "Required tool not found: $Name"
    return $false
  }
  return $true
}

function Get-HealthScore {
  param(
    [int]$CriticalCount,
    [int]$WarningCount,
    [int]$OkCount,
    [int]$UnknownCount
  )
  
  $totalChecks = $CriticalCount + $WarningCount + $OkCount + $UnknownCount
  
  if ($totalChecks -eq 0) { return 100 }
  
  # Calculate success rate
  $successRate = ($OkCount / $totalChecks) * 100
  
  # Apply penalties for issues
  $criticalPenalty = ($CriticalCount / $totalChecks) * 30  # Each critical can reduce up to 30 points proportionally
  $warningPenalty = ($WarningCount / $totalChecks) * 10   # Each warning can reduce up to 10 points proportionally
  $unknownPenalty = ($UnknownCount / $totalChecks) * 5    # Each unknown reduces up to 5 points proportionally
  
  $score = $successRate - $criticalPenalty - $warningPenalty - $unknownPenalty
  
  return [Math]::Max(0, [Math]::Min(100, [Math]::Round($score, 0)))
}

function Get-SeverityLevel {
  param([int]$Score)
  
  if ($Score -ge 90) { return @{Level='HEALTHY'; Color='#10b981'; Icon='✓'} }
  elseif ($Score -ge 70) { return @{Level='WARNING'; Color='#f59e0b'; Icon='⚠'} }
  elseif ($Score -ge 50) { return @{Level='CRITICAL'; Color='#ef4444'; Icon='✗'} }
  else { return @{Level='EMERGENCY'; Color='#991b1b'; Icon='🚨'} }
}

function ConvertFrom-WmiDateTime {
  param([string]$WmiDateTime)
  try {
    if ($WmiDateTime -match '(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})') {
      $year = $matches[1]; $month = $matches[2]; $day = $matches[3]
      $hour = $matches[4]; $minute = $matches[5]; $second = $matches[6]
      return [DateTime]::ParseExact("$year-$month-$day $($hour):$($minute):$($second)", "yyyy-MM-dd HH:mm:ss", $null)
    }
  } catch { }
  return $null
}

function Format-Uptime {
  param([double]$Hours)
  if ($null -eq $Hours) { return "N/A" }
  if ($Hours -ge 24) {
    $days = [Math]::Floor($Hours / 24)
    $remainingHours = [Math]::Round($Hours % 24, 1)
    if ($remainingHours -eq 0) { return "$days days" }
    else { return "$days days $remainingHours hrs" }
  }
  return "$([Math]::Round($Hours, 1)) hrs"
}

function Escape-HtmlAttribute {
  param([string]$Text)
  if ([string]::IsNullOrEmpty($Text)) { return "" }
  return $Text.Replace('"', '&quot;').Replace("'", '&#39;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('`', '&#96;').Replace('\', '\\')
}

# ===================== PRE-FLIGHT CHECKS =====================
Write-Log "Starting AD Health Check v$SCRIPT_VERSION"

if (-not (Get-Module -ListAvailable ActiveDirectory)) {
  throw "ActiveDirectory PowerShell module is required. Install RSAT tools."
}

$requiredTools = @('dcdiag.exe', 'repadmin.exe', 'nltest.exe')
foreach ($tool in $requiredTools) {
  if (-not (Test-Tool $tool)) {
    throw "Required tool missing: $tool. Ensure AD administration tools are installed."
  }
}

Import-Module ActiveDirectory -ErrorAction Stop

# ===================== DATA COLLECTION =====================
Write-Log "Collecting domain information..."

try {
  $domain = Get-ADDomain -ErrorAction Stop
  $forest = Get-ADForest -ErrorAction Stop
  $pdcEmulator = $domain.PDCEmulator
} catch {
  throw "Failed to retrieve domain information: $_"
}

# Get DC List
if ($UsingOU) {
  if (-not $OrganizationUnitDN) {
    $OrganizationUnitDN = "OU=Domain Controllers,$($domain.DistinguishedName)"
  }
  $allDCs = Get-ADComputer -SearchBase $OrganizationUnitDN -LDAPFilter '(objectClass=computer)' -Properties dnsHostName |
            Where-Object { $_.dnsHostName } | Select-Object -ExpandProperty dnsHostName
} elseif ($DomainControllers -and $DomainControllers.Count) {
  $allDCs = $DomainControllers
} else {
  $allDCs = (Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
}

if (-not $allDCs -or $allDCs.Count -eq 0) {
  throw "No domain controllers found!"
}

Write-Log "Found $($allDCs.Count) domain controllers"

# ===================== ISSUE TRACKING =====================
$script:issues = @{
  Critical = @()
  Warning = @()
  Info = @()
}

# Track issue categories to avoid double-counting
$script:issueCategoryCounts = @{
  Critical = @{}
  Warning = @{}
}

# Track all validation results for detailed report
$script:validationResults = @()

function Add-ValidationResult {
  param(
    [string]$DC,
    [string]$Category,
    [string]$CheckName,
    [string]$Status,  # OK, WARNING, CRITICAL, UNKNOWN
    [string]$Details,
    [string]$TestCommand = "",
    [string]$TestOutput = ""
  )
  
  $result = [PSCustomObject]@{
    DC = $DC
    Category = $Category
    CheckName = $CheckName
    Status = $Status
    Details = $Details
    TestCommand = $TestCommand
    TestOutput = $TestOutput
    Timestamp = Get-Date
  }
  
  $script:validationResults += $result
}

function Add-Issue {
  param(
    [string]$Severity,  # Critical, Warning, Info
    [string]$Category,
    [string]$DC,
    [string]$Title,
    [string]$Description,
    [string]$Recommendation,
    [switch]$GroupByCategory  # If true, only count once per DC+Category combination
  )
  
  $issue = [PSCustomObject]@{
    Severity = $Severity
    Category = $Category
    DC = $DC
    Title = $Title
    Description = $Description
    Recommendation = $Recommendation
    Timestamp = Get-Date
  }
  
  $script:issues[$Severity] += $issue
  
  # Track category counts for score calculation
  if ($GroupByCategory -and ($Severity -eq 'Critical' -or $Severity -eq 'Warning')) {
    $key = "$DC|$Category"
    if (-not $script:issueCategoryCounts[$Severity].ContainsKey($key)) {
      $script:issueCategoryCounts[$Severity][$key] = 1
    }
  }
  
  Write-Log "[$Severity] $DC - $Title" -Level $Severity
}

# ===================== CONSOLIDATED CHECKS =====================

function Test-DCHealth {
  param([string]$DCName)
  
  Write-Log "========================================" -Level "INFO"
  Write-Log "Checking DC: $DCName" -Level "INFO"
  Write-Log "========================================" -Level "INFO"
  
  $dcHealth = [PSCustomObject]@{
    Name = $DCName
    IP = "Unknown"
    IsGC = $false
    IsPDC = $false
    Reachable = $false
    CriticalServices = @{}
    ReplicationStatus = "Unknown"
    TimeSyncOffset = $null
    EventsCritical = 0
    CertificatesExpiring = 0
    CertificatesExpired = 0
    UptimeHours = $null
    CPUUsage = $null
    MemoryUsedPct = $null
    DiskCritical = $false
    DCDiagResults = @{}
    HealthScore = 0
  }
  
  # Basic connectivity
  Write-Log "Testing connectivity to $DCName..." -Level "INFO"
  $pingResult = Test-Connection -ComputerName $DCName -Count 1 -ErrorAction SilentlyContinue
  $dcHealth.Reachable = $null -ne $pingResult
  
  $pingCmd = "Test-Connection -ComputerName $DCName -Count 1"
  $pingOutput = if ($dcHealth.Reachable) { 
    "Success: Reply from $($pingResult.IPV4Address) in $($pingResult.ResponseTime)ms" 
  } else { 
    "Failed: No response from $DCName" 
  }
  
  Add-ValidationResult -DC $DCName -Category "Connectivity" -CheckName "Ping" `
    -Status $(if ($dcHealth.Reachable) { "OK" } else { "CRITICAL" }) `
    -Details $(if ($dcHealth.Reachable) { "DC is reachable via ICMP" } else { "DC did not respond to ping" }) `
    -TestCommand $pingCmd -TestOutput $pingOutput
  
  if (-not $dcHealth.Reachable) {
    Add-Issue -Severity 'Critical' -Category 'Connectivity' -DC $DCName `
      -Title 'Domain Controller Unreachable' `
      -Description "Unable to ping $DCName" `
      -Recommendation 'Verify network connectivity, firewall rules, and DC operational status'
    return $dcHealth
  }
  
  # Get DC Info
  Write-Log "Getting DC information for $DCName..." -Level "INFO"
  try {
    $dcInfo = Get-ADDomainController -Identity $DCName -ErrorAction Stop
    $dcHealth.IP = $dcInfo.IPv4Address
    if (-not $dcHealth.IP) {
      $dcHealth.IP = [System.Net.Dns]::GetHostAddresses($DCName) | 
                     Where-Object { $_.AddressFamily -eq 'InterNetwork' } | 
                     Select-Object -First 1 -ExpandProperty IPAddressToString
    }
    $dcHealth.IsGC = $dcInfo.IsGlobalCatalog
    $dcHealth.IsPDC = ($dcInfo.HostName -eq $pdcEmulator)
    
    $adCmd = "Get-ADDomainController -Identity $DCName"
    $adOutput = "Success: IP=$($dcHealth.IP), GlobalCatalog=$($dcHealth.IsGC), PDC=$($dcHealth.IsPDC), Site=$($dcInfo.Site)"
    
    Add-ValidationResult -DC $DCName -Category "Configuration" -CheckName "AD DC Object" `
      -Status "OK" `
      -Details "DC Info: IP=$($dcHealth.IP), GlobalCatalog=$($dcHealth.IsGC), PDC=$($dcHealth.IsPDC)" `
      -TestCommand $adCmd -TestOutput $adOutput
  } catch {
    Add-ValidationResult -DC $DCName -Category "Configuration" -CheckName "AD DC Object" `
      -Status "WARNING" `
      -Details "Unable to retrieve DC information: $($_.Exception.Message)" `
      -TestCommand "Get-ADDomainController -Identity $DCName" `
      -TestOutput "Error: $($_.Exception.Message)"
    
    Add-Issue -Severity 'Warning' -Category 'Configuration' -DC $DCName `
      -Title 'Unable to retrieve DC information' `
      -Description $_.Exception.Message `
      -Recommendation 'Verify AD replication and DNS resolution'
  }
  
  # Hardware Info
  Write-Log "Collecting hardware info for $DCName..." -Level "INFO"
  try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $DCName -ErrorAction Stop
    
    # Uptime
    if ($os.LastBootUpTime) {
      if ($os.LastBootUpTime -is [DateTime]) {
        $dcHealth.UptimeHours = [Math]::Round((New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)).TotalHours, 1)
      } else {
        $bootTime = ConvertFrom-WmiDateTime -WmiDateTime $os.LastBootUpTime
        if ($bootTime) {
          $dcHealth.UptimeHours = [Math]::Round((New-TimeSpan -Start $bootTime -End (Get-Date)).TotalHours, 1)
        }
      }
    }
    
    $uptimeCmd = "Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $DCName"
    $uptimeOutput = "LastBootUpTime: $($os.LastBootUpTime), Current Uptime: $(Format-Uptime -Hours $dcHealth.UptimeHours)"
    
    Add-ValidationResult -DC $DCName -Category "Hardware" -CheckName "System Uptime" `
      -Status "OK" `
      -Details "Uptime: $(Format-Uptime -Hours $dcHealth.UptimeHours)" `
      -TestCommand $uptimeCmd -TestOutput $uptimeOutput
    
    # Memory
    if ($os.TotalVisibleMemorySize -and $os.FreePhysicalMemory) {
      $memTotalGB = [Math]::Round($os.TotalVisibleMemorySize/1MB, 1)
      $memFreeGB = [Math]::Round($os.FreePhysicalMemory/1MB, 1)
      $memUsedGB = [Math]::Round($memTotalGB - $memFreeGB, 1)
      $dcHealth.MemoryUsedPct = [Math]::Round(($memUsedGB/$memTotalGB)*100, 1)
      
      $memStatus = if ($dcHealth.MemoryUsedPct -gt 90) { "CRITICAL" } 
                   elseif ($dcHealth.MemoryUsedPct -gt 80) { "WARNING" } 
                   else { "OK" }
      
      $memCmd = "Get-CimInstance Win32_OperatingSystem | Select TotalVisibleMemorySize, FreePhysicalMemory"
      $memOutput = "Total: $memTotalGB GB, Used: $memUsedGB GB, Free: $memFreeGB GB, Usage: $($dcHealth.MemoryUsedPct)%"
      
      Add-ValidationResult -DC $DCName -Category "Hardware" -CheckName "Memory Usage" `
        -Status $memStatus `
        -Details "RAM: $memUsedGB GB / $memTotalGB GB ($($dcHealth.MemoryUsedPct)% used)" `
        -TestCommand $memCmd -TestOutput $memOutput
      
      if ($dcHealth.MemoryUsedPct -gt 90) {
        Add-Issue -Severity 'Critical' -Category 'Hardware' -DC $DCName `
          -Title "Memory usage critically high ($($dcHealth.MemoryUsedPct)%)" `
          -Description "RAM usage is at $($dcHealth.MemoryUsedPct)% - performance degradation likely" `
          -Recommendation 'Investigate memory-consuming processes or add more RAM' -GroupByCategory
      } elseif ($dcHealth.MemoryUsedPct -gt 80) {
        Add-Issue -Severity 'Warning' -Category 'Hardware' -DC $DCName `
          -Title "Memory usage high ($($dcHealth.MemoryUsedPct)%)" `
          -Description "RAM usage is at $($dcHealth.MemoryUsedPct)%" `
          -Recommendation 'Monitor memory usage and plan for capacity increase' -GroupByCategory
      }
    }
    
    # Disk Space
    try {
      $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $DCName -ErrorAction Stop
      foreach ($disk in $disks) {
        $freeGB = [Math]::Round($disk.FreeSpace/1GB, 1)
        $sizeGB = [Math]::Round($disk.Size/1GB, 1)
        $freePct = [Math]::Round(($freeGB/$sizeGB)*100, 1)
        
        $diskStatus = if ($freePct -lt 10) { "CRITICAL"; $dcHealth.DiskCritical = $true }
                      elseif ($freePct -lt 20) { "WARNING" }
                      else { "OK" }
        
        $diskCmd = "Get-CimInstance Win32_LogicalDisk -Filter `"DriveType=3`" -ComputerName $DCName"
        $diskOutput = "Drive $($disk.DeviceID): Total=$sizeGB GB, Free=$freeGB GB ($freePct% free)"
        
        Add-ValidationResult -DC $DCName -Category "Hardware" -CheckName "Disk $($disk.DeviceID)" `
          -Status $diskStatus `
          -Details "Size: $sizeGB GB, Free: $freeGB GB ($freePct% free)" `
          -TestCommand $diskCmd -TestOutput $diskOutput
        
        if ($freePct -lt 10) {
          Add-Issue -Severity 'Critical' -Category 'Hardware' -DC $DCName `
            -Title "Disk $($disk.DeviceID) critically low ($freePct% free)" `
            -Description "Only $freeGB GB free on $($disk.DeviceID) - immediate action required" `
            -Recommendation 'Free up disk space immediately or expand volume' -GroupByCategory
        } elseif ($freePct -lt 20) {
          Add-Issue -Severity 'Warning' -Category 'Hardware' -DC $DCName `
            -Title "Disk $($disk.DeviceID) running low ($freePct% free)" `
            -Description "$freeGB GB free on $($disk.DeviceID)" `
            -Recommendation 'Plan to free up disk space or expand volume' -GroupByCategory
        }
      }
    } catch {
      Add-ValidationResult -DC $DCName -Category "Hardware" -CheckName "Disk Space" `
        -Status "UNKNOWN" `
        -Details "Unable to check disk space" `
        -TestCommand "Get-CimInstance Win32_LogicalDisk -ComputerName $DCName" `
        -TestOutput "Error: $($_.Exception.Message)"
    }
    
  } catch {
    Add-ValidationResult -DC $DCName -Category "Hardware" -CheckName "Hardware Info" `
      -Status "UNKNOWN" `
      -Details "Unable to retrieve hardware information: $($_.Exception.Message)" `
      -TestCommand "Get-CimInstance Win32_OperatingSystem -ComputerName $DCName" `
      -TestOutput "Error: $($_.Exception.Message)"
    Write-Log "Unable to get hardware info for $DCName : $_" -Level "WARNING"
  }
  
  # CPU Usage - Continuous monitoring over 5 seconds
  Write-Log "Measuring CPU usage for $DCName (monitoring for 5 seconds)..." -Level "INFO"
  $cpuMeasured = $false
  $cpuSamples = @()
  
  try {
    $cpuCounter = "\\$DCName\Processor(_Total)\% Processor Time"
    $sampleCount = 10  # 10 samples over 5 seconds = 1 sample every 500ms
    $intervalMs = 500
    
    Write-Log "Collecting $sampleCount CPU samples from $DCName..." -Level "INFO"
    
    for ($i = 0; $i -lt $sampleCount; $i++) {
      try {
        $sample = (Get-Counter -Counter $cpuCounter -ErrorAction Stop).CounterSamples[0].CookedValue
        $cpuSamples += $sample
        Write-Log "  Sample $($i+1)/$sampleCount : $([Math]::Round($sample, 1))%" -Level "INFO"
        
        if ($i -lt ($sampleCount - 1)) {
          Start-Sleep -Milliseconds $intervalMs
        }
      } catch {
        Write-Log "  Failed to collect sample $($i+1): $($_.Exception.Message)" -Level "WARNING"
      }
    }
    
    if ($cpuSamples.Count -gt 0) {
      # Calculate statistics
      $cpuAvg = ($cpuSamples | Measure-Object -Average).Average
      $cpuMin = ($cpuSamples | Measure-Object -Minimum).Minimum
      $cpuMax = ($cpuSamples | Measure-Object -Maximum).Maximum
      
      $dcHealth.CPUUsage = [Math]::Round($cpuAvg, 1)
      $cpuMeasured = $true
      
      Write-Log "CPU usage for $DCName - Average: $($dcHealth.CPUUsage)%, Min: $([Math]::Round($cpuMin, 1))%, Max: $([Math]::Round($cpuMax, 1))%" -Level "INFO"
      
      $cpuStatus = if ($dcHealth.CPUUsage -gt 85) { "WARNING" } else { "OK" }
      
      $cpuCmd = "Get-Counter '\\$DCName\Processor(_Total)\% Processor Time' (monitored for 5 seconds, $sampleCount samples)"
      $cpuOutput = "Samples collected: $($cpuSamples.Count)`n" +
                   "Average CPU: $($dcHealth.CPUUsage)%`n" +
                   "Minimum CPU: $([Math]::Round($cpuMin, 1))%`n" +
                   "Maximum CPU: $([Math]::Round($cpuMax, 1))%`n" +
                   "Sample values: " + (($cpuSamples | ForEach-Object { [Math]::Round($_, 1) }) -join '%, ') + '%'
      
      Add-ValidationResult -DC $DCName -Category "Hardware" -CheckName "CPU Usage" `
        -Status $cpuStatus `
        -Details "CPU: $($dcHealth.CPUUsage)% (avg over 5 seconds)" `
        -TestCommand $cpuCmd -TestOutput $cpuOutput
      
      if ($dcHealth.CPUUsage -gt 85) {
        Add-Issue -Severity 'Warning' -Category 'Hardware' -DC $DCName `
          -Title "CPU usage high ($($dcHealth.CPUUsage)%)" `
          -Description "CPU usage is at $($dcHealth.CPUUsage)% - may impact performance" `
          -Recommendation 'Investigate high CPU processes and consider load balancing' -GroupByCategory
      }
    } else {
      Write-Log "No CPU samples collected for $DCName" -Level "WARNING"
    }
  } catch {
    Write-Log "Exception measuring CPU for $DCName : $($_.Exception.Message)" -Level "WARNING"
  }
  
  if (-not $cpuMeasured) {
    Write-Log "CPU measurement failed for $DCName, marking as UNKNOWN" -Level "WARNING"
    Add-ValidationResult -DC $DCName -Category "Hardware" -CheckName "CPU Usage" `
      -Status "UNKNOWN" `
      -Details "Unable to measure CPU usage" `
      -TestCommand "Get-Counter '\\$DCName\Processor(_Total)\% Processor Time'" `
      -TestOutput "Error: Unable to collect performance counter data"
  }
  
  # Critical Services Check
  Write-Log "Checking critical services on $DCName..." -Level "INFO"
  $criticalServices = @('NTDS', 'DNS', 'Netlogon', 'Kdc', 'W32Time')
  foreach ($svcName in $criticalServices) {
    try {
      $svc = Get-Service -ComputerName $DCName -Name $svcName -ErrorAction Stop
      $isRunning = ($svc.Status -eq 'Running')
      $dcHealth.CriticalServices[$svcName] = $isRunning
      
      $svcCmd = "Get-Service -ComputerName $DCName -Name $svcName"
      $svcOutput = "Service: $svcName, Status: $($svc.Status), StartType: $($svc.StartType)"
      
      Add-ValidationResult -DC $DCName -Category "Services" -CheckName "$svcName Service" `
        -Status $(if ($isRunning) { "OK" } else { "CRITICAL" }) `
        -Details "Service status: $($svc.Status)" `
        -TestCommand $svcCmd -TestOutput $svcOutput
      
      if (-not $isRunning) {
        Add-Issue -Severity 'Critical' -Category 'Services' -DC $DCName `
          -Title "$svcName service is not running" `
          -Description "Critical AD service $svcName is stopped or failed" `
          -Recommendation "Investigate and restart the $svcName service immediately" -GroupByCategory
      }
    } catch {
      $dcHealth.CriticalServices[$svcName] = $false
      
      Add-ValidationResult -DC $DCName -Category "Services" -CheckName "$svcName Service" `
        -Status "CRITICAL" `
        -Details "Unable to query service: $($_.Exception.Message)" `
        -TestCommand "Get-Service -ComputerName $DCName -Name $svcName" `
        -TestOutput "Error: $($_.Exception.Message)"
      
      Add-Issue -Severity 'Critical' -Category 'Services' -DC $DCName `
        -Title "Unable to query $svcName service" `
        -Description $_.Exception.Message `
        -Recommendation 'Check WMI connectivity and service status manually' -GroupByCategory
    }
  }
  
  # DCDiag Tests
  Write-Log "Running DCDiag tests for $DCName..." -Level "INFO"
  foreach ($testName in $DCDIAG_TESTS) {
    try {
      Write-Log "  Running dcdiag test: $testName" -Level "INFO"
      $dcdiagOutput = & dcdiag /s:$DCName /test:$testName 2>&1
      $outputText = $dcdiagOutput -join "`n"
      
      # Parse result
      $testPassed = $true
      if ($outputText -match 'failed test') {
        $testPassed = $false
      } elseif ($outputText -match '\. \. \. \. \. \. (.*) (passed|failed)') {
        $testPassed = ($matches[2] -eq 'passed')
      }
      
      $dcHealth.DCDiagResults[$testName] = if ($testPassed) { "PASS" } else { "FAIL" }
      
      $dcdiagStatus = if ($testPassed) { "OK" } else { "CRITICAL" }
      
      $dcdiagCmd = "dcdiag /s:$DCName /test:$testName"
      
      Add-ValidationResult -DC $DCName -Category "DCDiag" -CheckName $testName `
        -Status $dcdiagStatus `
        -Details $(if ($testPassed) { "Test passed successfully" } else { "Test failed - check dcdiag output" }) `
        -TestCommand $dcdiagCmd -TestOutput $outputText
      
      if (-not $testPassed) {
        Add-Issue -Severity 'Critical' -Category 'DCDiag' -DC $DCName `
          -Title "DCDiag test '$testName' failed" `
          -Description "DCDiag test $testName reported failures" `
          -Recommendation "Run 'dcdiag /s:$DCName /test:$testName /v' for detailed information" -GroupByCategory
      }
    } catch {
      $dcHealth.DCDiagResults[$testName] = "ERROR"
      Add-ValidationResult -DC $DCName -Category "DCDiag" -CheckName $testName `
        -Status "UNKNOWN" `
        -Details "Unable to run test: $($_.Exception.Message)" `
        -TestCommand "dcdiag /s:$DCName /test:$testName" `
        -TestOutput "Error: $($_.Exception.Message)"
    }
  }
  
  # Replication Check
  Write-Log "Checking replication for $DCName..." -Level "INFO"
  try {
    $replResult = & repadmin /showrepl $DCName /csv 2>&1 | ConvertFrom-Csv -ErrorAction Stop
    $replErrors = $replResult | Where-Object { 
      ($_.'Number of Failures' -and [int]$_.'Number of Failures' -gt 0) -or 
      ($_.'Last Failure Status' -and $_.'Last Failure Status' -ne '0')
    }
    
    $replCmd = "repadmin /showrepl $DCName /csv"
    $replOutputText = if ($replErrors) {
      "Replication issues found:`n" + ($replErrors | ForEach-Object { 
        "Source: $($_.'Source DSA'), NC: $($_.'Naming Context'), Failures: $($_.'Number of Failures'), Last Result: $($_.'Last Failure Status')" 
      } | Out-String)
    } else {
      "All replication partners healthy. Total partners: $($replResult.Count)"
    }
    
    if ($replErrors) {
      $dcHealth.ReplicationStatus = 'ERROR'
      
      Add-ValidationResult -DC $DCName -Category "Replication" -CheckName "AD Replication" `
        -Status "CRITICAL" `
        -Details "Replication errors detected: $($replErrors.Count) partners failing" `
        -TestCommand $replCmd -TestOutput $replOutputText
      
      Add-Issue -Severity 'Critical' -Category 'Replication' -DC $DCName `
        -Title 'AD Replication Failures Detected' `
        -Description "Replication errors found: $($replErrors.Count) partners failing" `
        -Recommendation 'Run repadmin /showrepl and dcdiag /test:replications for detailed analysis' -GroupByCategory
    } else {
      $dcHealth.ReplicationStatus = 'OK'
      
      Add-ValidationResult -DC $DCName -Category "Replication" -CheckName "AD Replication" `
        -Status "OK" `
        -Details "All replication partners are healthy" `
        -TestCommand $replCmd -TestOutput $replOutputText
    }
  } catch {
    $dcHealth.ReplicationStatus = 'Unknown'
    
    Add-ValidationResult -DC $DCName -Category "Replication" -CheckName "AD Replication" `
      -Status "UNKNOWN" `
      -Details "Unable to check replication status" `
      -TestCommand "repadmin /showrepl $DCName /csv" `
      -TestOutput "Error: $($_.Exception.Message)"
    
    Write-Log "Unable to check replication for $DCName : $_" -Level "WARNING"
  }
  
  # Time Sync Check
  Write-Log "Checking time sync for $DCName..." -Level "INFO"
  try {
    $w32tmResult = & w32tm /stripchart /computer:$DCName /samples:1 /dataonly 2>&1
    $w32tmOutput = $w32tmResult -join "`n"
    
    if ($w32tmResult -match '([\+\-]?\d+\.\d+)s') {
      $offset = [Math]::Abs([double]$matches[1])
      $dcHealth.TimeSyncOffset = $offset
      
      $timeStatus = if ($offset -gt 5) { "CRITICAL" }
                    elseif ($offset -gt 1) { "WARNING" }
                    else { "OK" }
      
      $timeCmd = "w32tm /stripchart /computer:$DCName /samples:1 /dataonly"
      
      Add-ValidationResult -DC $DCName -Category "Time Sync" -CheckName "NTP Synchronization" `
        -Status $timeStatus `
        -Details "Time offset: ${offset}s" `
        -TestCommand $timeCmd -TestOutput $w32tmOutput
      
      if ($offset -gt 5) {
        Add-Issue -Severity 'Critical' -Category 'Time' -DC $DCName `
          -Title "Time sync offset is ${offset}s" `
          -Description 'Time drift exceeds 5 seconds - Kerberos authentication may fail!' `
          -Recommendation 'Check NTP configuration. Run: w32tm /resync /rediscover' -GroupByCategory
      } elseif ($offset -gt 1) {
        Add-Issue -Severity 'Warning' -Category 'Time' -DC $DCName `
          -Title "Time sync offset is ${offset}s" `
          -Description 'Time drift detected' `
          -Recommendation 'Monitor time sync. Consider reviewing NTP sources.' -GroupByCategory
      }
    }
  } catch {
    Add-ValidationResult -DC $DCName -Category "Time Sync" -CheckName "NTP Synchronization" `
      -Status "UNKNOWN" `
      -Details "Unable to check time synchronization" `
      -TestCommand "w32tm /stripchart /computer:$DCName /samples:1 /dataonly" `
      -TestOutput "Error: $($_.Exception.Message)"
    Write-Log "Unable to check time sync for $DCName" -Level "INFO"
  }
  
  # Critical Events Check (last 24h)
  Write-Log "Checking critical events for $DCName..." -Level "INFO"
  try {
    $startTime = (Get-Date).AddHours(-24)
    $eventLogNames = @('Directory Service', 'System', 'DFS Replication')
    $criticalEvents = @()
    
    $eventCmd = "Get-WinEvent -ComputerName $DCName -FilterHashtable @{LogName='Directory Service','System','DFS Replication'; Level=1,2; StartTime='$startTime'}"
    $eventOutputList = @()
    
    foreach ($logName in $eventLogNames) {
      try {
        $events = Get-WinEvent -ComputerName $DCName -FilterHashtable @{
          LogName = $logName
          Level = 1, 2
          StartTime = $startTime
        } -ErrorAction SilentlyContinue
        
        if ($events) {
          $criticalEvents += $events | Where-Object { $CRITICAL_EVENT_IDS.Keys -contains $_.Id }
        }
      } catch {
        Write-Log "Unable to query $logName log on $DCName" -Level "INFO"
      }
    }
    
    if ($criticalEvents -and $criticalEvents.Count -gt 0) {
      $dcHealth.EventsCritical = $criticalEvents.Count
      $eventGroups = $criticalEvents | Group-Object -Property Id
      $eventSummary = @()
      foreach ($group in $eventGroups) {
        $eventSummary += "$($group.Count)x Event $($group.Name)"
        $eventOutputList += "Event ID $($group.Name): $($group.Count) occurrences - $($CRITICAL_EVENT_IDS[$group.Name])"
      }
      
      $eventOutput = ($eventOutputList -join "`n")
      
      Add-ValidationResult -DC $DCName -Category "Events" -CheckName "Critical Events (24h)" `
        -Status "WARNING" `
        -Details "$($criticalEvents.Count) critical events found: $($eventSummary -join ', ')" `
        -TestCommand $eventCmd -TestOutput $eventOutput
      
      Add-Issue -Severity 'Warning' -Category 'Events' -DC $DCName `
        -Title "$($criticalEvents.Count) critical events in last 24h" `
        -Description ($eventSummary -join ', ') `
        -Recommendation 'Review Event Viewer for detailed error messages' -GroupByCategory
    } else {
      Add-ValidationResult -DC $DCName -Category "Events" -CheckName "Critical Events (24h)" `
        -Status "OK" `
        -Details "No critical events found in the last 24 hours" `
        -TestCommand $eventCmd -TestOutput "No critical events found matching the specified criteria in the last 24 hours"
    }
  } catch {
    Add-ValidationResult -DC $DCName -Category "Events" -CheckName "Critical Events (24h)" `
      -Status "UNKNOWN" `
      -Details "Unable to check event logs: $($_.Exception.Message)" `
      -TestCommand $eventCmd -TestOutput "Error: $($_.Exception.Message)"
    Write-Log "Unable to check events for $DCName : $($_.Exception.Message)" -Level "WARNING"
  }
  
  # Certificate Expiration Check
  Write-Log "Checking certificates for $DCName..." -Level "INFO"
  try {
    $certs = Invoke-Command -ComputerName $DCName -ScriptBlock {
      Get-ChildItem -Path Cert:\LocalMachine\My | 
      Where-Object { $_.HasPrivateKey -and $_.NotAfter -lt (Get-Date).AddDays($args[0]) }
    } -ArgumentList $CertWarningDays -ErrorAction Stop
    
    $certCmd = "Invoke-Command -ComputerName $DCName { Get-ChildItem Cert:\LocalMachine\My | Where HasPrivateKey }"
    
    if ($certs) {
      $expiredCerts = @($certs | Where-Object { $_.NotAfter -lt (Get-Date) })
      $expiringSoon = @($certs | Where-Object { $_.NotAfter -ge (Get-Date) })
      
      $dcHealth.CertificatesExpired = $expiredCerts.Count
      $dcHealth.CertificatesExpiring = $expiringSoon.Count
      
      $certDetails = @()
      $certOutputList = @()
      foreach ($cert in $certs) {
        $daysLeft = ($cert.NotAfter - (Get-Date)).Days
        $status = if ($daysLeft -lt 0) { "EXPIRED $([Math]::Abs($daysLeft)) days ago" } else { "expires in $daysLeft days" }
        $certDetails += "• Subject: $($cert.Subject)`n  Issuer: $($cert.Issuer)`n  Status: $status`n  Expiry: $($cert.NotAfter.ToString('yyyy-MM-dd'))"
        $certOutputList += "Subject: $($cert.Subject), Thumbprint: $($cert.Thumbprint), NotAfter: $($cert.NotAfter), Status: $status"
      }
      
      $certStatus = if ($expiredCerts.Count -gt 0) { "CRITICAL" } else { "WARNING" }
      $certOutput = ($certOutputList -join "`n")
      
      Add-ValidationResult -DC $DCName -Category "Certificates" -CheckName "Certificate Expiration" `
        -Status $certStatus `
        -Details "Expired: $($expiredCerts.Count), Expiring soon: $($expiringSoon.Count)" `
        -TestCommand $certCmd -TestOutput $certOutput
      
      if ($expiredCerts.Count -gt 0) {
        Add-Issue -Severity 'Critical' -Category 'Certificates' -DC $DCName `
          -Title "$($expiredCerts.Count) certificate(s) expired, $($expiringSoon.Count) expiring soon" `
          -Description ($certDetails -join "`n`n") `
          -Recommendation 'Renew or replace certificates immediately to avoid service disruption' -GroupByCategory
      } elseif ($expiringSoon.Count -gt 0) {
        Add-Issue -Severity 'Warning' -Category 'Certificates' -DC $DCName `
          -Title "$($expiringSoon.Count) certificate(s) expiring within $CertWarningDays days" `
          -Description ($certDetails -join "`n`n") `
          -Recommendation 'Plan certificate renewal to avoid service disruption' -GroupByCategory
      }
    } else {
      Add-ValidationResult -DC $DCName -Category "Certificates" -CheckName "Certificate Expiration" `
        -Status "OK" `
        -Details "All certificates are valid and not expiring soon" `
        -TestCommand $certCmd -TestOutput "All certificates in LocalMachine\My are valid and not expiring within $CertWarningDays days"
    }
  } catch {
    Add-ValidationResult -DC $DCName -Category "Certificates" -CheckName "Certificate Expiration" `
      -Status "UNKNOWN" `
      -Details "Unable to check certificates" `
      -TestCommand $certCmd -TestOutput "Error: $($_.Exception.Message)"
    Write-Log "Unable to check certificates for $DCName : $_" -Level "INFO"
  }
  
  Write-Log "Completed checks for $DCName" -Level "INFO"
  return $dcHealth
}

# ===================== DOMAIN-WIDE CHECKS =====================

function Test-FSMORoles {
  Write-Log "Checking FSMO role holders..."
  
  $fsmoRoles = @{
    'Schema Master' = $forest.SchemaMaster
    'Domain Naming Master' = $forest.DomainNamingMaster
    'PDC Emulator' = $domain.PDCEmulator
    'RID Master' = $domain.RIDMaster
    'Infrastructure Master' = $domain.InfrastructureMaster
  }
  
  foreach ($role in $fsmoRoles.GetEnumerator()) {
    $holder = $role.Value
    $reachable = Test-Connection -ComputerName $holder -Count 1 -Quiet -ErrorAction SilentlyContinue
    
    $fsmoStatus = if ($reachable) { "OK" } else { "CRITICAL" }
    
    $fsmoCmd = "Test-Connection -ComputerName $holder -Count 1"
    $fsmoOutput = if ($reachable) { "Role holder $holder is reachable and operational" } else { "Role holder $holder is NOT reachable" }
    
    Add-ValidationResult -DC "Domain-Wide" -Category "FSMO Roles" -CheckName $role.Key `
      -Status $fsmoStatus `
      -Details $(if ($reachable) { "Role holder is reachable" } else { "Role holder is UNREACHABLE" }) `
      -TestCommand $fsmoCmd -TestOutput $fsmoOutput
    
    if (-not $reachable) {
      Add-Issue -Severity 'Critical' -Category 'FSMO' -DC $holder `
        -Title "$($role.Key) holder is unreachable" `
        -Description "FSMO role holder $holder is not responding" `
        -Recommendation 'Verify DC health. Consider seizing FSMO roles if DC is permanently offline.'
    }
  }
  
  return $fsmoRoles
}

function Test-RIDPool {
  Write-Log "Checking RID pool availability..."
  
  try {
    $ridMaster = $domain.RIDMaster
    $dcdiagRid = & dcdiag /test:ridmanager /s:$ridMaster /v 2>&1
    $ridOutput = $dcdiagRid -join "`n"
    
    # Parse the "Available RID Pool for the Domain" line
    # Example: * Available RID Pool for the Domain is 2600 to 1073741823
    if ($ridOutput -match '\*\s+Available RID Pool for the Domain is\s+(\d+)\s+to\s+(\d+)') {
      $ridStart = [int]$matches[1]
      $ridEnd = [int]$matches[2]
      $availableRids = $ridEnd - $ridStart + 1
      
      Write-Log "RID Pool: Start=$ridStart, End=$ridEnd, Available=$availableRids" -Level "INFO"
      
      $ridStatus = if ($availableRids -lt 100000) { "CRITICAL" }
                   elseif ($availableRids -lt 500000) { "WARNING" }
                   else { "OK" }
      
      $ridCmd = "dcdiag /test:ridmanager /s:$ridMaster /v"
      
      Add-ValidationResult -DC "Domain-Wide" -Category "RID Pool" -CheckName "Available RIDs" `
        -Status $ridStatus `
        -Details "Available RID Pool: $availableRids RIDs (from $ridStart to $ridEnd)" `
        -TestCommand $ridCmd -TestOutput $ridOutput
      
      if ($availableRids -lt 100000) {
        Add-Issue -Severity 'Critical' -Category 'RID Pool' -DC $ridMaster `
          -Title "Low RID pool: $availableRids RIDs remaining" `
          -Description "RID pool is critically low - may impact object creation" `
          -Recommendation 'Contact Microsoft Support to extend RID pool or investigate excessive consumption'
      } elseif ($availableRids -lt 500000) {
        Add-Issue -Severity 'Warning' -Category 'RID Pool' -DC $ridMaster `
          -Title "RID pool usage high: $availableRids RIDs remaining" `
          -Description 'RID pool is being consumed - monitor for trends' `
          -Recommendation 'Monitor RID consumption and plan for pool expansion if needed'
      }
      
      return $availableRids
    } else {
      Write-Log "Unable to parse RID pool information from dcdiag output" -Level "WARNING"
      
      Add-ValidationResult -DC "Domain-Wide" -Category "RID Pool" -CheckName "Available RIDs" `
        -Status "UNKNOWN" `
        -Details "Unable to parse RID pool information from dcdiag output" `
        -TestCommand "dcdiag /test:ridmanager /s:$ridMaster /v" `
        -TestOutput $ridOutput
    }
  } catch {
    Add-ValidationResult -DC "Domain-Wide" -Category "RID Pool" -CheckName "Available RIDs" `
      -Status "UNKNOWN" `
      -Details "Unable to check RID pool: $($_.Exception.Message)" `
      -TestCommand "dcdiag /test:ridmanager /s:$ridMaster /v" `
      -TestOutput "Error: $($_.Exception.Message)"
    Write-Log "Unable to check RID pool: $($_.Exception.Message)" -Level "WARNING"
  }
  return $null
}

function Test-DNSHealth {
  Write-Log "Checking DNS health..."
  
  $domainDNS = (Get-ADDomain).DNSRoot
  $requiredSRV = @(
    "_ldap._tcp.$domainDNS",
    "_kerberos._tcp.$domainDNS",
    "_kpasswd._tcp.$domainDNS",
    "_gc._tcp.$domainDNS"
  )
  
  $missingCount = 0
  $missingSRVs = @()
  $dnsOutputList = @()
  
  foreach ($srv in $requiredSRV) {
    try {
      $result = Resolve-DnsName -Name $srv -Type SRV -ErrorAction Stop
      if (-not $result) {
        $missingCount++
        $missingSRVs += $srv
        $dnsOutputList += "$srv - MISSING"
      } else {
        $dnsOutputList += "$srv - OK ($($result.Count) records found)"
      }
    } catch {
      $missingCount++
      $missingSRVs += $srv
      $dnsOutputList += "$srv - MISSING (Error: $($_.Exception.Message))"
    }
  }
  
  $dnsStatus = if ($missingCount -gt 0) { "CRITICAL" } else { "OK" }
  $dnsCmd = "Resolve-DnsName -Name '_ldap._tcp.$domainDNS' -Type SRV"
  $dnsOutput = ($dnsOutputList -join "`n")
  
  Add-ValidationResult -DC "Domain-Wide" -Category "DNS" -CheckName "Critical SRV Records" `
    -Status $dnsStatus `
    -Details $(if ($missingCount -gt 0) { "Missing SRV records: $($missingSRVs -join ', ')" } else { "All critical SRV records are present" }) `
    -TestCommand $dnsCmd -TestOutput $dnsOutput
  
  if ($missingCount -gt 0) {
    Add-Issue -Severity 'Critical' -Category 'DNS' -DC 'Domain-Wide' `
      -Title "$missingCount critical SRV record(s) missing" `
      -Description 'Required DNS SRV records not found - authentication may fail' `
      -Recommendation 'Register missing SRV records: dcdiag /fix or restart Netlogon service on all DCs'
  }
}

function Format-LargeNumber {
  param([long]$Number)
  
  if ($Number -ge 1000000000) {
    return "$([Math]::Round($Number / 1000000000, 1))B"
  } elseif ($Number -ge 1000000) {
    return "$([Math]::Round($Number / 1000000, 1))M"
  } elseif ($Number -ge 1000) {
    return "$([Math]::Round($Number / 1000, 1))K"
  } else {
    return "$Number"
  }
}

function Get-ADStatistics {
  Write-Log "Collecting AD statistics..."
  
  try {
    $stats = @{
      Users = (Get-ADUser -Filter * -ErrorAction SilentlyContinue | Measure-Object).Count
      Computers = (Get-ADComputer -Filter * -ErrorAction SilentlyContinue | Measure-Object).Count
      Groups = (Get-ADGroup -Filter * -ErrorAction SilentlyContinue | Measure-Object).Count
      DomainControllers = $allDCs.Count
    }
    
    $statsCmd = "Get-ADUser -Filter *; Get-ADComputer -Filter *; Get-ADGroup -Filter *"
    $statsOutput = "Users: $($stats.Users), Computers: $($stats.Computers), Groups: $($stats.Groups), DCs: $($stats.DomainControllers)"
    
    Add-ValidationResult -DC "Domain-Wide" -Category "Statistics" -CheckName "AD Object Count" `
      -Status "OK" `
      -Details "Users: $($stats.Users), Computers: $($stats.Computers), Groups: $($stats.Groups), DCs: $($stats.DomainControllers)" `
      -TestCommand $statsCmd -TestOutput $statsOutput
    
    return $stats
  } catch {
    Add-ValidationResult -DC "Domain-Wide" -Category "Statistics" -CheckName "AD Object Count" `
      -Status "UNKNOWN" `
      -Details "Unable to collect AD statistics" `
      -TestCommand "Get-ADUser/Computer/Group -Filter *" `
      -TestOutput "Error: $($_.Exception.Message)"
    return @{Users=0; Computers=0; Groups=0; DomainControllers=0}
  }
}

# ===================== EXECUTE ALL CHECKS =====================

Write-Log "Starting health checks..."

# Domain-wide checks
$fsmoRoles = Test-FSMORoles
$ridPoolAvailable = Test-RIDPool
Test-DNSHealth
$adStats = Get-ADStatistics

# Per-DC checks
$dcHealthResults = @()
foreach ($dc in $allDCs) {
  $dcHealthResults += Test-DCHealth -DCName $dc
}

# Calculate overall health score
$statusCounts = $script:validationResults | Group-Object -Property Status
$okCount = (($statusCounts | Where-Object { $_.Name -eq "OK" }).Count) 
if (-not $okCount) { $okCount = 0 }
$warningCount = (($statusCounts | Where-Object { $_.Name -eq "WARNING" }).Count)
if (-not $warningCount) { $warningCount = 0 }
$criticalCount = (($statusCounts | Where-Object { $_.Name -eq "CRITICAL" }).Count)
if (-not $criticalCount) { $criticalCount = 0 }
$unknownCount = (($statusCounts | Where-Object { $_.Name -eq "UNKNOWN" }).Count)
if (-not $unknownCount) { $unknownCount = 0 }

$criticalCategoryCount = $script:issueCategoryCounts.Critical.Keys.Count
$warningCategoryCount = $script:issueCategoryCounts.Warning.Keys.Count

$healthScore = Get-HealthScore -CriticalCount $criticalCount `
                                -WarningCount $warningCount `
                                -OkCount $okCount `
                                -UnknownCount $unknownCount

$severityInfo = Get-SeverityLevel -Score $healthScore

Write-Log "Health check completed. Score: $healthScore/100 ($($severityInfo.Level))"
Write-Log "Validation Counts - OK: $okCount, Warning: $warningCount, Critical: $criticalCount, Unknown: $unknownCount"
Write-Log "Issue Categories - Critical: $criticalCategoryCount, Warning: $warningCategoryCount"

# ===================== HTML REPORT GENERATION =====================

$css = @"
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
       background: #0f172a; color: #e2e8f0; line-height: 1.6; }
.container { max-width: 1400px; margin: 0 auto; padding: 20px; }

/* Executive Summary */
.exec-summary { background: linear-gradient(135deg, #1e293b, #0f172a); 
                border-radius: 12px; padding: 30px; margin-bottom: 30px; 
                border: 2px solid $($severityInfo.Color); box-shadow: 0 8px 32px rgba(0,0,0,0.3); }
.health-score { text-align: center; margin-bottom: 30px; }
.score-circle { width: 180px; height: 180px; margin: 0 auto 20px; 
                border-radius: 50%; border: 12px solid $($severityInfo.Color);
                display: flex; align-items: center; justify-content: center;
                background: rgba(0,0,0,0.3); position: relative; }
.score-value { font-size: 56px; font-weight: 700; color: $($severityInfo.Color); }
.score-label { font-size: 18px; color: #94a3b8; text-transform: uppercase; 
               letter-spacing: 2px; margin-top: 10px; }
.status-badge { display: inline-block; padding: 8px 20px; border-radius: 6px;
                background: $($severityInfo.Color); color: #fff; font-weight: 700;
                font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }

/* Key Metrics */
.metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); 
                gap: 20px; margin-top: 30px; }
.metric-card { background: rgba(30, 41, 59, 0.6); border: 1px solid #334155; 
               border-radius: 8px; padding: 20px; text-align: center; transition: all 0.2s; 
               cursor: pointer; }
.metric-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
.metric-value { font-size: 36px; font-weight: 700; color: #fff; margin-bottom: 5px; }
.metric-label { font-size: 11px; color: #94a3b8; text-transform: uppercase; 
                letter-spacing: 1px; }
.metric-critical .metric-value { color: #ef4444; }
.metric-warning .metric-value { color: #f59e0b; }
.metric-success .metric-value { color: #10b981; }

/* Issues Section */
.section { background: #1e293b; border-radius: 8px; padding: 25px; 
           margin-bottom: 20px; border: 1px solid #334155; }
.section-title { font-size: 20px; font-weight: 700; color: #f1f5f9; 
                 margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #334155; 
                 display: flex; align-items: center; gap: 10px; }
.issue-card { background: #0f172a; border-left: 4px solid #ef4444; 
              border-radius: 6px; padding: 15px; margin-bottom: 15px; }
.issue-card.warning { border-left-color: #f59e0b; }
.issue-card.info { border-left-color: #3b82f6; }
.issue-header { display: flex; justify-content: space-between; align-items: flex-start; 
                margin-bottom: 10px; flex-wrap: wrap; gap: 10px; }
.issue-title { font-size: 16px; font-weight: 700; color: #f1f5f9; flex: 1; }
.issue-dc { font-size: 12px; color: #94a3b8; background: rgba(148, 163, 184, 0.1); 
            padding: 4px 10px; border-radius: 4px; white-space: nowrap; }
.issue-desc { font-size: 14px; color: #cbd5e1; margin-bottom: 10px; line-height: 1.6; 
              white-space: pre-wrap; }
.issue-rec { font-size: 13px; color: #94a3b8; padding: 10px; 
             background: rgba(59, 130, 246, 0.1); border-radius: 4px; 
             border-left: 3px solid #3b82f6; }
.issue-rec strong { color: #60a5fa; }

/* DC Summary Table */
table { width: 100%; border-collapse: collapse; margin-top: 15px; }
th { background: #0f172a; padding: 12px; text-align: left; font-size: 11px; 
     color: #94a3b8; text-transform: uppercase; border-bottom: 2px solid #334155; }
td { padding: 12px; border-bottom: 1px solid #334155; font-size: 13px; color: #e2e8f0; }
tr:hover { background: rgba(59, 130, 246, 0.05); }
.status-ok { color: #10b981; font-weight: 600; }
.status-error { color: #ef4444; font-weight: 600; }
.status-warn { color: #f59e0b; font-weight: 600; }
.status-unknown { color: #94a3b8; font-weight: 600; }
.hw-info { font-size: 11px; color: #64748b; margin-top: 4px; }

/* Expandable Section */
.expandable-header { background: #0f172a; padding: 15px 20px; border-radius: 6px; 
                     cursor: pointer; display: flex; justify-content: space-between; 
                     align-items: center; transition: all 0.2s; user-select: none; }
.expandable-header:hover { background: #1a2332; }
.expandable-icon { font-size: 18px; font-weight: 700; color: #94a3b8; 
                   transition: transform 0.3s; }
.expandable-icon.open { transform: rotate(90deg); }
.expandable-content { max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out; }
.expandable-content.open { max-height: 10000px; transition: max-height 0.5s ease-in; }

/* Filter Buttons */
.filter-container { display: flex; gap: 10px; margin: 20px 0; flex-wrap: wrap; 
                    align-items: center; }
.filter-label { color: #94a3b8; font-size: 14px; font-weight: 600; }
.filter-btn { padding: 8px 16px; border: 2px solid #334155; background: #1e293b; 
              color: #e2e8f0; border-radius: 6px; cursor: pointer; font-size: 13px;
              font-weight: 600; transition: all 0.2s; }
.filter-btn:hover { background: #334155; }
.filter-btn.active { border-color: #3b82f6; background: rgba(59, 130, 246, 0.2); 
                     color: #60a5fa; }
.filter-btn.ok.active { border-color: #10b981; background: rgba(16, 185, 129, 0.2); 
                        color: #10b981; }
.filter-btn.warning.active { border-color: #f59e0b; background: rgba(245, 158, 11, 0.2); 
                             color: #f59e0b; }
.filter-btn.critical.active { border-color: #ef4444; background: rgba(239, 68, 68, 0.2); 
                              color: #ef4444; }
.filter-btn.unknown.active { border-color: #64748b; background: rgba(100, 116, 139, 0.2); 
                             color: #94a3b8; }

/* DC Section Card */
.dc-section-card { background: #0f172a; border-radius: 8px; padding: 20px; 
                   margin-bottom: 20px; border: 1px solid #334155; }
.dc-section-header { background: linear-gradient(135deg, #1e3a8a, #1e40af); 
                     padding: 12px 20px; border-radius: 6px; margin-bottom: 15px;
                     border-left: 4px solid #3b82f6; }
.dc-section-title { font-size: 18px; font-weight: 700; color: #fff; margin: 0; 
                    display: flex; align-items: center; gap: 10px; }

/* Validation Grid */
.validation-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); 
                   gap: 12px; }
.validation-item { background: #1e293b; padding: 14px; border-radius: 6px; 
                   border-left: 3px solid #334155; transition: all 0.2s; cursor: pointer; }
.validation-item:hover { transform: translateX(2px); box-shadow: 0 2px 8px rgba(0,0,0,0.3); }
.validation-item.ok { border-left-color: #10b981; }
.validation-item.warning { border-left-color: #f59e0b; }
.validation-item.critical { border-left-color: #ef4444; }
.validation-item.unknown { border-left-color: #64748b; }
.validation-item.hidden { display: none; }
.validation-header { display: flex; justify-content: space-between; align-items: center; 
                     margin-bottom: 8px; }
.validation-name { font-size: 14px; font-weight: 600; color: #f1f5f9; }
.validation-status { font-size: 10px; padding: 3px 10px; border-radius: 4px; 
                     font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
.validation-status.ok { background: rgba(16, 185, 129, 0.2); color: #10b981; }
.validation-status.warning { background: rgba(245, 158, 11, 0.2); color: #f59e0b; }
.validation-status.critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
.validation-status.unknown { background: rgba(148, 163, 184, 0.2); color: #94a3b8; }
.validation-details { font-size: 12px; color: #cbd5e1; line-height: 1.5; margin-bottom: 6px; }
.validation-category { font-size: 11px; color: #64748b; display: flex; align-items: center; 
                       gap: 4px; }

/* Test Details Modal */
.test-details-panel { background: #0f172a; border: 1px solid #334155; border-radius: 8px; 
                      padding: 20px; margin-top: 20px; display: none; }
.test-details-panel.show { display: block; }
.test-details-header { display: flex; justify-content: space-between; align-items: center; 
                       margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #334155; }
.test-details-title { font-size: 18px; font-weight: 700; color: #f1f5f9; }
.test-details-close { background: #ef4444; color: #fff; border: none; padding: 6px 12px; 
                      border-radius: 4px; cursor: pointer; font-weight: 600; }
.test-details-close:hover { background: #dc2626; }
.test-details-section { margin-bottom: 20px; }
.test-details-label { font-size: 12px; color: #94a3b8; text-transform: uppercase; 
                      letter-spacing: 1px; margin-bottom: 8px; font-weight: 600; }
.test-details-content { background: #1e293b; padding: 15px; border-radius: 6px; 
                        border-left: 3px solid #3b82f6; font-family: 'Courier New', monospace; 
                        font-size: 12px; color: #e2e8f0; white-space: pre-wrap; 
                        overflow-x: auto; max-height: 300px; overflow-y: auto; }

/* Footer */
.footer { text-align: center; padding: 20px; color: #64748b; font-size: 12px; 
          border-top: 1px solid #334155; margin-top: 30px; }

/* Empty State */
.empty-state { text-align: center; padding: 40px; color: #64748b; }
.empty-state-icon { font-size: 48px; margin-bottom: 15px; }
</style>
"@

# Build Top Issues
$topIssues = @()
$topIssues += $script:issues.Critical | Select-Object -First 5
if ($topIssues.Count -lt 5) {
  $topIssues += $script:issues.Warning | Select-Object -First (5 - $topIssues.Count)
}

$topIssuesHtml = ""
if ($topIssues.Count -gt 0) {
  foreach ($issue in $topIssues) {
    $severityClass = $issue.Severity.ToLower()
    $topIssuesHtml += @"
<div class="issue-card $severityClass">
  <div class="issue-header">
    <div class="issue-title">$($issue.Title)</div>
    <div class="issue-dc">$($issue.DC) | $($issue.Category)</div>
  </div>
  <div class="issue-desc">$($issue.Description)</div>
  <div class="issue-rec"><strong>Recommendation:</strong> $($issue.Recommendation)</div>
</div>
"@
  }
} else {
  $topIssuesHtml = @"
<div class="empty-state">
  <div class="empty-state-icon">✓</div>
  <div>No critical or warning issues detected. All checks passed successfully.</div>
</div>
"@
}

# Build DC Summary Table with Hardware Info
$dcTableRows = ""
if ($dcHealthResults -and $dcHealthResults.Count -gt 0) {
  foreach ($dcHealth in $dcHealthResults) {
    $servicesStatus = if ($dcHealth.CriticalServices.Values -contains $false) { 
      '<span class="status-error">ISSUES</span>' 
    } else { 
      '<span class="status-ok">OK</span>' 
    }
    
    $replStatus = switch ($dcHealth.ReplicationStatus) {
      'OK' { '<span class="status-ok">OK</span>' }
      'ERROR' { '<span class="status-error">ERROR</span>' }
      default { '<span class="status-warn">UNKNOWN</span>' }
    }
    
    $gcBadge = if ($dcHealth.IsGC) { '🌐 GC' } else { '' }
    $pdcBadge = if ($dcHealth.IsPDC) { '👑 PDC' } else { '' }
    $badges = (($gcBadge, $pdcBadge) | Where-Object { $_ }) -join ' '
    
    # Hardware Info
    $hwInfo = @()
    if ($dcHealth.UptimeHours) { $hwInfo += "Uptime: $(Format-Uptime -Hours $dcHealth.UptimeHours)" }
    if ($null -ne $dcHealth.CPUUsage) { 
      $cpuColor = if ($dcHealth.CPUUsage -gt 85) { '#ef4444' } elseif ($dcHealth.CPUUsage -gt 70) { '#f59e0b' } else { '#10b981' }
      $hwInfo += "<span style='color:$cpuColor'>CPU: $($dcHealth.CPUUsage)%</span>" 
    } else {
      $hwInfo += "<span style='color:#94a3b8'>CPU: N/A</span>"
    }
    if ($dcHealth.MemoryUsedPct) { 
      $memColor = if ($dcHealth.MemoryUsedPct -gt 90) { '#ef4444' } elseif ($dcHealth.MemoryUsedPct -gt 80) { '#f59e0b' } else { '#10b981' }
      $hwInfo += "<span style='color:$memColor'>RAM: $($dcHealth.MemoryUsedPct)%</span>" 
    }
    if ($dcHealth.DiskCritical) { $hwInfo += "<span style='color:#ef4444'>⚠ Disk Low</span>" }
    
    $hwInfoHtml = if ($hwInfo.Count -gt 0) { 
      "<div class='hw-info'>$($hwInfo -join ' | ')</div>" 
    } else { "" }
    
    $eventsDisplay = if ($dcHealth.EventsCritical -gt 0) { 
      "<span class='status-warn'>$($dcHealth.EventsCritical)</span>" 
    } else { 
      '<span class="status-ok">0</span>' 
    }
    
    $dcTableRows += @"
<tr>
  <td><strong>$($dcHealth.Name)</strong> $badges<br><small style="color:#64748b;">$($dcHealth.IP)</small>$hwInfoHtml</td>
  <td>$servicesStatus</td>
  <td>$replStatus</td>
  <td>$eventsDisplay</td>
  <td>$(if ($dcHealth.CertificatesExpired -gt 0) { "<span class='status-error'>$($dcHealth.CertificatesExpired) exp / $($dcHealth.CertificatesExpiring) soon</span>" } elseif ($dcHealth.CertificatesExpiring -gt 0) { "<span class='status-warn'>$($dcHealth.CertificatesExpiring) expiring</span>" } else { '<span class="status-ok">OK</span>' })</td>
</tr>
"@
  }
} else {
  $dcTableRows = '<tr><td colspan="5" style="text-align:center;color:#64748b;">No domain controller data available</td></tr>'
}

# All Issues Section (Collapsible)
$allIssuesSection = ""
$allIssues = @($script:issues.Critical) + @($script:issues.Warning)
if ($allIssues.Count -gt 0) {
  $allIssuesHtml = ""
  
  foreach ($issue in $allIssues) {
    $severityClass = $issue.Severity.ToLower()
    $allIssuesHtml += @"
<div class="issue-card $severityClass">
  <div class="issue-header">
    <div class="issue-title">$($issue.Title)</div>
    <div class="issue-dc">$($issue.DC) | $($issue.Category)</div>
  </div>
  <div class="issue-desc">$($issue.Description)</div>
  <div class="issue-rec"><strong>Recommendation:</strong> $($issue.Recommendation)</div>
</div>
"@
  }
  
  $allIssuesSection = @"
  <div class="section" id="allissues">
    <div class="expandable-header" onclick="toggleSection('allissues')">
      <h2 class="section-title" style="margin:0; padding:0; border:none;">📋 All Issues ($($allIssues.Count) items)</h2>
      <span class="expandable-icon" id="allissues-icon">▶</span>
    </div>
    <div class="expandable-content" id="allissues-content">
      <div style="margin-top:20px;">
        $allIssuesHtml
      </div>
    </div>
  </div>
"@
}

# FSMO Roles Table
$fsmoTableRows = ""
foreach ($role in $fsmoRoles.GetEnumerator()) {
  $fsmoTableRows += "<tr><td>$($role.Key)</td><td>$($role.Value)</td></tr>`n"
}

# Build Validation Results Section - GROUPED BY DC with Domain-Wide FIRST
$validationHtml = ""

# Prepare validation data as JSON array with proper escaping
$validationDataArray = @()
foreach ($validation in $script:validationResults) {
  $validationDataArray += @{
    DC = $validation.DC
    Category = $validation.Category
    CheckName = $validation.CheckName
    Status = $validation.Status
    Details = $validation.Details
    TestCommand = (Escape-HtmlAttribute $validation.TestCommand)
    TestOutput = (Escape-HtmlAttribute $validation.TestOutput)
    Timestamp = $validation.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')
  }
}

$validationDataJson = ($validationDataArray | ConvertTo-Json -Depth 5 -Compress)

# Group validations by DC
$groupedValidations = $script:validationResults | Group-Object -Property DC

# First: Domain-Wide section
$validationIndex = 0
$domainWideGroup = $groupedValidations | Where-Object { $_.Name -eq "Domain-Wide" }
if ($domainWideGroup) {
  $validationHtml += @"
<div class="dc-section-card">
  <div class="dc-section-header">
    <h3 class="dc-section-title">🌐 Domain-Wide Checks</h3>
  </div>
  <div class="validation-grid">
"@
  
  foreach ($validation in $domainWideGroup.Group) {
    $statusClass = $validation.Status.ToLower()
    $validationHtml += @"
<div class="validation-item $statusClass" data-status="$statusClass" data-index="$validationIndex" onclick="showTestDetails($validationIndex)">
  <div class="validation-header">
    <div class="validation-name">$($validation.CheckName)</div>
    <div class="validation-status $statusClass">$($validation.Status)</div>
  </div>
  <div class="validation-details">$($validation.Details)</div>
  <div class="validation-category">📁 $($validation.Category)</div>
</div>
"@
    $validationIndex++
  }
  
  $validationHtml += "</div></div>`n"
}

# Then: Individual DC sections
$dcGroups = $groupedValidations | Where-Object { $_.Name -ne "Domain-Wide" } | Sort-Object Name
foreach ($dcGroup in $dcGroups) {
  $dcName = $dcGroup.Name
  $validations = $dcGroup.Group
  
  $validationHtml += @"
<div class="dc-section-card">
  <div class="dc-section-header">
    <h3 class="dc-section-title">🖥 $dcName</h3>
  </div>
  <div class="validation-grid">
"@
  
  foreach ($validation in $validations) {
    $statusClass = $validation.Status.ToLower()
    $validationHtml += @"
<div class="validation-item $statusClass" data-status="$statusClass" data-index="$validationIndex" onclick="showTestDetails($validationIndex)">
  <div class="validation-header">
    <div class="validation-name">$($validation.CheckName)</div>
    <div class="validation-status $statusClass">$($validation.Status)</div>
  </div>
  <div class="validation-details">$($validation.Details)</div>
  <div class="validation-category">📁 $($validation.Category)</div>
</div>
"@
    $validationIndex++
  }
  
  $validationHtml += "</div></div>`n"
}

# Build Full HTML
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD Health Check - $($domain.DNSRoot)</title>
$css
</head>
<body>
<div class="container">
  
  <!-- Executive Summary -->
  <div class="exec-summary">
    <h1 style="text-align:center; color:#f1f5f9; margin-bottom:10px;">Active Directory Health Check</h1>
    <p style="text-align:center; color:#94a3b8; margin-bottom:30px;">$($domain.DNSRoot) | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>
    
    <div class="health-score">
      <div class="score-circle">
        <div class="score-value">$healthScore</div>
      </div>
      <div class="score-label">Overall Health Score</div>
      <div style="margin-top:15px;"><span class="status-badge">$($severityInfo.Icon) $($severityInfo.Level)</span></div>
    </div>
    
    <div class="metrics-grid">
      <div class="metric-card metric-critical" onclick="scrollToElement('topissues')">
        <div class="metric-value">$criticalCount</div>
        <div class="metric-label">Critical Issues</div>
      </div>
      <div class="metric-card metric-warning" onclick="scrollToElement('allissues')">
        <div class="metric-value">$warningCount</div>
        <div class="metric-label">Warnings</div>
      </div>
      <div class="metric-card" onclick="scrollToElement('dcsummary')">
        <div class="metric-value">$($allDCs.Count)</div>
        <div class="metric-label">Domain Controllers</div>
      </div>
      <div class="metric-card">
        <div class="metric-value">$($adStats.Users)</div>
        <div class="metric-label">User Accounts</div>
      </div>
      <div class="metric-card">
        <div class="metric-value">$($adStats.Computers)</div>
        <div class="metric-label">Computer Accounts</div>
      </div>
        $(if ($ridPoolAvailable) {
          $ridFormatted = Format-LargeNumber -Number $ridPoolAvailable
          "<div class='metric-card'><div class='metric-value'>$ridFormatted</div><div class='metric-label'>RID Pool Available</div></div>"
        })
    </div>
  </div>
  
  <!-- DC Summary -->
  <div class="section" id="dcsummary">
    <div class="expandable-header" onclick="toggleSection('dcsummary')">
      <h2 class="section-title" style="margin:0; padding:0; border:none;">📊 Domain Controllers Summary</h2>
      <span class="expandable-icon open" id="dcsummary-icon">▶</span>
    </div>
    <div class="expandable-content open" id="dcsummary-content">
      <table>
        <thead>
          <tr>
            <th>Domain Controller</th>
            <th>Services</th>
            <th>Replication</th>
            <th>Critical Events (24h)</th>
            <th>Certificates</th>
          </tr>
        </thead>
        <tbody>
          $dcTableRows
        </tbody>
      </table>
    </div>
  </div>
  
  <!-- Top Issues -->
  $(if ($topIssues.Count -gt 0) {
    @"
  <div class="section" id="topissues">
    <div class="expandable-header" onclick="toggleSection('topissues')">
      <h2 class="section-title" style="margin:0; padding:0; border:none;">🚨 Top Priority Issues</h2>
      <span class="expandable-icon open" id="topissues-icon">▶</span>
    </div>
    <div class="expandable-content open" id="topissues-content">
      <div style="margin-top:20px;">
        $topIssuesHtml
      </div>
    </div>
  </div>
"@
  })
  
  <!-- All Issues (Collapsible) -->
  $allIssuesSection
  
  <!-- FSMO Roles -->
  <div class="section" id="fsmo">
    <div class="expandable-header" onclick="toggleSection('fsmo')">
      <h2 class="section-title" style="margin:0; padding:0; border:none;">🎯 FSMO Role Holders</h2>
      <span class="expandable-icon" id="fsmo-icon">▶</span>
    </div>
    <div class="expandable-content" id="fsmo-content">
      <table>
        <thead>
          <tr>
            <th>Role</th>
            <th>Holder</th>
          </tr>
        </thead>
        <tbody>
          $fsmoTableRows
        </tbody>
      </table>
    </div>
  </div>
  
  <!-- Validation Results (Collapsible with Filters and Sections) -->
  <div class="section">
    <div class="expandable-header" onclick="toggleSection('validation')">
      <h2 class="section-title" style="margin:0; padding:0; border:none;">🔍 Evaluated Items ($($script:validationResults.Count) checks)</h2>
      <span class="expandable-icon" id="validation-icon">▶</span>
    </div>
    <div class="expandable-content" id="validation-content">
      
      <!-- Filter Buttons -->
      <div class="filter-container">
        <span class="filter-label">Filter by Status:</span>
        <button class="filter-btn all active" onclick="filterValidations('all')">All ($($script:validationResults.Count))</button>
        <button class="filter-btn ok" onclick="filterValidations('ok')">OK ($okCount)</button>
        <button class="filter-btn warning" onclick="filterValidations('warning')">Warning ($warningCount)</button>
        <button class="filter-btn critical" onclick="filterValidations('critical')">Critical ($criticalCount)</button>
        <button class="filter-btn unknown" onclick="filterValidations('unknown')">Unknown ($unknownCount)</button>
      </div>
      
      <!-- Validation Sections -->
      $validationHtml
      
      <!-- Test Details Panel -->
      <div class="test-details-panel" id="testDetailsPanel">
        <div class="test-details-header">
          <div class="test-details-title" id="testDetailsTitle">Test Details</div>
          <button class="test-details-close" onclick="hideTestDetails()">Close</button>
        </div>
        <div class="test-details-section">
          <div class="test-details-label">Test Information</div>
          <div class="test-details-content" id="testDetailsInfo"></div>
        </div>
        <div class="test-details-section">
          <div class="test-details-label">Command Executed</div>
          <div class="test-details-content" id="testDetailsCommand"></div>
        </div>
        <div class="test-details-section">
          <div class="test-details-label">Test Output</div>
          <div class="test-details-content" id="testDetailsOutput"></div>
        </div>
      </div>
      
    </div>
  </div>
  
  <div class="footer">
    AD Health Check Report v$SCRIPT_VERSION | Powered by PowerShell | LA
  </div>
  
</div>

<script>
let currentFilter = 'all';
const validationData = $validationDataJson;

function scrollToElement(elementId) {
  const element = document.getElementById(elementId);
  if (element) {
    element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    const content = document.getElementById(elementId + '-content');
    const icon = document.getElementById(elementId + '-icon');
    if (content && !content.classList.contains('open')) {
      content.classList.add('open');
      icon.classList.add('open');
    }
  }
}

function toggleSection(sectionId) {
  const content = document.getElementById(sectionId + '-content');
  const icon = document.getElementById(sectionId + '-icon');
  
  if (content.classList.contains('open')) {
    content.classList.remove('open');
    icon.classList.remove('open');
  } else {
    content.classList.add('open');
    icon.classList.add('open');
  }
}

function filterValidations(status) {
  currentFilter = status;
  
  const buttons = document.querySelectorAll('.filter-btn');
  buttons.forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');
  
  const items = document.querySelectorAll('.validation-item');
  items.forEach(item => {
    if (status === 'all') {
      item.classList.remove('hidden');
    } else {
      if (item.dataset.status === status) {
        item.classList.remove('hidden');
      } else {
        item.classList.add('hidden');
      }
    }
  });
  
  const sections = document.querySelectorAll('.dc-section-card');
  sections.forEach(section => {
    const visibleItems = section.querySelectorAll('.validation-item:not(.hidden)');
    if (visibleItems.length === 0 && status !== 'all') {
      section.style.display = 'none';
    } else {
      section.style.display = 'block';
    }
  });
}

function showTestDetails(index) {
  const validation = validationData[index];
  if (!validation) return;
  
  document.getElementById('testDetailsTitle').textContent = validation.CheckName + ' - ' + validation.DC;
  
  const infoText = 'DC: ' + validation.DC + '\\nCategory: ' + validation.Category + '\\nStatus: ' + validation.Status + '\\nDetails: ' + validation.Details + '\\nTimestamp: ' + validation.Timestamp;
  document.getElementById('testDetailsInfo').textContent = infoText;
  
  document.getElementById('testDetailsCommand').textContent = validation.TestCommand || 'No command information available';
  document.getElementById('testDetailsOutput').textContent = validation.TestOutput || 'No output information available';
  
  document.getElementById('testDetailsPanel').classList.add('show');
  document.getElementById('testDetailsPanel').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function hideTestDetails() {
  document.getElementById('testDetailsPanel').classList.remove('show');
}
</script>

</body>
</html>
"@

# ===================== SAVE & SEND =====================

$fullPath = (New-Item -Path $OutputPath -ItemType File -Force).FullName
[System.IO.File]::WriteAllText($fullPath, $html, [System.Text.UTF8Encoding]::new($false))

Write-Host "`n✓ Report saved: $fullPath" -ForegroundColor Green
Write-Host "  Health Score: $healthScore/100 ($($severityInfo.Level))" -ForegroundColor $(
  switch ($severityInfo.Level) {
    'HEALTHY' { 'Green' }
    'WARNING' { 'Yellow' }
    default { 'Red' }
  }
)
Write-Host "  Validation Counts - OK: $okCount, Warning: $warningCount, Critical: $criticalCount, Unknown: $unknownCount" -ForegroundColor Cyan
Write-Host "  Total Issues: $($allIssues.Count)" -ForegroundColor Gray

# Email Logic
$shouldSend = $true
if ($EmailOnErrorOnly -and $criticalCount -eq 0) {
  $shouldSend = $false
  Write-Host "`n⚠ Email suppressed (no critical issues + EmailOnErrorOnly flag)" -ForegroundColor Yellow
}

if ($shouldSend -and $To -and $To.Count -gt 0) {
  $emailSubject = "[$($severityInfo.Level)] AD Health: $($domain.DNSRoot) - Score: $healthScore/100"
  
  try {
    if ($UseGraph) {
      if (-not (Get-Module -ListAvailable Microsoft.Graph)) {
        throw "Microsoft.Graph module not installed"
      }
      Import-Module Microsoft.Graph -ErrorAction Stop
      if (-not (Get-MgContext)) {
        Connect-MgGraph -Scopes "Mail.Send" | Out-Null
      }
      
      $bytes = [System.IO.File]::ReadAllBytes($fullPath)
      $b64 = [Convert]::ToBase64String($bytes)
      
      $message = @{
        message = @{
          subject = $emailSubject
          body = @{ contentType = "HTML"; content = $html }
          toRecipients = @($To | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
          attachments = @(@{
            "@odata.type" = "#microsoft.graph.fileAttachment"
            name = [IO.Path]::GetFileName($fullPath)
            contentBytes = $b64
            contentType = "text/html"
          })
        }
        saveToSentItems = $true
      }
      
      Send-MgUserMail -UserId $GraphSenderUpn -BodyParameter $message
      Write-Host "✓ Email sent via Microsoft Graph" -ForegroundColor Green
      
    } elseif ($SmtpServer) {
      $mailParams = @{
        SmtpServer = $SmtpServer
        Port = $SmtpPort
        UseSsl = $SmtpUseSsl
        From = $From
        To = $To
        Subject = $emailSubject
        Body = $html
        BodyAsHtml = $true
        Attachments = $fullPath
      }
      
      if ($Credential) {
        $mailParams.Credential = $Credential
      }
      
      Send-MailMessage @mailParams -ErrorAction Stop
      Write-Host "✓ Email sent via SMTP" -ForegroundColor Green
    }
  } catch {
    Write-Warning "Failed to send email: $_"
  }
}

# CSV Export
if ($Csv) {
  $csvPath = [IO.Path]::ChangeExtension($fullPath, '.csv')
  $allCsvIssues = @($script:issues.Critical) + @($script:issues.Warning) + @($script:issues.Info)
  if ($allCsvIssues.Count -gt 0) {
    $allCsvIssues | 
      Select-Object Severity, Category, DC, Title, Description, Recommendation |
      Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "✓ Issues exported to CSV: $csvPath" -ForegroundColor Green
  }
}

Write-Host "`n✓ AD Health Check completed successfully`n" -ForegroundColor Green
