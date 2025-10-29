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
  $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ComputerName $Server -ErrorAction SilentlyContinue

  if (-not $os)   { $os   = Try-GetWmi -Class Win32_OperatingSystem -ComputerName $Server }
  if (-not $disk) { $disk = Try-GetWmi -Class Win32_LogicalDisk -ComputerName $Server -Filter "DeviceID='C:'" }

  $memTotalGB = if ($os) { [Math]::Round($os.TotalVisibleMemorySize/1MB,1) } else { $null }
  $memFreeGB  = if ($os) { [Math]::Round($os.FreePhysicalMemory/1MB,1) } else { $null }
  $uptime     = if ($os) { [Math]::Round((New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)).TotalHours,1) } else { $null }

  $freeGB = if ($disk) { [Math]::Round($disk.FreeSpace/1GB,1) } else { $null }
  $sizeGB = if ($disk) { [Math]::Round($disk.Size/1GB,1) } else { $null }
  $freePct = if ($sizeGB -gt 0) { [Math]::Round(($freeGB/$sizeGB)*100,1) } else { $null }

  [pscustomobject]@{
    UptimeHours   = $uptime
    MemFreeGB     = $memFreeGB
    MemTotalGB    = $memTotalGB
    DiskC_FreeGB  = $freeGB
    DiskC_SizeGB  = $sizeGB
    DiskC_FreePct = $freePct
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

  $diag = Invoke-DcDiag -Server $dc

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

  $hw = $null
  if ($IncludeHardware) { $hw = Get-HardwareInfo -Server $dc }

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

    UptimeHours          = if ($hw) { $hw.UptimeHours } else { $null }
    DiskC_FreePct        = if ($hw) { $hw.DiskC_FreePct } else { $null }
    MemFreeGB            = if ($hw) { $hw.MemFreeGB } else { $null }
  }
  $results += $obj

  $detailBlobs += [pscustomobject]@{
    DC = $dc
    DcDiagText    = $diag.Output
    RepAdminText  = $rep.Output
    PerTestOutput = $testOutputs
  }
}

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
  .dc-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
  .dc-item { background: #151f30; padding: 12px; border-radius: 6px; border-left: 3px solid #374151; }
  .dc-item-label { font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
  .dc-item-value { display: flex; align-items: center; gap: 8px; }
  
  .badge { display: inline-flex; align-items: center; padding: 4px 12px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .ok { background: rgba(6, 78, 59, 0.3); color: #6ee7b7; border: 1px solid #10b981; }
  .fail { background: rgba(127, 29, 29, 0.3); color: #fca5a5; border: 1px solid #ef4444; }
  .na { background: rgba(55, 65, 81, 0.3); color: #e5e7eb; border: 1px solid #6b7280; }
  
  .icon { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  .icon-ok { background: #10b981; box-shadow: 0 0 8px rgba(16, 185, 129, 0.5); }
  .icon-fail { background: #ef4444; box-shadow: 0 0 8px rgba(239, 68, 68, 0.5); }
  
  details { background: #0b1220; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; margin-bottom: 12px; transition: all 0.2s; }
  details:hover { border-color: #374151; }
  details[open] { background: #0d1829; }
  summary { cursor: pointer; font-weight: 600; color: #e5e7eb; user-select: none; padding: 4px 0; }
  summary:hover { color: #60a5fa; }
  pre { white-space: pre-wrap; color: #cbd5e1; background: #030712; padding: 16px; border-radius: 6px; font-size: 12px; line-height: 1.6; overflow-x: auto; border: 1px solid #1f2937; }
  
  ul { list-style: none; padding: 0; }
  ul li { padding: 8px 0; color: #cbd5e1; border-bottom: 1px solid #1f2937; }
  ul li:last-child { border-bottom: none; }
  ul li b { color: #e5e7eb; font-weight: 600; min-width: 180px; display: inline-block; }
  
  .footer { font-size: 12px; color: #64748b; margin-top: 32px; text-align: center; padding: 20px; border-top: 1px solid #1f2937; }
  a { color: #60a5fa; text-decoration: none; transition: color 0.2s; }
  a:hover { color: #93c5fd; }
  
  .status-summary { display: flex; gap: 8px; flex-wrap: wrap; }
  
  @media (max-width: 768px) {
    .dc-grid { grid-template-columns: 1fr; }
    .grid { grid-template-columns: 1fr; }
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
  $statusItems = @(
    @{Label='Ping'; Value=$_.Ping},
    @{Label='DNS Service'; Value=$_.DNS_Service},
    @{Label='NTDS Service'; Value=$_.NTDS_Service},
    @{Label='NetLogon'; Value=$_.NetLogon_Service},
    @{Label='Connectivity'; Value=$_.Connectivity},
    @{Label='Advertising'; Value=$_.Advertising},
    @{Label='NetLogons'; Value=$_.NetLogons},
    @{Label='Services'; Value=$_.ServicesTest},
    @{Label='Replications'; Value=$_.ReplicationsTest},
    @{Label='RepAdmin'; Value=$_.Replication_RepAdmin},
    @{Label='FSMO'; Value=$_.FSMO},
    @{Label='SysVol'; Value=$_.SysVol},
    @{Label='Topology'; Value=$_.Topology}
  )
  
  if ($IncludeHardware) {
    $statusItems += @(
      @{Label='Uptime (h)'; Value=$(Show-NA $_.UptimeHours)},
      @{Label='Disk C: Free'; Value=$(Show-NA $_.DiskC_FreePct '%')},
      @{Label='Mem Free'; Value=$(Show-NA $_.MemFreeGB ' GB')}
    )
  }
  
  $itemsHtml = $statusItems | ForEach-Object {
    $badgeHtml = if ($_.Value -match '^[0-9.]+' -or $_.Value -eq 'N/A') { $_.Value } else { Badge $_.Value }
    @"
    <div class="dc-item">
      <div class="dc-item-label">$($_.Label)</div>
      <div class="dc-item-value">$badgeHtml</div>
    </div>
"@
  } | Out-String

  @"
<div class="dc-card">
  <div class="dc-header">
    <div class="dc-name">$($_.DC)</div>
  </div>
  <div class="dc-grid">
    $itemsHtml
  </div>
</div>
"@
} | Out-String

$detailsHtml = $detailBlobs | ForEach-Object {
  $perTests = ($_.PerTestOutput).GetEnumerator() | ForEach-Object {
@"
  <details>
    <summary><strong>DCDIAG Test:</strong> $($_.Key)</summary>
    <pre>$([System.Web.HttpUtility]::HtmlEncode($_.Value))</pre>
  </details>
"@
} | Out-String

@"
<details>
  <summary>Diagnostics Details — <strong>$($_.DC)</strong></summary>
  <h3>Overall DCDIAG (/c /v)</h3>
  <pre>$([System.Web.HttpUtility]::HtmlEncode($_.DcDiagText))</pre>
  <h3>REPADMIN</h3>
  <pre>$([System.Web.HttpUtility]::HtmlEncode($_.RepAdminText))</pre>
  <h3>Per-Test Outputs</h3>
  $perTests
</details>
"@
} | Out-String

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
        <div class="tile">
          <div class="k">Total Failures</div>
          <div class="v" style="color: $(if($failCount -gt 0){'#ef4444'}else{'#10b981'})">$failCount</div>
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
      $dcCards
    </div>

    <div class="card">
      <h2>FSMO Role Holders</h2>
      $fsmoHtml
    </div>

    <div class="card">
      <h2>Detailed Diagnostics</h2>
      $detailsHtml
    </div>

    <div class="footer">
      Report generated by Invoke-ADHealthReport.ps1
    </div>
  </div>
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
  Write-Host "No failures detected — email
