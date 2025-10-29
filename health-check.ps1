<#
.SYNOPSIS
  Active Directory Health Check with modern HTML report and email delivery (SMTP or Microsoft Graph).

.DESCRIPTION
  Collects health from Domain Controllers (Ping, Services, DCDiag targeted tests, Repadmin),
  optionally collects basic hardware stats (uptime, C: free, memory),
  renders a clean HTML report (dark theme) and sends it by email if configured.

.NOTES
  Requirements: PowerShell 5.1+ (or 7+), RSAT ActiveDirectory, dcdiag.exe, repadmin.exe.
  Permissions: rights to query DCs and run dcdiag/repadmin remotely.

.PARAMETER UsingOU
  If set, discover DCs by querying the Domain Controllers OU.

.PARAMETER OrganizationUnitDN
  DN of the OU containing the DCs (default: "OU=Domain Controllers,<current domain DN>").

.PARAMETER DomainControllers
  Explicit list of DCs (FQDN/hostnames). Ignored if UsingOU is true.

.PARAMETER IncludeHardware
  Collect OS disk (C:) and free memory via CIM/WMI.

.PARAMETER OutputPath
  Final HTML path (default: .\ADHealthReport.html). CSV optional in the same directory.

.PARAMETER Csv
  Also export a CSV summary.

.PARAMETER EmailOnErrorOnly
  Only send email when there are failures/warnings.

# SMTP
.PARAMETER SmtpServer
  SMTP server (e.g., smtp.office365.com).

.PARAMETER SmtpPort
  SMTP port (default 587).

.PARAMETER SmtpUseSsl
  Use TLS/SSL on SMTP.

.PARAMETER From
  Email sender.

.PARAMETER To
  Email recipients (string[]).

.PARAMETER Subject
  Email subject.

.PARAMETER Credential
  SMTP credentials (Get-Credential). Avoid clear-text passwords.

# Microsoft Graph
.PARAMETER UseGraph
  If specified, sends email via Microsoft Graph (delegated).

.PARAMETER GraphSenderUpn
  Sender UPN for Send-MgUserMail (e.g., reports@yourdomain.com).

.EXAMPLE
  .\Invoke-ADHealthReport.ps1 -UsingOU -IncludeHardware -Csv `
    -SmtpServer smtp.office365.com -SmtpPort 587 -SmtpUseSsl `
    -From 'ad-health@contoso.com' -To 'infra@contoso.com' `
    -Subject 'AD Health - Daily' -Credential (Get-Credential)

.EXAMPLE
  .\Invoke-ADHealthReport.ps1 -DomainControllers dc1.contoso.com,dc2.contoso.com `
    -UseGraph -GraphSenderUpn 'ad-health@contoso.com' -To 'secops@contoso.com' -IncludeHardware
#>

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
  <#
    Runs a single targeted DCDiag test.
    Returns PSCustomObject: @{ Test='Advertising'; Status='OK'|'FAIL'; Output='<raw text>' }
  #>
  param(
    [string]$Server,
    [string]$TestName
  )
  $res = Invoke-External -FileName 'dcdiag.exe' -Arguments @("/s:$Server", "/test:$TestName", "/v")
  $text = $res.Output + "`n" + $res.Error
  $isFail = $false

  # Robust fail heuristics: exit code non-zero OR typical fail/error tokens, ignoring false positives like "0 failed".
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
  <#
    Returns PSCustomObject with values or $null when unknown.
    Uses CIM, falls back to legacy WMI.
  #>
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

# DCDiag tests to run and show as columns (matches screenshot semantics)
$dcdiagTests = @(
  'Connectivity',
  'Advertising',
  'NetLogons',
  'Services',
  'Replications',
  'Topology',
  'SysVolCheck',
  # FSMO will be a composite of the 2 below; still collect for details
  'KnowsOfRoleHolders',
  'RidManager'
)

foreach ($dc in $allDCs) {
  Write-Verbose "Collecting $dc ..."

  # Basic checks
  $pingOk = Test-Connection -ComputerName $dc -Count 1 -Quiet -ErrorAction SilentlyContinue
  $svc    = Test-Services -Server $dc

  # DCDiag summary (kept for details)
  $diag = Invoke-DcDiag -Server $dc

  # Run targeted DCDiag tests
  $testResults = @{}
  $testOutputs = @{}
  foreach ($t in $dcdiagTests) {
    $tres = Invoke-DcDiagTest -Server $dc -TestName $t
    $testResults[$t] = $tres.Status
    $testOutputs[$t] = $tres.Output
  }

  # Composite FSMO: FAIL if any of the two fails
  $fsmStatus = if ($testResults['KnowsOfRoleHolders'] -eq 'FAIL' -or $testResults['RidManager'] -eq 'FAIL') { 'FAIL' } else { 'OK' }

  # Repadmin check (independent perspective)
  $rep  = Invoke-RepAdmin -Server $dc
  $repFail = ($rep.Output -match '(?i)\b(fail|failed|error|erro)\b')
  $repStatus = if ($repFail) { 'FAIL' } else { 'OK' }

  # Hardware (optional)
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

# Count fails across key health columns (do not include hardware)
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
  body { font-family: Segoe UI, Roboto, Arial, sans-serif; margin: 0; background:#0f172a; color:#e2e8f0;}
  .container { max-width:1200px; margin:40px auto; padding:0 16px;}
  .card { background:#111827; border:1px solid #1f2937; border-radius:10px; padding:20px; margin-bottom:20px; box-shadow:0 10px 30px rgba(0,0,0,.35); }
  h1,h2,h3 { color:#e5e7eb; margin-top:0 }
  .muted { color:#94a3b8; }
  .grid { display:grid; grid-template-columns: repeat(12, 1fr); gap:16px;}
  .col-3 { grid-column: span 3; } .col-12 { grid-column: span 12; }
  .tile { background:#0b1220; border:1px solid #1f2937; border-radius:10px; padding:16px; text-align:center;}
  .tile .k { font-size:12px; color:#9ca3af; } .tile .v { font-size:28px; font-weight:700; color:#fff; }
  table { width:100%; border-collapse: collapse; }
  th,td { padding:10px 12px; border-bottom:1px solid #1f2937; vertical-align:top}
  th { text-align:left; background:#0b1220; color:#cbd5e1; position:sticky; top:0; }
  .badge { display:inline-block; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:700; }
  .ok { background:#064e3b; color:#a7f3d0; border:1px solid #10b981; }
  .fail { background:#7f1d1d; color:#fecaca; border:1px solid #ef4444; }
  .na { background:#374151; color:#e5e7eb; border:1px solid #6b7280; }
  details { background:#0b1220; border:1px solid #1f2937; border-radius:8px; padding:12px; margin-bottom:10px; }
  summary { cursor:pointer; font-weight:600; color:#e5e7eb; }
  pre { white-space: pre-wrap; color:#e2e8f0; }
  .footer { font-size:12px; color:#94a3b8; margin-top:24px; }
  a { color:#93c5fd; }
  .nowrap { white-space:nowrap; }
  .scroll-x { overflow:auto; }
</style>
"@

function Badge($val){
  if ($val -eq 'OK') { '<span class="badge ok">OK</span>' }
  elseif ($val -eq 'FAIL') { '<span class="badge fail">FAIL</span>' }
  else { '<span class="badge na">N/A</span>' }
}

$rows = $results | ForEach-Object {
  @"
<tr>
  <td>$($_.DC)</td>
  <td>$(Badge $_.Ping)</td>
  <td>$(Badge $_.DNS_Service)</td>
  <td>$(Badge $_.NTDS_Service)</td>
  <td>$(Badge $_.NetLogon_Service)</td>

  <td>$(Badge $_.Connectivity)</td>
  <td>$(Badge $_.Advertising)</td>
  <td>$(Badge $_.NetLogons)</td>
  <td>$(Badge $_.ServicesTest)</td>
  <td>$(Badge $_.ReplicationsTest)</td>
  <td>$(Badge $_.Replication_RepAdmin)</td>
  <td>$(Badge $_.FSMO)</td>
  <td>$(Badge $_.SysVol)</td>
  <td>$(Badge $_.Topology)</td>

  <td class="nowrap">$(Show-NA $_.UptimeHours)</td>
  <td class="nowrap">$(Show-NA $_.DiskC_FreePct '%')</td>
  <td class="nowrap">$(Show-NA $_.MemFreeGB ' GB')</td>
</tr>
"@
} | Out-String

$detailsHtml = $detailBlobs | ForEach-Object {
  # Render per-test collapsible blocks
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
  <h4>Overall DCDIAG (/c /v)</h4>
  <pre>$([System.Web.HttpUtility]::HtmlEncode($_.DcDiagText))</pre>
  <h4>REPADMIN</h4>
  <pre>$([System.Web.HttpUtility]::HtmlEncode($_.RepAdminText))</pre>
  <h4>Per-Test Outputs</h4>
  $perTests
</details>
"@
} | Out-String

$fsmoHtml = @"
<ul class="muted">
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
<title>Active Directory Health Report</title>
$css
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>Active Directory — Health Report</h1>
      <div class="muted">Generated: $(Get-Date) — Domain: $($domain.DNSRoot)</div>
      <div class="grid" style="margin-top:16px;">
        <div class="col-3"><div class="tile"><div class="k">Domain Controllers</div><div class="v">$total</div></div></div>
        <div class="col-3"><div class="tile"><div class="k">Total Failures</div><div class="v">$failCount</div></div></div>
        <div class="col-3"><div class="tile"><div class="k">Forest</div><div class="v">$($forest.Name)</div></div></div>
        <div class="col-3"><div class="tile"><div class="k">Domain</div><div class="v">$($domain.DNSRoot)</div></div></div>
      </div>
    </div>

    <div class="card">
      <h2>Per-DC Summary</h2>
      <div class="scroll-x" style="max-height:560px;">
      <table>
        <thead>
          <tr>
            <th>DC</th>
            <th>Ping</th>
            <th>Service DNS</th>
            <th>Service NTDS</th>
            <th>Service NetLogon</th>

            <th>Connectivity</th>
            <th>Advertising</th>
            <th>NetLogons</th>
            <th>Services (DCDiag)</th>
            <th>Replications (DCDiag)</th>
            <th>Replication (RepAdmin)</th>
            <th>FSMO</th>
            <th>SysVol</th>
            <th>Topology</th>

            <th>Uptime (h)</th>
            <th>C: Free (%)</th>
            <th>Mem Free</th>
          </tr>
        </thead>
        <tbody>
        $rows
        </tbody>
      </table>
      </div>
    </div>

    <div class="card">
      <h2>FSMO Role Holders</h2>
      $fsmoHtml
    </div>

    <div class="card">
      <h2>Details</h2>
      $detailsHtml
    </div>

    <div class="footer">
      Report generated by Invoke-ADHealthReport.ps1 — inspired by the legacy vbs-ad-health-report concept.
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
Write-Host "Report saved at: $fullPath"
if ($Csv -and (Test-Path $csvPath)) { Write-Host "CSV saved at: $csvPath" }
if ($shouldSend -and ($To -and $To.Count -gt 0)) {
  Write-Host "Email sent."
} elseif (-not $shouldSend -and $EmailOnErrorOnly) {
  Write-Host "No failures — email suppressed (EmailOnErrorOnly)."
}
