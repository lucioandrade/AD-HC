<#
.SYNOPSIS
  Active Directory Health Check com relatório HTML bonito e envio por e-mail.

.DESCRIPTION
  Converte e moderniza a ideia do script VBS "vbs-ad-health-report" para PowerShell.
  Coleta saúde dos Domain Controllers (DCDiag/RepAdmin), serviços, ping e (opcional) hardware,
  gera HTML com visual aprimorado e envia por e-mail (SMTP ou Microsoft Graph).

.NOTES
  Requisitos: PowerShell 5.1+ (ou 7+), RSAT ActiveDirectory, dcdiag.exe, repadmin.exe.
  Permissões: privilégios para consultar DCs e executar dcdiag/repadmin remotamente.

.PARAMETER UsingOU
  Se verdadeiro, descobre DCs consultando a OU de Controladores de Domínio.

.PARAMETER OrganizationUnitDN
  DN da OU com os DCs (padrão: "OU=Domain Controllers,<DN do domínio atual>").

.PARAMETER DomainControllers
  Lista explícita de DCs (FQDN/hostnames). Ignorado se UsingOU for verdadeiro.

.PARAMETER IncludeHardware
  Coleta disco do SO (C:) e memória livre via CIM/WMI.

.PARAMETER OutputPath
  Caminho do HTML final (padrão: .\ADHealthReport.html). CSV opcional no mesmo diretório.

.PARAMETER Csv
  Exporta também um CSV com o resumo.

.PARAMETER EmailOnErrorOnly
  Envia e-mail somente quando houver falhas/alertas.

# SMTP
.PARAMETER SmtpServer
  Servidor SMTP (ex.: smtp.office365.com).

.PARAMETER SmtpPort
  Porta SMTP (padrão 587).

.PARAMETER SmtpUseSsl
  Usa TLS/SSL no SMTP.

.PARAMETER From
  Remetente do e-mail.

.PARAMETER To
  Destinatários (string[]).

.PARAMETER Subject
  Assunto do e-mail.

.PARAMETER Credential
  Credenciais para SMTP (Get-Credential). Evite senhas em texto claro.

# Microsoft Graph
.PARAMETER UseGraph
  Se especificado, envia e-mail via Microsoft Graph (delegado).

.PARAMETER GraphSenderUpn
  UPN do remetente para Send-MgUserMail (ex.: relatorios@seudominio.com).

.EXAMPLE
  .\Invoke-ADHealthReport.ps1 -UsingOU -IncludeHardware -Csv `
    -SmtpServer smtp.office365.com -SmtpPort 587 -SmtpUseSsl `
    -From 'ad-health@contoso.com' -To 'infra@contoso.com' `
    -Subject 'AD Health - Diário' -Credential (Get-Credential)

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

# ======== Utilitários ========
function Test-Tool {
  param([string]$Name)
  return Get-Command $Name -ErrorAction SilentlyContinue
}

function Get-DomainDN {
  try { (Get-ADDomain).DistinguishedName } catch { throw "Não foi possível obter o DN do domínio. RSAT AD instalado?" }
}

function Get-DCList {
  param([switch]$UsingOU,[string]$OrganizationUnitDN,[string[]]$DomainControllers)
  if ($UsingOU) {
    if (-not $OrganizationUnitDN) { $OrganizationUnitDN = "OU=Domain Controllers,$(Get-DomainDN)" }
    # Busca computadores na OU informada
    $dcs = Get-ADComputer -SearchBase $OrganizationUnitDN -LDAPFilter '(objectClass=computer)' -Properties dnsHostName |
           Where-Object { $_.dnsHostName } | Select-Object -ExpandProperty dnsHostName
    if (-not $dcs) { throw "Nenhum DC encontrado na OU $OrganizationUnitDN" }
    return $dcs
  }
  if ($DomainControllers -and $DomainControllers.Count) { return $DomainControllers }
  # Padrão: todos os DCs do domínio
  (Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
}

function Invoke-DcDiag {
  param([string]$Server,[string[]]$ExtraArgs)
  $args = @('/s:{0}' -f $Server, '/c', '/v')
  if ($ExtraArgs) { $args += $ExtraArgs }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = 'dcdiag.exe'
  $psi.Arguments = ($args -join ' ')
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()
  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  [pscustomobject]@{
    Output = $stdout
    Error  = $stderr
    ExitCode = $p.ExitCode
  }
}

function Invoke-RepAdmin {
  param([string]$Server,[string[]]$Args)
  $args = if ($Args) { $Args } else { @('/showrepl', $Server, '/verbose', '/all', '/intersite') }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = 'repadmin.exe'
  $psi.Arguments = ($args -join ' ')
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()
  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  [pscustomobject]@{
    Output = $stdout
    Error  = $stderr
    ExitCode = $p.ExitCode
  }
}

function Get-HardwareInfo {
  param([string]$Server)
  $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Server -ErrorAction SilentlyContinue
  $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ComputerName $Server -ErrorAction SilentlyContinue
  if ($os) {
    $memTotalGB = [Math]::Round($os.TotalVisibleMemorySize/1MB,1)
    $memFreeGB  = [Math]::Round($os.FreePhysicalMemory/1MB,1)
  }
  if ($disk) {
    $freeGB = [Math]::Round($disk.FreeSpace/1GB,1)
    $sizeGB = [Math]::Round($disk.Size/1GB,1)
    $freePct = if ($sizeGB -gt 0) { [Math]::Round(($freeGB/$sizeGB)*100,1) } else { $null }
  }
  [pscustomobject]@{
    UptimeHours = if ($os) { [Math]::Round((New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)).TotalHours,1) }
    MemFreeGB   = $memFreeGB
    MemTotalGB  = $memTotalGB
    DiskC_FreeGB= $freeGB
    DiskC_SizeGB= $sizeGB
    DiskC_FreePct=$freePct
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

function New-Status {
  param([bool]$Ok)
  if ($Ok) { 'OK' } else { 'FAIL' }
}

# ======== Valida ferramentas ========
if (-not (Get-Module -ListAvailable ActiveDirectory)) { throw "Módulo ActiveDirectory não encontrado. Instale RSAT." }
if (-not (Test-Tool 'dcdiag.exe')) { throw "dcdiag.exe não encontrado. Instale RSAT/DC tools." }
if (-not (Test-Tool 'repadmin.exe')) { throw "repadmin.exe não encontrado. Instale RSAT/DC tools." }

Import-Module ActiveDirectory -ErrorAction Stop

# ======== Descobre DCs ========
$allDCs = Get-DCList -UsingOU:$UsingOU -OrganizationUnitDN $OrganizationUnitDN -DomainControllers $DomainControllers

# ======== Coleta por DC ========
$results = @()
$detailBlobs = @()

foreach ($dc in $allDCs) {
  Write-Verbose "Coletando $dc ..."
  $pingOk = Test-Connection -ComputerName $dc -Count 1 -Quiet -ErrorAction SilentlyContinue
  $svc = Test-Services -Server $dc

  $diag = Invoke-DcDiag -Server $dc
  $rep  = Invoke-RepAdmin -Server $dc

  # Heurística simples para falhas (dcdiag varia por idioma; procuramos "fail" e "error")
  $dcdiagFail = ($diag.Output -match '(fail|erro|error)' -and $diag.Output -notmatch '0 failed')
  $repFail    = ($rep.Output -match '(fail|erro|error)')

  $hw = $null
  if ($IncludeHardware) {
    $hw = Get-HardwareInfo -Server $dc
  }

  $obj = [pscustomobject]@{
    DC              = $dc
    Ping            = New-Status $pingOk
    DNS_Service     = New-Status $svc.DNS
    NTDS_Service    = New-Status $svc.NTDS
    NetLogon_Service= New-Status $svc.Netlogon
    DcDiag          = if ($dcdiagFail) { 'FAIL' } else { 'OK' }
    Replication     = if ($repFail) { 'FAIL' } else { 'OK' }
    UptimeHours     = $hw.UptimeHours
    DiskC_FreePct   = $hw.DiskC_FreePct
    MemFreeGB       = $hw.MemFreeGB
  }
  $results += $obj

  $detailBlobs += [pscustomobject]@{
    DC = $dc
    DcDiagText = $diag.Output
    RepAdminText = $rep.Output
  }
}

# ======== FSMO / Info de Floresta & Domínio ========
$forest = Get-ADForest
$domain = Get-ADDomain
$fsmo = [pscustomobject]@{
  SchemaMaster       = $forest.SchemaMaster
  DomainNamingMaster = $forest.DomainNamingMaster
  PDCEmulator        = $domain.PDCEmulator
  RIDMaster          = $domain.RIDMaster
  InfrastructureMaster = $domain.InfrastructureMaster
}

# ======== Métricas/Sumário ========
$total = $results.Count
$failCount = ($results | Where-Object { $_.Ping -eq 'FAIL' -or $_.DNS_Service -eq 'FAIL' -or $_.NTDS_Service -eq 'FAIL' -or $_.NetLogon_Service -eq 'FAIL' -or $_.DcDiag -eq 'FAIL' -or $_.Replication -eq 'FAIL' }).Count

if ($Csv) {
  $csvPath = [IO.Path]::ChangeExtension((Resolve-Path $OutputPath),'.csv')
  $results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath
}

# ======== HTML ========
$css = @"
<style>
  body { font-family: Segoe UI, Roboto, Arial, sans-serif; margin: 0; background:#0f172a; color:#e2e8f0;}
  .container { max-width:1200px; margin:40px auto; padding:0 16px;}
  .card { background:#111827; border:1px solid #1f2937; border-radius:10px; padding:20px; margin-bottom:20px; box-shadow:0 10px 30px rgba(0,0,0,.35);}
  h1,h2,h3 { color:#e5e7eb; margin-top:0 }
  .muted { color:#94a3b8; }
  .grid { display:grid; grid-template-columns: repeat(12, 1fr); gap:16px;}
  .col-3 { grid-column: span 3; } .col-12 { grid-column: span 12; }
  .tile { background:#0b1220; border:1px solid #1f2937; border-radius:10px; padding:16px; text-align:center;}
  .tile .k { font-size:12px; color:#9ca3af; } .tile .v { font-size:28px; font-weight:700; color:#fff; }
  table { width:100%; border-collapse: collapse; }
  th,td { padding:10px 12px; border-bottom:1px solid #1f2937;}
  th { text-align:left; background:#0b1220; color:#cbd5e1; position:sticky; top:0;}
  .badge { display:inline-block; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:700; }
  .ok { background:#064e3b; color:#a7f3d0; border:1px solid #10b981; }
  .fail { background:#7f1d1d; color:#fecaca; border:1px solid #ef4444; }
  details { background:#0b1220; border:1px solid #1f2937; border-radius:8px; padding:12px; margin-bottom:10px; }
  summary { cursor:pointer; font-weight:600; color:#e5e7eb; }
  .footer { font-size:12px; color:#94a3b8; margin-top:24px; }
  a { color:#93c5fd; }
</style>
"@

function Badge($val){
  if ($val -eq 'OK') { '<span class="badge ok">OK</span>' } else { '<span class="badge fail">FAIL</span>' }
}

$rows = $results | ForEach-Object {
  @"
<tr>
  <td>$($_.DC)</td>
  <td>$(Badge $_.Ping)</td>
  <td>$(Badge $_.DNS_Service)</td>
  <td>$(Badge $_.NTDS_Service)</td>
  <td>$(Badge $_.NetLogon_Service)</td>
  <td>$(Badge $_.DcDiag)</td>
  <td>$(Badge $_.Replication)</td>
  <td>$($_.UptimeHours)</td>
  <td>$($_.DiskC_FreePct)%</td>
  <td>$($_.MemFreeGB) GB</td>
</tr>
"@
} | Out-String

$detailsHtml = $detailBlobs | ForEach-Object {
  @"
<details>
  <summary>Detalhes de Diagnóstico — <strong>$($_.DC)</strong></summary>
  <h4>DCDIAG</h4>
  <pre style="white-space: pre-wrap; color:#e2e8f0;">$([System.Web.HttpUtility]::HtmlEncode($_.DcDiagText))</pre>
  <h4>REPADMIN</h4>
  <pre style="white-space: pre-wrap; color:#e2e8f0;">$([System.Web.HttpUtility]::HtmlEncode($_.RepAdminText))</pre>
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
<html lang="pt-BR">
<head>
<meta charset="utf-8" />
<title>Active Directory Health Report</title>
$css
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>Active Directory — Health Report</h1>
      <div class="muted">Geração: $(Get-Date) — Domínio: $($domain.DNSRoot)</div>
      <div class="grid" style="margin-top:16px;">
        <div class="col-3"><div class="tile"><div class="k">Domain Controllers</div><div class="v">$total</div></div></div>
        <div class="col-3"><div class="tile"><div class="k">Falhas Totais</div><div class="v">$failCount</div></div></div>
        <div class="col-3"><div class="tile"><div class="k">Floresta</div><div class="v">$($forest.Name)</div></div></div>
        <div class="col-3"><div class="tile"><div class="k">Domínio</div><div class="v">$($domain.DNSRoot)</div></div></div>
      </div>
    </div>

    <div class="card">
      <h2>Resumo por DC</h2>
      <div style="overflow:auto; max-height:520px;">
      <table>
        <thead>
          <tr>
            <th>DC</th><th>Ping</th><th>DNS</th><th>NTDS</th><th>NetLogon</th><th>DCDiag</th><th>Replicação</th><th>Uptime(h)</th><th>C: Livre(%)</th><th>Mem Livre</th>
          </tr>
        </thead>
        <tbody>
        $rows
        </tbody>
      </table>
      </div>
    </div>

    <div class="card">
      <h2>Funções FSMO</h2>
      $fsmoHtml
    </div>

    <div class="card">
      <h2>Detalhes</h2>
      $detailsHtml
    </div>

    <div class="footer">
      Relatório gerado por Invoke-ADHealthReport.ps1 — baseado no conceito do vbs-ad-health-report (VBS).
    </div>
  </div>
</body>
</html>
"@

# Grava HTML
$fullPath = (Resolve-Path (New-Item -Path $OutputPath -ItemType File -Force)).Path
[IO.File]::WriteAllText($fullPath, $html, [Text.UTF8Encoding]::new($false))

# ======== Envio por e-mail ========
function Send-ReportViaSmtp {
  param([string]$Server,[int]$Port,[switch]$UseSsl,[string]$From,[string[]]$To,[string]$Subject,[pscredential]$Cred,[string]$BodyHtml,[string]$Attachment)
  if (-not $Server) { throw "SmtpServer não informado." }
  if (-not $From -or -not $To) { throw "From/To não informados." }
  Send-MailMessage -SmtpServer $Server -Port $Port -UseSsl:$UseSsl `
    -From $From -To $To -Subject $Subject -Body $BodyHtml -BodyAsHtml `
    -Credential $Cred -Attachments $Attachment -ErrorAction Stop
}

function Send-ReportViaGraph {
  param([string]$SenderUpn,[string[]]$To,[string]$Subject,[string]$BodyHtml,[string]$Attachment)
  if (-not (Get-Module -ListAvailable Microsoft.Graph)) { throw "Módulo Microsoft.Graph não encontrado. Instale com: Install-Module Microsoft.Graph" }
  if (-not $SenderUpn) { throw "GraphSenderUpn não informado." }
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

# Saída final
Write-Host "Relatório salvo em: $fullPath"
if ($Csv -and (Test-Path $csvPath)) { Write-Host "CSV salvo em: $csvPath" }
if ($shouldSend -and ($To -and $To.Count -gt 0)) {
  Write-Host "E-mail enviado." 
} elseif (-not $shouldSend -and $EmailOnErrorOnly) {
  Write-Host "Sem falhas — envio por e-mail suprimido (EmailOnErrorOnly)."
}
