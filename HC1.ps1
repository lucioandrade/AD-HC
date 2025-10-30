<#
.SYNOPSIS
  Health check de Domain Controllers com relatório HTML.

.PARAMETER OutputPath
  Caminho do arquivo HTML a ser gerado (padrão: C:\Temp\AD-DC-HealthReport.html)

.PARAMETER Hours
  Janela em horas para coletar eventos (padrão: 24)

.PARAMETER DCs
  Lista de DCs a inspecionar. Se omitido, lista todos via AD PowerShell.

.NOTES
  - Executar em um DC (elevado) ou em servidor com RSAT AD DS.
  - Gera sumário PASS/WARN/FAIL no topo.
#>

[CmdletBinding()]
param(
  [string]$OutputPath = "C:\Temp\AD-DC-HealthReport.html",
  [int]$Hours = 24,
  [string[]]$DCs
)

# --- Preparação ---
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Path (Split-Path $OutputPath) -Force | Out-Null
$since = (Get-Date).AddHours(-$Hours)
$report = [System.Collections.Generic.List[Object]]::new()
$sections = @()
$overallStatus = "PASS"

function Add-Section {
  param([string]$Title,[string]$Html,[string]$Status="PASS")
  $global:sections += @{
    Title=$Title; Html=$Html; Status=$Status
  }
  if($Status -eq "FAIL" -and $global:overallStatus -ne "FAIL"){ $global:overallStatus = "FAIL" }
  elseif($Status -eq "WARN" -and $global:overallStatus -eq "PASS"){ $global:overallStatus = "WARN" }
}

function Run-Cmd {
  param([string]$Cmd,[int]$TimeoutSec=180)
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "cmd.exe"
    $psi.Arguments = "/c $Cmd"
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    if(-not $p.WaitForExit($TimeoutSec*1000)){ $p.Kill(); throw "Timeout executando: $Cmd" }
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    return ($stdout + "`n" + $stderr)
  } catch {
    return "ERRO executando '$Cmd': $($_.Exception.Message)"
  }
}

# --- Descoberta de ambiente ---
try {
  if(-not $DCs){
    if(Get-Module -ListAvailable -Name ActiveDirectory){
      Import-Module ActiveDirectory -ErrorAction Stop
      $DCs = (Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
    } else {
      # fallback: usa nltest
      $DCs = (Run-Cmd "nltest /dclist:$( (Run-Cmd 'nltest /dsgetdc: .') -replace '.*Domain Name:\\s*','' -split '\\r?\\n' | Select-Object -First 1 )") `
             -split '\r?\n' | Where-Object {$_ -match '^\s*\\\\'} | ForEach-Object { $_.Trim().Trim('\') }
      if(-not $DCs -or $DCs.Count -eq 0){ throw "Não foi possível enumerar DCs automaticamente. Informe via -DCs." }
    }
  }
} catch {
  Add-Section -Title "Descoberta de DCs" -Html "<pre>$($_.Exception.Message)</pre>" -Status "FAIL"
}

# --- FSMO Roles ---
$fsmoOut = Run-Cmd "netdom query fsmo"
Add-Section -Title "FSMO Roles" -Html ("<pre>"+[System.Web.HttpUtility]::HtmlEncode($fsmoOut)+"</pre>")

# --- Resumo de Replicação ---
$replSummary = Run-Cmd "repadmin /replsummary"
$replStatus = if($replSummary -match 'fails:\s*[1-9]' -or $replSummary -match 'error'){"FAIL"} else {"PASS"}
Add-Section -Title "Replicação - repadmin /replsummary" -Html ("<pre>"+[System.Web.HttpUtility]::HtmlEncode($replSummary)+"</pre>") -Status $replStatus

# --- Fila de Replicação ---
$queue = Run-Cmd "repadmin /queue"
$queueStatus = if($queue -match 'entries:\s*[1-9]'){"WARN"} else {"PASS"}
Add-Section -Title "Fila de Replicação - repadmin /queue" -Html ("<pre>"+[System.Web.HttpUtility]::HtmlEncode($queue)+"</pre>") -Status $queueStatus

# --- Por DC ---
$dcRows = @()
foreach($dc in $DCs){
  $row = [ordered]@{
    DC = $dc
    DCDIAG = "OK"
    DNS = "OK"
    SYSVOL = "OK"
    Services = "OK"
    Time = "OK"
    Disk = "OK"
    Events = "OK"
  }

  # DCDIAG (geral)
  $dcdiag = Run-Cmd "dcdiag /v /c /s:$dc"
  if($dcdiag -match 'failed test' -or $dcdiag -match '\bERROR\b'){
    $row.DCDIAG = "FAIL"
  }

  # DNS
  $dnsdiag = Run-Cmd "dcdiag /test:dns /s:$dc /v"
  if($dnsdiag -match 'fail' -or $dnsdiag -match 'error'){
    $row.DNS = "FAIL"
  }

  # SYSVOL/NETLOGON share
  $shares = Run-Cmd "cmd /c \\$dc\admin$ & net view \\$dc"
  if($shares -notmatch 'SYSVOL' -or $shares -notmatch 'NETLOGON'){
    $row.SYSVOL = "FAIL"
  }

  # Serviços
  try{
    $svc = Get-Service -ComputerName $dc -Name NTDS,DFSR,DNS,Netlogon,KTG,Krbtgt,W32Time -ErrorAction SilentlyContinue
    # Em alguns sistemas o serviço KDC é "KDC" e não "KTG/Krbtgt"
    if(-not $svc -or ($svc | Where-Object {$_.Status -ne 'Running' -and $_.StartType -eq 'Automatic'})){
      # tenta com nomes alternativos
      $svc = Get-Service -ComputerName $dc -Name NTDS,DFSR,DNS,Netlogon,KDC,W32Time -ErrorAction SilentlyContinue
      if(-not $svc -or ($svc | Where-Object {$_.Status -ne 'Running' -and $_.StartType -eq 'Automatic'})){
        $row.Services = "FAIL"
      }
    }
  } catch { $row.Services = "FAIL" }

  # Tempo
  $time = Run-Cmd "w32tm /query /status /computer:$dc"
  if($time -match 'error' -or $time -match 'unsynchronized'){
    $row.Time = "FAIL"
  }

  # Disco (20% livre)
  try{
    $disks = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $dc -Filter "DriveType=3" |
      Select-Object DeviceID, @{n="FreeGB";e={[math]::Round($_.FreeSpace/1GB,2)}}, @{n="SizeGB";e={[math]::Round($_.Size/1GB,2)}},
        @{n="PctFree";e={[math]::Round(($_.FreeSpace/$_.Size)*100,0)}}
    if($disks | Where-Object {$_.PctFree -lt 20}){ $row.Disk = "WARN" }
  } catch { $row.Disk = "WARN" }

  # Eventos últimas $Hours horas
  try{
    $levels = @('Error','Warning')
    $logs = @('Directory Service','DNS Server','System','DFS Replication')
    $hasBad = $false
    foreach($log in $logs){
      $ev = Get-WinEvent -ComputerName $dc -FilterHashtable @{LogName=$log; StartTime=$since} -ErrorAction SilentlyContinue |
            Where-Object { $levels -contains $_.LevelDisplayName } |
            Select-Object -First 1
      if($ev){ $hasBad = $true; break }
    }
    if($hasBad){ $row.Events = "WARN" }
  } catch { $row.Events = "WARN" }

  $dcRows += New-Object PSObject -Property $row

  # Anexos por DC (detalhes)
  $dcHtml = @()
  $dcHtml += "<h4>$dc - DCDIAG</h4><pre>$([System.Web.HttpUtility]::HtmlEncode($dcdiag))</pre>"
  $dcHtml += "<h4>$dc - DNS</h4><pre>$([System.Web.HttpUtility]::HtmlEncode($dnsdiag))</pre>"
  $dcHtml += "<h4>$dc - Tempo (w32tm)</h4><pre>$([System.Web.HttpUtility]::HtmlEncode($time))</pre>"
  Add-Section -Title "Detalhes - $dc" -Html ($dcHtml -join "`n")
}

# --- Replication detail ---
$showrepl = Run-Cmd "repadmin /showrepl * /verbose /all /intersite"
$srStatus = if($showrepl -match 'Last error' -or $showrepl -match 'convergence failure'){"FAIL"} else {"PASS"}
Add-Section -Title "Replicação - repadmin /showrepl" -Html ("<pre>"+[System.Web.HttpUtility]::HtmlEncode($showrepl)+"</pre>") -Status $srStatus

# --- Sumário por DC (tabela) ---
$summaryTable = $dcRows | Select-Object DC,DCDIAG,DNS,SYSVOL,Services,Time,Disk,Events |
  ConvertTo-Html -Fragment
Add-Section -Title "Sumário por DC" -Html $summaryTable -Status (
  if($dcRows.DCDIAG -contains "FAIL" -or $dcRows.DNS -contains "FAIL" -or $dcRows.Services -contains "FAIL" -or $dcRows.SYSVOL -contains "FAIL"){"FAIL"}
  elseif($dcRows.Events -contains "WARN" -or $dcRows.Disk -contains "WARN" -or $queueStatus -eq "WARN"){"WARN"}
  else{"PASS"}
)

# --- Montagem HTML final ---
$badge = switch ($overallStatus) {
  "PASS" {"<span style='background:#2e7d32;color:#fff;padding:4px 8px;border-radius:6px;'>PASS ✅</span>"}
  "WARN" {"<span style='background:#f9a825;color:#000;padding:4px 8px;border-radius:6px;'>WARN ⚠️</span>"}
  "FAIL" {"<span style='background:#c62828;color:#fff;padding:4px 8px;border-radius:6px;'>FAIL ❌</span>"}
}

$head = @"
<html><head><meta charset='utf-8'/>
<title>AD DC Health Report</title>
<style>
 body {font-family:Segoe UI, Arial; margin:20px;}
 h1,h2,h3 {margin-bottom:6px;}
 pre {background:#111;color:#eee;padding:10px;border-radius:8px;overflow:auto;}
 table {border-collapse:collapse;width:100%;}
 th, td {border:1px solid #ddd;padding:6px;text-align:left;}
 th {background:#f5f5f5;}
 .section {margin:18px 0;}
 .status {float:right;}
</style>
</head><body>
<h1>AD DC Health Report <span class='status'>$badge</span></h1>
<p>Janela de eventos: últimas $Hours horas. Gerado em $(Get-Date -Format "yyyy-MM-dd HH:mm:ss").</p>
"@

$body = ""
foreach($s in $sections){
  $flag = switch ($s.Status) {
    "PASS" {"✅"}
    "WARN" {"⚠️"}
    "FAIL" {"❌"}
    default {""}
  }
  $body += "<div class='section'><h2>$flag $($s.Title)</h2>$($s.Html)</div>"
}

$tail = "</body></html>"

$finalHtml = $head + $body + $tail
$finalHtml | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "Relatório gerado em: $OutputPath"
if(Test-Path $OutputPath){ Invoke-Item $OutputPath }
