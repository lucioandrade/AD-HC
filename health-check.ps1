<#
.SYNOPSIS
  Coleta informações de servidores Windows, exporta para CSV e (opcionalmente) envia por e-mail via Microsoft Graph.

.PARAMETER Servers
  Lista de servidores. Padrão: 'localhost'. Aceita nomes/FQDN/IP.

.PARAMETER CsvPath
  Caminho completo do CSV de saída. Se omitido, grava em .\Relatorio_<yyyyMMdd_HHmmss>.csv

.PARAMETER Email
  Se presente, envia o CSV por e-mail via Microsoft Graph (app-only).

.PARAMETER From
  Remetente para o Graph (ex.: no-reply@avanade.com ou uma Shared Mailbox).

.PARAMETER To
  Um ou mais destinatários.

.PARAMETER Subject
  Assunto do e-mail.

.PARAMETER BodyHtml
  Corpo HTML do e-mail.

.PARAMETER TenantId
  Tenant (GUID) para autenticar no Graph (app-only).

.PARAMETER ClientId
  Application (client) ID do App Registration.

.PARAMETER CertThumbprint
  Thumbprint de certificado instalado na máquina de execução (recomendado). Opcional se usar ClientSecret.

.PARAMETER ClientSecret
  Client Secret do App Registration (evite em produção; prefira certificado).

.EXAMPLE
  .\Coleta-Relatorio-Infra.ps1 -Servers DC01,FS01 -Email `
    -From no-reply@avanade.com -To lucio.andrade@avanade.com `
    -TenantId 11111111-2222-3333-4444-555555555555 -ClientId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee `
    -CertThumbprint 0123456789ABCDEF0123456789ABCDEF01234567

.NOTES
  Requer PowerShell 5.1+ e módulos: Microsoft.Graph (para envio por e-mail).
#>

[CmdletBinding()]
param(
    [string[]]$Servers = @('localhost'),
    [string]$CsvPath,

    [switch]$Email,
    [Parameter(Mandatory=$false)][string]$From,
    [Parameter(Mandatory=$false)][string[]]$To,
    [Parameter(Mandatory=$false)][string]$Subject = "Relatório de Saúde dos Servidores",
    [Parameter(Mandatory=$false)][string]$BodyHtml = "<p>Olá,</p><p>Segue o relatório em anexo.</p><p>Abs,</p>",

    [Parameter(Mandatory=$false)][string]$TenantId,
    [Parameter(Mandatory=$false)][string]$ClientId,
    [Parameter(Mandatory=$false)][string]$CertThumbprint,
    [Parameter(Mandatory=$false)][string]$ClientSecret
)

#region ===== Util =====
function Write-Info($msg){ Write-Host "[INFO ] $msg" -ForegroundColor Cyan }
function Write-Warn($msg){ Write-Warning $msg }
function Write-Err ($msg){ Write-Host "[ERRO ] $msg" -ForegroundColor Red }

function Test-GraphModule {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Write-Err "Módulo Microsoft.Graph não encontrado. Instale com: Install-Module Microsoft.Graph -Scope AllUsers -Force"
        throw "Microsoft.Graph ausente"
    }
}

function New-OutputPath([string]$CsvPathParam){
    if ([string]::IsNullOrWhiteSpace($CsvPathParam)){
        $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
        return (Join-Path -Path (Get-Location) -ChildPath "Relatorio_$stamp.csv")
    }
    return $CsvPathParam
}
#endregion

#region ===== Coleta de dados =====
function Get-ServerInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    $reachable = $false
    try {
        $reachable = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -TimeoutSeconds 2
    } catch {
        $reachable = $false
    }
    if (-not $reachable){
        return [PSCustomObject]@{
            ComputerName    = $ComputerName
            Reachable       = $false
            OS              = $null
            LastBootHours   = $null
            MemTotalGB      = $null
            MemFreeGB       = $null
            MemUsedPct      = $null
            DiskSizeGB      = $null
            DiskFreeGB      = $null
            DiskFreePct     = $null
            DNS             = $null
            NTDS            = $null
            Netlogon        = $null
            Notes           = "Host inacessível (ping falhou)."
        }
    }

    try {
        $os  = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
        $cs  = Get-CimInstance -ClassName Win32_ComputerSystem     -ComputerName $ComputerName -ErrorAction Stop
        $lds = Get-CimInstance -ClassName Win32_LogicalDisk        -ComputerName $ComputerName -Filter "DriveType=3" -ErrorAction Stop

        # Memória (GB)
        $memTotalGB = [Math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        $memFreeGB  = [Math]::Round($os.FreePhysicalMemory / 1MB, 1) # FreePhysicalMemory em KB
        $memUsedPct = if ($memTotalGB -gt 0) { [Math]::Round((($memTotalGB - $memFreeGB) / $memTotalGB) * 100, 1) } else { $null }

        # Discos (soma)
        $sizeGB   = [Math]::Round(($lds | Measure-Object -Property Size      -Sum).Sum / 1GB, 1)
        $freeGB   = [Math]::Round(($lds | Measure-Object -Property FreeSpace -Sum).Sum / 1GB, 1)
        $freePct  = if ($sizeGB -gt 0) { [Math]::Round(($freeGB / $sizeGB) * 100, 1) } else { $null }

        # Uptime (horas)
        $lastBootHours = [Math]::Round((New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)).TotalHours, 1)

        # Serviços (se existirem nesse host)
        $svcNames = 'DNS','NTDS','Netlogon'
        $svcState = @{}
        foreach($n in $svcNames){
            try {
                $s = Get-Service -ComputerName $ComputerName -Name $n -ErrorAction Stop
                $svcState[$n] = $s.Status.ToString()
            } catch {
                $svcState[$n] = 'N/A'
            }
        }

        # Notas (drives com pouco espaço)
        $lowDrives = $lds | ForEach-Object {
            $dSize = $_.Size
            $dFree = $_.FreeSpace
            if ($dSize -gt 0) {
                $pct = [Math]::Round(($dFree / $dSize) * 100, 1)
                if ($pct -lt 15) { "$($_.DeviceID)=$pct%" }
            }
        }
        $notes = if ($lowDrives) { "Baixo espaço: " + ($lowDrives -join ', ') } else { $null }

        [PSCustomObject]@{
            ComputerName    = $ComputerName
            Reachable       = $true
            OS              = $os.Caption
            LastBootHours   = $lastBootHours
            MemTotalGB      = $memTotalGB
            MemFreeGB       = $memFreeGB
            MemUsedPct      = $memUsedPct
            DiskSizeGB      = $sizeGB
            DiskFreeGB      = $freeGB
            DiskFreePct     = $freePct
            DNS             = $svcState['DNS']
            NTDS            = $svcState['NTDS']
            Netlogon        = $svcState['Netlogon']
            Notes           = $notes
        }
    } catch {
        [PSCustomObject]@{
            ComputerName    = $ComputerName
            Reachable       = $true
            OS              = $null
            LastBootHours   = $null
            MemTotalGB      = $null
            MemFreeGB       = $null
            MemUsedPct      = $null
            DiskSizeGB      = $null
            DiskFreeGB      = $null
            DiskFreePct     = $null
            DNS             = $null
            NTDS            = $null
            Netlogon        = $null
            Notes           = "Falha ao coletar CIM: $($_.Exception.Message)"
        }
    }
}
#endregion

#region ===== Envio por e-mail via Graph (app-only) =====
function Connect-GraphAppOnly {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$TenantId,
        [Parameter(Mandatory)] [string]$ClientId,
        [string]$CertThumbprint,
        [string]$ClientSecret
    )

    Test-GraphModule

    if ($CertThumbprint){
        Write-Info "Conectando ao Graph com certificado (app-only)..."
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertThumbprint -NoWelcome | Out-Null
    }
    elseif ($ClientSecret){
        Write-Info "Conectando ao Graph com client secret (app-only)..."
        # Necessário Microsoft.Graph 2.5+ (suporte a -ClientSecret)
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret (ConvertTo-SecureString $ClientSecret -AsPlainText -Force) -NoWelcome | Out-Null
    }
    else {
        throw "Informe CertThumbprint OU ClientSecret para app-only."
    }
}

function Send-ReportViaGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$From,
        [Parameter(Mandatory)] [string[]]$To,
        [Parameter(Mandatory)] [string]$Subject,
        [Parameter(Mandatory)] [string]$BodyHtml,
        [Parameter(Mandatory)] [string]$AttachmentPath
    )

    # Monta anexo (base64)
    if (-not (Test-Path -Path $AttachmentPath)){
        throw "Arquivo de anexo não encontrado: $AttachmentPath"
    }
    $bytes = [System.IO.File]::ReadAllBytes($AttachmentPath)
    $b64   = [Convert]::ToBase64String($bytes)
    $name  = [System.IO.Path]::GetFileName($AttachmentPath)

    $message = @{
        subject = $Subject
        body    = @{
            contentType = "HTML"
            content     = $BodyHtml
        }
        toRecipients = @($To | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
        attachments  = @(
            @{
                "@odata.type" = "#microsoft.graph.fileAttachment"
                name          = $name
                contentType   = "text/csv"
                contentBytes  = $b64
            }
        )
    }

    Write-Info "Enviando e-mail via Graph como '$From'..."
    Send-MgUserMail -UserId $From -Message $message -SaveToSentItems:$true
    Write-Info "E-mail enviado."
}
#endregion

#region ===== Execução =====
try {
    $outCsv = New-OutputPath -CsvPathParam $CsvPath
    Write-Info "Coletando dados de: $($Servers -join ', ')"

    $results = foreach($srv in $Servers){
        Get-ServerInfo -ComputerName $srv
    }

    # Exporta
    $results | Export-Csv -Path $outCsv -Encoding UTF8 -UseCulture -NoTypeInformation
    Write-Info "CSV salvo em: $outCsv"

    if ($Email.IsPresent){
        # Valida parâmetros obrigatórios de e-mail
        $required = @('From','To','TenantId','ClientId')
        foreach($p in $required){ if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $p -ValueOnly))) { throw "Parâmetro obrigatório ausente para envio por e-mail: $p" } }
        if (-not $CertThumbprint -and -not $ClientSecret){ throw "Informe CertThumbprint OU ClientSecret para autenticação app-only." }

        # Conecta e envia
        Connect-GraphAppOnly -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -ClientSecret $ClientSecret
        Send-ReportViaGraph  -From $From -To $To -Subject $Subject -BodyHtml $BodyHtml -AttachmentPath $outCsv
    }

    Write-Info "Concluído."
}
catch {
    Write-Err $_
    throw
}
#endregion
