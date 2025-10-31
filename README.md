# Active Directory Health Check Script - Documentação Completa

## Índice
- [Visão Geral](#visão-geral)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Parâmetros](#parâmetros)
- [Recursos](#recursos)
- [Exemplos de Uso](#exemplos-de-uso)
- [Interpretação dos Resultados](#interpretação-dos-resultados)
- [Troubleshooting](#troubleshooting)
- [Boas Práticas](#boas-práticas)

---

## Visão Geral

O **AD Health Check Script v2.4** é uma ferramenta PowerShell avançada para monitoramento e diagnóstico abrangente de ambientes Active Directory. O script executa mais de 15 categorias de verificações e gera um relatório HTML interativo com scoring de saúde, métricas detalhadas e recomendações acionáveis.

### Principais Características

✅ **Verificação Completa de DCs**: Conectividade, serviços críticos, replicação, sincronização de tempo  
✅ **Monitoramento de Hardware**: CPU, memória, espaço em disco com limiares configuráveis  
✅ **Diagnóstico Automatizado**: DCDiag completo com 15 testes integrados  
✅ **Análise de Eventos**: Detecção de eventos críticos nas últimas 24 horas  
✅ **Gestão de Certificados**: Alertas de expiração configuráveis  
✅ **Health Score**: Pontuação automática de 0-100 baseada em múltiplas métricas  
✅ **Relatório Interativo**: HTML responsivo com filtros, expansíveis e detalhes de testes  
✅ **Notificações**: Envio por SMTP ou Microsoft Graph API  
✅ **Exportação CSV**: Opção para análise de dados estruturados  

---

## Requisitos

### Software Necessário

| Componente | Versão Mínima | Obrigatório |
|------------|---------------|-------------|
| Windows PowerShell | 5.1+ | ✓ |
| RSAT - Active Directory | Qualquer | ✓ |
| Módulo ActiveDirectory | Incluído no RSAT | ✓ |
| DCDiag.exe | Windows Server Tools | ✓ |
| Repadmin.exe | Windows Server Tools | ✓ |
| NLTest.exe | Windows Server Tools | ✓ |
| Microsoft.Graph (para Graph API) | 2.0+ | Opcional |

### Permissões Necessárias

- **Domain Admins** ou **Enterprise Admins** (recomendado para verificação completa)
- Leitura em todos os Domain Controllers
- Acesso WMI/CIM remoto aos DCs
- Acesso aos logs de eventos dos DCs
- Permissões para executar DCDiag e Repadmin

### Configuração de Firewall

Portas necessárias abertas entre a máquina de execução e os DCs:
- **ICMP** - Ping (verificação de conectividade)
- **TCP 389** - LDAP
- **TCP 3268** - Global Catalog
- **TCP 135** - RPC Endpoint Mapper
- **TCP 445** - SMB (para WMI/CIM)
- **Portas dinâmicas RPC** - Geralmente 49152-65535

---

## Instalação

### Passo 1: Instalar RSAT Tools

**Windows 10/11:**
```powershell
# Via Settings > Apps > Optional Features > Add "RSAT: Active Directory Domain Services"

# Ou via PowerShell (como Administrador):
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online
```

**Windows Server:**
```powershell
Install-WindowsFeature -Name RSAT-AD-PowerShell, RSAT-AD-Tools, RSAT-DNS-Server
```

### Passo 2: Baixar o Script

```powershell
# Salvar o script como ADHealthCheck.ps1 em um diretório acessível
# Exemplo: C:\Scripts\ADHealthCheck.ps1
```

### Passo 3: Configurar Política de Execução (se necessário)

```powershell
# Verificar política atual
Get-ExecutionPolicy

# Definir política para permitir scripts locais (como Administrador)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Passo 4: (Opcional) Instalar Microsoft Graph para Email

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

---

## Parâmetros

### Parâmetros de Seleção de DCs

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `-UsingOU` | Switch | Desabilitado | Busca DCs em uma OU específica |
| `-OrganizationUnitDN` | String | "OU=Domain Controllers,DC=..." | DN da OU quando `-UsingOU` está ativo |
| `-DomainControllers` | String[] | Todos os DCs | Lista manual de DCs para verificar |

### Parâmetros de Saída

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `-OutputPath` | String | `.\ADHealthReport.html` | Caminho completo do arquivo HTML |
| `-Csv` | Switch | Desabilitado | Gera arquivo CSV adicional com issues |

### Parâmetros de Email - SMTP

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `-SmtpServer` | String | - | Servidor SMTP (ex: smtp.office365.com) |
| `-SmtpPort` | Int | 587 | Porta SMTP |
| `-SmtpUseSsl` | Switch | Desabilitado | Habilita SSL/TLS |
| `-From` | String | - | Endereço de email remetente |
| `-To` | String[] | - | Lista de destinatários |
| `-Subject` | String | "AD Health Check Report" | Assunto do email |
| `-Credential` | PSCredential | - | Credenciais SMTP (se requerido) |
| `-EmailOnErrorOnly` | Switch | Desabilitado | Envia email apenas se houver issues críticos |

### Parâmetros de Email - Microsoft Graph

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `-UseGraph` | Switch | Desabilitado | Usa Microsoft Graph em vez de SMTP |
| `-GraphSenderUpn` | String | - | UPN do usuário remetente no Graph |

### Parâmetros de Limiares

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `-CertWarningDays` | Int | 30 | Dias antes da expiração para alertar certificados |
| `-RidPoolWarningPercent` | Int | 20 | Percentual de RIDs restantes para alertar |

---

## Recursos

### Categorias de Verificação

#### 1. **Conectividade**
- Teste de ping ICMP
- Resolução DNS
- Validação de objeto AD

#### 2. **Serviços Críticos**
Monitoramento dos serviços essenciais:
- **NTDS** - Active Directory Domain Services
- **DNS** - Domain Name System
- **Netlogon** - Network Logon
- **KDC** - Kerberos Key Distribution Center
- **W32Time** - Windows Time Service

#### 3. **Hardware e Performance**
- **CPU Usage**: Medição contínua por 5 segundos (10 amostras)
  - ⚠️ Warning: > 85%
- **Memória RAM**: Utilização percentual
  - ⚠️ Warning: > 80%
  - 🚨 Critical: > 90%
- **Espaço em Disco**: Todos os volumes locais
  - ⚠️ Warning: < 20% livre
  - 🚨 Critical: < 10% livre
- **Uptime**: Tempo desde o último boot

#### 4. **Replicação AD**
- Status de replicação com todos os parceiros
- Número de falhas por parceiro
- Último status de erro
- Alertas para falhas de replicação

#### 5. **Sincronização de Tempo**
- Offset de tempo via W32Time
  - ⚠️ Warning: > 1 segundo
  - 🚨 Critical: > 5 segundos
- Crítico para autenticação Kerberos

#### 6. **DCDiag Tests**
Execução completa de 15 testes DCDiag:
- Connectivity
- Advertising
- DFSREvent
- SysVolCheck
- KccEvent
- KnowsOfRoleHolders
- MachineAccount
- NCSecDesc
- NetLogons
- ObjectsReplicated
- Replications
- RidManager
- Services
- SystemLog
- VerifyReferences

#### 7. **Eventos Críticos**
Monitoramento de IDs de eventos críticos nas últimas 24 horas:

| Event ID | Descrição |
|----------|-----------|
| 1864 | Espaço em disco crítico para logs AD |
| 2042 | Replicação não ocorreu por período estendido |
| 2092 | Replicação bloqueada |
| 1168 | Erro de banco de dados AD detectado |
| 1173 | Corrupção de banco de dados detectada |
| 2089 | Backup AD criticamente desatualizado |
| 13508 | Erro de replicação SYSVOL |
| 13509 | Compartilhamento SYSVOL não acessível |

#### 8. **Certificados**
- Verificação de certificados na loja LocalMachine\My
- Alertas para certificados expirados
- Alertas para certificados próximos da expiração
- Detalhes: Subject, Issuer, Data de expiração

#### 9. **FSMO Roles**
Validação de acessibilidade dos role holders:
- Schema Master
- Domain Naming Master
- PDC Emulator
- RID Master
- Infrastructure Master

#### 10. **RID Pool**
- Análise de RIDs disponíveis no domínio
- 🚨 Critical: < 100.000 RIDs
- ⚠️ Warning: < 500.000 RIDs

#### 11. **DNS Health**
Verificação de registros SRV críticos:
- `_ldap._tcp`
- `_kerberos._tcp`
- `_kpasswd._tcp`
- `_gc._tcp`

#### 12. **Estatísticas AD**
Contagem de objetos:
- Usuários
- Computadores
- Grupos
- Domain Controllers

### Health Score (0-100)

O script calcula automaticamente um **Health Score** baseado em:

```
Score = Taxa de Sucesso - (Penalidades Proporcionais)

Taxa de Sucesso = (Checks OK / Total de Checks) × 100

Penalidades:
- Critical: até 30 pontos (proporcional à quantidade)
- Warning: até 10 pontos (proporcional à quantidade)
- Unknown: até 5 pontos (proporcional à quantidade)
```

**Classificação de Severidade:**

| Score | Nível | Cor | Ícone |
|-------|-------|-----|-------|
| 90-100 | HEALTHY | Verde | ✓ |
| 70-89 | WARNING | Laranja | ⚠ |
| 50-69 | CRITICAL | Vermelho | ✗ |
| 0-49 | EMERGENCY | Vermelho Escuro | 🚨 |

### Relatório HTML Interativo

O relatório gerado inclui:

1. **Executive Summary**
   - Health Score visual com círculo colorido
   - Métricas principais em cards clicáveis
   - Status badge com severidade

2. **Domain Controllers Summary**
   - Tabela com status de cada DC
   - Informações de hardware inline
   - Badges para GC e PDC Emulator
   - Status colorido por categoria

3. **Top Priority Issues**
   - Até 5 issues mais críticos
   - Cards com descrição e recomendação
   - Separação visual por severidade

4. **All Issues (Expandível)**
   - Lista completa de issues detectados
   - Agrupados por severidade
   - Recomendações específicas

5. **FSMO Role Holders**
   - Tabela com roles e holders
   - Expandível

6. **Evaluated Items (Filtrável)**
   - Todos os checks executados
   - Filtros por status: All, OK, Warning, Critical, Unknown
   - Agrupados por DC (Domain-Wide primeiro)
   - Clique para ver detalhes do teste:
     - Comando executado
     - Output completo
     - Timestamp

### Design Responsivo

- **Dark Theme** moderno e profissional
- **Mobile-Friendly** - adaptável a dispositivos móveis
- **Filtros Interativos** - JavaScript para navegação rápida
- **Seções Expansíveis** - Reduz scroll inicial
- **Test Details Modal** - Informações técnicas completas por check

---

## Exemplos de Uso

### Exemplo 1: Verificação Básica (Todos os DCs)

```powershell
.\ADHealthCheck.ps1
```

**Resultado:**
- Verifica todos os DCs do domínio
- Gera `ADHealthReport.html` no diretório atual
- Sem envio de email

---

### Exemplo 2: Verificação com Saída Personalizada

```powershell
.\ADHealthCheck.ps1 -OutputPath "C:\Reports\AD-Health-$(Get-Date -Format 'yyyy-MM-dd').html"
```

**Resultado:**
- Relatório salvo com data no nome
- Exemplo: `C:\Reports\AD-Health-2025-10-31.html`

---

### Exemplo 3: Verificar DCs Específicos

```powershell
.\ADHealthCheck.ps1 -DomainControllers "DC01.contoso.com","DC02.contoso.com" -Verbose
```

**Resultado:**
- Verifica apenas DC01 e DC02
- Mostra logs detalhados durante execução (`-Verbose`)

---

### Exemplo 4: Verificação com Email via SMTP

```powershell
$smtpCred = Get-Credential

.\ADHealthCheck.ps1 `
    -SmtpServer "smtp.office365.com" `
    -SmtpPort 587 `
    -SmtpUseSsl `
    -From "ad-monitoring@contoso.com" `
    -To "it-team@contoso.com","manager@contoso.com" `
    -Subject "[AD Health] Relatório Diário - $(Get-Date -Format 'dd/MM/yyyy')" `
    -Credential $smtpCred
```

**Resultado:**
- Gera relatório HTML
- Envia por email para 2 destinatários
- Anexa o arquivo HTML
- Usa autenticação SMTP

---

### Exemplo 5: Email Apenas em Caso de Erros

```powershell
.\ADHealthCheck.ps1 `
    -SmtpServer "smtp.contoso.com" `
    -From "ad-health@contoso.com" `
    -To "admins@contoso.com" `
    -EmailOnErrorOnly
```

**Resultado:**
- Executa todas as verificações
- **Envia email SOMENTE** se houver issues críticos
- Economiza caixa de entrada em dias sem problemas

---

### Exemplo 6: Usando Microsoft Graph (Office 365)

```powershell
# Primeiro login no Graph (uma vez por sessão)
Connect-MgGraph -Scopes "Mail.Send"

.\ADHealthCheck.ps1 `
    -UseGraph `
    -GraphSenderUpn "admin@contoso.onmicrosoft.com" `
    -To "team@contoso.com"
```

**Resultado:**
- Usa Microsoft Graph API em vez de SMTP
- Requer módulo Microsoft.Graph
- Ideal para ambientes Office 365/Azure AD

---

### Exemplo 7: Verificação com Exportação CSV

```powershell
.\ADHealthCheck.ps1 `
    -OutputPath "C:\Reports\AD-Health.html" `
    -Csv
```

**Resultado:**
- Gera `AD-Health.html`
- Gera `AD-Health.csv` com todos os issues
- CSV útil para análise em Excel ou PowerBI

---

### Exemplo 8: Verificação de OU Específica

```powershell
.\ADHealthCheck.ps1 `
    -UsingOU `
    -OrganizationUnitDN "OU=Branch DCs,OU=Servers,DC=contoso,DC=com"
```

**Resultado:**
- Verifica apenas DCs em uma OU específica
- Útil para ambientes multi-site com OUs separadas

---

### Exemplo 9: Limiares Personalizados

```powershell
.\ADHealthCheck.ps1 `
    -CertWarningDays 60 `
    -RidPoolWarningPercent 30
```

**Resultado:**
- Alerta certificados expirando em 60 dias (padrão: 30)
- Alerta RID pool abaixo de 30% (padrão: 20%)

---

### Exemplo 10: Agendamento com Task Scheduler

**Script Wrapper** (`Run-ADHealthCheck.ps1`):
```powershell
# Configurações
$scriptPath = "C:\Scripts\ADHealthCheck.ps1"
$reportPath = "\\FileServer\Reports\AD-Health-$(Get-Date -Format 'yyyy-MM-dd').html"
$smtpCred = Import-Clixml "C:\Scripts\.credentials\smtp.xml"

# Executar
& $scriptPath `
    -OutputPath $reportPath `
    -SmtpServer "smtp.office365.com" `
    -SmtpPort 587 `
    -SmtpUseSsl `
    -From "ad-health@contoso.com" `
    -To "it-admins@contoso.com" `
    -Credential $smtpCred `
    -EmailOnErrorOnly `
    -Csv
```

**Criar Credencial Criptografada** (executar uma vez):
```powershell
Get-Credential | Export-Clixml "C:\Scripts\.credentials\smtp.xml"
```

**Task Scheduler:**
1. Abrir Task Scheduler
2. Criar Tarefa Básica
3. **Trigger**: Diariamente às 06:00
4. **Ação**: Iniciar um programa
   - Programa: `powershell.exe`
   - Argumentos: `-ExecutionPolicy Bypass -File "C:\Scripts\Run-ADHealthCheck.ps1"`
5. **Configurações**:
   - ✓ Executar com privilégios mais altos
   - ✓ Executar mesmo se o usuário não estiver conectado
   - Conta: Domain Admin ou service account com permissões

---

### Exemplo 11: Monitoramento Multi-Domínio (Forest)

```powershell
# Script para verificar múltiplos domínios
$domains = @("contoso.com", "subsidiary.contoso.com", "partner.com")

foreach ($domain in $domains) {
    Write-Host "Checking domain: $domain" -ForegroundColor Cyan
    
    $reportPath = "C:\Reports\$domain-Health-$(Get-Date -Format 'yyyyMMdd').html"
    
    # Muda contexto para o domínio
    $dcList = (Get-ADDomainController -Server $domain -Filter *).HostName
    
    .\ADHealthCheck.ps1 `
        -DomainControllers $dcList `
        -OutputPath $reportPath `
        -Verbose
}
```

**Resultado:**
- Gera relatório separado por domínio
- Útil para ambientes de floresta com múltiplos domínios

---

### Exemplo 12: Modo Debug com Transcript

```powershell
$transcriptPath = "C:\Logs\ADHealthCheck-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
Start-Transcript -Path $transcriptPath

.\ADHealthCheck.ps1 -Verbose

Stop-Transcript
```

**Resultado:**
- Captura toda a saída do console
- Log completo salvo para análise posterior
- Útil para troubleshooting

---

## Interpretação dos Resultados

### Health Score Guidelines

| Score Range | Ação Recomendada | Prioridade |
|-------------|------------------|------------|
| **90-100** | Manutenção de rotina | Baixa |
| **80-89** | Revisar warnings, planejar correções | Média |
| **70-79** | Investigar issues, agendar manutenção | Média-Alta |
| **50-69** | Ação imediata em issues críticos | Alta |
| **0-49** | Resposta emergencial necessária | Crítica |

### Interpretação de Issues

#### Conectividade

**Critical: "Domain Controller Unreachable"**
- **Causa**: DC não responde a ping ou está offline
- **Impacto**: Usuários podem não conseguir autenticar
- **Ação**: 
  1. Verificar se o servidor está ligado
  2. Testar conectividade de rede
  3. Verificar firewall
  4. Consultar logs do servidor

#### Serviços

**Critical: "NTDS service is not running"**
- **Causa**: Active Directory Domain Services parado
- **Impacto**: DC não funcional, replicação interrompida
- **Ação**:
  1. Verificar Event Viewer (Directory Service log)
  2. Tentar iniciar serviço: `Start-Service NTDS`
  3. Se falhar, verificar integridade do database: `ntdsutil files integrity`

**Critical: "DNS service is not running"**
- **Causa**: Serviço DNS parado
- **Impacto**: Resolução de nomes falha, clientes não localizam DCs
- **Ação**:
  1. Iniciar serviço: `Start-Service DNS`
  2. Verificar configuração de forwarders
  3. Testar registros SRV

#### Replicação

**Critical: "AD Replication Failures Detected"**
- **Causa**: Falha na sincronização entre DCs
- **Impacto**: Inconsistência de dados, objetos desatualizados
- **Ação**:
  1. Executar: `repadmin /showrepl DC01 /verbose`
  2. Verificar conectividade entre DCs
  3. Validar DNS: `dcdiag /test:dns`
  4. Forçar replicação: `repadmin /syncall`

#### Hardware

**Critical: "Disk critically low (8% free)"**
- **Causa**: Espaço em disco insuficiente
- **Impacto**: Logs podem parar, database pode corromper
- **Ação IMEDIATA**:
  1. Limpar arquivos temporários
  2. Arquivar/comprimir logs antigos
  3. Expandir volume (se possível)
  4. Mover database/logs para volume maior

**Warning: "Memory usage high (85%)"**
- **Causa**: Carga alta ou leak de memória
- **Impacto**: Performance degradada
- **Ação**:
  1. Identificar processos com alto consumo
  2. Considerar adicionar RAM
  3. Investigar memory leak

#### Tempo

**Critical: "Time sync offset is 7.2s"**
- **Causa**: Sincronização NTP falhando
- **Impacto**: Kerberos falha (max 5s de diferença)
- **Ação**:
  1. Verificar fonte NTP: `w32tm /query /status`
  2. Forçar sync: `w32tm /resync /rediscover`
  3. Configurar fontes confiáveis:
     ```powershell
     w32tm /config /manualpeerlist:"time.windows.com,0x8" /syncfromflags:manual /update
     w32tm /resync
     ```

#### Certificados

**Critical: "2 certificate(s) expired"**
- **Causa**: Certificados vencidos
- **Impacto**: LDAPS, autenticação de DC pode falhar
- **Ação**:
  1. Identificar certificados: Certmgr.msc → Personal → Certificates
  2. Renovar via CA ou emitir novos
  3. Reiniciar serviços dependentes

#### FSMO

**Critical: "PDC Emulator holder is unreachable"**
- **Causa**: Servidor PDC offline ou inacessível
- **Impacto**: Sincronização de tempo, alterações de senha podem falhar
- **Ação**:
  1. Restaurar PDC se possível
  2. Se permanentemente offline, transferir role:
     ```powershell
     Move-ADDirectoryServerOperationMasterRole -Identity "DC02" -OperationMasterRole PDCEmulator
     ```
  3. Ou seizure (se DC morto):
     ```powershell
     Move-ADDirectoryServerOperationMasterRole -Identity "DC02" -OperationMasterRole PDCEmulator -Force
     ```

#### RID Pool

**Warning: "RID pool usage high: 450000 RIDs remaining"**
- **Causa**: Muitos objetos criados, consumo anormal
- **Impacto**: Impossibilidade de criar novos objetos ao esgotar
- **Ação**:
  1. Investigar criação massiva de objetos
  2. Limpar objetos órfãos/inativos
  3. Se legítimo, contatar Microsoft para extensão

#### DNS

**Critical: "4 critical SRV record(s) missing"**
- **Causa**: Registros DNS não cadastrados
- **Impacto**: Clientes não localizam serviços AD
- **Ação**:
  1. Executar: `dcdiag /fix`
  2. Reiniciar Netlogon: `Restart-Service Netlogon`
  3. Registrar manualmente: `nltest /dsregdns`

---

## Troubleshooting

### Problema: "Active Directory module not found"

**Erro:**
```
Import-Module : The specified module 'ActiveDirectory' was not loaded because no valid module file was found
```

**Solução:**
```powershell
# Windows 10/11
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online

# Windows Server
Install-WindowsFeature -Name RSAT-AD-PowerShell
```

---

### Problema: "Access Denied" ao executar script

**Erro:**
```
Get-ADDomainController : Access is denied
```

**Solução:**
- Executar PowerShell como Administrador
- Usar credenciais de Domain Admin:
  ```powershell
  $cred = Get-Credential
  Import-Module ActiveDirectory -Credential $cred
  .\ADHealthCheck.ps1
  ```

---

### Problema: DCDiag/Repadmin não encontrado

**Erro:**
```
dcdiag.exe : The term 'dcdiag.exe' is not recognized
```

**Solução:**
```powershell
# Adicionar ao PATH
$env:Path += ";C:\Windows\System32"

# Ou instalar ferramentas completas
Install-WindowsFeature -Name RSAT-AD-Tools
```

---

### Problema: WMI/CIM Access Denied

**Erro:**
```
Get-CimInstance : Access is denied
```

**Solução:**
1. Verificar firewall no DC destino:
   ```powershell
   # No DC, habilitar WMI no firewall
   Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"
   ```

2. Verificar permissões WMI:
   - `wmimgmt.msc` → Botão direito em WMI Control → Properties
   - Security → Adicionar grupo de admins com Full Control

---

### Problema: Email não enviado

**Erro (SMTP):**
```
Send-MailMessage : Unable to connect to the remote server
```

**Soluções:**

1. **Verificar conectividade:**
   ```powershell
   Test-NetConnection -ComputerName smtp.office365.com -Port 587
   ```

2. **Testar credenciais:**
   ```powershell
   $cred = Get-Credential
   Send-MailMessage -SmtpServer "smtp.office365.com" -Port 587 -UseSsl `
       -From "test@contoso.com" -To "test@contoso.com" `
       -Subject "Test" -Body "Test" -Credential $cred
   ```

3. **Office 365 - Habilitar SMTP AUTH:**
   - Admin Center → Users → Active Users → Selecionar usuário
   - Mail → Manage email apps → ✓ Authenticated SMTP

4. **Usar App Password (se MFA ativado):**
   - Gerar app password em https://account.microsoft.com
   - Usar app password como senha

**Erro (Graph):**
```
Connect-MgGraph : The term 'Connect-MgGraph' is not recognized
```

**Solução:**
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
Import-Module Microsoft.Graph
Connect-MgGraph -Scopes "Mail.Send"
```

---

### Problema: Performance Lenta

**Sintoma:** Script demora mais de 30 minutos

**Causas e Soluções:**

1. **Muitos DCs:**
   - Executar em paralelo (Jobs):
     ```powershell
     $jobs = $allDCs | ForEach-Object {
         Start-Job -ScriptBlock { Test-DCHealth -DCName $using:_ }
     }
     $results = $jobs | Wait-Job | Receive-Job
     ```

2. **Timeout de rede:**
   - Verificar DCs inacessíveis (pulados mais rápido)
   - Ajustar timeout de ping

3. **Logs de eventos grandes:**
   - Reduzir janela de análise de eventos (hardcoded 24h)

---

### Problema: "Unable to parse RID pool information"

**Causa:** Output do DCDiag mudou (versão diferente)

**Solução:**
- Executar manualmente: `dcdiag /test:ridmanager /s:DC01 /v`
- Verificar formato da saída
- Reportar issue para atualização do regex no script

---

### Problema: Relatório HTML não abre

**Sintoma:** Arquivo HTML em branco ou erro ao abrir

**Solução:**
1. Verificar se arquivo foi gerado:
   ```powershell
   Test-Path ".\ADHealthReport.html"
   Get-Item ".\ADHealthReport.html" | Select-Object Length
   ```

2. Abrir com navegador específico:
   ```powershell
   Start-Process chrome.exe "C:\Reports\ADHealthReport.html"
   ```

3. Verificar encoding UTF-8 (se caracteres estranhos)

---

## Boas Práticas

### 1. Execução Regular

**Frequência Recomendada:**
- **Produção Crítica**: Diariamente
- **Ambientes Normais**: Semanalmente
- **Após Mudanças**: Imediatamente

**Implementação:**
```powershell
# Task Scheduler - Diariamente às 6AM
Register-ScheduledTask -TaskName "AD Health Check" `
    -Trigger (New-ScheduledTaskTrigger -Daily -At 6am) `
    -Action (New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-ExecutionPolicy Bypass -File C:\Scripts\Run-ADHealthCheck.ps1") `
    -RunLevel Highest `
    -User "DOMAIN\ServiceAccount"
```

---

### 2. Histórico de Relatórios

**Manter Histórico:**
```powershell
# Incluir timestamp no nome
$reportPath = "C:\Reports\AD-Health-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"

# Rotação automática (manter últimos 30 dias)
Get-ChildItem "C:\Reports\AD-Health-*.html" | 
    Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-30) } | 
    Remove-Item -Force
```

---

### 3. Baseline de Saúde

**Estabelecer Baseline:**
1. Executar em momento de estabilidade
2. Documentar Health Score "normal" (ex: 95)
3. Alertar quando score cair > 10 pontos

**Script de Comparação:**
```powershell
$baselineScore = 95
$currentScore = 82  # Extraído do relatório atual

if ($currentScore -lt ($baselineScore - 10)) {
    Write-Warning "Health score degraded significantly: $currentScore (baseline: $baselineScore)"
    # Enviar alerta crítico
}
```

---

### 4. Integração com SIEM/Monitoring

**Exportar Métricas:**
```powershell
# Após execução, extrair score para monitoramento
$htmlContent = Get-Content ".\ADHealthReport.html" -Raw
if ($htmlContent -match 'score-value">(\d+)</div>') {
    $score = [int]$matches[1]
    
    # Enviar para sistema de monitoramento
    Send-MetricToSIEM -MetricName "AD.HealthScore" -Value $score
}
```

---

### 5. Documentação de Issues Recorrentes

**Criar KB Interno:**
- Documentar issues frequentes e resoluções
- Adicionar links no relatório (customizar HTML)
- Treinar equipe nas correções comuns

---

### 6. Testes em Não-Produção

**Antes de Produção:**
```powershell
# Testar em lab/dev primeiro
.\ADHealthCheck.ps1 `
    -DomainControllers "LAB-DC01.dev.contoso.com" `
    -OutputPath "C:\Temp\Test-Report.html" `
    -Verbose
```

---

### 7. Segurança de Credenciais

**NUNCA hardcode senhas:**
```powershell
# ❌ ERRADO
$password = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force

# ✅ CORRETO - Usar credenciais criptografadas
$smtpCred = Import-Clixml "C:\Secure\.smtp-cred.xml"

# Gerar credencial (uma vez):
Get-Credential | Export-Clixml "C:\Secure\.smtp-cred.xml"
# Proteger arquivo com NTFS permissions (somente conta de serviço)
```

---

### 8. Alertas Inteligentes

**Configurar Limiares:**
```powershell
# Enviar email apenas se score < 80
if ($healthScore -lt 80) {
    # Enviar com prioridade alta
    Send-MailMessage ... -Priority High
}

# Ou usar -EmailOnErrorOnly para alertas críticos apenas
.\ADHealthCheck.ps1 -EmailOnErrorOnly ...
```

---

### 9. Auditoria de Execução

**Logging:**
```powershell
# Adicionar ao wrapper script
$logFile = "C:\Logs\ADHealthCheck-Audit.log"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

"[$timestamp] Started AD Health Check" | Add-Content $logFile

try {
    & .\ADHealthCheck.ps1 ...
    "[$timestamp] Completed successfully" | Add-Content $logFile
} catch {
    "[$timestamp] FAILED: $_" | Add-Content $logFile
    throw
}
```

---

### 10. Review Periódico

**Trimestral:**
- Revisar limiares de alerta (CPU, RAM, Disk)
- Atualizar documentação de issues
- Validar integrações (email, SIEM)
- Testar restore de script de backup

**Anual:**
- Atualizar para versão mais recente do script
- Revisar política de retenção de relatórios
- Treinar nova equipe nas ferramentas

---

## Suporte e Contribuições

### Logs de Debug

Para reportar problemas, incluir:
```powershell
# Executar com verbose
.\ADHealthCheck.ps1 -Verbose | Out-File "debug.log"

# Informações de ambiente
Get-Module ActiveDirectory
$PSVersionTable
```

### Customização

O script é altamente customizável:
- **Limiares**: Ajustar `$CertWarningDays`, `$RidPoolWarningPercent`
- **Testes DCDiag**: Modificar array `$DCDIAG_TESTS`
- **Event IDs**: Adicionar/remover em `$CRITICAL_EVENT_IDS`
- **HTML/CSS**: Customizar seção `$css` para branding

### Melhorias Futuras (Roadmap)

- [ ] Suporte para Azure AD Connect health
- [ ] Exportação para JSON/XML
- [ ] Dashboards PowerBI nativos
- [ ] Comparação de relatórios (diff)
- [ ] Integração com Slack/Teams webhooks
- [ ] Suporte multi-forest nativo

---

## Changelog

### v2.4 (Atual)
- ✅ Monitoramento CPU com múltiplas amostras (5s)
- ✅ Detalhes de testes expandidos no HTML
- ✅ Filtros interativos por status
- ✅ Agrupamento de validações por DC
- ✅ Health score aprimorado com penalidades proporcionais

### v2.3
- Adicionada verificação de certificados
- Suporte para Microsoft Graph email
- Melhorias no layout HTML

### v2.2
- DCDiag completo integrado
- Análise de eventos críticos
- Exportação CSV

### v2.1
- Relatório HTML inicial
- Verificações básicas de hardware
- Email via SMTP

### v2.0
- Reescrita completa
- Suporte multi-DC
- Health scoring

---

## Licença

Este script é fornecido "como está", sem garantias. Use por sua conta e risco.

**Recomendado:** Testar em ambiente de laboratório antes de produção.

---

## Autor

**Script Version:** 2.4  
**Documentação:** LA  
**Última Atualização:** Outubro 2025

---

## Recursos Adicionais

### Links Úteis

- [Active Directory Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/)
- [DCDiag Documentation](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc731968(v=ws.11))
- [Repadmin Documentation](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc770963(v=ws.11))
- [FSMO Roles Explained](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/fsmo-roles)

### Comandos Úteis de Diagnóstico

```powershell
# Verificar replicação
repadmin /replsummary
repadmin /showrepl * /csv | ConvertFrom-Csv | Out-GridView

# Forçar replicação
repadmin /syncall /AdeP

# Verificar FSMO roles
netdom query fsmo

# Testar conectividade AD
Test-ComputerSecureChannel -Verbose

# Verificar registros DNS
nslookup -type=srv _ldap._tcp.dc._msdcs.contoso.com

# Backup de estado do sistema (System State)
wbadmin start systemstatebackup -backupTarget:E:

# Verificar integridade do database
ntdsutil "activate instance ntds" "files" "info" quit quit
```

---

**Fim da Documentação**
