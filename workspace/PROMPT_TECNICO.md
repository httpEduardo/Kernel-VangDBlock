# PROMPT TÉCNICO: Sistema de Cibersegurança em Nível de Kernel para Windows

## CONTEXTO DO PROJETO

Desenvolver um mecanismo avançado de cibersegurança que opera em **Kernel-mode** no Windows (NT Kernel), focado em **detecção e resposta automática** contra tentativas de interceptação, manipulação ou exploração de componentes internos do kernel.

---

## ESPECIFICAÇÕES TÉCNICAS CONFIRMADAS

### Plataforma e Arquitetura
- **Sistema Operacional**: Windows 10/11 (NT Kernel 10.0+)
- **Arquitetura**: x86_64
- **Modo de Operação**: Kernel-mode driver (KMDF - Kernel-Mode Driver Framework)
- **Abordagem**: Combinação de múltiplas técnicas (driver de filtro, hooks legítimos, callbacks, minifilter)

### Escopo Funcional
- **Detecção**: Monitoramento contínuo de estruturas críticas e comportamentos anômalos
- **Resposta Automática**: Ações imediatas (kill process, block load, quarantine, rollback)
- **Prevenção**: Opcional, via hardening de superfícies críticas

### Stack Técnico
- **Linguagem Principal**: C/C++ (WDK - Windows Driver Kit)
- **Framework**: KMDF (Kernel-Mode Driver Framework)
- **Sem Restrições**: Uso de APIs documentadas e não documentadas (com justificativa técnica)
- **Nível de Detalhamento**: Documentação executável (estruturas de dados, algoritmos, pseudo-código detalhado)

### Contexto de Implantação
- **Ambiente**: Computadores desktop/workstation (usuários finais, estações corporativas)
- **Compatibilidade**: Windows 10 22H2+ e Windows 11 (versões modernas apenas)
- **Observabilidade**: Logs imutáveis, integração com SIEM
- **Rollback**: Mecanismo de desinstalação segura e reversão de estado

### Documentação e Artefatos
- **Diagramas C4**: Context, Container, Component, Code
- **Fluxogramas**: Decisão de detecção e resposta
- **Matrizes**: Vetores de ataque vs mitigações
- **Especificações**: Estruturas internas, algoritmos, validações

---

## REQUISITOS FUNCIONAIS DETALHADOS

### 1. Monitoramento de Integridade Kernel

#### 1.1 Tabela de Processos (EPROCESS)
- Validar integridade da lista `PsActiveProcessHead`
- Detectar processos ocultos (DKOM - Direct Kernel Object Manipulation)
- Verificar assinaturas de imagens carregadas em memória
- Monitorar criação/término de processos via callbacks `PsSetCreateProcessNotifyRoutineEx`

#### 1.2 System Service Dispatch Table (SSDT)
- Hash inicial da SSDT no boot (baseline)
- Verificação periódica de modificações não autorizadas
- Detecção de hooks inline em syscalls
- Restauração automática de entradas adulteradas

#### 1.3 Interrupt Descriptor Table (IDT)
- Snapshot da IDT na inicialização
- Monitoramento de alterações em interrupt handlers
- Validação de endereços de handlers (devem estar em módulos assinados)

#### 1.4 Drivers e Módulos Carregados
- Lista de drivers autorizados (whitelist + assinatura digital)
- Detecção de drivers não assinados ou com assinatura inválida
- Monitoramento de carregamento via `PsSetLoadImageNotifyRoutine`
- Bloqueio automático de módulos suspeitos

### 2. Detecção de Hooks e Manipulações

#### 2.1 Kernel Hooks
- Detecção de hooks em:
  - SSDT (System Service Dispatch Table)
  - Shadow SSDT (Win32k.sys)
  - IRP (I/O Request Packet) handlers
  - Funções exportadas de drivers críticos (ntoskrnl.exe, hal.dll)
- Técnicas:
  - Análise de prologues de funções (busca por JMP, CALL não esperados)
  - Comparação com imagens em disco (verificação de integridade)

#### 2.2 User-Mode Hooks (visíveis do Kernel)
- Detecção de injeção de DLLs maliciosas via APC (Asynchronous Procedure Call)
- Monitoramento de `NtCreateThreadEx` com contexto remoto
- Análise de VADs (Virtual Address Descriptors) suspeitos

### 3. Prevenção Contra Rootkits

#### 3.1 Detecção de DKOM
- Varredura de discrepâncias entre:
  - Lista de processos (`PsActiveProcessHead`)
  - Handles de processos abertos
  - Informações em `PEB` (Process Environment Block)
- Reconstrução de listas adulteradas

#### 3.2 Detecção de TDL (Turla Driver Loader) e Bootkits
- Verificação de integridade do MBR/GPT
- Análise de drivers carregados antes do antivírus (Early Launch Anti-Malware - ELAM)
- Integração com Secure Boot e Measured Boot (TPM)

### 4. Observabilidade e Telemetria

#### 4.1 Sistema de Logs Imutáveis
- Buffer circular em memória não paginável (non-paged pool)
- Escrita periódica em arquivo protegido (user-mode service com privilégios mínimos)
- Formato estruturado (JSON ou ETW - Event Tracing for Windows)
- Campos obrigatórios:
  - Timestamp (QueryPerformanceCounter + SystemTime)
  - Tipo de evento (hook detectado, driver bloqueado, processo terminado)
  - Contexto (PID, driver name, endereço de memória, hash)
  - Ação tomada (block, kill, alert, rollback)

#### 4.2 Integração com SIEM
- Exportação de eventos via ETW (consumo externo)
- Suporte a forwarding para Syslog, Splunk, ELK
- Rate limiting para evitar flood

### 5. Resposta Automática

#### 5.1 Ações Imediatas
- **Kill Process**: `ZwTerminateProcess` para processos maliciosos
- **Block Driver Load**: Retornar erro em callback de load (`PsSetLoadImageNotifyRoutine`)
- **Quarantine**: Mover arquivo para diretório protegido (via minifilter)
- **Rollback**: Restaurar SSDT/IDT original
- **Isolamento**: Remover handles de rede, filesystem

#### 5.2 Critérios de Decisão
- Scoring de risco (heurísticas + machine learning básico)
- Whitelist de processos/drivers confiáveis
- Modo de operação configurável (detect-only, auto-respond)

### 6. Surface Hardening

#### 6.1 Proteção de Estruturas Críticas
- Memory Descriptor Lists (MDLs) para páginas críticas (read-only após boot)
- Guard pages em torno de estruturas sensíveis
- Randomização de offsets internos (ASLR em kernel-space)

#### 6.2 Isolamento de Superfícies de Ataque
- Minifilter para filesystem (controle de acesso a arquivos críticos)
- Network filter para bloquear comunicação C2
- Registry filter para proteger chaves críticas (drivers, boot)

---

## REQUISITOS NÃO FUNCIONAIS

### Desempenho
- Overhead máximo de CPU: 3% em operação normal
- Latência de detecção: <100ms após evento suspeito
- Verificação periódica de SSDT/IDT: a cada 500ms
- Otimização de callbacks (evitar locking excessivo)

### Segurança
- Driver assinado digitalmente (obrigatório para Windows 10+)
- Proteção contra unload malicioso do próprio driver
- Mecanismo de auto-verificação (verificar integridade do próprio código)
- Comunicação kernel ↔ user-mode via IOCTL com validação rigorosa

### Compatibilidade
- Windows 10 22H2+ (build 19045+)
- Windows 11 21H2+ (build 22000+)
- Não há necessidade de suportar versões antigas

### Auditoria e Compliance
- Logs imutáveis com timestamp confiável (TSC + NTP sync)
- Trilha completa de ações tomadas (auditável)
- Suporte a exportação de logs para análise forense

### Rollback e Recuperação
- Desinstalação limpa do driver (via `sc delete` ou GUI)
- Restauração de estado original do sistema (SSDT, IDT)
- Modo seguro: desabilitar proteções em Safe Mode (evitar lock-out)

---

## ARQUITETURA DE ALTO NÍVEL

### Camadas e Componentes

```
┌─────────────────────────────────────────────────────────────┐
│                    USER MODE (Ring 3)                        │
├─────────────────────────────────────────────────────────────┤
│  Service de Controle (C# ou C++)                             │
│  - Configuração (whitelist, thresholds)                      │
│  - Consumo de logs do driver                                 │
│  - Interface para SIEM/Dashboard                             │
│  - Comunicação via DeviceIoControl (IOCTL)                   │
└────────────────────┬────────────────────────────────────────┘
                     │ IOCTL
┌────────────────────▼────────────────────────────────────────┐
│                   KERNEL MODE (Ring 0)                       │
├─────────────────────────────────────────────────────────────┤
│  Driver Principal (KMDF)                                     │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Módulo de Inicialização (DriverEntry)                 │  │
│  │ - Registrar callbacks                                 │  │
│  │ - Baseline inicial (SSDT, IDT, drivers)               │  │
│  │ - Criar device object e symbolic link                 │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Módulo de Monitoramento                               │  │
│  │ - Thread de verificação periódica                     │  │
│  │ - Callbacks (Process, LoadImage, Registry)            │  │
│  │ - Detecção de DKOM                                    │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Módulo de Análise                                     │  │
│  │ - Heurísticas de comportamento                        │  │
│  │ - Scoring de risco                                    │  │
│  │ - Decisão de ação (allow, block, kill)                │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Módulo de Resposta                                    │  │
│  │ - Executar ações (kill, block, quarantine)            │  │
│  │ - Rollback de modificações                            │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Módulo de Logging                                     │  │
│  │ - Buffer circular em memória                          │  │
│  │ - ETW provider                                        │  │
│  │ - Queue para user-mode service                        │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Minifilter (Filesystem)                               │  │
│  │ - Proteção de arquivos críticos                       │  │
│  │ - Quarentena de executáveis suspeitos                 │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## FLUXOS OPERACIONAIS DETALHADOS

### Fluxo 1: Detecção de Hook na SSDT

```
1. Thread de verificação periódica acorda (KeDelayExecutionThread)
2. Obter endereço base da SSDT (KeServiceDescriptorTable)
3. Para cada entrada na SSDT:
   a. Ler endereço da função (descomprimir offset no Windows 10+)
   b. Comparar com baseline armazenado
   c. Se diferente:
      i.  Verificar se endereço está em módulo assinado
      ii. Se não assinado ou fora de ntoskrnl.exe:
          - Calcular hash da função hookada
          - Logar evento (SSDT_HOOK_DETECTED)
          - Decisão: restaurar SSDT ou alertar
          - Restaurar: copiar entrada original do baseline
4. Dormir 500ms (configurável)
```

### Fluxo 2: Callback de Carregamento de Driver

```
1. Sistema tenta carregar driver (PsSetLoadImageNotifyRoutine)
2. Driver recebe notificação com FullImageName
3. Verificar assinatura digital:
   a. Chamar CiValidateImageHeader (API não documentada)
   b. Se não assinado ou assinatura inválida:
      i.  Logar evento (DRIVER_LOAD_BLOCKED)
      ii. Retornar STATUS_ACCESS_DENIED (bloqueia load)
4. Verificar whitelist:
   a. Hash SHA256 do arquivo
   b. Comparar com whitelist em memória
   c. Se não na whitelist e não da Microsoft:
      i.  Calcular score de risco (heurísticas)
      ii. Se score > threshold: bloquear
5. Permitir carregamento (STATUS_SUCCESS)
```

### Fluxo 3: Detecção de Processo Oculto (DKOM)

```
1. Thread de verificação periódica
2. Varrer PsActiveProcessHead (lista encadeada):
   a. Para cada EPROCESS, extrair PID e ImageName
   b. Armazenar em array temporário
3. Varrer handle table do System process:
   a. Obter handles de tipo Process
   b. Comparar PIDs com array anterior
   c. Se PID no handle table mas NÃO em PsActiveProcessHead:
      i.  Processo oculto detectado (DKOM)
      ii. Logar evento (HIDDEN_PROCESS_DETECTED)
      iii. Ação: tentar re-linkar EPROCESS ou kill
4. Repetir a cada 5 segundos
```

### Fluxo 4: Resposta Automática - Kill Process

```
1. Evento detectado (ex: hook em SSDT por PID 1234)
2. Módulo de Análise calcula score:
   a. Processo não assinado: +30
   b. Hook em syscall crítico (NtReadVirtualMemory): +40
   c. Comunicação de rede suspeita: +20
   d. Score total: 90 (threshold: 70)
3. Decisão: KILL_PROCESS
4. Módulo de Resposta:
   a. Obter PEPROCESS via PsLookupProcessByProcessId
   b. Chamar ZwTerminateProcess(handle, STATUS_VIRUS_INFECTED)
   c. Logar ação (PROCESS_KILLED, PID=1234, Reason=SSDT_HOOK)
   d. Opcional: deletar executável via minifilter
5. Notificar user-mode service (IOCTL ou ETW)
```

---

## ESTRUTURAS DE DADOS PRINCIPAIS

### 1. Baseline Snapshot (inicialização)

```c
typedef struct _SYSTEM_BASELINE {
    // SSDT
    ULONG64 SsdtBaseAddress;
    ULONG SsdtEntryCount;
    ULONG64* SsdtOriginalEntries; // array de endereços originais
    
    // IDT
    ULONG64 IdtBaseAddress;
    ULONG IdtEntryCount;
    PVOID* IdtOriginalHandlers; // array de handlers originais
    
    // Drivers confiáveis (whitelist)
    ULONG DriverCount;
    DRIVER_INFO* TrustedDrivers; // array de {hash, nome, base address}
    
    // Hash de módulos críticos
    UCHAR NtoskrnlHash[32]; // SHA256
    UCHAR HalHash[32];
    
    LARGE_INTEGER CreationTime; // timestamp do baseline
} SYSTEM_BASELINE, *PSYSTEM_BASELINE;
```

### 2. Event Log Entry

```c
typedef struct _SECURITY_EVENT {
    LARGE_INTEGER Timestamp;
    ULONG EventId;
    ULONG Severity; // 1=INFO, 2=WARNING, 3=CRITICAL
    
    ULONG ProcessId;
    WCHAR ProcessName[260];
    
    ULONG64 TargetAddress; // endereço de memória afetado
    ULONG64 OriginalValue;
    ULONG64 NewValue;
    
    UCHAR FileHash[32]; // SHA256 do executável (se aplicável)
    
    ULONG ActionTaken; // NONE, BLOCK, KILL, ROLLBACK, QUARANTINE
    
    WCHAR Description[512];
} SECURITY_EVENT, *PSECURITY_EVENT;
```

### 3. Circular Buffer de Logs

```c
typedef struct _LOG_BUFFER {
    KSPIN_LOCK Lock;
    ULONG ReadIndex;
    ULONG WriteIndex;
    ULONG Capacity; // ex: 10000 eventos
    SECURITY_EVENT* Events; // array alocado em NonPagedPool
    KEVENT NewEventSignal; // para notificar thread de flush
} LOG_BUFFER, *PLOG_BUFFER;
```

### 4. Configuração (recebida via IOCTL)

```c
typedef struct _DRIVER_CONFIG {
    BOOLEAN AutoResponseEnabled;
    ULONG RiskThreshold; // 0-100
    ULONG SsdtCheckIntervalMs;
    ULONG IdtCheckIntervalMs;
    BOOLEAN BlockUnsignedDrivers;
    BOOLEAN EnableFilesystemProtection;
    // Whitelist de processos/drivers (hashs)
    ULONG WhitelistCount;
    UCHAR Whitelist[100][32]; // até 100 hashes SHA256
} DRIVER_CONFIG, *PDRIVER_CONFIG;
```

---

## ANÁLISE DE RISCO E MITIGAÇÕES

### Matriz de Vetores de Ataque

| Vetor de Ataque | Impacto | Probabilidade | Detecção | Mitigação | Controle |
|----------------|---------|---------------|----------|-----------|----------|
| Hook inline em syscall (SSDT) | CRÍTICO | Alta | Verificação periódica + hash | Restauração automática | Logs imutáveis |
| Driver rootkit não assinado | CRÍTICO | Média | Callback LoadImage + verificação assinatura | Bloqueio de carga | Whitelist |
| DKOM (ocultar processo) | ALTO | Média | Varredura dupla (lista vs handles) | Re-link ou kill | Auditoria contínua |
| Injeção de DLL via APC | ALTO | Alta | Callback de thread remoto | Block CreateRemoteThread | Proteção de VADs |
| Bootkit (MBR/GPT) | CRÍTICO | Baixa | Verificação de integridade boot + ELAM | Restauração MBR | Secure Boot + TPM |
| Exploração de driver legítimo (BYOVD) | ALTO | Média | Whitelist de drivers + versioning | Bloqueio de versões vulneráveis | Atualização forçada |
| Desativação do próprio driver | ALTO | Baixa | Auto-verificação + proteção de handle | Bloquear ZwUnloadDriver | Watchdog em user-mode |
| Evasão via timing (TOCTOU) | MÉDIO | Baixa | Locks consistentes + verificação dupla | Atomic operations | Retry logic |

---

## BLUEPRINT TÉCNICO MODULAR

### Módulo 1: Inicialização (DriverEntry)

**Responsabilidades:**
- Alocar memória para baseline (NonPagedPool)
- Capturar snapshot inicial de SSDT, IDT, drivers carregados
- Calcular hashes de ntoskrnl.exe, hal.dll
- Registrar callbacks (Process, LoadImage, CreateThread, Registry)
- Criar device object (`\Device\KernelSecDriver`)
- Criar symbolic link (`\??\KernelSecDriver`)
- Iniciar thread de verificação periódica
- Inicializar minifilter (se habilitado)

**Dependências:**
- APIs: `PsSetCreateProcessNotifyRoutineEx`, `PsSetLoadImageNotifyRoutine`, `IoCreateDevice`, `IoCreateSymbolicLink`, `PsCreateSystemThread`

**Pontos Críticos:**
- Falha em obter SSDT/IDT: abortar carregamento
- Falha em registrar callbacks: desregistrar anteriores e abortar

---

### Módulo 2: Monitoramento Contínuo

**Responsabilidades:**
- Thread dedicado (KeDelayExecutionThread)
- Verificar SSDT/IDT a cada intervalo configurado
- Detectar drivers não autorizados (varredura de PsLoadedModuleList)
- Detectar processos ocultos (DKOM)

**Algoritmos:**

**Verificação SSDT (Windows 10+):**
```c
// SSDT entries são offsets comprimidos (4 bytes)
// Endereço real = base + (entry >> 4)
PVOID GetSyscallAddress(ULONG index) {
    PULONG table = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
    LONG offset = table[index] >> 4;
    return (PVOID)((ULONG64)table + offset);
}

// Comparar com baseline
if (GetSyscallAddress(index) != baseline->SsdtOriginalEntries[index]) {
    // Hook detectado
}
```

**Detecção DKOM:**
```c
// Varrer lista de processos
LIST_ENTRY* entry = PsActiveProcessHead->Flink;
while (entry != PsActiveProcessHead) {
    PEPROCESS process = CONTAINING_RECORD(entry, EPROCESS, ActiveProcessLinks);
    ULONG pid = PsGetProcessId(process);
    // Armazenar PID
    entry = entry->Flink;
}

// Varrer handle table
HANDLE hProcess;
NTSTATUS status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, NULL, &clientId);
// Se sucesso mas PID não estava na lista -> DKOM
```

---

### Módulo 3: Análise e Decisão

**Responsabilidades:**
- Receber eventos de detecção
- Calcular score de risco
- Decidir ação (allow, block, kill, rollback)

**Heurísticas:**

| Indicador | Pontos |
|-----------|--------|
| Processo não assinado | +30 |
| Driver não assinado | +50 |
| Hook em syscall crítico (Read/Write VM) | +40 |
| DKOM detectado | +60 |
| Comunicação com IP em blacklist | +35 |
| Modificação de registro (Run keys) | +25 |
| Injeção de código remoto | +45 |

**Threshold padrão: 70 pontos**

**Pseudo-código:**
```c
ULONG CalculateRiskScore(PSECURITY_EVENT event) {
    ULONG score = 0;
    if (!IsProcessSigned(event->ProcessId)) score += 30;
    if (event->EventId == EVENT_SSDT_HOOK) score += 40;
    if (event->EventId == EVENT_DKOM) score += 60;
    // ... mais regras
    return score;
}

VOID DecideAction(PSECURITY_EVENT event) {
    ULONG score = CalculateRiskScore(event);
    if (score >= Config.RiskThreshold && Config.AutoResponseEnabled) {
        if (event->EventId == EVENT_SSDT_HOOK) {
            RestoreSsdt(event->TargetAddress);
        } else if (event->EventId == EVENT_MALICIOUS_DRIVER) {
            BlockDriverLoad(event->TargetAddress);
        } else if (score >= 80) {
            KillProcess(event->ProcessId);
        }
    }
    LogEvent(event);
}
```

---

### Módulo 4: Resposta Automática

**Responsabilidades:**
- Executar ações decididas pelo módulo de análise
- Garantir atomicidade (evitar race conditions)
- Logar todas as ações

**Ações Implementadas:**

**1. Restaurar SSDT:**
```c
VOID RestoreSsdt(ULONG index) {
    KIRQL oldIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql); // prevenir preempção
    
    // Desabilitar WP (Write Protect) em CR0
    ULONG64 cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000);
    
    // Restaurar entrada
    PULONG table = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
    table[index] = EncodeOffset(baseline->SsdtOriginalEntries[index]);
    
    // Reabilitar WP
    __writecr0(cr0);
    
    KeLowerIrql(oldIrql);
}
```

**2. Kill Process:**
```c
VOID KillProcess(ULONG pid) {
    HANDLE hProcess;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId = { (HANDLE)pid, NULL };
    
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    NTSTATUS status = ZwOpenProcess(&hProcess, PROCESS_TERMINATE, &objAttr, &clientId);
    
    if (NT_SUCCESS(status)) {
        ZwTerminateProcess(hProcess, STATUS_VIRUS_INFECTED);
        ZwClose(hProcess);
    }
}
```

**3. Bloquear Carregamento de Driver:**
```c
VOID LoadImageNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
) {
    if (ImageInfo->SystemModeImage) { // é driver
        if (!IsImageSigned(FullImageName)) {
            ImageInfo->ImageSignatureLevel = SE_SIGNING_LEVEL_UNCHECKED;
            // Isso faz o sistema rejeitar o load
        }
    }
}
```

---

### Módulo 5: Logging e Telemetria

**Responsabilidades:**
- Buffer circular em memória
- Flush periódico para user-mode service
- Emissão de eventos ETW

**Implementação Buffer Circular:**
```c
VOID LogEvent(PSECURITY_EVENT event) {
    KeAcquireSpinLock(&LogBuffer.Lock, &oldIrql);
    
    // Copiar evento
    RtlCopyMemory(&LogBuffer.Events[LogBuffer.WriteIndex], event, sizeof(SECURITY_EVENT));
    
    // Avançar índice
    LogBuffer.WriteIndex = (LogBuffer.WriteIndex + 1) % LogBuffer.Capacity;
    
    // Se buffer cheio, sobrescrever mais antigo (circular)
    if (LogBuffer.WriteIndex == LogBuffer.ReadIndex) {
        LogBuffer.ReadIndex = (LogBuffer.ReadIndex + 1) % LogBuffer.Capacity;
    }
    
    KeReleaseSpinLock(&LogBuffer.Lock, oldIrql);
    
    // Sinalizar thread de flush
    KeSetEvent(&LogBuffer.NewEventSignal, IO_NO_INCREMENT, FALSE);
}
```

**Integração ETW:**
```c
// Registrar provider
EventRegister(&GUID_KERNELSEC_PROVIDER, NULL, NULL, &RegHandle);

// Escrever evento
EventWriteString(RegHandle, 0, 0, event->Description);
```

---

### Módulo 6: Minifilter (Filesystem)

**Responsabilidades:**
- Proteger arquivos críticos (drivers, executáveis do sistema)
- Quarentena de executáveis suspeitos
- Bloquear modificação de registry keys críticas

**Callbacks de Interesse:**
- `PreCreate`: verificar acesso a arquivos protegidos
- `PreWrite`: impedir modificação de drivers assinados
- `PreSetInformation`: bloquear rename/delete de arquivos críticos

**Exemplo:**
```c
FLT_PREOP_CALLBACK_STATUS PreWriteCallback(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
) {
    // Obter nome do arquivo
    PFLT_FILE_NAME_INFORMATION nameInfo;
    FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &nameInfo);
    
    // Se arquivo está em C:\Windows\System32\drivers\
    if (IsProtectedPath(nameInfo->Name)) {
        // Bloquear escrita
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        return FLT_PREOP_COMPLETE;
    }
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
```

---

## COMUNICAÇÃO KERNEL ↔ USER MODE

### IOCTL Codes (DeviceIoControl)

```c
#define IOCTL_KERNELSEC_GET_CONFIG    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KERNELSEC_SET_CONFIG    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KERNELSEC_GET_EVENTS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_KERNELSEC_ADD_WHITELIST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

### Dispatcher IOCTL

```c
NTSTATUS DeviceIoControlDispatcher(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    
    switch (controlCode) {
        case IOCTL_KERNELSEC_SET_CONFIG:
            // Validar tamanho do buffer
            if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(DRIVER_CONFIG)) {
                PDRIVER_CONFIG newConfig = (PDRIVER_CONFIG)Irp->AssociatedIrp.SystemBuffer;
                // Validar valores
                if (newConfig->RiskThreshold <= 100) {
                    RtlCopyMemory(&Config, newConfig, sizeof(DRIVER_CONFIG));
                    status = STATUS_SUCCESS;
                }
            }
            break;
            
        case IOCTL_KERNELSEC_GET_EVENTS:
            // Copiar eventos do buffer circular
            PSECURITY_EVENT outBuffer = (PSECURITY_EVENT)Irp->AssociatedIrp.SystemBuffer;
            ULONG maxEvents = stack->Parameters.DeviceIoControl.OutputBufferLength / sizeof(SECURITY_EVENT);
            ULONG eventsCopied = FlushLogBuffer(outBuffer, maxEvents);
            Irp->IoStatus.Information = eventsCopied * sizeof(SECURITY_EVENT);
            status = STATUS_SUCCESS;
            break;
    }
    
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
```

---

## CONSIDERAÇÕES DE ASSINATURA E PERMISSÕES

### Assinatura de Driver (Obrigatório no Windows 10+)

**Processo:**
1. Obter certificado EV (Extended Validation) de CA aprovada (DigiCert, Sectigo)
2. Usar Windows Hardware Dev Center para attestation signing
3. Assinar arquivo .sys com SignTool:
   ```cmd
   signtool sign /v /fd sha256 /tr http://timestamp.digicert.com /td sha256 /sha1 <cert_thumbprint> KernelSecDriver.sys
   ```

**Alternativa para Teste:**
- Habilitar Test Signing no sistema:
  ```cmd
  bcdedit /set testsigning on
  ```
- Criar certificado self-signed e instalar no Trusted Root

### Permissões Necessárias

**Driver (Kernel):**
- DRIVER_INITIALIZE: registrar callbacks
- SeLoadDriverPrivilege: carregar/descarregar drivers
- SeDebugPrivilege: abrir handles de processos arbitrários
- SeTcbPrivilege: atuar como parte do TCB (Trusted Computing Base)

**Service (User-Mode):**
- SeServiceLogonRight: rodar como serviço
- Acesso ao device object: `\\.\KernelSecDriver`
- Privilégios mínimos (princípio de least privilege)

### Proteção Contra Unload Malicioso

**Estratégia 1: Incrementar referência do próprio driver**
```c
PDRIVER_OBJECT g_DriverObject;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    g_DriverObject = DriverObject;
    ObReferenceObject(DriverObject); // incrementa ref count
    // ... resto da inicialização
}

// No DriverUnload, só decrementar se unload for legítimo
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    if (IsLegitimateUnload()) { // verificar via IOCTL específico
        ObDereferenceObject(g_DriverObject);
    } else {
        // Rejeitar unload
        return;
    }
}
```

**Estratégia 2: Watchdog em user-mode**
- Service monitora presença do driver (via IOCTL ping)
- Se driver desaparece sem shutdown planejado: logar incidente crítico + alerta

---

## ROLLBACK E DESINSTALAÇÃO SEGURA

### Procedimento de Rollback Manual

**1. Via Service de Controle:**
```c
// User-mode envia IOCTL para desabilitar proteções
DeviceIoControl(hDevice, IOCTL_KERNELSEC_DISABLE_PROTECTION, ...);

// Driver restaura estado original:
// - Remove hooks próprios (se houver)
// - Não restaura hooks de terceiros (deixar como está)
// - Desregistra callbacks
```

**2. Desinstalação Completa:**
```cmd
sc stop KernelSecDriver
sc delete KernelSecDriver
del C:\Windows\System32\drivers\KernelSecDriver.sys
```

### Modo Seguro (Safe Mode)

**Comportamento:**
- Detectar boot em Safe Mode: verificar registry `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option`
- Se Safe Mode: não carregar proteções (evitar lock-out do sistema)
- Apenas logar eventos (modo passivo)

---

## DIAGRAMAS C4

### Nível 1: Context Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    CONTEXTO DE SISTEMA                       │
└─────────────────────────────────────────────────────────────┘

          ┌──────────────┐
          │   Usuário    │
          │   (Admin)    │
          └──────┬───────┘
                 │ configura/monitora
                 ▼
       ┌─────────────────────┐
       │ Sistema de          │◄────────── SIEM/Dashboard
       │ Cibersegurança      │            (externo)
       │ Kernel-Mode         │
       └─────────┬───────────┘
                 │ protege
                 ▼
       ┌─────────────────────┐
       │  Windows OS         │
       │  (Kernel/Drivers)   │
       └─────────────────────┘
```

### Nível 2: Container Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    CONTAINERS (COMPONENTES)                  │
└─────────────────────────────────────────────────────────────┘

┌──────────────┐
│  Dashboard   │───────┐
│  Web UI      │       │ REST API
└──────────────┘       │
                       ▼
                ┌──────────────┐
                │  Service     │ (User-Mode)
                │  de Controle │
                │  (Windows    │
                │   Service)   │
                └──────┬───────┘
                       │ IOCTL
                       ▼
                ┌──────────────────────┐
                │  Driver Kernel-Mode  │
                │  (KernelSecDriver)   │
                ├──────────────────────┤
                │ - Monitor            │
                │ - Análise            │
                │ - Resposta           │
                │ - Logging            │
                │ - Minifilter         │
                └──────┬───────────────┘
                       │ callbacks/hooks
                       ▼
                ┌──────────────────────┐
                │  Windows NT Kernel   │
                │  (ntoskrnl.exe)      │
                └──────────────────────┘
```

### Nível 3: Component Diagram (Driver)

```
┌─────────────────────────────────────────────────────────────┐
│              COMPONENTES INTERNOS DO DRIVER                  │
└─────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│                    DriverEntry                              │
│  - Inicialização                                            │
│  - Baseline snapshot                                        │
└──────────┬─────────────────────────────────────────────────┘
           │
           ├───► ┌─────────────────────┐
           │     │ Módulo Monitor      │
           │     │ - Thread periódico  │
           │     │ - Callbacks         │
           │     └──────┬──────────────┘
           │            │ eventos
           │            ▼
           ├───► ┌─────────────────────┐
           │     │ Módulo Análise      │
           │     │ - Heurísticas       │
           │     │ - Risk scoring      │
           │     └──────┬──────────────┘
           │            │ decisões
           │            ▼
           ├───► ┌─────────────────────┐
           │     │ Módulo Resposta     │
           │     │ - Kill/Block/Restore│
           │     └──────┬──────────────┘
           │            │
           │            ├───► ┌─────────────────┐
           │            │     │ Logging Buffer  │
           │            │     │ (circular)      │
           │            │     └─────────────────┘
           │            │
           └────────────┴───► ┌─────────────────┐
                              │ Minifilter      │
                              │ (filesystem)    │
                              └─────────────────┘
```

---

## ROADMAP DE IMPLEMENTAÇÃO (SEM CÓDIGO)

### Fase 1: Fundação (Semana 1-2)
- Criar projeto WDK no Visual Studio
- Implementar DriverEntry e DriverUnload básicos
- Device object e IOCTL dispatcher
- Baseline de SSDT (captura inicial)
- Teste: carregar/descarregar driver com sucesso

### Fase 2: Monitoramento (Semana 3-4)
- Thread de verificação periódica
- Callbacks (Process, LoadImage)
- Detecção de hook em SSDT (comparação com baseline)
- Sistema de logging básico (buffer circular)
- Teste: detectar hook manual em syscall

### Fase 3: Resposta Automática (Semana 5-6)
- Implementar restauração de SSDT
- Kill process via ZwTerminateProcess
- Bloqueio de driver não assinado
- Teste: resposta automática a hook simulado

### Fase 4: Análise Avançada (Semana 7-8)
- Heurísticas de scoring
- Detecção de DKOM
- Monitoramento de IDT
- Teste: detectar processo oculto

### Fase 5: Filesystem Protection (Semana 9-10)
- Minifilter registration
- Proteção de arquivos críticos
- Quarentena de executáveis suspeitos
- Teste: impedir modificação de driver do sistema

### Fase 6: User-Mode Service (Semana 11-12)
- Criar Windows Service em C#
- Comunicação via IOCTL com driver
- Interface de configuração (whitelist, thresholds)
- Dashboard básico (logs em tempo real)
- Teste: configurar e monitorar via service

### Fase 7: Observabilidade (Semana 13-14)
- Integração ETW
- Export de logs para SIEM (Syslog/JSON)
- Logs imutáveis (assinatura ou HMAC)
- Teste: consumir eventos via ETW consumer

### Fase 8: Hardening e Testes (Semana 15-16)
- Proteção contra unload malicioso
- Auto-verificação de integridade
- Assinatura digital do driver
- Testes de stress (overhead de CPU)
- Testes de segurança (bypass attempts)

---

## MÉTRICAS DE SUCESSO

### Detecção
- Taxa de detecção de hooks (SSDT/IDT): > 99%
- Falsos positivos: < 1% (com whitelist bem configurada)
- Tempo de detecção: < 100ms após evento

### Desempenho
- Overhead de CPU em idle: < 1%
- Overhead de CPU sob carga: < 3%
- Latência de IOCTL: < 10ms
- Memória consumida: < 50MB (NonPagedPool)

### Resposta
- Tempo de kill process: < 50ms após decisão
- Taxa de sucesso de rollback (SSDT): > 95%
- Taxa de bloqueio de drivers maliciosos: > 98%

### Observabilidade
- Logs perdidos (buffer overflow): < 0.1%
- Latência de flush para user-mode: < 500ms
- Integridade de logs: 100% (verificação HMAC)

---

## PRÓXIMOS PASSOS

1. **Revisar este documento técnico** e solicitar esclarecimentos, se necessário
2. **Validar arquitetura** com stakeholders
3. **Criar diagramas C4 detalhados** (usar Draw.io, Mermaid, ou PlantUML)
4. **Definir prioridades** de features (MVP vs. full scope)
5. **Iniciar Fase 1** (Fundação) conforme roadmap
6. **Estabelecer ambiente de desenvolvimento:**
   - Windows 10/11 com WDK instalado
   - Visual Studio 2022
   - VM de teste (snapshot antes de cada teste)
   - Debugger kernel (WinDbg + serial connection)

---

## GLOSSÁRIO

- **SSDT**: System Service Dispatch Table (tabela de syscalls)
- **IDT**: Interrupt Descriptor Table (tabela de interrupções)
- **DKOM**: Direct Kernel Object Manipulation (manipulação direta de objetos do kernel)
- **EPROCESS**: Estrutura interna do kernel representando um processo
- **APC**: Asynchronous Procedure Call (chamada assíncrona de procedimento)
- **KMDF**: Kernel-Mode Driver Framework
- **IOCTL**: Input/Output Control (comunicação com driver)
- **ETW**: Event Tracing for Windows
- **VAD**: Virtual Address Descriptor (descritor de endereço virtual)
- **ELAM**: Early Launch Anti-Malware
- **BYOVD**: Bring Your Own Vulnerable Driver

---

**DOCUMENTO GERADO PARA:**
- Projeto: Sistema de Cibersegurança Kernel-Mode Windows
- Data: 2025-11-19
- Destinatário: Codex / Compile LUT
- Autor: GitHub Copilot (Claude Sonnet 4.5)
