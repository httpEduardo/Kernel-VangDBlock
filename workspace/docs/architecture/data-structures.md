# Especificação de Estruturas de Dados

## Visão Geral

Este documento detalha todas as estruturas de dados utilizadas no sistema, incluindo propósito, campos, alinhamento de memória e uso.

---

## 1. SYSTEM_BASELINE

**Propósito**: Armazenar snapshot inicial do estado do sistema (SSDT, IDT, drivers) para detecção de modificações.

**Localização**: NonPagedPool (memória sempre residente)

**Tamanho Estimado**: ~50KB (varia com número de syscalls e drivers)

### Definição

```c
typedef struct _SYSTEM_BASELINE {
    // === SSDT (System Service Dispatch Table) ===
    ULONG64 SsdtBaseAddress;              // Endereço base da SSDT (KeServiceDescriptorTable)
    ULONG SsdtEntryCount;                 // Número de syscalls (tipicamente ~460 no Win10)
    PULONG64 SsdtOriginalEntries;         // Array de endereços originais (alocado dinamicamente)
    
    // === IDT (Interrupt Descriptor Table) ===
    ULONG64 IdtBaseAddress;               // Endereço base da IDT (via SIDT)
    ULONG IdtEntryCount;                  // Sempre 256 (0x00 a 0xFF)
    PVOID* IdtOriginalHandlers;           // Array de ponteiros para handlers originais
    
    // === Drivers Confiáveis ===
    ULONG DriverCount;                    // Número de drivers na whitelist inicial
    PDRIVER_INFO TrustedDrivers;          // Array de informações de drivers (alocado dinamicamente)
    
    // === Hashes de Módulos Críticos ===
    UCHAR NtoskrnlHash[32];               // SHA256 de ntoskrnl.exe
    UCHAR HalHash[32];                    // SHA256 de hal.dll
    UCHAR Win32kHash[32];                 // SHA256 de win32k.sys
    
    // === Metadados ===
    LARGE_INTEGER CreationTime;           // Timestamp da criação do baseline (QueryPerformanceCounter)
    ULONG Version;                        // Versão do formato (para compatibilidade futura)
    ULONG Flags;                          // Flags de estado (ex: BASELINE_VALID, BASELINE_CORRUPTED)
    
} SYSTEM_BASELINE, *PSYSTEM_BASELINE;
```

### Campos Detalhados

| Campo | Tipo | Tamanho | Descrição |
|-------|------|---------|-----------|
| SsdtBaseAddress | ULONG64 | 8 bytes | Ponteiro para KeServiceDescriptorTable |
| SsdtEntryCount | ULONG | 4 bytes | Número de syscalls (obtido de KeServiceDescriptorTable->NumberOfServices) |
| SsdtOriginalEntries | PULONG64 | 8 bytes | Ponteiro para array alocado (SsdtEntryCount * 8 bytes) |
| IdtBaseAddress | ULONG64 | 8 bytes | Obtido via instrução SIDT |
| IdtEntryCount | ULONG | 4 bytes | Sempre 256 |
| IdtOriginalHandlers | PVOID* | 8 bytes | Ponteiro para array (256 * 8 bytes = 2KB) |
| DriverCount | ULONG | 4 bytes | Número de drivers no snapshot inicial |
| TrustedDrivers | PDRIVER_INFO | 8 bytes | Ponteiro para array de DRIVER_INFO |
| NtoskrnlHash | UCHAR[32] | 32 bytes | SHA256 do arquivo ntoskrnl.exe em disco |
| CreationTime | LARGE_INTEGER | 8 bytes | Timestamp de alta resolução |
| Version | ULONG | 4 bytes | Versão atual: 1 |
| Flags | ULONG | 4 bytes | Bitmask de status |

### Flags de Status

```c
#define BASELINE_VALID          0x00000001  // Baseline foi criado com sucesso
#define BASELINE_CORRUPTED      0x00000002  // Detectada corrupção nos dados
#define BASELINE_OUTDATED       0x00000004  // Baseline precisa ser recriado
#define BASELINE_SSDT_CAPTURED  0x00000008  // SSDT foi capturada
#define BASELINE_IDT_CAPTURED   0x00000010  // IDT foi capturada
```

### Uso

```c
// DriverEntry - Criação do baseline
PSYSTEM_BASELINE g_Baseline = NULL;

NTSTATUS CreateBaseline() {
    g_Baseline = (PSYSTEM_BASELINE)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(SYSTEM_BASELINE),
        'BSLN'
    );
    
    if (!g_Baseline) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(g_Baseline, sizeof(SYSTEM_BASELINE));
    
    // Capturar SSDT
    g_Baseline->SsdtBaseAddress = (ULONG64)KeServiceDescriptorTable;
    g_Baseline->SsdtEntryCount = KeServiceDescriptorTable->NumberOfServices;
    
    // Alocar array para entradas originais
    g_Baseline->SsdtOriginalEntries = (PULONG64)ExAllocatePoolWithTag(
        NonPagedPool,
        g_Baseline->SsdtEntryCount * sizeof(ULONG64),
        'SSDT'
    );
    
    // Copiar entradas originais...
    
    g_Baseline->Flags |= BASELINE_VALID | BASELINE_SSDT_CAPTURED;
    KeQuerySystemTime(&g_Baseline->CreationTime);
    
    return STATUS_SUCCESS;
}
```

---

## 2. SECURITY_EVENT

**Propósito**: Representar um evento de segurança detectado (hook, processo suspeito, etc.)

**Localização**: Buffer circular em NonPagedPool

**Tamanho**: 1024 bytes (alinhado)

### Definição

```c
typedef struct _SECURITY_EVENT {
    // === Identificação ===
    LARGE_INTEGER Timestamp;              // Timestamp do evento (KeQuerySystemTime)
    ULONG EventId;                        // ID único do tipo de evento (enum)
    ULONG Severity;                       // 1=INFO, 2=WARNING, 3=CRITICAL
    ULONG SequenceNumber;                 // Número sequencial (para ordenação)
    
    // === Contexto de Processo ===
    ULONG ProcessId;                      // PID do processo relacionado (0 se não aplicável)
    WCHAR ProcessName[260];               // Nome da imagem (obtido de EPROCESS)
    ULONG ParentProcessId;                // PID do processo pai
    ULONG SessionId;                      // Session ID (para ambientes multi-usuário)
    
    // === Contexto de Thread ===
    ULONG ThreadId;                       // TID da thread que causou o evento
    ULONG64 ThreadStartAddress;           // Endereço de início da thread (para análise)
    
    // === Detalhes Técnicos ===
    ULONG64 TargetAddress;                // Endereço de memória afetado
    ULONG64 OriginalValue;                // Valor original (ex: entrada SSDT)
    ULONG64 NewValue;                     // Novo valor detectado (hookado)
    
    UCHAR FileHash[32];                   // SHA256 do executável (se disponível)
    WCHAR FilePath[512];                  // Caminho completo do arquivo
    
    // === Resposta ===
    ULONG ActionTaken;                    // Ação executada (enum)
    ULONG RiskScore;                      // Score calculado (0-100)
    
    // === Descrição ===
    WCHAR Description[512];               // Descrição legível do evento
    
} SECURITY_EVENT, *PSECURITY_EVENT;
```

### Event IDs (Enum)

```c
typedef enum _EVENT_TYPE {
    EVENT_UNKNOWN = 0,
    
    // SSDT/IDT
    EVENT_SSDT_HOOK_DETECTED = 100,
    EVENT_SSDT_RESTORED = 101,
    EVENT_IDT_HOOK_DETECTED = 102,
    EVENT_IDT_RESTORED = 103,
    EVENT_INLINE_HOOK_DETECTED = 104,
    
    // Drivers
    EVENT_DRIVER_LOAD_BLOCKED = 200,
    EVENT_UNSIGNED_DRIVER_DETECTED = 201,
    EVENT_DRIVER_UNLOAD_BLOCKED = 202,
    EVENT_VULNERABLE_DRIVER_DETECTED = 203,
    
    // Processos
    EVENT_HIDDEN_PROCESS_DETECTED = 300,
    EVENT_PROCESS_KILLED = 301,
    EVENT_PROCESS_INJECTION_DETECTED = 302,
    EVENT_REMOTE_THREAD_BLOCKED = 303,
    
    // Filesystem
    EVENT_PROTECTED_FILE_ACCESS_DENIED = 400,
    EVENT_FILE_QUARANTINED = 401,
    EVENT_SUSPICIOUS_FILE_DELETED = 402,
    
    // Registry
    EVENT_REGISTRY_PROTECTION_TRIGGERED = 500,
    EVENT_BOOT_KEY_MODIFICATION_BLOCKED = 501,
    
    // Sistema
    EVENT_BASELINE_CREATED = 900,
    EVENT_BASELINE_CORRUPTED = 901,
    EVENT_DRIVER_INITIALIZED = 902,
    EVENT_DRIVER_UNLOADING = 903,
    
} EVENT_TYPE;
```

### Action Taken (Enum)

```c
typedef enum _ACTION_TYPE {
    ACTION_NONE = 0,            // Apenas detectado, nenhuma ação
    ACTION_LOGGED = 1,          // Evento registrado
    ACTION_BLOCKED = 2,         // Operação bloqueada
    ACTION_KILLED = 3,          // Processo terminado
    ACTION_RESTORED = 4,        // Estado restaurado (SSDT/IDT)
    ACTION_QUARANTINED = 5,     // Arquivo movido para quarentena
    ACTION_DELETED = 6,         // Arquivo deletado
    ACTION_ISOLATED = 7,        // Processo isolado (sem rede/filesystem)
} ACTION_TYPE;
```

---

## 3. LOG_BUFFER

**Propósito**: Buffer circular para armazenamento eficiente de eventos em alta frequência.

**Localização**: NonPagedPool

**Tamanho**: Configurável (padrão: 10.000 eventos = ~10MB)

### Definição

```c
typedef struct _LOG_BUFFER {
    // === Sincronização ===
    KSPIN_LOCK Lock;                      // Spinlock para acesso thread-safe
    KEVENT NewEventSignal;                // Evento para notificar thread de flush
    
    // === Índices Circulares ===
    volatile ULONG ReadIndex;             // Próxima posição a ler
    volatile ULONG WriteIndex;            // Próxima posição a escrever
    ULONG Capacity;                       // Capacidade total do buffer
    
    // === Estatísticas ===
    ULONG64 TotalEventsLogged;            // Total de eventos registrados (desde boot)
    ULONG64 EventsDropped;                // Eventos perdidos (buffer cheio)
    LARGE_INTEGER LastFlushTime;          // Timestamp do último flush
    
    // === Buffer de Eventos ===
    PSECURITY_EVENT Events;               // Array de eventos (alocado dinamicamente)
    
} LOG_BUFFER, *PLOG_BUFFER;
```

### Operações

#### LogEvent (Producer)

```c
VOID LogEvent(PSECURITY_EVENT Event) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_LogBuffer.Lock, &oldIrql);
    
    // Verificar se buffer está cheio
    ULONG nextWriteIndex = (g_LogBuffer.WriteIndex + 1) % g_LogBuffer.Capacity;
    if (nextWriteIndex == g_LogBuffer.ReadIndex) {
        // Buffer cheio - sobrescrever mais antigo
        g_LogBuffer.ReadIndex = (g_LogBuffer.ReadIndex + 1) % g_LogBuffer.Capacity;
        g_LogBuffer.EventsDropped++;
    }
    
    // Copiar evento
    RtlCopyMemory(
        &g_LogBuffer.Events[g_LogBuffer.WriteIndex],
        Event,
        sizeof(SECURITY_EVENT)
    );
    
    // Atribuir sequence number
    g_LogBuffer.Events[g_LogBuffer.WriteIndex].SequenceNumber = (ULONG)g_LogBuffer.TotalEventsLogged;
    
    // Avançar índice
    g_LogBuffer.WriteIndex = nextWriteIndex;
    g_LogBuffer.TotalEventsLogged++;
    
    KeReleaseSpinLock(&g_LogBuffer.Lock, oldIrql);
    
    // Sinalizar thread de flush
    KeSetEvent(&g_LogBuffer.NewEventSignal, IO_NO_INCREMENT, FALSE);
}
```

#### FlushEvents (Consumer)

```c
ULONG FlushLogBuffer(PSECURITY_EVENT OutBuffer, ULONG MaxEvents) {
    KIRQL oldIrql;
    ULONG eventsCopied = 0;
    
    KeAcquireSpinLock(&g_LogBuffer.Lock, &oldIrql);
    
    while (g_LogBuffer.ReadIndex != g_LogBuffer.WriteIndex && eventsCopied < MaxEvents) {
        RtlCopyMemory(
            &OutBuffer[eventsCopied],
            &g_LogBuffer.Events[g_LogBuffer.ReadIndex],
            sizeof(SECURITY_EVENT)
        );
        
        g_LogBuffer.ReadIndex = (g_LogBuffer.ReadIndex + 1) % g_LogBuffer.Capacity;
        eventsCopied++;
    }
    
    KeQuerySystemTime(&g_LogBuffer.LastFlushTime);
    
    KeReleaseSpinLock(&g_LogBuffer.Lock, oldIrql);
    
    return eventsCopied;
}
```

---

## 4. DRIVER_CONFIG

**Propósito**: Configuração do driver (recebida via IOCTL de user-mode)

**Localização**: NonPagedPool

**Tamanho**: ~4KB

### Definição

```c
typedef struct _DRIVER_CONFIG {
    // === Modo de Operação ===
    BOOLEAN AutoResponseEnabled;          // Se TRUE, executa ações automaticamente
    BOOLEAN DetectOnlyMode;               // Se TRUE, apenas detecta (não age)
    
    // === Thresholds ===
    ULONG RiskThreshold;                  // 0-100, padrão: 70
    ULONG CriticalThreshold;              // 0-100, padrão: 90 (kill imediato)
    
    // === Intervalos de Verificação ===
    ULONG SsdtCheckIntervalMs;            // Padrão: 500ms
    ULONG IdtCheckIntervalMs;             // Padrão: 1000ms
    ULONG DkomCheckIntervalMs;            // Padrão: 5000ms
    
    // === Políticas de Bloqueio ===
    BOOLEAN BlockUnsignedDrivers;         // Bloquear drivers não assinados
    BOOLEAN BlockUnsignedProcesses;       // Alertar sobre processos não assinados
    BOOLEAN BlockRemoteThreadCreation;    // Bloquear CreateRemoteThread
    
    // === Proteções ===
    BOOLEAN EnableFilesystemProtection;   // Habilitar minifilter
    BOOLEAN EnableRegistryProtection;     // Habilitar callback de registry
    BOOLEAN EnableNetworkIsolation;       // Isolar processos suspeitos da rede
    
    // === Whitelist ===
    ULONG WhitelistCount;                 // Número de hashes na whitelist
    UCHAR Whitelist[100][32];             // Até 100 hashes SHA256
    
    // === Logging ===
    ULONG LogBufferSize;                  // Tamanho do buffer circular (em eventos)
    BOOLEAN EnableEtwLogging;             // Habilitar ETW provider
    ULONG MinSeverityToLog;               // 1=INFO, 2=WARNING, 3=CRITICAL
    
} DRIVER_CONFIG, *PDRIVER_CONFIG;
```

### Valores Padrão

```c
DRIVER_CONFIG g_DefaultConfig = {
    .AutoResponseEnabled = TRUE,
    .DetectOnlyMode = FALSE,
    .RiskThreshold = 70,
    .CriticalThreshold = 90,
    .SsdtCheckIntervalMs = 500,
    .IdtCheckIntervalMs = 1000,
    .DkomCheckIntervalMs = 5000,
    .BlockUnsignedDrivers = TRUE,
    .BlockUnsignedProcesses = FALSE,
    .BlockRemoteThreadCreation = TRUE,
    .EnableFilesystemProtection = TRUE,
    .EnableRegistryProtection = TRUE,
    .EnableNetworkIsolation = FALSE,
    .WhitelistCount = 0,
    .LogBufferSize = 10000,
    .EnableEtwLogging = TRUE,
    .MinSeverityToLog = 2  // WARNING e acima
};
```

---

## 5. DRIVER_INFO

**Propósito**: Informações sobre um driver carregado (para whitelist e validação)

**Localização**: Array em SYSTEM_BASELINE

### Definição

```c
typedef struct _DRIVER_INFO {
    WCHAR DriverName[260];                // Nome do arquivo do driver
    WCHAR DriverPath[512];                // Caminho completo
    ULONG64 BaseAddress;                  // Endereço de carga em memória
    ULONG ImageSize;                      // Tamanho da imagem
    UCHAR Hash[32];                       // SHA256 do arquivo
    LARGE_INTEGER LoadTime;               // Timestamp de carregamento
    BOOLEAN IsSigned;                     // Se possui assinatura digital válida
    BOOLEAN IsMicrosoft;                  // Se é driver da Microsoft
    ULONG SignatureLevel;                 // Nível de assinatura (SE_SIGNING_LEVEL_*)
} DRIVER_INFO, *PDRIVER_INFO;
```

---

## 6. MONITOR_CONTEXT

**Propósito**: Contexto da thread de monitoramento contínuo

**Localização**: NonPagedPool

### Definição

```c
typedef struct _MONITOR_CONTEXT {
    PKTHREAD MonitorThread;               // Handle da thread de monitor
    BOOLEAN StopMonitoring;               // Flag para parar a thread
    KEVENT StopEvent;                     // Evento para sincronizar shutdown
    
    PSYSTEM_BASELINE Baseline;            // Referência ao baseline global
    PDRIVER_CONFIG Config;                // Referência à configuração
    
    // Estatísticas
    ULONG64 SsdtChecksPerformed;
    ULONG64 IdtChecksPerformed;
    ULONG64 DkomChecksPerformed;
    ULONG64 HooksDetected;
    
} MONITOR_CONTEXT, *PMONITOR_CONTEXT;
```

---

## Alinhamento e Otimizações

### Padding e Alignment

Todas as estruturas são naturalmente alinhadas em 8 bytes (x64). Campos ULONG64 sempre no início ou em offsets múltiplos de 8.

### Cache Line Optimization

Campos frequentemente acessados juntos são colocados próximos para melhor localidade de cache (ex: LOG_BUFFER.ReadIndex e WriteIndex).

### Memory Pool Tags

Todas as alocações usam tags únicas para facilitar debugging:

```c
#define TAG_BASELINE    'BSLN'
#define TAG_LOG_BUFFER  'LOGB'
#define TAG_EVENT       'EVNT'
#define TAG_CONFIG      'CNFG'
#define TAG_DRIVER_INFO 'DRVR'
```

---

## Validações

### Verificação de Integridade

```c
BOOLEAN ValidateBaseline(PSYSTEM_BASELINE Baseline) {
    if (!Baseline) return FALSE;
    if (!(Baseline->Flags & BASELINE_VALID)) return FALSE;
    if (Baseline->Version != BASELINE_VERSION) return FALSE;
    if (!Baseline->SsdtOriginalEntries) return FALSE;
    if (!Baseline->IdtOriginalHandlers) return FALSE;
    return TRUE;
}
```

### Checksum de Estruturas

Para detectar corrupção de memória, podemos adicionar checksums:

```c
typedef struct _SECURE_BASELINE {
    SYSTEM_BASELINE Data;
    ULONG Checksum;  // CRC32 ou hash dos dados
} SECURE_BASELINE;
```

---

## Referências

- [Windows Driver Kit: Memory Allocation](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/allocating-system-space-memory)
- [Spinlocks and Synchronization](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/spin-locks)
- [Data Alignment](https://docs.microsoft.com/en-us/cpp/cpp/alignment-cpp-declarations)
