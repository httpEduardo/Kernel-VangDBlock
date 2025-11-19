# Documentação de APIs e IOCTLs

## Visão Geral

Este documento especifica todas as interfaces de comunicação entre user-mode e kernel-mode, incluindo códigos IOCTL, estruturas de dados e exemplos de uso.

---

## 1. Device Interface

### Device Name
```
\Device\KernelSecDriver
```

### Symbolic Link
```
\??\KernelSecDriver
\Global??\KernelSecDriver (acessível de todas as sessões)
```

### Acesso User-Mode
```c
// C/C++
HANDLE hDevice = CreateFileW(
    L"\\\\.\\KernelSecDriver",
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL
);

if (hDevice == INVALID_HANDLE_VALUE) {
    printf("Erro ao abrir device: %d\n", GetLastError());
    return FALSE;
}
```

```csharp
// C#
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

SafeFileHandle hDevice = CreateFile(
    @"\\.\KernelSecDriver",
    FileAccess.ReadWrite,
    FileShare.None,
    IntPtr.Zero,
    FileMode.Open,
    0,
    IntPtr.Zero
);

if (hDevice.IsInvalid) {
    throw new Win32Exception(Marshal.GetLastWin32Error());
}
```

---

## 2. IOCTL Codes

### Definição de Macros

```c
#define FILE_DEVICE_KERNELSEC   0x8000

#define IOCTL_KERNELSEC_GET_CONFIG \
    CTL_CODE(FILE_DEVICE_KERNELSEC, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_KERNELSEC_SET_CONFIG \
    CTL_CODE(FILE_DEVICE_KERNELSEC, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_KERNELSEC_GET_EVENTS \
    CTL_CODE(FILE_DEVICE_KERNELSEC, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_KERNELSEC_ADD_WHITELIST \
    CTL_CODE(FILE_DEVICE_KERNELSEC, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_KERNELSEC_REMOVE_WHITELIST \
    CTL_CODE(FILE_DEVICE_KERNELSEC, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_KERNELSEC_GET_STATS \
    CTL_CODE(FILE_DEVICE_KERNELSEC, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_KERNELSEC_RESET_BASELINE \
    CTL_CODE(FILE_DEVICE_KERNELSEC, 0x806, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_KERNELSEC_ENABLE_PROTECTION \
    CTL_CODE(FILE_DEVICE_KERNELSEC, 0x807, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_KERNELSEC_DISABLE_PROTECTION \
    CTL_CODE(FILE_DEVICE_KERNELSEC, 0x808, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_KERNELSEC_GET_VERSION \
    CTL_CODE(FILE_DEVICE_KERNELSEC, 0x809, METHOD_BUFFERED, FILE_READ_ACCESS)
```

### Valores Hexadecimais

| IOCTL | Valor Hex | Descrição |
|-------|-----------|-----------|
| GET_CONFIG | 0x80002000 | Obter configuração atual |
| SET_CONFIG | 0x80002004 | Definir nova configuração |
| GET_EVENTS | 0x80002008 | Obter eventos do buffer |
| ADD_WHITELIST | 0x8000200C | Adicionar hash à whitelist |
| REMOVE_WHITELIST | 0x80002010 | Remover hash da whitelist |
| GET_STATS | 0x80002014 | Obter estatísticas |
| RESET_BASELINE | 0x80002018 | Recriar baseline |
| ENABLE_PROTECTION | 0x8000201C | Ativar proteções |
| DISABLE_PROTECTION | 0x80002020 | Desativar proteções |
| GET_VERSION | 0x80002024 | Obter versão do driver |

---

## 3. Estruturas de Dados (User-Mode)

### DRIVER_CONFIG

```c
#pragma pack(push, 1)
typedef struct _DRIVER_CONFIG {
    // Modo de operação
    BOOLEAN AutoResponseEnabled;          // Offset 0
    BOOLEAN DetectOnlyMode;               // Offset 1
    UCHAR Reserved1[2];                   // Padding
    
    // Thresholds
    ULONG RiskThreshold;                  // Offset 4 (0-100)
    ULONG CriticalThreshold;              // Offset 8 (0-100)
    
    // Intervalos (ms)
    ULONG SsdtCheckIntervalMs;            // Offset 12
    ULONG IdtCheckIntervalMs;             // Offset 16
    ULONG DkomCheckIntervalMs;            // Offset 20
    
    // Políticas de bloqueio
    BOOLEAN BlockUnsignedDrivers;         // Offset 24
    BOOLEAN BlockUnsignedProcesses;       // Offset 25
    BOOLEAN BlockRemoteThreadCreation;    // Offset 26
    UCHAR Reserved2[1];                   // Padding
    
    // Proteções
    BOOLEAN EnableFilesystemProtection;   // Offset 28
    BOOLEAN EnableRegistryProtection;     // Offset 29
    BOOLEAN EnableNetworkIsolation;       // Offset 30
    UCHAR Reserved3[1];                   // Padding
    
    // Whitelist
    ULONG WhitelistCount;                 // Offset 32 (0-100)
    UCHAR Whitelist[100][32];             // Offset 36 (3200 bytes)
    
    // Logging
    ULONG LogBufferSize;                  // Offset 3236
    BOOLEAN EnableEtwLogging;             // Offset 3240
    UCHAR MinSeverityToLog;               // Offset 3241 (1=INFO, 2=WARN, 3=CRIT)
    UCHAR Reserved4[2];                   // Padding
    
} DRIVER_CONFIG, *PDRIVER_CONFIG;
#pragma pack(pop)
// Tamanho total: 3244 bytes
```

### SECURITY_EVENT

```c
#pragma pack(push, 1)
typedef struct _SECURITY_EVENT {
    // Identificação
    LARGE_INTEGER Timestamp;              // Offset 0 (8 bytes)
    ULONG EventId;                        // Offset 8
    ULONG Severity;                       // Offset 12 (1=INFO, 2=WARN, 3=CRIT)
    ULONG SequenceNumber;                 // Offset 16
    
    // Contexto de processo
    ULONG ProcessId;                      // Offset 20
    WCHAR ProcessName[260];               // Offset 24 (520 bytes)
    ULONG ParentProcessId;                // Offset 544
    ULONG SessionId;                      // Offset 548
    
    // Contexto de thread
    ULONG ThreadId;                       // Offset 552
    ULONG Reserved1;                      // Padding
    ULONG64 ThreadStartAddress;           // Offset 560
    
    // Detalhes técnicos
    ULONG64 TargetAddress;                // Offset 568
    ULONG64 OriginalValue;                // Offset 576
    ULONG64 NewValue;                     // Offset 584
    
    UCHAR FileHash[32];                   // Offset 592 (SHA256)
    WCHAR FilePath[512];                  // Offset 624 (1024 bytes)
    
    // Resposta
    ULONG ActionTaken;                    // Offset 1648 (enum ACTION_TYPE)
    ULONG RiskScore;                      // Offset 1652 (0-100)
    
    // Descrição
    WCHAR Description[512];               // Offset 1656 (1024 bytes)
    
} SECURITY_EVENT, *PSECURITY_EVENT;
#pragma pack(pop)
// Tamanho total: 2680 bytes
```

### DRIVER_STATS

```c
#pragma pack(push, 1)
typedef struct _DRIVER_STATS {
    // Versão
    ULONG StructVersion;                  // Offset 0 (sempre 1)
    
    // Uptime
    LARGE_INTEGER DriverLoadTime;         // Offset 4 (8 bytes)
    LARGE_INTEGER CurrentTime;            // Offset 12 (8 bytes)
    
    // Contadores de verificação
    ULONG64 SsdtChecksPerformed;          // Offset 20
    ULONG64 IdtChecksPerformed;           // Offset 28
    ULONG64 DkomChecksPerformed;          // Offset 36
    
    // Contadores de detecção
    ULONG64 TotalEventsDetected;          // Offset 44
    ULONG64 HooksDetected;                // Offset 52
    ULONG64 MaliciousDriversBlocked;      // Offset 60
    ULONG64 HiddenProcessesDetected;      // Offset 68
    ULONG64 InjectionsBlocked;            // Offset 76
    
    // Contadores de resposta
    ULONG64 ProcessesKilled;              // Offset 84
    ULONG64 SsdtRestored;                 // Offset 92
    ULONG64 IdtRestored;                  // Offset 100
    ULONG64 FilesQuarantined;             // Offset 108
    
    // Logging
    ULONG64 TotalEventsLogged;            // Offset 116
    ULONG64 EventsDropped;                // Offset 124 (buffer cheio)
    ULONG CurrentLogBufferUsage;          // Offset 132 (%)
    
    // Performance
    ULONG CpuUsagePercent;                // Offset 136 (estimado)
    ULONG MemoryUsageMB;                  // Offset 140
    
} DRIVER_STATS, *PDRIVER_STATS;
#pragma pack(pop)
// Tamanho total: 144 bytes
```

### VERSION_INFO

```c
#pragma pack(push, 1)
typedef struct _VERSION_INFO {
    ULONG MajorVersion;                   // Ex: 1
    ULONG MinorVersion;                   // Ex: 0
    ULONG BuildNumber;                    // Ex: 1234
    ULONG RevisionNumber;                 // Ex: 0
    WCHAR VersionString[64];              // Ex: L"1.0.1234.0"
    LARGE_INTEGER BuildDate;              // Timestamp de compilação
} VERSION_INFO, *PVERSION_INFO;
#pragma pack(pop)
// Tamanho total: 152 bytes
```

---

## 4. Exemplos de Uso

### 4.1 Obter Configuração Atual

```c
DRIVER_CONFIG config = {0};
DWORD bytesReturned = 0;

BOOL success = DeviceIoControl(
    hDevice,
    IOCTL_KERNELSEC_GET_CONFIG,
    NULL,                               // Sem input
    0,
    &config,                            // Output buffer
    sizeof(DRIVER_CONFIG),
    &bytesReturned,
    NULL
);

if (success) {
    printf("Auto-response: %s\n", config.AutoResponseEnabled ? "Enabled" : "Disabled");
    printf("Risk threshold: %d\n", config.RiskThreshold);
    printf("Whitelist count: %d\n", config.WhitelistCount);
} else {
    printf("Erro: %d\n", GetLastError());
}
```

### 4.2 Definir Nova Configuração

```c
DRIVER_CONFIG newConfig = {0};

// Configurar valores
newConfig.AutoResponseEnabled = TRUE;
newConfig.DetectOnlyMode = FALSE;
newConfig.RiskThreshold = 75;
newConfig.CriticalThreshold = 90;
newConfig.SsdtCheckIntervalMs = 500;
newConfig.IdtCheckIntervalMs = 1000;
newConfig.DkomCheckIntervalMs = 5000;
newConfig.BlockUnsignedDrivers = TRUE;
newConfig.BlockRemoteThreadCreation = TRUE;
newConfig.EnableFilesystemProtection = TRUE;
newConfig.EnableRegistryProtection = TRUE;
newConfig.LogBufferSize = 10000;
newConfig.EnableEtwLogging = TRUE;
newConfig.MinSeverityToLog = 2; // WARNING e acima

DWORD bytesReturned = 0;

BOOL success = DeviceIoControl(
    hDevice,
    IOCTL_KERNELSEC_SET_CONFIG,
    &newConfig,                         // Input buffer
    sizeof(DRIVER_CONFIG),
    NULL,                               // Sem output
    0,
    &bytesReturned,
    NULL
);

if (success) {
    printf("Configuração atualizada com sucesso\n");
} else {
    printf("Erro: %d\n", GetLastError());
}
```

### 4.3 Obter Eventos

```c
#define MAX_EVENTS 100
SECURITY_EVENT events[MAX_EVENTS];
DWORD bytesReturned = 0;

BOOL success = DeviceIoControl(
    hDevice,
    IOCTL_KERNELSEC_GET_EVENTS,
    NULL,
    0,
    events,
    sizeof(SECURITY_EVENT) * MAX_EVENTS,
    &bytesReturned,
    NULL
);

if (success) {
    ULONG eventCount = bytesReturned / sizeof(SECURITY_EVENT);
    printf("Recebidos %d eventos\n", eventCount);
    
    for (ULONG i = 0; i < eventCount; i++) {
        SYSTEMTIME st;
        FileTimeToSystemTime((FILETIME*)&events[i].Timestamp, &st);
        
        printf("[%02d:%02d:%02d] Evento %d - Severity %d - PID %d - %ws\n",
            st.wHour, st.wMinute, st.wSecond,
            events[i].EventId,
            events[i].Severity,
            events[i].ProcessId,
            events[i].Description
        );
    }
} else {
    printf("Erro: %d\n", GetLastError());
}
```

### 4.4 Adicionar Hash à Whitelist

```c
// Hash SHA256 de um executável confiável
UCHAR trustedHash[32] = {
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
};

DWORD bytesReturned = 0;

BOOL success = DeviceIoControl(
    hDevice,
    IOCTL_KERNELSEC_ADD_WHITELIST,
    trustedHash,
    32,
    NULL,
    0,
    &bytesReturned,
    NULL
);

if (success) {
    printf("Hash adicionado à whitelist\n");
} else {
    DWORD error = GetLastError();
    if (error == ERROR_INSUFFICIENT_BUFFER) {
        printf("Whitelist cheia (máximo 100 hashes)\n");
    } else {
        printf("Erro: %d\n", error);
    }
}
```

### 4.5 Obter Estatísticas

```c
DRIVER_STATS stats = {0};
DWORD bytesReturned = 0;

BOOL success = DeviceIoControl(
    hDevice,
    IOCTL_KERNELSEC_GET_STATS,
    NULL,
    0,
    &stats,
    sizeof(DRIVER_STATS),
    &bytesReturned,
    NULL
);

if (success) {
    printf("=== Estatísticas do Driver ===\n");
    printf("SSDT checks: %lld\n", stats.SsdtChecksPerformed);
    printf("IDT checks: %lld\n", stats.IdtChecksPerformed);
    printf("DKOM checks: %lld\n", stats.DkomChecksPerformed);
    printf("Hooks detectados: %lld\n", stats.HooksDetected);
    printf("Drivers bloqueados: %lld\n", stats.MaliciousDriversBlocked);
    printf("Processos ocultos detectados: %lld\n", stats.HiddenProcessesDetected);
    printf("Processos terminados: %lld\n", stats.ProcessesKilled);
    printf("SSDT restaurado: %lld\n", stats.SsdtRestored);
    printf("Eventos logados: %lld\n", stats.TotalEventsLogged);
    printf("Eventos perdidos: %lld\n", stats.EventsDropped);
    printf("Uso de CPU: %d%%\n", stats.CpuUsagePercent);
    printf("Uso de memória: %d MB\n", stats.MemoryUsageMB);
} else {
    printf("Erro: %d\n", GetLastError());
}
```

### 4.6 Resetar Baseline

```c
// CUIDADO: Isso recria o baseline com o estado atual do sistema!
// Use apenas se tiver certeza de que o sistema está limpo.

DWORD bytesReturned = 0;

BOOL success = DeviceIoControl(
    hDevice,
    IOCTL_KERNELSEC_RESET_BASELINE,
    NULL,
    0,
    NULL,
    0,
    &bytesReturned,
    NULL
);

if (success) {
    printf("Baseline recriado com sucesso\n");
    printf("AVISO: Novos hooks instalados antes desta operação serão considerados legítimos!\n");
} else {
    printf("Erro: %d\n", GetLastError());
}
```

---

## 5. Códigos de Erro

| Código | Constante | Descrição |
|--------|-----------|-----------|
| 0 | ERROR_SUCCESS | Operação bem-sucedida |
| 5 | ERROR_ACCESS_DENIED | Privilégios insuficientes |
| 87 | ERROR_INVALID_PARAMETER | Parâmetro inválido na estrutura |
| 122 | ERROR_INSUFFICIENT_BUFFER | Buffer de output muito pequeno |
| 1168 | ERROR_NOT_FOUND | Elemento não encontrado (ex: hash na whitelist) |
| Custom: 0xE0000001 | ERROR_BASELINE_INVALID | Baseline corrompido ou inválido |
| Custom: 0xE0000002 | ERROR_PROTECTION_DISABLED | Proteções estão desabilitadas |
| Custom: 0xE0000003 | ERROR_DRIVER_BUSY | Driver ocupado, tente novamente |

---

## 6. Exemplos em C#

### Service Wrapper

```csharp
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class KernelSecDriver : IDisposable
{
    private SafeFileHandle _deviceHandle;
    
    // IOCTLs
    private const uint IOCTL_GET_CONFIG = 0x80002000;
    private const uint IOCTL_SET_CONFIG = 0x80002004;
    private const uint IOCTL_GET_EVENTS = 0x80002008;
    private const uint IOCTL_GET_STATS = 0x80002014;
    
    // P/Invoke
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);
    
    // Constructor
    public KernelSecDriver()
    {
        _deviceHandle = CreateFile(
            @"\\.\KernelSecDriver",
            0xC0000000, // GENERIC_READ | GENERIC_WRITE
            0,
            IntPtr.Zero,
            3, // OPEN_EXISTING
            0,
            IntPtr.Zero);
        
        if (_deviceHandle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
    
    // Obter configuração
    public DriverConfig GetConfiguration()
    {
        DriverConfig config = new DriverConfig();
        IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf<DriverConfig>());
        
        try
        {
            bool success = DeviceIoControl(
                _deviceHandle,
                IOCTL_GET_CONFIG,
                IntPtr.Zero,
                0,
                buffer,
                (uint)Marshal.SizeOf<DriverConfig>(),
                out uint bytesReturned,
                IntPtr.Zero);
            
            if (!success)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            
            config = Marshal.PtrToStructure<DriverConfig>(buffer);
            return config;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
    
    // Definir configuração
    public void SetConfiguration(DriverConfig config)
    {
        IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf<DriverConfig>());
        
        try
        {
            Marshal.StructureToPtr(config, buffer, false);
            
            bool success = DeviceIoControl(
                _deviceHandle,
                IOCTL_SET_CONFIG,
                buffer,
                (uint)Marshal.SizeOf<DriverConfig>(),
                IntPtr.Zero,
                0,
                out uint bytesReturned,
                IntPtr.Zero);
            
            if (!success)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
    
    // Obter eventos
    public SecurityEvent[] GetEvents(int maxEvents = 100)
    {
        int bufferSize = Marshal.SizeOf<SecurityEvent>() * maxEvents;
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        
        try
        {
            bool success = DeviceIoControl(
                _deviceHandle,
                IOCTL_GET_EVENTS,
                IntPtr.Zero,
                0,
                buffer,
                (uint)bufferSize,
                out uint bytesReturned,
                IntPtr.Zero);
            
            if (!success)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            
            int eventCount = (int)(bytesReturned / Marshal.SizeOf<SecurityEvent>());
            SecurityEvent[] events = new SecurityEvent[eventCount];
            
            IntPtr current = buffer;
            for (int i = 0; i < eventCount; i++)
            {
                events[i] = Marshal.PtrToStructure<SecurityEvent>(current);
                current = IntPtr.Add(current, Marshal.SizeOf<SecurityEvent>());
            }
            
            return events;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
    
    // Dispose
    public void Dispose()
    {
        _deviceHandle?.Dispose();
    }
}
```

---

## 7. Segurança e Validação

### Validação Kernel-Side

```c
NTSTATUS ValidateConfigStructure(PDRIVER_CONFIG Config)
{
    // Verificar thresholds
    if (Config->RiskThreshold > 100 || Config->CriticalThreshold > 100) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Verificar intervalos (mínimo 100ms)
    if (Config->SsdtCheckIntervalMs < 100 ||
        Config->IdtCheckIntervalMs < 100 ||
        Config->DkomCheckIntervalMs < 100) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Verificar whitelist count
    if (Config->WhitelistCount > 100) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Verificar severity
    if (Config->MinSeverityToLog < 1 || Config->MinSeverityToLog > 3) {
        return STATUS_INVALID_PARAMETER;
    }
    
    return STATUS_SUCCESS;
}
```

### Controle de Acesso

```c
// Verificar privilégios do chamador
BOOLEAN IsCallerAuthorized()
{
    // Verificar se é SYSTEM ou Administrator
    PACCESS_TOKEN token = PsReferencePrimaryToken(PsGetCurrentProcess());
    
    BOOLEAN isAdmin = SeTokenIsAdmin(token);
    
    PsDereferencePrimaryToken(token);
    
    return isAdmin;
}
```

---

## Referências

- [IOCTL Interface Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-i-o-control-codes)
- [DeviceIoControl Function](https://docs.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol)
- [Buffering Methods](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/buffer-descriptions-for-i-o-control-codes)
