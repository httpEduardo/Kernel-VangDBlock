# Diagramas C4 - Sistema de Cibersegurança Kernel

## Nível 1: Diagrama de Contexto

```mermaid
C4Context
    title Contexto do Sistema - Cibersegurança Kernel-Mode

    Person(admin, "Administrador", "Configura e monitora o sistema de segurança")
    
    System(kernelsec, "Sistema de Cibersegurança Kernel", "Detecta e responde a ameaças em nível de kernel")
    
    System_Ext(siem, "SIEM", "Sistema de gerenciamento de eventos de segurança")
    System_Ext(dashboard, "Dashboard Web", "Interface de monitoramento em tempo real")
    
    System_Boundary(windows, "Windows OS") {
        System(kernel, "NT Kernel", "Núcleo do sistema operacional")
        System(drivers, "Drivers", "Drivers de terceiros e do sistema")
    }
    
    Rel(admin, dashboard, "Monitora", "HTTPS")
    Rel(admin, kernelsec, "Configura", "Service Control")
    Rel(kernelsec, siem, "Envia eventos", "Syslog/JSON")
    Rel(dashboard, kernelsec, "Consulta status", "REST API")
    Rel(kernelsec, kernel, "Monitora e protege", "Callbacks/Hooks")
    Rel(kernelsec, drivers, "Valida e controla", "Load Image Notify")
```

## Nível 2: Diagrama de Containers

```mermaid
C4Container
    title Containers - Componentes do Sistema

    Person(admin, "Administrador")
    
    Container_Boundary(usermode, "User Mode (Ring 3)") {
        Container(dashboard, "Dashboard Web", "ASP.NET Core", "Interface web para monitoramento")
        Container(service, "Serviço de Controle", "C# Windows Service", "Gerencia configuração e consome logs")
    }
    
    Container_Boundary(kernelmode, "Kernel Mode (Ring 0)") {
        Container(driver, "KernelSecDriver", "KMDF Driver", "Driver principal de segurança")
        Container(minifilter, "Minifilter", "Filter Driver", "Proteção de filesystem")
    }
    
    System_Ext(siem, "SIEM Externo")
    System(ntkernel, "NT Kernel", "Windows Kernel")
    
    Rel(admin, dashboard, "Acessa", "HTTPS")
    Rel(dashboard, service, "Consulta", "REST API")
    Rel(service, driver, "Controla", "IOCTL")
    Rel(driver, minifilter, "Coordena", "FltSendMessage")
    Rel(driver, ntkernel, "Monitora", "Callbacks")
    Rel(service, siem, "Exporta logs", "Syslog/ETW")
```

## Nível 3: Diagrama de Componentes (Driver)

```mermaid
C4Component
    title Componentes Internos do Driver Kernel

    Container_Boundary(driver, "KernelSecDriver") {
        Component(init, "Módulo Inicialização", "C", "DriverEntry, baseline snapshot")
        Component(monitor, "Módulo Monitor", "C", "Verificação periódica, callbacks")
        Component(analysis, "Módulo Análise", "C", "Heurísticas, risk scoring")
        Component(response, "Módulo Resposta", "C", "Kill, block, restore")
        Component(logging, "Módulo Logging", "C", "Buffer circular, ETW")
        Component(ioctl, "IOCTL Dispatcher", "C", "Comunicação com user-mode")
    }
    
    Component(minifilter, "Minifilter", "C", "Proteção filesystem")
    
    System_Ext(ntkernel, "NT Kernel")
    System_Ext(service, "Serviço User-Mode")
    
    Rel(init, monitor, "Inicia")
    Rel(monitor, analysis, "Envia eventos")
    Rel(analysis, response, "Decide ações")
    Rel(response, logging, "Registra ações")
    Rel(logging, ioctl, "Fornece eventos")
    Rel(service, ioctl, "IOCTL calls")
    Rel(monitor, ntkernel, "Callbacks")
    Rel(response, ntkernel, "Syscalls")
    Rel(init, minifilter, "Registra")
```

## Nível 4: Diagrama de Código (Estruturas Principais)

```mermaid
classDiagram
    class SYSTEM_BASELINE {
        +ULONG64 SsdtBaseAddress
        +ULONG SsdtEntryCount
        +ULONG64* SsdtOriginalEntries
        +ULONG64 IdtBaseAddress
        +PVOID* IdtOriginalHandlers
        +DRIVER_INFO* TrustedDrivers
        +UCHAR NtoskrnlHash[32]
        +LARGE_INTEGER CreationTime
    }
    
    class SECURITY_EVENT {
        +LARGE_INTEGER Timestamp
        +ULONG EventId
        +ULONG Severity
        +ULONG ProcessId
        +WCHAR ProcessName[260]
        +ULONG64 TargetAddress
        +ULONG ActionTaken
        +WCHAR Description[512]
    }
    
    class LOG_BUFFER {
        +KSPIN_LOCK Lock
        +ULONG ReadIndex
        +ULONG WriteIndex
        +ULONG Capacity
        +SECURITY_EVENT* Events
        +KEVENT NewEventSignal
        +LogEvent()
        +FlushEvents()
    }
    
    class DRIVER_CONFIG {
        +BOOLEAN AutoResponseEnabled
        +ULONG RiskThreshold
        +ULONG SsdtCheckIntervalMs
        +BOOLEAN BlockUnsignedDrivers
        +UCHAR Whitelist[100][32]
    }
    
    class MONITOR_CONTEXT {
        +PKTHREAD MonitorThread
        +BOOLEAN StopMonitoring
        +SYSTEM_BASELINE Baseline
        +CheckSSDT()
        +CheckIDT()
        +DetectDKOM()
    }
    
    MONITOR_CONTEXT --> SYSTEM_BASELINE
    MONITOR_CONTEXT --> SECURITY_EVENT : gera
    SECURITY_EVENT --> LOG_BUFFER : armazenado em
    DRIVER_CONFIG ..> MONITOR_CONTEXT : configura
```

## Fluxo de Dados - Detecção de Hook

```mermaid
sequenceDiagram
    participant MT as Monitor Thread
    participant SSDT as SSDT
    participant BL as Baseline
    participant AN as Análise
    participant RP as Resposta
    participant LOG as Logging
    
    MT->>SSDT: Ler entrada syscall
    MT->>BL: Comparar com baseline
    alt Hook detectado
        MT->>AN: Evento SSDT_HOOK_DETECTED
        AN->>AN: Calcular risk score
        alt Score >= Threshold
            AN->>RP: Decisão: RESTORE_SSDT
            RP->>SSDT: Restaurar entrada original
            RP->>LOG: Registrar ação
        else Score < Threshold
            AN->>LOG: Registrar alerta apenas
        end
    end
    MT->>MT: Sleep 500ms
```

## Fluxo de Resposta - Kill Process

```mermaid
flowchart TD
    A[Evento Detectado] --> B{Calcular Score}
    B --> C{Score >= 70?}
    C -->|Não| D[Apenas Logar]
    C -->|Sim| E{Auto-Response Ativo?}
    E -->|Não| D
    E -->|Sim| F{Tipo de Ameaça}
    F -->|Hook SSDT| G[Restaurar SSDT]
    F -->|Driver Malicioso| H[Bloquear Load]
    F -->|Processo Malicioso| I[Kill Process]
    F -->|Arquivo Suspeito| J[Quarentena]
    G --> K[Registrar Ação]
    H --> K
    I --> K
    J --> K
    K --> L[Notificar User-Mode]
    D --> L
```

## Arquitetura de Memória

```mermaid
graph TB
    subgraph "Non-Paged Pool"
        A[SYSTEM_BASELINE]
        B[LOG_BUFFER]
        C[DRIVER_CONFIG]
        D[Monitor Thread Stack]
    end
    
    subgraph "Paged Pool"
        E[Whitelist Cache]
        F[Temporary Buffers]
    end
    
    subgraph "Code Sections"
        G[.text - Código]
        H[.rdata - Constantes]
    end
    
    A -.->|referenciado por| D
    B -.->|escrito por| D
    C -.->|lido por| D
    G -->|executa| D
```

## Integração com Windows Kernel

```mermaid
graph LR
    subgraph "KernelSecDriver"
        A[Callbacks Registrados]
    end
    
    subgraph "NT Kernel"
        B[PsSetCreateProcessNotifyRoutineEx]
        C[PsSetLoadImageNotifyRoutine]
        D[PsSetCreateThreadNotifyRoutineEx]
        E[CmRegisterCallbackEx]
    end
    
    A -->|registra| B
    A -->|registra| C
    A -->|registra| D
    A -->|registra| E
    
    B -.->|notifica| A
    C -.->|notifica| A
    D -.->|notifica| A
    E -.->|notifica| A
```

## Notas de Implementação

1. **SSDT Monitoring**: No Windows 10+, entradas SSDT são offsets comprimidos (4 bytes)
2. **Thread Context**: Monitor thread executa em PASSIVE_LEVEL, usa KeDelayExecutionThread
3. **Spin Locks**: LOG_BUFFER usa KSPIN_LOCK para sincronização (DISPATCH_LEVEL)
4. **Memory Allocation**: Estruturas críticas em NonPagedPool (sempre residentes)
5. **ETW Integration**: EventRegister no DriverEntry, EventWrite em LogEvent

## Referências de Diagramas

- [C4 Model](https://c4model.com/)
- [Mermaid Documentation](https://mermaid-js.github.io/)
- [Windows Driver Architecture](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/)
