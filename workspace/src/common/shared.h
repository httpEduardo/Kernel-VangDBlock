/*++

Copyright (c) 2025 KernelSec Project. All rights reserved.

Module Name:
    shared.h

Abstract:
    Definições compartilhadas entre kernel-mode e user-mode.
    Este header contém estruturas de dados, constantes e enums
    utilizados na comunicação via IOCTL.

Author:
    KernelSec Team

Environment:
    Kernel mode e User mode

--*/

#ifndef _KERNELSEC_SHARED_H_
#define _KERNELSEC_SHARED_H_

#pragma once

//
// Versão do driver
//
#define KERNELSEC_MAJOR_VERSION    1
#define KERNELSEC_MINOR_VERSION    0
#define KERNELSEC_BUILD_NUMBER     1
#define KERNELSEC_REVISION         0

//
// Limites e constantes
//
#define MAX_WHITELIST_ENTRIES      100
#define MAX_PATH_LENGTH            512
#define MAX_PROCESS_NAME_LENGTH    260
#define MAX_DESCRIPTION_LENGTH     512
#define SHA256_HASH_SIZE           32

//
// Severidade de eventos
//
typedef enum _EVENT_SEVERITY {
    SeverityInfo = 1,
    SeverityWarning = 2,
    SeverityCritical = 3
} EVENT_SEVERITY;

//
// Tipos de eventos de segurança
//
typedef enum _EVENT_TYPE {
    EventUnknown = 0,
    
    // SSDT/IDT (100-199)
    EventSsdtHookDetected = 100,
    EventSsdtRestored = 101,
    EventIdtHookDetected = 102,
    EventIdtRestored = 103,
    EventInlineHookDetected = 104,
    
    // Drivers (200-299)
    EventDriverLoadBlocked = 200,
    EventUnsignedDriverDetected = 201,
    EventDriverUnloadBlocked = 202,
    EventVulnerableDriverDetected = 203,
    
    // Processos (300-399)
    EventHiddenProcessDetected = 300,
    EventProcessKilled = 301,
    EventProcessInjectionDetected = 302,
    EventRemoteThreadBlocked = 303,
    
    // Filesystem (400-499)
    EventProtectedFileAccessDenied = 400,
    EventFileQuarantined = 401,
    EventSuspiciousFileDeleted = 402,
    
    // Registry (500-599)
    EventRegistryProtectionTriggered = 500,
    EventBootKeyModificationBlocked = 501,
    
    // Sistema (900-999)
    EventBaselineCreated = 900,
    EventBaselineCorrupted = 901,
    EventDriverInitialized = 902,
    EventDriverUnloading = 903,
    EventConfigUpdated = 904
    
} EVENT_TYPE;

//
// Ações tomadas em resposta
//
typedef enum _ACTION_TYPE {
    ActionNone = 0,
    ActionLogged = 1,
    ActionBlocked = 2,
    ActionKilled = 3,
    ActionRestored = 4,
    ActionQuarantined = 5,
    ActionDeleted = 6,
    ActionIsolated = 7
} ACTION_TYPE;

//
// Configuração do driver
//
#pragma pack(push, 1)
typedef struct _DRIVER_CONFIG {
    
    // Modo de operação
    BOOLEAN AutoResponseEnabled;         // Resposta automática ativa
    BOOLEAN DetectOnlyMode;              // Apenas detectar, não agir
    UCHAR Reserved1[2];                  // Padding
    
    // Thresholds de risco
    ULONG RiskThreshold;                 // 0-100, padrão: 70
    ULONG CriticalThreshold;             // 0-100, padrão: 90
    
    // Intervalos de verificação (ms)
    ULONG SsdtCheckIntervalMs;           // Padrão: 500
    ULONG IdtCheckIntervalMs;            // Padrão: 1000
    ULONG DkomCheckIntervalMs;           // Padrão: 5000
    
    // Políticas de bloqueio
    BOOLEAN BlockUnsignedDrivers;
    BOOLEAN BlockUnsignedProcesses;
    BOOLEAN BlockRemoteThreadCreation;
    UCHAR Reserved2[1];
    
    // Proteções de superfície
    BOOLEAN EnableFilesystemProtection;
    BOOLEAN EnableRegistryProtection;
    BOOLEAN EnableNetworkIsolation;
    UCHAR Reserved3[1];
    
    // Whitelist de hashes (SHA256)
    ULONG WhitelistCount;
    UCHAR Whitelist[MAX_WHITELIST_ENTRIES][SHA256_HASH_SIZE];
    
    // Configuração de logging
    ULONG LogBufferSize;                 // Número de eventos no buffer
    BOOLEAN EnableEtwLogging;
    UCHAR MinSeverityToLog;              // 1=INFO, 2=WARN, 3=CRIT
    UCHAR Reserved4[2];
    
} DRIVER_CONFIG, *PDRIVER_CONFIG;
#pragma pack(pop)

//
// Evento de segurança
//
#pragma pack(push, 1)
typedef struct _SECURITY_EVENT {
    
    // Identificação
    LARGE_INTEGER Timestamp;             // Quando ocorreu
    ULONG EventId;                       // Tipo de evento (EVENT_TYPE)
    ULONG Severity;                      // Severidade (EVENT_SEVERITY)
    ULONG SequenceNumber;                // Número sequencial
    
    // Contexto de processo
    ULONG ProcessId;
    WCHAR ProcessName[MAX_PROCESS_NAME_LENGTH];
    ULONG ParentProcessId;
    ULONG SessionId;
    
    // Contexto de thread
    ULONG ThreadId;
    ULONG Reserved1;
    ULONG64 ThreadStartAddress;
    
    // Detalhes técnicos
    ULONG64 TargetAddress;               // Endereço afetado
    ULONG64 OriginalValue;
    ULONG64 NewValue;
    
    UCHAR FileHash[SHA256_HASH_SIZE];
    WCHAR FilePath[MAX_PATH_LENGTH];
    
    // Resposta
    ULONG ActionTaken;                   // Ação executada (ACTION_TYPE)
    ULONG RiskScore;                     // Score calculado (0-100)
    
    // Descrição
    WCHAR Description[MAX_DESCRIPTION_LENGTH];
    
} SECURITY_EVENT, *PSECURITY_EVENT;
#pragma pack(pop)

//
// Estatísticas do driver
//
#pragma pack(push, 1)
typedef struct _DRIVER_STATS {
    
    // Versão da estrutura
    ULONG StructVersion;
    
    // Uptime
    LARGE_INTEGER DriverLoadTime;
    LARGE_INTEGER CurrentTime;
    
    // Contadores de verificação
    ULONG64 SsdtChecksPerformed;
    ULONG64 IdtChecksPerformed;
    ULONG64 DkomChecksPerformed;
    
    // Contadores de detecção
    ULONG64 TotalEventsDetected;
    ULONG64 HooksDetected;
    ULONG64 MaliciousDriversBlocked;
    ULONG64 HiddenProcessesDetected;
    ULONG64 InjectionsBlocked;
    
    // Contadores de resposta
    ULONG64 ProcessesKilled;
    ULONG64 SsdtRestored;
    ULONG64 IdtRestored;
    ULONG64 FilesQuarantined;
    
    // Logging
    ULONG64 TotalEventsLogged;
    ULONG64 EventsDropped;
    ULONG CurrentLogBufferUsage;         // Percentual (0-100)
    
    // Performance
    ULONG CpuUsagePercent;               // Estimado
    ULONG MemoryUsageMB;                 // Consumo de memória
    
} DRIVER_STATS, *PDRIVER_STATS;
#pragma pack(pop)

//
// Informações de versão
//
#pragma pack(push, 1)
typedef struct _VERSION_INFO {
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG BuildNumber;
    ULONG RevisionNumber;
    WCHAR VersionString[64];
    LARGE_INTEGER BuildDate;
} VERSION_INFO, *PVERSION_INFO;
#pragma pack(pop)

//
// Informações de driver
//
#pragma pack(push, 1)
typedef struct _DRIVER_INFO {
    WCHAR DriverName[MAX_PROCESS_NAME_LENGTH];
    WCHAR DriverPath[MAX_PATH_LENGTH];
    ULONG64 BaseAddress;
    ULONG ImageSize;
    UCHAR Hash[SHA256_HASH_SIZE];
    LARGE_INTEGER LoadTime;
    BOOLEAN IsSigned;
    BOOLEAN IsMicrosoft;
    USHORT Reserved;
    ULONG SignatureLevel;
} DRIVER_INFO, *PDRIVER_INFO;
#pragma pack(pop)

#endif // _KERNELSEC_SHARED_H_
