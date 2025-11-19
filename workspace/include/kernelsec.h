/*++

Module Name:
    kernelsec.h

Abstract:
    Header principal do driver - definições internas kernel-only

--*/

#ifndef _KERNELSEC_H_
#define _KERNELSEC_H_

#pragma once

//
// Headers do sistema
//
#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

//
// Headers do projeto
//
#include "..\\common\\shared.h"
#include "..\\common\\ioctl.h"

//
// Tags de pool memory
//
#define TAG_BASELINE    'BSLN'
#define TAG_LOG_BUFFER  'LOGB'
#define TAG_EVENT       'EVNT'
#define TAG_CONFIG      'CNFG'
#define TAG_DRIVER_INFO 'DRVR'
#define TAG_MONITOR     'MNTR'
#define TAG_TEMP        'TEMP'

//
// Versão do baseline
//
#define BASELINE_VERSION    1

//
// Flags de baseline
//
#define BASELINE_VALID          0x00000001
#define BASELINE_CORRUPTED      0x00000002
#define BASELINE_OUTDATED       0x00000004
#define BASELINE_SSDT_CAPTURED  0x00000008
#define BASELINE_IDT_CAPTURED   0x00000010

//
// Estrutura de baseline do sistema
//
typedef struct _SYSTEM_BASELINE {
    // SSDT
    ULONG64 SsdtBaseAddress;
    ULONG SsdtEntryCount;
    PULONG64 SsdtOriginalEntries;
    
    // IDT
    ULONG64 IdtBaseAddress;
    ULONG IdtEntryCount;
    PVOID* IdtOriginalHandlers;
    
    // Drivers confiáveis
    ULONG DriverCount;
    PDRIVER_INFO TrustedDrivers;
    
    // Hashes de módulos críticos
    UCHAR NtoskrnlHash[32];
    UCHAR HalHash[32];
    UCHAR Win32kHash[32];
    
    // Metadados
    LARGE_INTEGER CreationTime;
    ULONG Version;
    ULONG Flags;
    
} SYSTEM_BASELINE, *PSYSTEM_BASELINE;

//
// Buffer circular de logs
//
typedef struct _LOG_BUFFER {
    KSPIN_LOCK Lock;
    KEVENT NewEventSignal;
    volatile ULONG ReadIndex;
    volatile ULONG WriteIndex;
    ULONG Capacity;
    ULONG64 TotalEventsLogged;
    ULONG64 EventsDropped;
    LARGE_INTEGER LastFlushTime;
    PSECURITY_EVENT Events;
} LOG_BUFFER, *PLOG_BUFFER;

//
// Contexto do monitor thread
//
typedef struct _MONITOR_CONTEXT {
    PKTHREAD MonitorThread;
    BOOLEAN StopMonitoring;
    KEVENT StopEvent;
    PSYSTEM_BASELINE Baseline;
    PDRIVER_CONFIG Config;
    ULONG64 SsdtChecksPerformed;
    ULONG64 IdtChecksPerformed;
    ULONG64 DkomChecksPerformed;
    ULONG64 HooksDetected;
} MONITOR_CONTEXT, *PMONITOR_CONTEXT;

//
// Variáveis globais (definidas em entry.c)
//
extern PDEVICE_OBJECT g_DeviceObject;
extern SYSTEM_BASELINE g_Baseline;
extern DRIVER_CONFIG g_Config;
extern LOG_BUFFER g_LogBuffer;
extern MONITOR_CONTEXT g_MonitorContext;
extern DRIVER_STATS g_Stats;

//
// Protótipos - Core (entry.c, device.c, config.c)
//
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

NTSTATUS InitializeGlobalStructures(VOID);
VOID CleanupGlobalStructures(VOID);

NTSTATUS CreateDeviceObject(_In_ PDRIVER_OBJECT DriverObject);
VOID DeleteDeviceObject(_In_ PDRIVER_OBJECT DriverObject);

NTSTATUS ValidateConfig(_In_ PDRIVER_CONFIG Config);
VOID ApplyDefaultConfig(_Out_ PDRIVER_CONFIG Config);

//
// Protótipos - Monitor (ssdt.c, idt.c, dkom.c, callbacks.c)
//
NTSTATUS CreateSystemBaseline(VOID);
VOID DestroyBaseline(VOID);
BOOLEAN ValidateBaseline(_In_ PSYSTEM_BASELINE Baseline);

NTSTATUS StartMonitorThread(VOID);
VOID StopMonitorThread(VOID);
VOID MonitorThreadRoutine(_In_ PVOID Context);

VOID MonitorSSDT(VOID);
VOID MonitorIDT(VOID);
VOID DetectDKOM(VOID);

NTSTATUS RegisterCallbacks(VOID);
VOID UnregisterCallbacks(VOID);

VOID ProcessCreateNotifyRoutine(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

VOID LoadImageNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
);

//
// Protótipos - Analysis (scoring.c, heuristics.c, decision.c)
//
ULONG CalculateRiskScore(_In_ PSECURITY_EVENT Event);
VOID HandleSecurityEvent(_In_ PSECURITY_EVENT Event);
VOID DecideAction(_In_ PSECURITY_EVENT Event);

//
// Protótipos - Response (restore.c, kill.c, block.c)
//
VOID RestoreSSDTEntry(_In_ ULONG Index);
VOID RestoreIDTEntry(_In_ ULONG Index);
VOID KillMaliciousProcess(_In_ ULONG ProcessId, _In_ PWCHAR Reason);
VOID BlockDriverLoad(_In_ PUNICODE_STRING DriverPath);

//
// Protótipos - Logging (buffer.c, etw.c)
//
NTSTATUS InitializeLogBuffer(VOID);
VOID CleanupLogBuffer(VOID);
VOID LogEvent(_In_ PSECURITY_EVENT Event);
ULONG FlushLogBuffer(_Out_ PSECURITY_EVENT OutBuffer, _In_ ULONG MaxEvents);

NTSTATUS InitializeETW(VOID);
VOID CleanupETW(VOID);
VOID LogEventToETW(_In_ PSECURITY_EVENT Event);

//
// Protótipos - Dispatch (device.c)
//
_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH DispatchCreate;

_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH DispatchClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DispatchIoControl;

//
// Utilitários inline
//
FORCEINLINE BOOLEAN IsAddressInKernelSpace(_In_ PVOID Address) {
    return (ULONG_PTR)Address >= 0xFFFF800000000000ULL;
}

FORCEINLINE VOID SecureZeroMemoryKernel(_In_ PVOID Ptr, _In_ SIZE_T Size) {
    volatile UCHAR* p = (volatile UCHAR*)Ptr;
    while (Size--) *p++ = 0;
}

#endif // _KERNELSEC_H_
