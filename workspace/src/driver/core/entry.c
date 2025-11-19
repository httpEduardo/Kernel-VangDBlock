/*++

Module Name:
    entry.c

Abstract:
    Ponto de entrada do driver - DriverEntry e DriverUnload

Environment:
    Kernel mode only

--*/

#include "..\\..\\include\\kernelsec.h"

//
// Variáveis globais
//
PDEVICE_OBJECT g_DeviceObject = NULL;
SYSTEM_BASELINE g_Baseline = {0};
DRIVER_CONFIG g_Config = {0};
LOG_BUFFER g_LogBuffer = {0};
MONITOR_CONTEXT g_MonitorContext = {0};
DRIVER_STATS g_Stats = {0};

//
// DriverEntry - Ponto de entrada do driver
//
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    UNREFERENCED_PARAMETER(RegistryPath);
    
    KdPrint(("[KernelSec] DriverEntry: Iniciando driver...\n"));
    KdPrint(("[KernelSec] Versão: %d.%d.%d.%d\n",
             KERNELSEC_MAJOR_VERSION,
             KERNELSEC_MINOR_VERSION,
             KERNELSEC_BUILD_NUMBER,
             KERNELSEC_REVISION));
    
    //
    // 1. Inicializar estruturas globais
    //
    status = InitializeGlobalStructures();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[KernelSec] ERRO: InitializeGlobalStructures falhou: 0x%X\n", status));
        return status;
    }
    
    //
    // 2. Aplicar configuração padrão
    //
    ApplyDefaultConfig(&g_Config);
    KdPrint(("[KernelSec] Configuração padrão aplicada\n"));
    
    //
    // 3. Criar baseline do sistema
    //
    status = CreateSystemBaseline();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[KernelSec] ERRO: CreateSystemBaseline falhou: 0x%X\n", status));
        CleanupGlobalStructures();
        return status;
    }
    KdPrint(("[KernelSec] Baseline do sistema criado\n"));
    
    //
    // 4. Inicializar sistema de logging
    //
    status = InitializeLogBuffer();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[KernelSec] ERRO: InitializeLogBuffer falhou: 0x%X\n", status));
        DestroyBaseline();
        CleanupGlobalStructures();
        return status;
    }
    KdPrint(("[KernelSec] Sistema de logging inicializado\n"));
    
    //
    // 5. Registrar callbacks do sistema
    //
    status = RegisterCallbacks();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[KernelSec] ERRO: RegisterCallbacks falhou: 0x%X\n", status));
        CleanupLogBuffer();
        DestroyBaseline();
        CleanupGlobalStructures();
        return status;
    }
    KdPrint(("[KernelSec] Callbacks registrados\n"));
    
    //
    // 6. Criar device object para comunicação user-mode
    //
    status = CreateDeviceObject(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[KernelSec] ERRO: CreateDeviceObject falhou: 0x%X\n", status));
        UnregisterCallbacks();
        CleanupLogBuffer();
        DestroyBaseline();
        CleanupGlobalStructures();
        return status;
    }
    KdPrint(("[KernelSec] Device object criado\n"));
    
    //
    // 7. Iniciar thread de monitoramento
    //
    status = StartMonitorThread();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[KernelSec] ERRO: StartMonitorThread falhou: 0x%X\n", status));
        DeleteDeviceObject(DriverObject);
        UnregisterCallbacks();
        CleanupLogBuffer();
        DestroyBaseline();
        CleanupGlobalStructures();
        return status;
    }
    KdPrint(("[KernelSec] Thread de monitoramento iniciada\n"));
    
    //
    // 8. Configurar unload routine
    //
    DriverObject->DriverUnload = DriverUnload;
    
    //
    // 9. Configurar dispatch routines
    //
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;
    
    //
    // 10. Registrar timestamp de inicialização
    //
    KeQuerySystemTime(&g_Stats.DriverLoadTime);
    
    //
    // 11. Logar evento de inicialização
    //
    SECURITY_EVENT initEvent = {0};
    KeQuerySystemTime(&initEvent.Timestamp);
    initEvent.EventId = EventDriverInitialized;
    initEvent.Severity = SeverityInfo;
    RtlStringCchPrintfW(
        initEvent.Description,
        MAX_DESCRIPTION_LENGTH,
        L"KernelSecDriver v%d.%d.%d inicializado com sucesso",
        KERNELSEC_MAJOR_VERSION,
        KERNELSEC_MINOR_VERSION,
        KERNELSEC_BUILD_NUMBER
    );
    LogEvent(&initEvent);
    
    KdPrint(("[KernelSec] Driver inicializado com sucesso!\n"));
    
    return STATUS_SUCCESS;
}

//
// DriverUnload - Rotina de descarregamento
//
VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    KdPrint(("[KernelSec] DriverUnload: Descarregando driver...\n"));
    
    //
    // Logar evento de unload
    //
    SECURITY_EVENT unloadEvent = {0};
    KeQuerySystemTime(&unloadEvent.Timestamp);
    unloadEvent.EventId = EventDriverUnloading;
    unloadEvent.Severity = SeverityInfo;
    RtlStringCchCopyW(
        unloadEvent.Description,
        MAX_DESCRIPTION_LENGTH,
        L"KernelSecDriver está sendo descarregado"
    );
    LogEvent(&unloadEvent);
    
    //
    // Parar thread de monitoramento
    //
    StopMonitorThread();
    KdPrint(("[KernelSec] Thread de monitoramento parada\n"));
    
    //
    // Desregistrar callbacks
    //
    UnregisterCallbacks();
    KdPrint(("[KernelSec] Callbacks desregistrados\n"));
    
    //
    // Deletar device object
    //
    DeleteDeviceObject(DriverObject);
    KdPrint(("[KernelSec] Device object deletado\n"));
    
    //
    // Limpar sistema de logging
    //
    CleanupLogBuffer();
    KdPrint(("[KernelSec] Sistema de logging limpo\n"));
    
    //
    // Destruir baseline
    //
    DestroyBaseline();
    KdPrint(("[KernelSec] Baseline destruído\n"));
    
    //
    // Limpar estruturas globais
    //
    CleanupGlobalStructures();
    KdPrint(("[KernelSec] Estruturas globais limpas\n"));
    
    KdPrint(("[KernelSec] Driver descarregado com sucesso\n"));
}

//
// InitializeGlobalStructures - Inicializar variáveis globais
//
NTSTATUS
InitializeGlobalStructures(VOID)
{
    //
    // Zerar todas as estruturas
    //
    RtlZeroMemory(&g_Baseline, sizeof(SYSTEM_BASELINE));
    RtlZeroMemory(&g_Config, sizeof(DRIVER_CONFIG));
    RtlZeroMemory(&g_LogBuffer, sizeof(LOG_BUFFER));
    RtlZeroMemory(&g_MonitorContext, sizeof(MONITOR_CONTEXT));
    RtlZeroMemory(&g_Stats, sizeof(DRIVER_STATS));
    
    //
    // Inicializar versão das estruturas
    //
    g_Stats.StructVersion = 1;
    
    return STATUS_SUCCESS;
}

//
// CleanupGlobalStructures - Limpar estruturas globais
//
VOID
CleanupGlobalStructures(VOID)
{
    //
    // Zerar memória de forma segura (prevenir vazamento de dados sensíveis)
    //
    SecureZeroMemoryKernel(&g_Baseline, sizeof(SYSTEM_BASELINE));
    SecureZeroMemoryKernel(&g_Config, sizeof(DRIVER_CONFIG));
    SecureZeroMemoryKernel(&g_LogBuffer, sizeof(LOG_BUFFER));
    SecureZeroMemoryKernel(&g_MonitorContext, sizeof(MONITOR_CONTEXT));
    SecureZeroMemoryKernel(&g_Stats, sizeof(DRIVER_STATS));
}
