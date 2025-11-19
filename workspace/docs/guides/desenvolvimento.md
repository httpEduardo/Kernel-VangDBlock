# Guia de Desenvolvimento

## Configuração do Ambiente

### Requisitos

#### Software Obrigatório
- **Windows 10 22H2** ou **Windows 11** (host de desenvolvimento)
- **Visual Studio 2022** (Community, Professional ou Enterprise)
  - Workload: "Desktop development with C++"
  - Workload: "Universal Windows Platform development"
- **Windows Driver Kit (WDK)** para Windows 11, versão 22H2
- **Windows SDK** 10.0.22621.0 ou superior
- **Debugging Tools for Windows** (WinDbg Preview)

#### Software Recomendado
- **VMware Workstation** ou **Hyper-V** (para testes)
- **Git** para controle de versão
- **Visual Studio Code** (para edição de documentação)
- **WinDbg Preview** (Microsoft Store)

### Instalação Passo a Passo

#### 1. Install Visual Studio 2022

```powershell
# Usando winget
winget install Microsoft.VisualStudio.2022.Community

# Ou baixar manualmente de:
# https://visualstudio.microsoft.com/downloads/
```

Durante a instalação, selecionar:
- ✅ Desktop development with C++
- ✅ Universal Windows Platform development

#### 2. Instalar Windows Driver Kit

```powershell
# Baixar WDK
# https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

# Instalar WDK + SDK
# O instalador irá detectar o Visual Studio 2022 automaticamente
```

Componentes necessários:
- WDK para Windows 11
- Debugging Tools for Windows
- Application Verifier
- Windows Performance Toolkit

#### 3. Configurar VM de Teste

**Requisitos da VM:**
- Windows 10 22H2 ou Windows 11
- 4GB RAM mínimo (8GB recomendado)
- 2 vCPUs
- 60GB disco
- **Serial port** configurado (para kernel debugging)

**Configuração Hyper-V:**

```powershell
# Criar VM
New-VM -Name "KernelSecTest" -MemoryStartupBytes 4GB -Generation 2

# Configurar serial port
Set-VMComPort -VMName "KernelSecTest" -Number 1 -Path "\\.\pipe\kernelsec_debug"

# Desabilitar Secure Boot (para test signing)
Set-VMFirmware -VMName "KernelSecTest" -EnableSecureBoot Off
```

**Configurar Test Signing na VM:**

```powershell
# Dentro da VM:
bcdedit /set testsigning on
bcdedit /set nointegritychecks on  # Apenas para desenvolvimento!
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200

# Reiniciar
shutdown /r /t 0
```

#### 4. Configurar Kernel Debugging

**No host (onde está o Visual Studio):**

```powershell
# Conectar WinDbg à VM
windbg -k com:pipe,port=\\.\pipe\kernelsec_debug,reconnect
```

**Comandos úteis no WinDbg:**

```
.reload                    # Recarregar símbolos
!process 0 0               # Listar processos
!drvobj KernelSecDriver 2  # Informações do driver
bp DriverEntry             # Breakpoint no entry point
g                          # Continuar execução
```

---

## Estrutura do Projeto

### Layout de Diretórios

```
workspace/
├── src/
│   ├── driver/              # Driver kernel-mode (C)
│   │   ├── core/           # Inicialização e gerenciamento
│   │   │   ├── entry.c
│   │   │   ├── device.c
│   │   │   └── config.c
│   │   ├── monitor/        # Monitoramento contínuo
│   │   │   ├── ssdt.c
│   │   │   ├── idt.c
│   │   │   ├── dkom.c
│   │   │   └── callbacks.c
│   │   ├── analysis/       # Análise e decisão
│   │   │   ├── scoring.c
│   │   │   ├── heuristics.c
│   │   │   └── decision.c
│   │   ├── response/       # Resposta automática
│   │   │   ├── restore.c
│   │   │   ├── kill.c
│   │   │   └── block.c
│   │   ├── logging/        # Sistema de logs
│   │   │   ├── buffer.c
│   │   │   └── etw.c
│   │   └── minifilter/     # Proteção filesystem
│   │       ├── filter.c
│   │       └── quarantine.c
│   ├── service/            # Serviço user-mode (C#)
│   │   ├── KernelSecService/
│   │   │   ├── Program.cs
│   │   │   ├── DriverInterface.cs
│   │   │   ├── ConfigManager.cs
│   │   │   └── EventProcessor.cs
│   │   └── KernelSecService.csproj
│   └── common/             # Definições compartilhadas
│       ├── shared.h
│       ├── events.h
│       └── ioctl.h
├── include/                # Headers públicos
│   ├── kernelsec.h
│   └── version.h
├── tests/                  # Testes
│   ├── unit/
│   └── integration/
└── tools/                  # Ferramentas auxiliares
    ├── injector/           # Teste de injeção
    └── hooker/             # Teste de hooks
```

### Arquivos de Build

#### KernelSecDriver.vcxproj (Driver)

```xml
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup Label="Globals">
    <ProjectGuid>{GUID-AQUI}</ProjectGuid>
    <TemplateGuid>{dd38f7fc-d7bd-488b-9242-7d8754cde80d}</TemplateGuid>
    <TargetFrameworkVersion>v4.5</TargetFrameworkVersion>
    <MinimumVisualStudioVersion>12.0</MinimumVisualStudioVersion>
    <Configuration>Debug</Configuration>
    <Platform>x64</Platform>
    <RootNamespace>KernelSecDriver</RootNamespace>
    <WindowsTargetPlatformVersion>10.0.22621.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <DebuggerFlavor>DbgengKernelDebugger</DebuggerFlavor>
    <EnableInf2cat>false</EnableInf2cat>
  </PropertyGroup>
  
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <ClCompile>
      <WarningLevel>Level4</WarningLevel>
      <TreatWarningAsError>true</TreatWarningAsError>
      <PreprocessorDefinitions>_AMD64_;_WIN64;DBG=1;%(PreprocessorDefinitions)</PreprocessorDefinitions>
    </ClCompile>
    <Link>
      <AdditionalDependencies>$(DDK_LIB_PATH)ntoskrnl.lib;$(DDK_LIB_PATH)hal.lib;$(DDK_LIB_PATH)wdmsec.lib;%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>
  
  <ItemGroup>
    <ClCompile Include="src\driver\core\entry.c" />
    <ClCompile Include="src\driver\core\device.c" />
    <ClCompile Include="src\driver\core\config.c" />
    <ClCompile Include="src\driver\monitor\ssdt.c" />
    <ClCompile Include="src\driver\monitor\idt.c" />
    <ClCompile Include="src\driver\monitor\dkom.c" />
    <ClCompile Include="src\driver\monitor\callbacks.c" />
    <ClCompile Include="src\driver\analysis\scoring.c" />
    <ClCompile Include="src\driver\analysis\heuristics.c" />
    <ClCompile Include="src\driver\analysis\decision.c" />
    <ClCompile Include="src\driver\response\restore.c" />
    <ClCompile Include="src\driver\response\kill.c" />
    <ClCompile Include="src\driver\response\block.c" />
    <ClCompile Include="src\driver\logging\buffer.c" />
    <ClCompile Include="src\driver\logging\etw.c" />
  </ItemGroup>
  
  <ItemGroup>
    <ClInclude Include="include\kernelsec.h" />
    <ClInclude Include="include\version.h" />
    <ClInclude Include="src\common\shared.h" />
    <ClInclude Include="src\common\events.h" />
    <ClInclude Include="src\common\ioctl.h" />
  </ItemGroup>
</Project>
```

---

## Workflow de Desenvolvimento

### 1. Desenvolvimento Local

```powershell
# Clonar repositório
git clone https://github.com/seu-repo/KernelSecProject.git
cd KernelSecProject\workspace

# Abrir solução
start KernelSecDriver.sln

# Build (Debug x64)
msbuild KernelSecDriver.sln /p:Configuration=Debug /p:Platform=x64
```

### 2. Deploy em VM de Teste

```powershell
# Script de deploy
$vmName = "KernelSecTest"
$driverPath = ".\x64\Debug\KernelSecDriver.sys"
$vmDriverPath = "C:\Drivers\KernelSecDriver.sys"

# Copiar driver para VM
Copy-VMFile -VMName $vmName -SourcePath $driverPath -DestinationPath $vmDriverPath -FileSource Host

# Executar comandos na VM
Invoke-Command -VMName $vmName -ScriptBlock {
    # Parar driver se estiver rodando
    sc stop KernelSecDriver
    
    # Desinstalar driver anterior
    sc delete KernelSecDriver
    
    # Instalar novo driver
    sc create KernelSecDriver type=kernel binPath=C:\Drivers\KernelSecDriver.sys
    
    # Iniciar driver
    sc start KernelSecDriver
}
```

### 3. Debugging

**Anexar debugger:**

```powershell
# Host: iniciar WinDbg
windbg -k com:pipe,port=\\.\pipe\kernelsec_debug,reconnect

# Aguardar conexão com VM...
```

**Comandos úteis:**

```
# Breakpoint no DriverEntry
bp KernelSecDriver!DriverEntry

# Breakpoint em função específica
bp KernelSecDriver!MonitorSSDT

# Listar módulos carregados
lm

# Examinar estrutura
dt KernelSecDriver!_SYSTEM_BASELINE

# Stack trace
k

# Listar threads do driver
!thread

# Examinar memória
db/dw/dd/dq <endereço>
```

### 4. Logs e Diagnóstico

**DebugView** (para KdPrint):

```powershell
# Habilitar saída de debug
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" /v DEFAULT /t REG_DWORD /d 0xF /f

# Executar DebugView (como Admin)
# https://docs.microsoft.com/en-us/sysinternals/downloads/debugview
```

**Verificar eventos ETW:**

```powershell
# Listar providers
logman query providers | findstr KernelSec

# Criar trace session
logman create trace KernelSecTrace -p "{GUID-DO-PROVIDER}" -o kernelsec.etl

# Iniciar trace
logman start KernelSecTrace

# Parar trace
logman stop KernelSecTrace

# Analisar trace
tracerpt kernelsec.etl -o report.xml
```

---

## Boas Práticas

### Codificação

1. **Sempre validar parâmetros**
   ```c
   if (!Param) {
       return STATUS_INVALID_PARAMETER;
   }
   ```

2. **Usar tagged allocations**
   ```c
   PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, size, 'TAG ');
   // Sempre liberar:
   ExFreePoolWithTag(buffer, 'TAG ');
   ```

3. **Gerenciar IRQLs corretamente**
   ```c
   KIRQL oldIrql;
   KeAcquireSpinLock(&lock, &oldIrql);
   // Código crítico
   KeReleaseSpinLock(&lock, oldIrql);
   ```

4. **Try/Except para acesso à memória**
   ```c
   __try {
       ULONG value = *(PULONG)userAddress;
   }
   __except(EXCEPTION_EXECUTE_HANDLER) {
       KdPrint(("Acesso inválido à memória\n"));
       return STATUS_ACCESS_VIOLATION;
   }
   ```

### Segurança

1. **Sempre verificar assinaturas**
2. **Validar input de user-mode**
3. **Usar operações atômicas**
4. **Limitar recursão**
5. **Implementar timeouts**

### Performance

1. **Evitar alocações frequentes**
2. **Usar pools separados para diferentes propósitos**
3. **Minimizar tempo em DISPATCH_LEVEL**
4. **Cachear resultados quando possível**
5. **Usar trabalho assíncrono (Work Items)**

---

## Troubleshooting

### Driver não carrega

```powershell
# Verificar assinatura
signtool verify /pa KernelSecDriver.sys

# Verificar dependências
dumpbin /dependents KernelSecDriver.sys

# Verificar logs do sistema
Get-EventLog -LogName System -Source "Service Control Manager" | Where-Object {$_.Message -like "*KernelSec*"}
```

### BSOD durante desenvolvimento

1. **Habilitar Driver Verifier**
   ```powershell
   verifier /standard /driver KernelSecDriver.sys
   ```

2. **Analisar crash dump**
   ```powershell
   windbg -z C:\Windows\MEMORY.DMP
   
   # No WinDbg:
   !analyze -v
   ```

3. **Causas comuns:**
   - Access Violation (Bad pointer)
   - IRQL_NOT_LESS_OR_EQUAL (IRQL errado)
   - DRIVER_CORRUPTED_EXPOOL (Pool corruption)

### Performance ruim

```powershell
# Usar Performance Recorder
wpr -start GeneralProfile -filemode

# Reproduzir problema

# Parar gravação
wpr -stop recording.etl

# Analisar com Windows Performance Analyzer
wpa recording.etl
```

---

## Referências

- [Windows Driver Kit Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [Kernel-Mode Driver Architecture](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/)
- [Debugging Tools for Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/)
- [Driver Verifier](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier)
