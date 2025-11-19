# Matriz de Vetores de Ataque vs Mitigações

## Visão Geral

Este documento mapeia os principais vetores de ataque contra sistemas Windows em nível de kernel e as mitigações implementadas pelo KernelSecDriver.

---

## Tabela Completa de Vetores

| # | Vetor de Ataque | Impacto | Probabilidade | Técnica de Detecção | Mitigação Implementada | Controle Adicional | Status |
|---|----------------|---------|---------------|---------------------|----------------------|-------------------|--------|
| 1 | Hook inline em syscall (SSDT) | CRÍTICO | Alta | Verificação periódica + comparação com baseline | Restauração automática da entrada original | Logs imutáveis + alertas | ✅ Implementado |
| 2 | Hook em Shadow SSDT (win32k) | CRÍTICO | Média | Verificação periódica similar ao SSDT | Restauração automática | Verificação de integridade win32k.sys | 🔄 Planejado |
| 3 | Hook em IDT | CRÍTICO | Baixa | Snapshot inicial + comparação periódica | Restauração de handlers originais | Validação de módulo assinado | ✅ Implementado |
| 4 | Driver rootkit não assinado | CRÍTICO | Média | Callback LoadImage + verificação de assinatura digital | Bloqueio de carregamento | Whitelist de drivers confiáveis | ✅ Implementado |
| 5 | Driver rootkit assinado (certificado roubado) | ALTO | Baixa | Verificação de revogação + whitelist | Bloqueio baseado em hash | Integração com CRL/OCSP | 🔄 Planejado |
| 6 | DKOM - Ocultar processo | ALTO | Média | Varredura dupla (lista vs handles) | Re-link na lista ou kill | Auditoria contínua | ✅ Implementado |
| 7 | DKOM - Elevar privilégios | ALTO | Média | Verificação de token consistency | Restauração de token | Snapshot de tokens legítimos | 🔄 Planejado |
| 8 | Injeção de DLL via APC | ALTO | Alta | Callback CreateThread remoto | Bloqueio de CreateRemoteThread | Proteção de VADs | ✅ Implementado |
| 9 | Process Hollowing | ALTO | Média | Detecção de write em seção .text | Bloqueio via minifilter | Verificação de integridade PE | 🔄 Planejado |
| 10 | Bootkit (MBR/GPT) | CRÍTICO | Baixa | Verificação de integridade boot sectors | Restauração de MBR/GPT | Secure Boot + TPM + ELAM | ⚠️ Requer ELAM |
| 11 | Exploração de driver vulnerável (BYOVD) | ALTO | Média | Whitelist + blacklist de drivers conhecidos | Bloqueio de versões vulneráveis | Atualização forçada | ✅ Implementado |
| 12 | Manipulação de PEB/TEB | MÉDIO | Alta | Verificação de consistency | Restauração de estruturas | Snapshot inicial | 🔄 Planejado |
| 13 | Desativação do próprio driver | ALTO | Baixa | Auto-verificação + proteção de handle | Bloquear ZwUnloadDriver | Watchdog em user-mode | ✅ Implementado |
| 14 | Evasão via timing (TOCTOU) | MÉDIO | Baixa | Locks consistentes + verificação dupla | Operações atômicas | Retry logic | ✅ Implementado |
| 15 | Manipulação de Object Callbacks | ALTO | Média | Verificação de callbacks registrados | Restauração de callback list | Snapshot de callbacks legítimos | 🔄 Planejado |
| 16 | Kernel Pool Overflow | CRÍTICO | Baixa | Detecção via Driver Verifier | N/A (dependente do Windows) | Pool tagging + validação | ⚠️ OS-level |
| 17 | Use-After-Free em kernel | CRÍTICO | Baixa | Detecção via Driver Verifier | N/A (dependente do Windows) | Reference counting rigoroso | ⚠️ OS-level |
| 18 | Modificação de EAT/IAT de drivers | ALTO | Média | Verificação de integridade de tabelas | Restauração de entradas | Hash de tabelas legítimas | 🔄 Planejado |
| 19 | Comunicação C2 via raw sockets | MÉDIO | Alta | Monitoramento de sockets kernel-mode | Isolamento de rede | Network filter driver | 🔄 Planejado |
| 20 | Persistência via Registry Run keys | MÉDIO | Alta | Callback de registry | Bloqueio de modificações suspeitas | Whitelist de valores legítimos | ✅ Implementado |

---

## Detalhamento por Categoria

### 1. Hooks e Manipulações de Tabelas

#### 1.1 SSDT Hooking

**Descrição**: Substituição de entradas na System Service Dispatch Table para interceptar syscalls.

**Cenário de Ataque**:
```c
// Rootkit hook em NtCreateFile
PVOID g_OriginalNtCreateFile = NULL;

NTSTATUS HookedNtCreateFile(...) {
    // Lógica maliciosa
    if (wcsstr(FileName, L"malware.exe")) {
        return STATUS_ACCESS_DENIED; // Ocultar arquivo
    }
    return g_OriginalNtCreateFile(...); // Chamar original
}

// Instalar hook
PULONG ssdt = KeServiceDescriptorTable->ServiceTableBase;
g_OriginalNtCreateFile = GetSyscallAddress(SYSCALL_NTCREATEFILE);
ssdt[SYSCALL_NTCREATEFILE] = EncodeOffset(HookedNtCreateFile);
```

**Nossa Detecção**:
```c
// Monitor thread - verificação periódica
for (ULONG i = 0; i < SsdtEntryCount; i++) {
    ULONG64 currentAddr = GetSyscallAddress(i);
    if (currentAddr != baseline->SsdtOriginalEntries[i]) {
        // Hook detectado!
        if (!IsAddressInSignedModule(currentAddr)) {
            // CRÍTICO: hook não assinado
            RestoreSsdt(i);
        }
    }
}
```

**Mitigação**: Restauração automática da entrada original da SSDT.

**Limitações**: 
- Janela de vulnerabilidade entre instalação do hook e detecção (~500ms)
- Possível race condition se rootkit reinstalar hook continuamente

**Controles Compensatórios**:
- Logging imediato em buffer circular
- Notificação via ETW para resposta externa
- Identificação do módulo responsável para blacklist

---

#### 1.2 IDT Hooking

**Descrição**: Substituição de interrupt handlers na Interrupt Descriptor Table.

**Cenário de Ataque**:
```c
// Hook em Page Fault (INT 14)
VOID HookedPageFaultHandler() {
    // Interceptar acesso à memória
    // Implementar DKOM (Direct Kernel Object Manipulation)
}

// Instalar hook
KIDTENTRY64* idt = GetIdtBase();
idt[14].OffsetLow = (USHORT)HookedPageFaultHandler;
idt[14].OffsetMiddle = (USHORT)(HookedPageFaultHandler >> 16);
idt[14].OffsetHigh = (ULONG)(HookedPageFaultHandler >> 32);
```

**Nossa Detecção**:
```c
// Capturar IDT no boot
SIDT(&idtDescriptor);
PKIDTENTRY64 idt = idtDescriptor.Base;

for (ULONG i = 0; i < 256; i++) {
    ULONG64 handler = GetHandlerFromIDT(idt, i);
    baseline->IdtOriginalHandlers[i] = handler;
}

// Verificar periodicamente
if (currentHandler != baseline->IdtOriginalHandlers[i]) {
    RestoreIdtEntry(i);
}
```

**Mitigação**: Restauração do handler original.

---

### 2. Rootkits e Drivers Maliciosos

#### 2.1 Driver Não Assinado

**Cenário**: Atacante tenta carregar driver sem assinatura digital válida.

**Detecção**:
```c
VOID LoadImageNotifyRoutine(...) {
    if (ImageInfo->SystemModeImage) {
        BOOLEAN isSigned = VerifyDriverSignature(FullImageName);
        if (!isSigned && g_Config.BlockUnsignedDrivers) {
            ImageInfo->ImageSignatureLevel = SE_SIGNING_LEVEL_UNCHECKED;
            LogEvent(EVENT_UNSIGNED_DRIVER_DETECTED);
        }
    }
}
```

**Mitigação**: Bloqueio de carregamento via callback.

---

#### 2.2 BYOVD (Bring Your Own Vulnerable Driver)

**Descrição**: Uso de driver legítimo mas vulnerável para escalar privilégios.

**Exemplos Conhecidos**:
- capcom.sys
- RTCore64.sys (MSI Afterburner)
- gdrv.sys (Gigabyte)

**Detecção**:
```c
// Blacklist de hashes conhecidos
UCHAR KNOWN_VULNERABLE_DRIVERS[][32] = {
    {0x12, 0x34, ...}, // capcom.sys SHA256
    {0x56, 0x78, ...}, // RTCore64.sys SHA256
    // ...
};

BOOLEAN IsKnownVulnerableDriver(PUCHAR Hash) {
    for (ULONG i = 0; i < NUM_VULNERABLE_DRIVERS; i++) {
        if (RtlCompareMemory(Hash, KNOWN_VULNERABLE_DRIVERS[i], 32) == 32) {
            return TRUE;
        }
    }
    return FALSE;
}
```

**Mitigação**: Bloqueio baseado em blacklist + scoring alto.

---

### 3. DKOM (Direct Kernel Object Manipulation)

#### 3.1 Ocultar Processo

**Técnica**: Remover EPROCESS da lista encadeada PsActiveProcessHead.

```c
// Rootkit DKOM
PEPROCESS targetProcess = GetProcessByName("malware.exe");
RemoveEntryList(&targetProcess->ActiveProcessLinks);
// Agora o processo está oculto de ferramentas user-mode
```

**Nossa Detecção**:
```c
// Comparar lista de processos com handle table
ULONG pidsInList[1000];
ULONG pidsInHandles[1000];

// Varrer PsActiveProcessHead
ScanProcessList(pidsInList);

// Varrer handles do System process
ScanHandleTable(pidsInHandles);

// Comparar
for (ULONG i = 0; i < handlesCount; i++) {
    if (!IsInArray(pidsInHandles[i], pidsInList)) {
        // Processo oculto detectado!
        LogEvent(EVENT_HIDDEN_PROCESS_DETECTED);
        AttemptRelink(pidsInHandles[i]);
    }
}
```

**Mitigação**: Re-linkar processo na lista ou kill.

---

### 4. Injeção de Código

#### 4.1 APC Injection

**Técnica**: Usar QueueUserAPC ou NtQueueApcThread para injetar código em processo remoto.

**Detecção**:
```c
VOID CreateThreadNotifyRoutine(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create
) {
    if (!Create) return;
    
    // Verificar se thread foi criada remotamente
    if (PsGetCurrentProcessId() != ProcessId) {
        // CreateRemoteThread detectado
        ULONG riskScore = CalculateInjectionRisk(ProcessId, ThreadId);
        if (riskScore >= threshold) {
            // Terminar thread
            ZwTerminateThread(ThreadHandle, STATUS_ACCESS_DENIED);
        }
    }
}
```

**Mitigação**: Bloqueio de criação de thread remota ou terminação imediata.

---

### 5. Bootkits

#### 5.1 MBR/GPT Infection

**Técnica**: Modificar Master Boot Record ou GUID Partition Table para carregar código antes do OS.

**Detecção**: Requer integração com ELAM (Early Launch Anti-Malware).

```c
// Registrar como ELAM driver
NTSTATUS DriverEntry(...) {
    // Verificar integridade do boot sector
    UCHAR mbrHash[32];
    CalculateMBRHash(mbrHash);
    
    if (memcmp(mbrHash, KNOWN_GOOD_MBR_HASH, 32) != 0) {
        // MBR modificado!
        LogEvent(EVENT_BOOTKIT_DETECTED);
        // Restaurar MBR de backup
        RestoreMBR();
    }
}
```

**Limitações**: Requer certificação especial Microsoft para ELAM.

**Controles Alternativos**:
- Secure Boot (UEFI)
- Measured Boot (TPM)
- Verificação periódica pós-boot

---

## Scoring de Risco - Pesos por Indicador

| Indicador | Pontos | Justificativa |
|-----------|--------|---------------|
| Processo não assinado | +30 | Comum, mas pode ser legítimo |
| Driver não assinado | +50 | Mais suspeito que processo |
| Hook em syscall crítico (Read/WriteVM) | +40 | Forte indicador de rootkit |
| Hook em syscall comum (CreateFile) | +25 | Pode ser AV legítimo |
| DKOM detectado | +60 | Técnica claramente maliciosa |
| Comunicação com IP em blacklist | +35 | C2 provável |
| Modificação de Run key | +25 | Persistência comum |
| Injeção de código remoto | +45 | Técnica ofensiva |
| Driver vulnerável conhecido (BYOVD) | +80 | Quase certamente malicioso |
| Criação de processo de injetor conhecido | +50 | Mimikatz, Cobalt Strike, etc. |
| Modificação de arquivo do sistema | +40 | Pode ser atualização legítima |
| Tentativa de descarregar nosso driver | +70 | Evasão clara |

**Threshold Padrão**: 70 pontos para ação automática

**Threshold Crítico**: 90 pontos para kill imediato sem análise adicional

---

## Matriz de Decisão de Resposta

```
┌─────────────────────────────────────────────────────────────┐
│                MATRIZ DE DECISÃO DE RESPOSTA                 │
├──────────────────┬──────────────────────────────────────────┤
│ Score            │ Ação                                      │
├──────────────────┼──────────────────────────────────────────┤
│ 0-40             │ Apenas logar (INFO/WARNING)               │
│ 41-69            │ Logar + alertar (WARNING)                 │
│ 70-89            │ Bloquear operação + logar (CRITICAL)      │
│ 90-100           │ Kill process + delete executável          │
├──────────────────┴──────────────────────────────────────────┤
│ Exceções:                                                     │
│ - DKOM: sempre score >= 60                                    │
│ - BYOVD: sempre score >= 80                                   │
│ - Tentativa de unload driver: sempre score >= 70             │
│ - Hook SSDT em NtReadVirtualMemory: sempre score >= 75       │
└───────────────────────────────────────────────────────────────┘
```

---

## Falsos Positivos Conhecidos

| Cenário | Causa | Mitigação |
|---------|-------|-----------|
| AV/EDR legítimo hooka SSDT | Detecção de comportamento | Whitelist de hashes de AVs conhecidos |
| Game anti-cheat modifica kernel | Proteção DRM | Whitelist + validação de assinatura |
| Driver de virtualização (VMware, VirtualBox) | Funcionamento normal | Whitelist de drivers conhecidos |
| Debugger kernel (WinDbg) | Desenvolvimento | Modo "development" configurável |
| Driver de captura de tela (OBS, ShareX) | Hook em GDI | Verificar assinatura + whitelist |

---

## Limitações e Considerações

### Limitações Técnicas

1. **Janela de Vulnerabilidade**: ~500ms entre hook e detecção
2. **Race Conditions**: Possível se rootkit reinstalar hook continuamente
3. **Rootkits Avançados**: Podem desabilitar callbacks ou manipular nosso driver
4. **Kernel Exploits**: Vulnerabilidades 0-day no kernel podem contornar proteções

### Considerações de Desempenho

1. **Overhead de CPU**: ~3% em operação normal
2. **Latência**: Verificações periódicas podem atrasar detecção
3. **Memória**: ~50MB NonPagedPool consumido

### Evasão Possível

1. **Timing Attacks**: Atacante pode sincronizar com nossos checks
2. **Código Polimórfico**: Hashes não detectam variantes
3. **Exploração do Próprio Driver**: Vulnerabilidades no nosso código
4. **Desabilitação do Driver**: Atacante com privilégios suficientes pode descarregar

---

## Referências

- [MITRE ATT&CK - Rootkit](https://attack.mitre.org/techniques/T1014/)
- [MITRE ATT&CK - Bootkit](https://attack.mitre.org/techniques/T1542/003/)
- [Windows Kernel Rootkits](https://www.amazon.com/Rootkit-Arsenal-Escape-Evasion-Corners/dp/144962636X)
- [LOLDrivers Project](https://www.loldrivers.io/)
