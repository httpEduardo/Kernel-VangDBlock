# Documentação de Arquitetura

## Índice

1. [Visão Geral da Arquitetura](overview.md)
2. [Diagramas C4](c4-diagrams.md)
3. [Estruturas de Dados](data-structures.md)
4. [Fluxos Operacionais](operational-flows.md)
5. [Matriz de Vetores de Ataque](attack-vectors-matrix.md)

## Níveis de Abstração

### Nível 1: Contexto
Define como o sistema interage com usuários externos e sistemas de terceiros (SIEM, dashboards).

### Nível 2: Containers
Descreve os principais componentes: Driver Kernel, Serviço User-Mode, Interface Web.

### Nível 3: Componentes
Detalha os módulos internos do driver: Monitor, Análise, Resposta, Logging, Minifilter.

### Nível 4: Código
Especifica estruturas de dados, algoritmos e implementações críticas.

## Princípios de Design

1. **Segurança por Design**: Validação em todas as camadas
2. **Desempenho**: Overhead mínimo (<3% CPU)
3. **Observabilidade**: Logs completos e imutáveis
4. **Modularidade**: Componentes independentes e testáveis
5. **Fail-Safe**: Degradação graciosa em caso de falhas

## Padrões Arquiteturais

- **Event-Driven**: Callbacks e notificações do kernel
- **Producer-Consumer**: Buffer circular para logs
- **Strategy Pattern**: Decisões de resposta configuráveis
- **Observer Pattern**: Monitoramento contínuo de estruturas

## Decisões Técnicas Chave

| Decisão | Justificativa | Alternativas Consideradas |
|---------|--------------|---------------------------|
| KMDF vs WDM | Abstração moderna, menos boilerplate | WDM (muito complexo) |
| Buffer circular | Melhor para alta frequência de eventos | Lista encadeada (overhead) |
| ETW para telemetria | Integração nativa Windows | Custom protocol |
| SHA256 para hashes | Balanço segurança/performance | MD5 (inseguro), SHA512 (lento) |

## Referências

- [Windows Driver Kit Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [Kernel-Mode Driver Architecture](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/)
- [Filter Manager Architecture](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts)
