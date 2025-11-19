using Microsoft.Extensions.Logging;

namespace KernelSecService.Dashboard;

/// <summary>
/// Processa eventos de segurança recebidos do driver
/// </summary>
public class EventProcessor
{
    private readonly ILogger<EventProcessor> _logger;

    public EventProcessor(ILogger<EventProcessor> logger)
    {
        _logger = logger;
    }

    public async Task ProcessEventsAsync(List<SecurityEvent> events)
    {
        foreach (var evt in events)
        {
            var severity = evt.Severity switch
            {
                1 => "INFO",
                2 => "WARNING",
                3 => "CRITICAL",
                _ => "UNKNOWN"
            };

            var action = evt.ActionTaken switch
            {
                0 => "NONE",
                1 => "BLOCK",
                2 => "KILL",
                3 => "ROLLBACK",
                4 => "QUARANTINE",
                _ => "UNKNOWN"
            };

            _logger.LogInformation(
                "[{Severity}] PID:{ProcessId} {ProcessName} - {Description} - Action: {Action}",
                severity,
                evt.ProcessId,
                evt.ProcessName,
                evt.Description,
                action
            );

            // Aqui pode adicionar lógica adicional:
            // - Notificações
            // - Alertas
            // - Dashboard em tempo real
            // - Armazenamento em banco de dados
        }

        await Task.CompletedTask;
    }
}
