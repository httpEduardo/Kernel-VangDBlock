using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace KernelSecService.Service;

/// <summary>
/// Serviço Windows principal que gerencia comunicação com driver kernel
/// </summary>
public class KernelSecWindowsService : BackgroundService
{
    private readonly ILogger<KernelSecWindowsService> _logger;
    private readonly DriverCommunication _driverComm;
    private readonly EventProcessor _eventProcessor;
    private readonly SiemExporter _siemExporter;

    public KernelSecWindowsService(
        ILogger<KernelSecWindowsService> logger,
        DriverCommunication driverComm,
        EventProcessor eventProcessor,
        SiemExporter siemExporter)
    {
        _logger = logger;
        _driverComm = driverComm;
        _eventProcessor = eventProcessor;
        _siemExporter = siemExporter;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("KernelSec Service iniciando...");

        try
        {
            // Conectar ao driver
            if (!_driverComm.Connect())
            {
                _logger.LogError("Falha ao conectar ao driver kernel. Verifique se o driver está carregado.");
                return;
            }

            _logger.LogInformation("Conectado ao driver kernel com sucesso.");

            // Loop principal de polling de eventos
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var events = _driverComm.GetEvents();
                    
                    if (events != null && events.Any())
                    {
                        _logger.LogInformation($"Recebidos {events.Count} eventos do driver");
                        
                        // Processar eventos
                        await _eventProcessor.ProcessEventsAsync(events);
                        
                        // Exportar para SIEM
                        await _siemExporter.ExportAsync(events);
                    }

                    await Task.Delay(1000, stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Erro no loop de polling de eventos");
                }
            }
        }
        finally
        {
            _driverComm.Disconnect();
            _logger.LogInformation("KernelSec Service finalizado.");
        }
    }
}
