using Microsoft.Extensions.Logging;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace KernelSecService.Dashboard;

/// <summary>
/// Exporta eventos para sistemas SIEM externos
/// </summary>
public class SiemExporter
{
    private readonly ILogger<SiemExporter> _logger;
    private readonly bool _enabled = true;
    private readonly string _host = "localhost";
    private readonly int _port = 514;

    public SiemExporter(ILogger<SiemExporter> logger)
    {
        _logger = logger;
    }

    public async Task ExportAsync(List<SecurityEvent> events)
    {
        if (!_enabled || events.Count == 0)
            return;

        try
        {
            using var client = new UdpClient();

            foreach (var evt in events)
            {
                // Formato Syslog RFC 5424
                var json = JsonSerializer.Serialize(new
                {
                    timestamp = evt.Timestamp.ToString("o"),
                    eventId = evt.EventId,
                    severity = evt.Severity,
                    processId = evt.ProcessId,
                    processName = evt.ProcessName,
                    targetAddress = $"0x{evt.TargetAddress:X}",
                    action = evt.ActionTaken,
                    description = evt.Description,
                    source = "KernelSecDriver"
                });

                var priority = evt.Severity switch
                {
                    3 => 2, // CRITICAL -> Alert
                    2 => 4, // WARNING -> Warning
                    _ => 6  // INFO -> Informational
                };

                var syslogMessage = $"<{priority * 8 + 1}>1 {evt.Timestamp:yyyy-MM-ddTHH:mm:ss.fffZ} KernelSec KernelSecDriver - - - {json}";
                var bytes = Encoding.UTF8.GetBytes(syslogMessage);

                await client.SendAsync(bytes, bytes.Length, _host, _port);
            }

            _logger.LogDebug($"Exportados {events.Count} eventos para SIEM ({_host}:{_port})");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao exportar eventos para SIEM");
        }
    }
}
