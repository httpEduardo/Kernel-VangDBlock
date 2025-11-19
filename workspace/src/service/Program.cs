using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using KernelSecService.Service;

namespace KernelSecService;

/// <summary>
/// Ponto de entrada do serviço Windows de controle do KernelSec Driver
/// </summary>
public class Program
{
    public static void Main(string[] args)
    {
        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .UseWindowsService(options =>
            {
                options.ServiceName = "KernelSecService";
            })
            .ConfigureServices((hostContext, services) =>
            {
                // Registrar o serviço Windows
                services.AddHostedService<KernelSecWindowsService>();
                
                // Registrar comunicação com driver
                services.AddSingleton<DriverCommunication>();
                
                // Registrar processamento de eventos
                services.AddSingleton<EventProcessor>();
                
                // Registrar exportação SIEM
                services.AddSingleton<SiemExporter>();
            });
}
