using System.Runtime.InteropServices;

namespace KernelSecService.Models;

/// <summary>
/// Configuração do driver kernel
/// </summary>
public class DriverConfig
{
    public bool AutoResponseEnabled { get; set; } = true;
    public uint RiskThreshold { get; set; } = 70;
    public uint SsdtCheckIntervalMs { get; set; } = 500;
    public uint IdtCheckIntervalMs { get; set; } = 500;
    public bool BlockUnsignedDrivers { get; set; } = true;
    public bool EnableFilesystemProtection { get; set; } = true;
    public List<byte[]> Whitelist { get; set; } = new();

    public DriverConfigNative ToNative()
    {
        var native = new DriverConfigNative
        {
            AutoResponseEnabled = AutoResponseEnabled ? 1 : 0,
            RiskThreshold = RiskThreshold,
            SsdtCheckIntervalMs = SsdtCheckIntervalMs,
            IdtCheckIntervalMs = IdtCheckIntervalMs,
            BlockUnsignedDrivers = BlockUnsignedDrivers ? 1 : 0,
            EnableFilesystemProtection = EnableFilesystemProtection ? 1 : 0,
            WhitelistCount = (uint)Math.Min(Whitelist.Count, 100)
        };

        for (int i = 0; i < native.WhitelistCount; i++)
        {
            Array.Copy(Whitelist[i], 0, native.Whitelist, i * 32, 32);
        }

        return native;
    }
}

[StructLayout(LayoutKind.Sequential)]
public struct DriverConfigNative
{
    public int AutoResponseEnabled;
    public uint RiskThreshold;
    public uint SsdtCheckIntervalMs;
    public uint IdtCheckIntervalMs;
    public int BlockUnsignedDrivers;
    public int EnableFilesystemProtection;
    public uint WhitelistCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3200)] // 100 hashes * 32 bytes
    public byte[] Whitelist;
}
