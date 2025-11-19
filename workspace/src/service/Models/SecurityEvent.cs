using System.Runtime.InteropServices;

namespace KernelSecService.Models;

/// <summary>
/// Evento de segurança capturado pelo driver kernel
/// </summary>
public class SecurityEvent
{
    public DateTime Timestamp { get; set; }
    public uint EventId { get; set; }
    public uint Severity { get; set; }
    public uint ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public ulong TargetAddress { get; set; }
    public ulong OriginalValue { get; set; }
    public ulong NewValue { get; set; }
    public byte[] FileHash { get; set; } = new byte[32];
    public uint ActionTaken { get; set; }
    public string Description { get; set; } = string.Empty;

    public static SecurityEvent FromNative(SecurityEventNative native)
    {
        return new SecurityEvent
        {
            Timestamp = DateTime.FromFileTime(native.Timestamp),
            EventId = native.EventId,
            Severity = native.Severity,
            ProcessId = native.ProcessId,
            ProcessName = native.ProcessName,
            TargetAddress = native.TargetAddress,
            OriginalValue = native.OriginalValue,
            NewValue = native.NewValue,
            FileHash = native.FileHash,
            ActionTaken = native.ActionTaken,
            Description = native.Description
        };
    }
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct SecurityEventNative
{
    public long Timestamp;
    public uint EventId;
    public uint Severity;
    public uint ProcessId;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ProcessName;
    public ulong TargetAddress;
    public ulong OriginalValue;
    public ulong NewValue;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] FileHash;
    public uint ActionTaken;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string Description;
}
