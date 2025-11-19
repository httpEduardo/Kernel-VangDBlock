using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace KernelSecService.Communication;

/// <summary>
/// Gerencia comunicação com driver kernel via DeviceIoControl
/// </summary>
public class DriverCommunication : IDisposable
{
    private const string DEVICE_NAME = "\\\\.\\KernelSecDriver";
    private SafeFileHandle? _deviceHandle;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    public bool Connect()
    {
        _deviceHandle = CreateFile(
            DEVICE_NAME,
            0xC0000000, // GENERIC_READ | GENERIC_WRITE
            0,
            IntPtr.Zero,
            3, // OPEN_EXISTING
            0,
            IntPtr.Zero);

        return _deviceHandle != null && !_deviceHandle.IsInvalid;
    }

    public void Disconnect()
    {
        _deviceHandle?.Dispose();
    }

    public List<SecurityEvent>? GetEvents()
    {
        if (_deviceHandle == null || _deviceHandle.IsInvalid)
            return null;

        const int maxEvents = 100;
        int bufferSize = maxEvents * Marshal.SizeOf<SecurityEventNative>();
        IntPtr outBuffer = Marshal.AllocHGlobal(bufferSize);

        try
        {
            bool success = DeviceIoControl(
                _deviceHandle,
                IoctlCodes.IOCTL_KERNELSEC_GET_EVENTS,
                IntPtr.Zero,
                0,
                outBuffer,
                (uint)bufferSize,
                out uint bytesReturned,
                IntPtr.Zero);

            if (!success || bytesReturned == 0)
                return new List<SecurityEvent>();

            int eventCount = (int)(bytesReturned / Marshal.SizeOf<SecurityEventNative>());
            var events = new List<SecurityEvent>(eventCount);

            for (int i = 0; i < eventCount; i++)
            {
                IntPtr eventPtr = IntPtr.Add(outBuffer, i * Marshal.SizeOf<SecurityEventNative>());
                var nativeEvent = Marshal.PtrToStructure<SecurityEventNative>(eventPtr);
                events.Add(SecurityEvent.FromNative(nativeEvent));
            }

            return events;
        }
        finally
        {
            Marshal.FreeHGlobal(outBuffer);
        }
    }

    public bool SetConfig(DriverConfig config)
    {
        if (_deviceHandle == null || _deviceHandle.IsInvalid)
            return false;

        var nativeConfig = config.ToNative();
        int size = Marshal.SizeOf(nativeConfig);
        IntPtr buffer = Marshal.AllocHGlobal(size);

        try
        {
            Marshal.StructureToPtr(nativeConfig, buffer, false);

            return DeviceIoControl(
                _deviceHandle,
                IoctlCodes.IOCTL_KERNELSEC_SET_CONFIG,
                buffer,
                (uint)size,
                IntPtr.Zero,
                0,
                out _,
                IntPtr.Zero);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public void Dispose()
    {
        Disconnect();
    }
}
