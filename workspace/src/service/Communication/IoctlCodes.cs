namespace KernelSecService.Communication;

/// <summary>
/// Códigos IOCTL para comunicação com driver kernel
/// </summary>
public static class IoctlCodes
{
    private const uint FILE_DEVICE_UNKNOWN = 0x00000022;
    private const uint METHOD_BUFFERED = 0;
    private const uint FILE_ANY_ACCESS = 0;
    private const uint FILE_READ_ACCESS = 1;

    private static uint CTL_CODE(uint deviceType, uint function, uint method, uint access)
    {
        return (deviceType << 16) | (access << 14) | (function << 2) | method;
    }

    public static readonly uint IOCTL_KERNELSEC_GET_CONFIG = 
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);

    public static readonly uint IOCTL_KERNELSEC_SET_CONFIG = 
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);

    public static readonly uint IOCTL_KERNELSEC_GET_EVENTS = 
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS);

    public static readonly uint IOCTL_KERNELSEC_ADD_WHITELIST = 
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);

    public static readonly uint IOCTL_KERNELSEC_REMOVE_WHITELIST = 
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);

    public static readonly uint IOCTL_KERNELSEC_GET_STATS = 
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS);

    public static readonly uint IOCTL_KERNELSEC_DISABLE_PROTECTION = 
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS);

    public static readonly uint IOCTL_KERNELSEC_ENABLE_PROTECTION = 
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS);
}
