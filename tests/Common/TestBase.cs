using System.Globalization;
using System.Runtime.InteropServices;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.Tests.Common;

public abstract class TestBase(ITestOutputHelper output) : IDisposable
{
    public ITestOutputHelper Output { get; } = output ?? throw new ArgumentNullException(nameof(output));
    private bool _disposed;

    public static OSPlatform CurrentPlatform
    {
        get
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return OSPlatform.Windows;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return OSPlatform.Linux;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                return OSPlatform.OSX;
            
            throw new PlatformNotSupportedException("Unsupported platform");
        }
    }
    
    public static Architecture CurrentArchitecture => RuntimeInformation.OSArchitecture;

    public void Log(string message)
    {
        Output.WriteLine($"[{DateTime.UtcNow:HH:mm:ss.fff}] {message}");
    }

    public void Log(string format, params object[] args)
    {
        Log(string.Format(CultureInfo.InvariantCulture, format, args));
    }
    
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
            return;
            
        if (disposing)
        {
        }
        
        _disposed = true;
    }
}