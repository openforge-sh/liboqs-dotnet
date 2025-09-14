using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.Tests.Common;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
internal sealed class SkipOnPlatformAttribute : FactAttribute
{
    public string[] Platforms { get; }

    public SkipOnPlatformAttribute(
        params string[] platforms) : this(platforms, null, -1)
    {
    }
    
    public SkipOnPlatformAttribute(
        string[] platforms,
        [CallerFilePath] string? sourceFilePath = null,
        [CallerLineNumber] int sourceLineNumber = -1) : base(sourceFilePath, sourceLineNumber)
    {
        Platforms = platforms ?? throw new ArgumentNullException(nameof(platforms));
        
        foreach (var platform in platforms)
        {
            if (IsCurrentPlatform(platform))
            {
                Skip = $"Test skipped on {platform}";
                break;
            }
        }
    }
    
    private static bool IsCurrentPlatform(string platform)
    {
        return platform.ToUpperInvariant() switch
        {
            "WINDOWS" => RuntimeInformation.IsOSPlatform(OSPlatform.Windows),
            "LINUX" => RuntimeInformation.IsOSPlatform(OSPlatform.Linux),
            "OSX" or "MACOS" => RuntimeInformation.IsOSPlatform(OSPlatform.OSX),
            _ => false
        };
    }
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
internal sealed class PlatformSpecificFactAttribute : FactAttribute
{
    public string[] Platforms { get; }

    public PlatformSpecificFactAttribute(
        params string[] platforms) : this(platforms, null, -1)
    {
    }
    
    public PlatformSpecificFactAttribute(
        string[] platforms,
        [CallerFilePath] string? sourceFilePath = null,
        [CallerLineNumber] int sourceLineNumber = -1) : base(sourceFilePath, sourceLineNumber)
    {
        Platforms = platforms ?? throw new ArgumentNullException(nameof(platforms));
        var runOnCurrentPlatform = false;
        
        foreach (var platform in platforms)
        {
            if (IsCurrentPlatform(platform))
            {
                runOnCurrentPlatform = true;
                break;
            }
        }
        
        if (!runOnCurrentPlatform)
        {
            Skip = $"Test only runs on: {string.Join(", ", platforms)}";
        }
    }
    
    private static bool IsCurrentPlatform(string platform)
    {
        return platform.ToUpperInvariant() switch
        {
            "WINDOWS" => RuntimeInformation.IsOSPlatform(OSPlatform.Windows),
            "LINUX" => RuntimeInformation.IsOSPlatform(OSPlatform.Linux),
            "OSX" or "MACOS" => RuntimeInformation.IsOSPlatform(OSPlatform.OSX),
            _ => false
        };
    }
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
internal sealed class PlatformSpecificTheoryAttribute : TheoryAttribute
{
    public string[] Platforms { get; }

    public PlatformSpecificTheoryAttribute(
        params string[] platforms) : this(platforms, null, -1)
    {
    }
    
    public PlatformSpecificTheoryAttribute(
        string[] platforms,
        [CallerFilePath] string? sourceFilePath = null,
        [CallerLineNumber] int sourceLineNumber = -1) : base(sourceFilePath, sourceLineNumber)
    {
        Platforms = platforms ?? throw new ArgumentNullException(nameof(platforms));
        var runOnCurrentPlatform = false;
        
        foreach (var platform in platforms)
        {
            if (IsCurrentPlatform(platform))
            {
                runOnCurrentPlatform = true;
                break;
            }
        }
        
        if (!runOnCurrentPlatform)
        {
            Skip = $"Test only runs on: {string.Join(", ", platforms)}";
        }
    }
    
    private static bool IsCurrentPlatform(string platform)
    {
        return platform.ToUpperInvariant() switch
        {
            "WINDOWS" => RuntimeInformation.IsOSPlatform(OSPlatform.Windows),
            "LINUX" => RuntimeInformation.IsOSPlatform(OSPlatform.Linux),
            "OSX" or "MACOS" => RuntimeInformation.IsOSPlatform(OSPlatform.OSX),
            _ => false
        };
    }
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
internal sealed class SkipOnArchitectureAttribute : FactAttribute
{
    public Architecture[] Architectures { get; }

    public SkipOnArchitectureAttribute(
        params Architecture[] architectures) : this(architectures, null, -1)
    {
    }
    
    public SkipOnArchitectureAttribute(
        Architecture[] architectures,
        [CallerFilePath] string? sourceFilePath = null,
        [CallerLineNumber] int sourceLineNumber = -1) : base(sourceFilePath, sourceLineNumber)
    {
        Architectures = architectures ?? throw new ArgumentNullException(nameof(architectures));
        var currentArch = RuntimeInformation.OSArchitecture;
        
        foreach (var arch in architectures)
        {
            if (arch == currentArch)
            {
                Skip = $"Test skipped on {arch} architecture";
                break;
            }
        }
    }
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
internal sealed class ArchitectureSpecificFactAttribute : FactAttribute
{
    public Architecture[] Architectures { get; }

    public ArchitectureSpecificFactAttribute(
        params Architecture[] architectures) : this(architectures, null, -1)
    {
    }
    
    public ArchitectureSpecificFactAttribute(
        Architecture[] architectures,
        [CallerFilePath] string? sourceFilePath = null,
        [CallerLineNumber] int sourceLineNumber = -1) : base(sourceFilePath, sourceLineNumber)
    {
        Architectures = architectures ?? throw new ArgumentNullException(nameof(architectures));
        var currentArch = RuntimeInformation.OSArchitecture;
        var runOnCurrentArch = false;
        
        foreach (var arch in architectures)
        {
            if (arch == currentArch)
            {
                runOnCurrentArch = true;
                break;
            }
        }
        
        if (!runOnCurrentArch)
        {
            Skip = $"Test only runs on: {string.Join(", ", architectures)}";
        }
    }
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
internal sealed class TestCategoryAttribute : Attribute
{
    public string Category { get; }

    public TestCategoryAttribute(string category)
    {
        Category = category ?? throw new ArgumentNullException(nameof(category));
    }
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
internal sealed class RequiresElevatedPrivilegesAttribute : FactAttribute
{
    public RequiresElevatedPrivilegesAttribute(
        [CallerFilePath] string? sourceFilePath = null,
        [CallerLineNumber] int sourceLineNumber = -1) : base(sourceFilePath, sourceLineNumber)
    {
        if (!IsElevated())
        {
            Skip = "Test requires elevated privileges (run as Administrator/root)";
        }
    }
    
    private static bool IsElevated()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        else
        {
            return Environment.GetEnvironmentVariable("USER") == "root" || 
                   Environment.GetEnvironmentVariable("EUID") == "0";
        }
    }
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
internal sealed class RequiresAlgorithmAttribute(
    string algorithmName,
    [CallerFilePath] string? sourceFilePath = null,
    [CallerLineNumber] int sourceLineNumber = -1) : FactAttribute(sourceFilePath, sourceLineNumber)
{
    public string AlgorithmName { get; } = algorithmName ?? throw new ArgumentNullException(nameof(algorithmName));
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
internal sealed class LongRunningTestAttribute(
    string durationCategory = "Medium",
    [CallerFilePath] string? sourceFilePath = null,
    [CallerLineNumber] int sourceLineNumber = -1) : FactAttribute(sourceFilePath, sourceLineNumber)
{
    public string DurationCategory { get; } = durationCategory ?? "Medium";
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
internal sealed class RequiresMinimumMemoryAttribute : FactAttribute
{
    public long MinimumMemoryBytes { get; }

    public RequiresMinimumMemoryAttribute(
        long minimumMemoryBytes,
        [CallerFilePath] string? sourceFilePath = null,
        [CallerLineNumber] int sourceLineNumber = -1) : base(sourceFilePath, sourceLineNumber)
    {
        MinimumMemoryBytes = minimumMemoryBytes;
        
        const long reasonableMemoryThreshold = 100 * 1024 * 1024; // 100MB
        
        if (minimumMemoryBytes > reasonableMemoryThreshold)
        {
            try
            {
                GC.GetTotalMemory(false);
                var availableMemory = GetAvailablePhysicalMemory();
                
                if (availableMemory.HasValue && availableMemory.Value < minimumMemoryBytes)
                {
                    Skip = $"Test requires at least {minimumMemoryBytes:N0} bytes of available memory, but only {availableMemory.Value:N0} bytes are available";
                }
                else if (!availableMemory.HasValue && minimumMemoryBytes > 1024 * 1024 * 1024) // 1GB
                {
                    Skip = $"Test requires at least {minimumMemoryBytes:N0} bytes of available memory";
                }
            }
            catch (Exception ex) when (ex is OutOfMemoryException or InvalidOperationException or UnauthorizedAccessException or PlatformNotSupportedException)
            {
                if (minimumMemoryBytes > 2L * 1024 * 1024 * 1024) // 2GB
                {
                    Skip = $"Test requires at least {minimumMemoryBytes:N0} bytes of available memory";
                }
            }
        }
    }
    
    private static long? GetAvailablePhysicalMemory()
    {
        try
        {
            var memoryInfo = GC.GetGCMemoryInfo();
            if (memoryInfo.TotalAvailableMemoryBytes > 0)
            {
                return memoryInfo.TotalAvailableMemoryBytes;
            }
        }
        catch (Exception ex) when (ex is OutOfMemoryException or InvalidOperationException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
        }
        
        return null;
    }
}

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
internal sealed class SecurityCriticalAttribute(string category = "General") : Attribute
{
    public string Category { get; } = category ?? "General";
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
internal sealed class AlgorithmSpecificTheoryAttribute : TheoryAttribute
{
    public string[] AlgorithmNames { get; }

    public AlgorithmSpecificTheoryAttribute(
        params string[] algorithmNames) : this(algorithmNames, null, -1)
    {
    }

    public AlgorithmSpecificTheoryAttribute(
        string[] algorithmNames,
        [CallerFilePath] string? sourceFilePath = null,
        [CallerLineNumber] int sourceLineNumber = -1) : base(sourceFilePath, sourceLineNumber)
    {
        AlgorithmNames = algorithmNames ?? throw new ArgumentNullException(nameof(algorithmNames));
    }
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
internal sealed class StressTestAttribute(
    string stressCategory = "Memory",
    int expectedDurationMs = 30000,
    [CallerFilePath] string? sourceFilePath = null,
    [CallerLineNumber] int sourceLineNumber = -1) : FactAttribute(sourceFilePath, sourceLineNumber)
{
    public string StressCategory { get; } = stressCategory ?? "Memory";

    public int ExpectedDurationMs { get; } = expectedDurationMs;
}