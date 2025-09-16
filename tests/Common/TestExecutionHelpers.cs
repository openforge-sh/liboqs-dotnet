using System.Runtime.InteropServices;

namespace OpenForge.Cryptography.LibOqs.Tests.Common;

public static class TestExecutionHelpers
{
    private const int DefaultStackSize = 8 * 1024 * 1024; // 8MB stack size
    
    private static readonly Lazy<bool> _isAlpineLinux = new(() => DetectAlpineLinux());
    
    private static bool DetectAlpineLinux()
    {
        #pragma warning disable CA1031 // Do not catch general exception types
        try
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return false;
                
            const string osReleasePath = "/etc/os-release";
            if (!File.Exists(osReleasePath))
                return false;
                
            var lines = File.ReadAllLines(osReleasePath);
            foreach (var line in lines)
            {
                if (line.StartsWith("ID=", StringComparison.OrdinalIgnoreCase))
                {
                    var value = line[3..].Trim('"', '\'');
                    return string.Equals(value, "alpine", StringComparison.OrdinalIgnoreCase);
                }
            }
        }
        catch
        {
            // If we can't detect, assume it's not Alpine
        }
        #pragma warning restore CA1031 // Do not catch general exception types
        return false;
    }
    
    private static bool RequiresLargeStackPlatform =>
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || 
        RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ||
        _isAlpineLinux.Value;

    /// <summary>
    /// Executes an action on a thread with a larger stack size to handle algorithms with large keys.
    /// This is particularly important for Classic McEliece, HQC (KEM) and SPHINCS+ (SIG) algorithms
    /// on Windows, macOS, and Alpine Linux which have smaller default stack sizes than regular Linux.
    /// </summary>
    public static void ExecuteWithLargeStack(Action action, int stackSizeBytes = DefaultStackSize)
    {
        ArgumentNullException.ThrowIfNull(action);

        if (RequiresLargeStackPlatform)
        {
            Exception? threadException = null;
            var thread = new Thread(() =>
            {
                #pragma warning disable CA1031 // Do not catch general exception types
                try
                {
                    action();
                }
                catch (Exception ex)
                {
                    threadException = ex;
                }
            }, stackSizeBytes);

            thread.Start();
            thread.Join();

            if (threadException != null)
            {
                throw threadException;
            }
        }
        else
        {
            // On regular Linux (non-Alpine), the default stack size is usually sufficient
            action();
        }
    }

    /// <summary>
    /// Executes a function on a thread with a larger stack size and returns the result.
    /// </summary>
    public static T ExecuteWithLargeStack<T>(Func<T> func, int stackSizeBytes = DefaultStackSize)
    {
        ArgumentNullException.ThrowIfNull(func);

        if (RequiresLargeStackPlatform)
        {
            T? result = default;
            Exception? threadException = null;
            var thread = new Thread(() =>
            {
                try
                {
                    result = func();
                }
                catch (Exception ex)
                {
                    threadException = ex;
                }
                #pragma warning restore CA1031 // Do not catch general exception types
            }, stackSizeBytes);

            thread.Start();
            thread.Join();

            if (threadException != null)
            {
                throw threadException;
            }

            return result!;
        }
        else
        {
            // On regular Linux (non-Alpine), the default stack size is usually sufficient
            return func();
        }
    }

    /// <summary>
    /// Determines if the current algorithm requires a larger stack size.
    /// </summary>
    public static bool RequiresLargeStack(string algorithm)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);
        // Algorithms known to require larger stack sizes
        return algorithm.Contains("Classic-McEliece", StringComparison.OrdinalIgnoreCase) ||
               algorithm.Contains("HQC", StringComparison.OrdinalIgnoreCase) ||
               algorithm.Contains("SPHINCS", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Conditionally executes with larger stack only for algorithms that need it.
    /// </summary>
    public static void ConditionallyExecuteWithLargeStack(string algorithm, Action action)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);
        ArgumentNullException.ThrowIfNull(action);

        if (RequiresLargeStack(algorithm) && RequiresLargeStackPlatform)
        {
            ExecuteWithLargeStack(action);
        }
        else
        {
            action();
        }
    }
}