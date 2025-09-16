using System.Runtime.InteropServices;

namespace OpenForge.Cryptography.LibOqs.Tests.Common;

public static class TestExecutionHelpers
{
    private const int DefaultStackSize = 8 * 1024 * 1024; // 8MB stack size

    /// <summary>
    /// Executes an action on a thread with a larger stack size to handle algorithms with large keys.
    /// This is particularly important for Classic McEliece, HQC (KEM) and SPHINCS+ (SIG) algorithms
    /// on Windows and macOS which have smaller default stack sizes than Linux.
    /// </summary>
    public static void ExecuteWithLargeStack(Action action, int stackSizeBytes = DefaultStackSize)
    {
        ArgumentNullException.ThrowIfNull(action);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
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
            // On Linux, the default stack size is usually sufficient
            action();
        }
    }

    /// <summary>
    /// Executes a function on a thread with a larger stack size and returns the result.
    /// </summary>
    public static T ExecuteWithLargeStack<T>(Func<T> func, int stackSizeBytes = DefaultStackSize)
    {
        ArgumentNullException.ThrowIfNull(func);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
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
            // On Linux, the default stack size is usually sufficient
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

        if (RequiresLargeStack(algorithm) &&
            (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX)))
        {
            ExecuteWithLargeStack(action);
        }
        else
        {
            action();
        }
    }
}