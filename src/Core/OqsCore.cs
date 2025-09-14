using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace OpenForge.Cryptography.LibOqs.Core;
#pragma warning disable S112 // OutOfMemoryException should not be thrown by user code - this is infrastructure code in a NuGet library wrapping native memory allocation

/// <summary>
/// Provides a managed C# wrapper for the liboqs native library, offering a safe and convenient interface
/// for post-quantum cryptographic operations. This static class includes methods for initializing and cleaning up
/// the library, managing memory securely, generating random data, and accessing CPU features.
/// </summary>
public static class OqsCore
{
    static OqsCore()
    {
        NativeLibraryLoader.Register(typeof(LibOqsNative).Assembly);
    }

    private static bool _initialized;
    private static readonly object _lock = new();

    /// <summary>
    /// Initializes the LibOQS library. This method is thread-safe and should be called before using any other LibOQS functionality.
    /// </summary>
    public static void Initialize()
    {
        if (_initialized)
            return;

        lock (_lock)
        {
            if (_initialized)
                return;

            NativeLibraryLoader.Initialize();
            LibOqsNative.OQS_init();
            _initialized = true;
        }
    }

    /// <summary>
    /// Destroys the LibOQS library and cleans up global resources.
    /// Call this when you're done using LibOQS to ensure proper cleanup.
    /// </summary>
    internal static void Destroy()
    {
        if (!_initialized)
            return;

        lock (_lock)
        {
            if (!_initialized)
                return;

            LibOqsNative.OQS_destroy();
            _initialized = false;
        }
    }

    /// <summary>
    /// Gets the version string of the liboqs library.
    /// </summary>
    /// <returns>The version string of liboqs.</returns>
    public static string GetVersion()
    {
        var versionPtr = LibOqsNative.OQS_version();
        return Marshal.PtrToStringAnsi(versionPtr) ?? "Unknown";
    }

    /// <summary>
    /// Stops and cleans up resources for the current thread.
    /// This should be called when a thread that has used liboqs is about to terminate.
    /// </summary>
    public static void ThreadStop()
    {
        LibOqsNative.OQS_thread_stop();
    }

    /// <summary>
    /// Allocates memory using LibOQS's memory allocator.
    /// Memory allocated with this method should be freed with <see cref="FreeMemory"/>.
    /// </summary>
    /// <param name="size">The size in bytes to allocate.</param>
    /// <returns>A pointer to the allocated memory.</returns>
    /// <exception cref="ArgumentException">Thrown if size is zero or exceeds the maximum allowed size (1GB).</exception>
    /// <exception cref="OutOfMemoryException">Thrown if allocation fails.</exception>
    /// <exception cref="InvalidOperationException">Thrown if LibOQS has not been initialized.</exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA2201:Exception type System.OutOfMemoryException is reserved by the runtime", Justification = "Infrastructure code in a NuGet library wrapping native memory allocation")]
    public static IntPtr AllocateMemory(nuint size)
    {
        if (size == 0)
            throw new ArgumentException("Size must be greater than zero", nameof(size));

        // Protect against excessive allocations (1GB limit)
        const nuint MaxAllowedSize = 1024 * 1024 * 1024;
        if (size > MaxAllowedSize)
            throw new ArgumentException($"Allocation size {size} exceeds maximum allowed size {MaxAllowedSize}", nameof(size));

        EnsureInitialized();
        var memPtr = LibOqsNative.OQS_MEM_malloc(size);
        if (memPtr == IntPtr.Zero)
        {
            throw new OutOfMemoryException("Failed to allocate memory using OQS_MEM_alloc");
        }
        return memPtr;
    }

    /// <summary>
    /// Frees memory allocated by <see cref="AllocateMemory"/> using secure free (clears memory first).
    /// This is the recommended method for freeing memory in cryptographic applications.
    /// </summary>
    /// <param name="memPtr">Pointer to the memory to free. Safe to pass IntPtr.Zero.</param>
    /// <param name="size">The size in bytes of the memory block.</param>
    /// <exception cref="InvalidOperationException">Thrown if LibOQS has not been initialized.</exception>
    public static void FreeMemory(IntPtr memPtr, nuint size)
    {
        if (memPtr == IntPtr.Zero)
            return;

        EnsureInitialized();
        LibOqsNative.OQS_MEM_secure_free(memPtr, size);
    }

    /// <summary>
    /// Securely clears memory by overwriting it with zeros.
    /// This operation cannot be optimized away by the compiler, making it suitable for clearing sensitive data.
    /// </summary>
    /// <param name="memPtr">Pointer to the memory to cleanse. Safe to pass IntPtr.Zero.</param>
    /// <param name="size">The size in bytes of the memory to cleanse.</param>
    /// <exception cref="InvalidOperationException">Thrown if LibOQS has not been initialized.</exception>
    public static void CleanseMemory(IntPtr memPtr, nuint size)
    {
        if (memPtr == IntPtr.Zero)
            return;

        EnsureInitialized();
        LibOqsNative.OQS_MEM_cleanse(memPtr, size);
    }


    /// <summary>
    /// Fills the provided buffer with cryptographically secure random bytes using LibOQS's random number generator.
    /// </summary>
    /// <param name="buffer">The buffer to fill with random bytes. Empty buffers are safely ignored.</param>
    /// <exception cref="InvalidOperationException">Thrown if LibOQS has not been initialized.</exception>
    public static unsafe void GenerateRandomBytes(Span<byte> buffer)
    {
        if (buffer.IsEmpty)
            return;

        EnsureInitialized();
        fixed (byte* ptr = buffer)
        {
            LibOqsNative.OQS_randombytes(ptr, (nuint)buffer.Length);
        }
    }

    /// <summary>
    /// Generates a new byte array filled with cryptographically secure random bytes.
    /// Includes basic entropy validation for buffers between 4 and 1024 bytes.
    /// </summary>
    /// <param name="length">The number of random bytes to generate. Maximum 1MB.</param>
    /// <returns>A new byte array containing cryptographically secure random bytes.</returns>
    /// <exception cref="ArgumentException">Thrown if length is negative or exceeds 1MB.</exception>
    /// <exception cref="InvalidOperationException">Thrown if LibOQS has not been initialized or if entropy validation fails.</exception>
    public static byte[] GenerateRandomBytes(int length)
    {
        SecurityUtilities.ValidateSize(length, 1024 * 1024, nameof(length)); // Limit to 1MB

        if (length == 0)
            return [];

        var buffer = new byte[length];
        GenerateRandomBytes(buffer);

        // Basic entropy validation for small buffers
        if (length >= 4 && length <= 1024)
        {
            SecurityUtilities.ValidateRandomBytesEntropy(buffer, "generated random bytes");
        }

        return buffer;
    }

    /// <summary>
    /// Switches the random number generator algorithm used by LibOQS.
    /// Common algorithms include "OpenSSL", "NIST-DRBG", and system-specific options.
    /// </summary>
    /// <param name="algorithmName">The name of the random algorithm to switch to.</param>
    /// <exception cref="ArgumentException">Thrown if the algorithm name is null, empty, whitespace, or not supported.</exception>
    /// <exception cref="InvalidOperationException">Thrown if LibOQS has not been initialized.</exception>
    public static void SwitchRandomAlgorithm(string algorithmName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithmName);

        EnsureInitialized();
        var result = LibOqsNative.OQS_randombytes_switch_algorithm(algorithmName);
        if (result != 0)
            throw new ArgumentException($"Failed to switch to random algorithm '{algorithmName}'", nameof(algorithmName));
    }

    /// <summary>
    /// Checks whether the current CPU supports a specific extension that can accelerate cryptographic operations.
    /// </summary>
    /// <param name="extension">The CPU extension to check for.</param>
    /// <returns>True if the CPU extension is available, false otherwise.</returns>
    /// <exception cref="InvalidOperationException">Thrown if LibOQS has not been initialized.</exception>
    public static bool HasCpuExtension(OqsCpUext extension)
    {
        EnsureInitialized();
        return LibOqsNative.OQS_CPU_has_extension(extension) != 0;
    }

    /// <summary>
    /// Allocates memory using the system's malloc function.
    /// Use this for temporary allocations when you need standard malloc behavior.
    /// </summary>
    /// <param name="size">The size in bytes to allocate.</param>
    /// <returns>A pointer to the allocated memory.</returns>
    /// <exception cref="ArgumentException">Thrown if size is zero or too large.</exception>
    /// <exception cref="OutOfMemoryException">Thrown if allocation fails.</exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA2201:Exception type System.OutOfMemoryException is reserved by the runtime", Justification = "Infrastructure code in a NuGet library wrapping native memory allocation")]
    public static IntPtr Malloc(nuint size)
    {
        if (size == 0)
            throw new ArgumentException("Size must be greater than zero", nameof(size));

        // Protect against excessive allocations (1GB limit)
        const nuint MaxAllowedSize = 1024 * 1024 * 1024;
        if (size > MaxAllowedSize)
            throw new ArgumentException($"Allocation size {size} exceeds maximum allowed size {MaxAllowedSize}", nameof(size));

        EnsureInitialized();
        var ptr = LibOqsNative.OQS_MEM_malloc(size);
        if (ptr == IntPtr.Zero)
        {
            throw new OutOfMemoryException("Failed to allocate memory using OQS_MEM_malloc");
        }
        return ptr;
    }

    /// <summary>
    /// Allocates zero-initialized memory using the system's calloc function.
    /// Use this when you need memory initialized to zero.
    /// </summary>
    /// <param name="numElements">The number of elements to allocate.</param>
    /// <param name="elementSize">The size of each element in bytes.</param>
    /// <returns>A pointer to the allocated and zero-initialized memory.</returns>
    /// <exception cref="ArgumentException">Thrown if parameters are invalid.</exception>
    /// <exception cref="OutOfMemoryException">Thrown if allocation fails.</exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA2201:Exception type System.OutOfMemoryException is reserved by the runtime", Justification = "Infrastructure code in a NuGet library wrapping native memory allocation")]
    public static IntPtr Calloc(nuint numElements, nuint elementSize)
    {
        if (numElements == 0)
            throw new ArgumentException("Number of elements must be greater than zero", nameof(numElements));
        if (elementSize == 0)
            throw new ArgumentException("Element size must be greater than zero", nameof(elementSize));

        // Check for overflow in total size calculation
        const nuint MaxAllowedSize = 1024 * 1024 * 1024;
        if (numElements > MaxAllowedSize / elementSize)
            throw new ArgumentException("Total allocation size would exceed maximum allowed size", nameof(numElements));

        EnsureInitialized();
        var ptr = LibOqsNative.OQS_MEM_calloc(numElements, elementSize);
        if (ptr == IntPtr.Zero)
        {
            throw new OutOfMemoryException("Failed to allocate memory using OQS_MEM_calloc");
        }
        return ptr;
    }

    /// <summary>
    /// Performs a secure comparison of two memory blocks in constant time.
    /// This prevents timing attacks when comparing sensitive data like cryptographic secrets.
    /// </summary>
    /// <param name="a">Pointer to the first memory block.</param>
    /// <param name="b">Pointer to the second memory block.</param>
    /// <param name="length">The length in bytes to compare.</param>
    /// <returns>0 if the memory blocks are equal, non-zero otherwise.</returns>
    public static int SecureCompare(IntPtr a, IntPtr b, nuint length)
    {
        if (a == IntPtr.Zero || b == IntPtr.Zero)
            throw new ArgumentException("Memory pointers cannot be null");

        EnsureInitialized();
        return LibOqsNative.OQS_MEM_secure_bcmp(a, b, length);
    }

    /// <summary>
    /// Internal fast-path version of SecureCompare for performance-critical scenarios.
    /// Assumes initialization has already been verified by the caller.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static int SecureCompareUnsafe(IntPtr a, IntPtr b, nuint length)
    {
        FastEnsureInitialized();
        return LibOqsNative.OQS_MEM_secure_bcmp(a, b, length);
    }

    /// <summary>
    /// Frees memory without secure clearing. Use only for non-sensitive data.
    /// For sensitive data, use <see cref="FreeMemory"/> instead (which uses secure clearing).
    /// </summary>
    /// <param name="memPtr">Pointer to the memory to free. Safe to pass IntPtr.Zero.</param>
    /// <exception cref="InvalidOperationException">Thrown if LibOQS has not been initialized.</exception>
    public static void InsecureFreeMemory(IntPtr memPtr)
    {
        if (memPtr == IntPtr.Zero)
            return;

        EnsureInitialized();
        LibOqsNative.OQS_MEM_insecure_free(memPtr);
    }

    /// <summary>
    /// Creates a secure byte array that automatically clears its contents when disposed.
    /// This is ideal for storing sensitive cryptographic material.
    /// </summary>
    /// <param name="length">The length of the array to create. Maximum 1MB.</param>
    /// <returns>A SecureByteArray instance that will securely clear its contents on disposal.</returns>
    /// <exception cref="ArgumentException">Thrown if length is negative or exceeds 1MB.</exception>
    public static SecureByteArray CreateSecureByteArray(int length)
    {
        SecurityUtilities.ValidateSize(length, 1024 * 1024, nameof(length)); // Limit to 1MB
        return new SecureByteArray(length);
    }

    /// <summary>
    /// Creates a secure byte array from existing data, which will be securely cleared when disposed.
    /// The input data is defensively copied to prevent external modification.
    /// </summary>
    /// <param name="data">The data to copy into the secure array.</param>
    /// <returns>A SecureByteArray instance containing a copy of the data.</returns>
    /// <exception cref="ArgumentException">Thrown if data length exceeds 1MB.</exception>
    public static SecureByteArray CreateSecureByteArray(ReadOnlySpan<byte> data)
    {
        SecurityUtilities.ValidateSize(data.Length, 1024 * 1024, nameof(data)); // Limit to 1MB
        var secureArray = new SecureByteArray(data.Length);
        data.CopyTo(secureArray.AsSpan());
        return secureArray;
    }

    private static void EnsureInitialized()
    {
        if (!_initialized)
            throw new InvalidOperationException("liboqs must be initialized before use. Call LibOqs.Initialize() first.");
    }

    /// <summary>
    /// Provides a hint about memory pressure after completing large cryptographic operations.
    /// This can help optimize garbage collection and memory usage in memory-constrained scenarios.
    /// </summary>
    /// <param name="bytesAllocated">The approximate number of bytes that were allocated for the operation.</param>
    /// <param name="forceGarbageCollection">Whether to immediately trigger garbage collection. Use sparingly in performance-critical code.</param>
    /// <remarks>
    /// This method is useful when:
    /// - Working with large-key algorithms (Classic McEliece, some NTRU variants)
    /// - Processing operations in batches
    /// - Running in memory-constrained environments (containers, IoT devices)
    /// - Experiencing memory pressure or frequent GC pauses
    /// 
    /// Call this after completing cryptographic operations that allocated significant memory.
    /// </remarks>
    public static void HintMemoryPressure(long bytesAllocated, bool forceGarbageCollection = false)
    {
        if (bytesAllocated <= 0)
            return;

        // Add memory pressure to help GC make informed decisions about when to collect
        GC.AddMemoryPressure(bytesAllocated);

        // Optionally force immediate collection (use sparingly)
        if (forceGarbageCollection)
        {
            #pragma warning disable S1215
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: false);
            #pragma warning restore S1215
        }
    }

    /// <summary>
    /// Removes memory pressure hint after memory has been freed.
    /// Call this to inform the GC that previously allocated cryptographic memory has been released.
    /// </summary>
    /// <param name="bytesFreed">The number of bytes that were freed.</param>
    /// <remarks>
    /// This should typically be called automatically by disposal methods, but can be used
    /// manually when implementing custom memory management scenarios.
    /// </remarks>
    public static void RemoveMemoryPressure(long bytesFreed)
    {
        if (bytesFreed <= 0)
            return;

        try
        {
            GC.RemoveMemoryPressure(bytesFreed);
        }
        catch (ArgumentOutOfRangeException)
        {
            // This can happen if RemoveMemoryPressure is called more than AddMemoryPressure
            // In cryptographic scenarios, it's better to be safe and ignore this edge case
        }
    }

    /// <summary>
    /// Gets memory usage recommendations for the specified algorithm.
    /// This helps applications understand memory requirements and plan accordingly.
    /// </summary>
    /// <param name="algorithmName">The algorithm name to get memory information for.</param>
    /// <returns>A structure containing memory usage estimates, or null if the algorithm is unknown.</returns>
    public static MemoryUsageInfo? GetMemoryUsageInfo(string algorithmName)
    {
        if (string.IsNullOrWhiteSpace(algorithmName))
            return null;

        return algorithmName switch
        {
            // Large-key algorithms that may benefit from memory pressure hints
            var alg when alg.StartsWith("Classic-McEliece", StringComparison.Ordinal) => new MemoryUsageInfo
            {
                EstimatedPeakUsage = alg switch
                {
                    "Classic-McEliece-6960119" => 2_500_000,  // ~2.5MB peak
                    "Classic-McEliece-8192128" => 3_000_000,  // ~3MB peak
                    _ => 1_500_000  // ~1.5MB peak for smaller variants
                },
                RecommendMemoryPressureHints = true,
                IsLargeKeyAlgorithm = true
            },

            var alg when alg.StartsWith("NTRU", StringComparison.Ordinal) => new MemoryUsageInfo
            {
                EstimatedPeakUsage = 100_000,  // ~100KB peak
                RecommendMemoryPressureHints = false,
                IsLargeKeyAlgorithm = false
            },

            var alg when alg.StartsWith("ML-KEM", StringComparison.Ordinal) || alg.StartsWith("Kyber", StringComparison.Ordinal) => new MemoryUsageInfo
            {
                EstimatedPeakUsage = 10_000,   // ~10KB peak
                RecommendMemoryPressureHints = false,
                IsLargeKeyAlgorithm = false
            },

            var alg when alg.StartsWith("ML-DSA", StringComparison.Ordinal) || alg.StartsWith("Dilithium", StringComparison.Ordinal) => new MemoryUsageInfo
            {
                EstimatedPeakUsage = 20_000,   // ~20KB peak
                RecommendMemoryPressureHints = false,
                IsLargeKeyAlgorithm = false
            },

            // Default for unknown algorithms
            _ => new MemoryUsageInfo
            {
                EstimatedPeakUsage = 50_000,   // Conservative 50KB estimate
                RecommendMemoryPressureHints = false,
                IsLargeKeyAlgorithm = false
            }
        };
    }

    /// <summary>
    /// Fast path initialization check for performance-critical internal methods.
    /// Only use this in methods where initialization has already been verified by the caller.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void FastEnsureInitialized()
    {
        if (!_initialized)
            ThrowNotInitialized();

        [MethodImpl(MethodImplOptions.NoInlining)]
        static void ThrowNotInitialized() => throw new InvalidOperationException("liboqs must be initialized before use. Call LibOqs.Initialize() first.");
    }
}

#pragma warning restore S112

/// <summary>
/// Provides information about memory usage characteristics for cryptographic algorithms.
/// This helps applications make informed decisions about memory management and optimization.
/// </summary>
public readonly record struct MemoryUsageInfo
{
    /// <summary>
    /// Estimated peak memory usage in bytes during cryptographic operations.
    /// This includes temporary allocations and key material.
    /// </summary>
    public long EstimatedPeakUsage { get; init; }

    /// <summary>
    /// Whether memory pressure hints are recommended for this algorithm.
    /// True for algorithms with large memory footprints that may benefit from GC hints.
    /// </summary>
    public bool RecommendMemoryPressureHints { get; init; }

    /// <summary>
    /// Whether this algorithm uses large keys (>1MB) that may impact memory usage.
    /// </summary>
    public bool IsLargeKeyAlgorithm { get; init; }

    /// <summary>
    /// Gets a human-readable description of the memory usage characteristics.
    /// </summary>
    public string UsageDescription => EstimatedPeakUsage switch
    {
        < 50_000 => "Low memory usage (< 50KB)",
        < 500_000 => "Moderate memory usage (50KB - 500KB)", 
        < 2_000_000 => "High memory usage (500KB - 2MB)",
        _ => "Very high memory usage (> 2MB)"
    };
}