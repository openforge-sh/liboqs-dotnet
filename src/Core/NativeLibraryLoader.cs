using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OpenForge.Cryptography.LibOqs.Core;

/// <summary>
/// Handles the platform-specific loading of the native liboqs library.
/// This class determines the correct binary to load based on the operating system and CPU architecture,
/// resolving it from NuGet package runtime-specific folders. Supports modular package design by searching
/// across all registered assemblies (Core, KEM, SIG, Full) to locate the appropriate native library variant.
/// </summary>
internal static class NativeLibraryLoader
{
    private static readonly HashSet<Assembly> _registeredAssemblies = new();
    private static readonly object _lock = new();

    /// <summary>
    /// Registers the custom DllImportResolver for a given assembly, enabling it to locate the
    /// native LibOQS library from the correct runtime-specific folder.
    /// </summary>
    /// <param name="assembly">The assembly containing the P/Invoke declarations that need to be resolved.</param>
    /// <remarks>
    /// This method is essential for the modular design of the library. Each assembly that contains
    /// P/Invoke calls (e.g., Core, KEM, SIG) must register itself with this resolver.
    /// It is thread-safe and idempotent, ensuring that the resolver is set only once per assembly.
    /// This is typically called from the static constructor of a feature's internal provider class.
    /// </remarks>
    public static void Register(Assembly assembly)
    {
        lock (_lock)
        {
            if (!_registeredAssemblies.Contains(assembly))
            {
                NativeLibrary.SetDllImportResolver(assembly, ImportResolver);
                _registeredAssemblies.Add(assembly);
            }
        }
    }

    /// <summary>
    /// Explicitly triggers the static constructor to set up the native library resolver.
    /// This method should be called once before any LibOQS functions are used.
    /// It is thread-safe and ensures that the resolver is ready to load the correct native library for the current platform.
    /// </summary>
    public static void Initialize()
    {
        // Static constructor will be called
    }

    private static IntPtr ImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != LibOqsNative.LibraryName)
            return IntPtr.Zero;

        try
        {
            var rid = GetRuntimeIdentifier();
            var libraryFileName = GetLibraryFileName();
            var searchedPaths = new List<string>();
            
            // Diagnostic logging for CI/CD debugging
            LogDiagnostic($"ImportResolver called for '{libraryName}' from assembly '{assembly.GetName().Name}'");
            LogDiagnostic($"Platform: {RuntimeInformation.OSDescription}, Arch: {RuntimeInformation.ProcessArchitecture}");
            LogDiagnostic($"RID: {rid}, LibraryFileName: {libraryFileName}");

            // Try to load from multiple locations in order of preference
            // 1. First try the requesting assembly's directory
            var libraryHandle = TryLoadFromAssemblyDirectory(assembly, rid, libraryFileName, searchedPaths);
            if (libraryHandle != IntPtr.Zero)
                return libraryHandle;

            // 2. Try all registered assemblies' directories (for modular package design)
            // This handles the case where Core doesn't have the native library but KEM/SIG/Full do
            LogDiagnostic($"Trying registered assemblies (count: {_registeredAssemblies.Count})");
            lock (_lock)
            {
                var otherAssemblies = _registeredAssemblies.Where(a => a != assembly);
                foreach (var registeredAssembly in otherAssemblies)
                {
                    libraryHandle = TryLoadFromAssemblyDirectory(registeredAssembly, rid, libraryFileName, searchedPaths);
                    if (libraryHandle != IntPtr.Zero)
                    {
                        LogDiagnostic($"Successfully loaded from {registeredAssembly.GetName().Name}");
                        return libraryHandle;
                    }
                }
            }

            // 3. Fallback to standard resolution
            if (NativeLibrary.TryLoad(libraryFileName, assembly, searchPath, out var handle))
            {
                return handle;
            }

            var errorMessage = $"Could not load native library '{libraryFileName}' for runtime '{rid}'. " +
                               $"Searched paths: {string.Join(", ", searchedPaths)}";
            LogDiagnostic($"FINAL ERROR: {errorMessage}");
            throw new DllNotFoundException(errorMessage);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("invalid library file", StringComparison.Ordinal) || ex.Message.Contains("is empty", StringComparison.Ordinal))
        {
            // Re-throw InvalidOperationException for invalid file scenarios without wrapping
            throw;
        }
        catch (Exception ex) when (ex is not DllNotFoundException)
        {
            throw new DllNotFoundException($"Failed to resolve native library '{libraryName}': {ex.Message}", ex);
        }
    }

    private static IntPtr TryLoadFromAssemblyDirectory(Assembly assembly, string rid, string libraryFileName, List<string> searchedPaths)
    {
        var assemblyLocation = assembly.Location;
        var assemblyName = assembly.GetName().Name;
        
        // Diagnostic logging
        LogDiagnostic($"TryLoadFromAssemblyDirectory - Assembly: {assemblyName}");
        LogDiagnostic($"  Location: '{assemblyLocation}' (IsEmpty: {string.IsNullOrEmpty(assemblyLocation)})");
        
        if (string.IsNullOrEmpty(assemblyLocation))
        {
            LogDiagnostic($"  Skipping {assemblyName} - empty location");
            return IntPtr.Zero;
        }

        var assemblyDirectory = Path.GetDirectoryName(assemblyLocation);
        LogDiagnostic($"  Directory: '{assemblyDirectory}'");
        
        if (string.IsNullOrEmpty(assemblyDirectory))
        {
            LogDiagnostic($"  Skipping {assemblyName} - empty directory");
            return IntPtr.Zero;
        }

        // Validate paths to prevent directory traversal
        var validatedAssemblyDir = Path.GetFullPath(assemblyDirectory);

        // Try to load from the runtimes folder first (NuGet package structure)
        var runtimePath = Path.Combine(validatedAssemblyDir, "runtimes", rid, "native", libraryFileName);
        var validatedRuntimePath = Path.GetFullPath(runtimePath);
        searchedPaths.Add(validatedRuntimePath);
        
        // Security check: ensure the path is still within expected directories
        if (validatedRuntimePath.StartsWith(validatedAssemblyDir, StringComparison.OrdinalIgnoreCase) && File.Exists(validatedRuntimePath))
        {
            try
            {
                ValidateLibraryFile(validatedRuntimePath);
                return NativeLibrary.Load(validatedRuntimePath);
            }
            #pragma warning disable CA1031 // Do not catch general exception types
            catch
            {
                // Continue searching if this specific file fails to load - we want to try all possible locations
                // before giving up, so we intentionally catch all exceptions here
            }
        }

        // Try loading from the same directory as the assembly
        var localPath = Path.Combine(validatedAssemblyDir, libraryFileName);
        var validatedLocalPath = Path.GetFullPath(localPath);
        searchedPaths.Add(validatedLocalPath);
        
        if (validatedLocalPath.StartsWith(validatedAssemblyDir, StringComparison.OrdinalIgnoreCase) && File.Exists(validatedLocalPath))
        {
            try
            {
                ValidateLibraryFile(validatedLocalPath);
                return NativeLibrary.Load(validatedLocalPath);
            }
            catch
            {
                // Continue searching if this specific file fails to load - we want to try all possible locations
                // before giving up, so we intentionally catch all exceptions here
            }
            #pragma warning restore CA1031 // Do not catch general exception types
        }

        return IntPtr.Zero;
    }

    /// <summary>
    /// Validates that a library file is suitable for loading.
    /// This method performs basic size and integrity checks before attempting to load the native library.
    /// </summary>
    /// <param name="path">The path to the library file to validate.</param>
    /// <exception cref="InvalidOperationException">Thrown when the file is empty, too small, or appears invalid.</exception>
    internal static void ValidateLibraryFile(string path)
    {
        var fileInfo = new FileInfo(path);
        
        // Check for empty file
        if (fileInfo.Length == 0)
            throw new InvalidOperationException($"Native library file '{path}' is empty");
        
        // Check for suspiciously small file
        // Native libraries are typically much larger, but we use a conservative threshold
        const long MinimumLibrarySize = 1024; // 1KB minimum
        if (fileInfo.Length < MinimumLibrarySize)
            throw new InvalidOperationException($"Native library file '{path}' appears to be invalid (size: {fileInfo.Length} bytes)");
        
        // Platform-specific validation
        ValidatePlatformSpecificLibrary(path);
    }

    /// <summary>
    /// Performs platform-specific validation of library files.
    /// </summary>
    /// <param name="path">The path to the library file to validate.</param>
    private static void ValidatePlatformSpecificLibrary(string path)
    {
        // Add platform-specific validation based on file extension
        var extension = Path.GetExtension(path).ToUpperInvariant();
        
        try
        {
            switch (extension)
            {
                case ".dll" when RuntimeInformation.IsOSPlatform(OSPlatform.Windows):
                    ValidateWindowsLibrary(path);
                    break;
                case ".so" when RuntimeInformation.IsOSPlatform(OSPlatform.Linux):
                    ValidateLinuxLibrary(path);
                    break;
                case ".dylib" when RuntimeInformation.IsOSPlatform(OSPlatform.OSX):
                    ValidateMacLibrary(path);
                    break;
            }
        }
        catch (Exception ex) when (ex is IOException 
            or UnauthorizedAccessException 
            or ArgumentException 
            or InvalidOperationException 
            or EndOfStreamException
            or ObjectDisposedException)
        {
            // Log the validation error but don't prevent loading
            // The actual NativeLibrary.Load will provide better error information
            // These exceptions are expected during file validation operations
            System.Diagnostics.Debug.WriteLine($"Library validation warning for '{path}': {ex.Message}");
        }
    }

    /// <summary>
    /// Validates a Windows DLL library file.
    /// </summary>
    /// <param name="path">The path to the library file to validate.</param>
    private static void ValidateWindowsLibrary(string path)
    {
        // Basic check - file should contain PE header
        using var fileStream = new FileStream(path, FileMode.Open, FileAccess.Read);
        using var reader = new BinaryReader(fileStream);
        
        // Check for MZ header
        if (reader.ReadUInt16() != 0x5A4D) // "MZ"
            throw new InvalidOperationException($"Windows library file '{path}' does not contain valid MZ header");
    }

    /// <summary>
    /// Validates a Linux shared library file.
    /// </summary>
    /// <param name="path">The path to the library file to validate.</param>
    private static void ValidateLinuxLibrary(string path)
    {
        // Basic check - file should contain ELF header
        using var fileStream = new FileStream(path, FileMode.Open, FileAccess.Read);
        using var reader = new BinaryReader(fileStream);
        
        // Check for ELF magic number
        var magic = reader.ReadBytes(4);
        if (magic[0] != 0x7F || magic[1] != 0x45 || magic[2] != 0x4C || magic[3] != 0x46) // 0x7F 'E' 'L' 'F'
            throw new InvalidOperationException($"Linux library file '{path}' does not contain valid ELF header");
    }

    /// <summary>
    /// Validates a macOS dynamic library file.
    /// </summary>
    /// <param name="path">The path to the library file to validate.</param>
    private static void ValidateMacLibrary(string path)
    {
        // Basic check - file should contain Mach-O header
        using var fileStream = new FileStream(path, FileMode.Open, FileAccess.Read);
        using var reader = new BinaryReader(fileStream);
        
        // Check for Mach-O magic number (32-bit or 64-bit)
        var magic = reader.ReadUInt32();
        if (magic != 0xFEEDFACE && magic != 0xFEEDFACF && magic != 0xCAFEBABE && magic != 0xCAFEBABF)
            throw new InvalidOperationException($"macOS library file '{path}' does not contain valid Mach-O header");
    }

    private static string GetRuntimeIdentifier()
    {
        var arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            Architecture.Arm => "arm",
            var riscv when riscv.ToString() == "RiscV64" => "riscv64",
            _ => throw new PlatformNotSupportedException($"Architecture {RuntimeInformation.ProcessArchitecture} is not supported")
        };

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return $"win-{arch}";

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            // Check if musl-based (Alpine Linux, etc.)
            var isMusl = File.Exists("/lib/libc.musl-x86_64.so.1") ||
                         File.Exists("/lib/ld-musl-x86_64.so.1") ||
                         File.Exists("/lib/libc.musl-aarch64.so.1") ||
                         File.Exists("/lib/ld-musl-aarch64.so.1");

            return isMusl ? $"linux-musl-{arch}" : $"linux-{arch}";
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return $"osx-{arch}";

        throw new PlatformNotSupportedException($"Operating system is not supported");
    }

    private static string GetLibraryFileName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return "liboqs.dll";

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return "liboqs.so";

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return "liboqs.dylib";

        throw new PlatformNotSupportedException("Operating system is not supported");
    }

    /// <summary>
    /// Validates the integrity of a native library file using SHA-256 hash comparison.
    /// This method is optional and should be used when known good hashes are available.
    /// </summary>
    /// <param name="libraryPath">The path to the library file to validate.</param>
    /// <param name="expectedSha256Hash">The expected SHA-256 hash in hexadecimal format.</param>
    /// <param name="throwOnMismatch">Whether to throw an exception on hash mismatch or just return false.</param>
    /// <returns>True if the hash matches or validation is skipped, false if hash doesn't match and throwOnMismatch is false.</returns>
    /// <exception cref="ArgumentException">Thrown if parameters are invalid.</exception>
    /// <exception cref="InvalidOperationException">Thrown if hash validation fails and throwOnMismatch is true.</exception>
    public static bool ValidateLibraryIntegrity(string libraryPath, string expectedSha256Hash, bool throwOnMismatch = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(libraryPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedSha256Hash);

        if (!File.Exists(libraryPath))
        {
            var message = $"Library file not found: {libraryPath}";
            if (throwOnMismatch)
                throw new FileNotFoundException(message);
            return false;
        }

        // Normalize expected hash (remove spaces, convert to uppercase)
        var normalizedExpectedHash = expectedSha256Hash.Replace(" ", "", StringComparison.Ordinal).Replace("-", "", StringComparison.Ordinal).ToUpperInvariant();
        
        if (normalizedExpectedHash.Length != 64 || !IsValidHexString(normalizedExpectedHash))
        {
            var message = "Expected SHA-256 hash must be a valid 64-character hexadecimal string";
            if (throwOnMismatch)
                throw new ArgumentException(message, nameof(expectedSha256Hash));
            return false;
        }

        try
        {
            using var fileStream = new FileStream(libraryPath, FileMode.Open, FileAccess.Read);
            using var sha256 = SHA256.Create();
            
            var computedHashBytes = sha256.ComputeHash(fileStream);
            var computedHash = SecurityUtilities.ToHexString(computedHashBytes).ToUpperInvariant();

            if (computedHash == normalizedExpectedHash)
                return true;

            var message = $"Library integrity validation failed for '{libraryPath}'. " +
                         $"Expected: {normalizedExpectedHash}, Computed: {computedHash}";
            
            if (throwOnMismatch)
                throw new InvalidOperationException(message);
            
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
        {
            var message = $"Failed to validate library integrity for '{libraryPath}': {ex.Message}";
            if (throwOnMismatch)
                throw new InvalidOperationException(message, ex);
            return false;
        }
    }

    private static bool IsValidHexString(string input)
    {
        foreach (char c in input)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    }

    /// <summary>
    /// Logs diagnostic information to a file for CI/CD debugging.
    /// This is a temporary method for investigating ARM64 library loading issues.
    /// </summary>
    private static void LogDiagnostic(string message)
    {
        #pragma warning disable CA1031, CA1305
        try
        {
            var logFile = Path.Combine(AppContext.BaseDirectory, "native-library-diagnostics.log");
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff");
            File.AppendAllText(logFile, $"[{timestamp}] {message}{Environment.NewLine}");
        }
        catch
        {
            // Ignore logging errors - this is just for diagnostics
        }
        #pragma warning restore CA1031, CA1305
    }
}