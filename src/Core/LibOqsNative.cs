using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace OpenForge.Cryptography.LibOqs.Core;

/// <summary>
/// Provides direct P/Invoke declarations for the core LibOQS functions.
/// This class contains low-level native method bindings and should not be used directly by application code.
/// </summary>
internal static partial class LibOqsNative
{
    #pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public const string LibraryName = "oqs";
    #pragma warning restore CS1591 // Missing XML comment for publicly visible type or member

    [LibraryImport(LibraryName, EntryPoint = "OQS_init")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void OQS_init();

    [LibraryImport(LibraryName, EntryPoint = "OQS_destroy")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void OQS_destroy();

    [LibraryImport(LibraryName, EntryPoint = "OQS_version")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr OQS_version();

    [LibraryImport(LibraryName, EntryPoint = "OQS_thread_stop")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void OQS_thread_stop();


    [LibraryImport(LibraryName, EntryPoint = "OQS_MEM_cleanse")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void OQS_MEM_cleanse(IntPtr ptr, UIntPtr size);

    [LibraryImport(LibraryName, EntryPoint = "OQS_MEM_secure_free")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void OQS_MEM_secure_free(IntPtr ptr, UIntPtr size);

    [LibraryImport(LibraryName, EntryPoint = "OQS_MEM_malloc")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr OQS_MEM_malloc(UIntPtr size);

    [LibraryImport(LibraryName, EntryPoint = "OQS_MEM_calloc")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr OQS_MEM_calloc(UIntPtr num_elements, UIntPtr element_size);

    [LibraryImport(LibraryName, EntryPoint = "OQS_MEM_secure_bcmp")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int OQS_MEM_secure_bcmp(IntPtr a, IntPtr b, UIntPtr len);

    [LibraryImport(LibraryName, EntryPoint = "OQS_MEM_insecure_free")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void OQS_MEM_insecure_free(IntPtr ptr);

    [LibraryImport(LibraryName, EntryPoint = "OQS_MEM_strdup", StringMarshalling = StringMarshalling.Utf8)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr OQS_MEM_strdup(string str);

    [LibraryImport(LibraryName, EntryPoint = "OQS_randombytes")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial void OQS_randombytes(byte* random_array, UIntPtr bytes_to_read);

    [LibraryImport(LibraryName, EntryPoint = "OQS_randombytes_switch_algorithm", StringMarshalling = StringMarshalling.Utf8)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int OQS_randombytes_switch_algorithm(string algorithm_name);

    [LibraryImport(LibraryName, EntryPoint = "OQS_CPU_has_extension")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int OQS_CPU_has_extension(OqsCpUext ext);

}

/// <summary>
/// Specifies CPU extensions that can be used to accelerate cryptographic operations.
/// </summary>
#pragma warning disable CA1707 // Identifiers should not contain underscores
public enum OqsCpUext
{
    /// <summary>
    /// Marker for initialization.
    /// </summary>
    OQS_CPU_EXT_INIT = 0,
    /// <summary>
    /// Multi-Precision Add-Carry Instruction Extensions.
    /// </summary>
    OQS_CPU_EXT_ADX = 1,
    /// <summary>
    /// Advanced Encryption Standard New Instructions.
    /// </summary>
    OQS_CPU_EXT_AES = 2,
    /// <summary>
    /// Advanced Vector Extensions.
    /// </summary>
    OQS_CPU_EXT_AVX = 3,
    /// <summary>
    /// Advanced Vector Extensions 2.
    /// </summary>
    OQS_CPU_EXT_AVX2 = 4,
    /// <summary>
    /// Advanced Vector Extensions 512.
    /// </summary>
    OQS_CPU_EXT_AVX512 = 5,
    /// <summary>
    /// Bit Manipulation Instruction Set 1.
    /// </summary>
    OQS_CPU_EXT_BMI1 = 6,
    /// <summary>
    /// Bit Manipulation Instruction Set 2.
    /// </summary>
    OQS_CPU_EXT_BMI2 = 7,
    /// <summary>
    /// Carry-Less Multiplication instruction.
    /// </summary>
    OQS_CPU_EXT_PCLMULQDQ = 8,
    /// <summary>
    /// Vector Carry-Less Multiplication instruction.
    /// </summary>
    OQS_CPU_EXT_VPCLMULQDQ = 9,
    /// <summary>
    /// Population Count instruction.
    /// </summary>
    OQS_CPU_EXT_POPCNT = 10,
    /// <summary>
    /// Streaming SIMD Extensions.
    /// </summary>
    OQS_CPU_EXT_SSE = 11,
    /// <summary>
    /// Streaming SIMD Extensions 2.
    /// </summary>
    OQS_CPU_EXT_SSE2 = 12,
    /// <summary>
    /// Streaming SIMD Extensions 3.
    /// </summary>
    OQS_CPU_EXT_SSE3 = 13,
    /// <summary>
    /// ARM AES instructions.
    /// </summary>
    OQS_CPU_EXT_ARM_AES = 14,
    /// <summary>
    /// ARM SHA2 instructions.
    /// </summary>
    OQS_CPU_EXT_ARM_SHA2 = 15,
    /// <summary>
    /// ARM SHA3 instructions.
    /// </summary>
    OQS_CPU_EXT_ARM_SHA3 = 16,
    /// <summary>
    /// ARM NEON advanced SIMD.
    /// </summary>
    OQS_CPU_EXT_ARM_NEON = 17,
}

#pragma warning restore CA1707 // Identifiers should not contain underscores