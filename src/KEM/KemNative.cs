using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace OpenForge.Cryptography.LibOqs.KEM;

/// <summary>
/// Provides direct P/Invoke declarations for LibOQS Key Encapsulation Mechanism (KEM) functions.
/// This class contains low-level native method bindings and should not be used directly by application code.
/// </summary>
internal static partial class KemNative
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public const string LibraryName = "oqs";
    #pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    [LibraryImport(LibraryName, EntryPoint = "OQS_KEM_alg_count")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int OQS_KEM_alg_count();

    [LibraryImport(LibraryName, EntryPoint = "OQS_KEM_alg_is_enabled", StringMarshalling = StringMarshalling.Utf8)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int OQS_KEM_alg_is_enabled(string method_name);

    [LibraryImport(LibraryName, EntryPoint = "OQS_KEM_alg_identifier")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr OQS_KEM_alg_identifier(UIntPtr i);

    [LibraryImport(LibraryName, EntryPoint = "OQS_KEM_new", StringMarshalling = StringMarshalling.Utf8)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr OQS_KEM_new(string method_name);

    [LibraryImport(LibraryName, EntryPoint = "OQS_KEM_free")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void OQS_KEM_free(IntPtr kem);

    [LibraryImport(LibraryName, EntryPoint = "OQS_KEM_keypair")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int OQS_KEM_keypair(IntPtr kem, byte* public_key, byte* secret_key);

    [LibraryImport(LibraryName, EntryPoint = "OQS_KEM_keypair_derand")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int OQS_KEM_keypair_derand(IntPtr kem, byte* public_key, byte* secret_key, byte* seed);

    [LibraryImport(LibraryName, EntryPoint = "OQS_KEM_encaps")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int OQS_KEM_encaps(IntPtr kem, byte* ciphertext, byte* shared_secret, byte* public_key);

    [LibraryImport(LibraryName, EntryPoint = "OQS_KEM_encaps_derand")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int OQS_KEM_encaps_derand(IntPtr kem, byte* ciphertext, byte* shared_secret, byte* public_key, byte* seed);

    [LibraryImport(LibraryName, EntryPoint = "OQS_KEM_decaps")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int OQS_KEM_decaps(IntPtr kem, byte* shared_secret, byte* ciphertext, byte* secret_key);
}

/// <summary>
/// Native structure representing LibOQS KEM algorithm information and function pointers.
/// This structure mirrors the OQS_KEM struct from the LibOQS C library.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public readonly struct OqsKem : IEquatable<OqsKem>
{
    /// <summary>Pointer to the algorithm method name string.</summary>
    public readonly IntPtr method_name;
    
    /// <summary>Pointer to the algorithm version string.</summary>
    public readonly IntPtr alg_version;
    
    /// <summary>NIST security level claimed by this algorithm (1, 2, 3, or 5).</summary>
    public readonly byte claimed_nist_level;
    
    /// <summary>Indicates whether the algorithm provides IND-CCA security (0 = false, non-zero = true).</summary>
    public readonly byte ind_cca;
    
    /// <summary>Length of public keys in bytes for this algorithm.</summary>
    public readonly UIntPtr length_public_key;
    
    /// <summary>Length of secret keys in bytes for this algorithm.</summary>
    public readonly UIntPtr length_secret_key;
    
    /// <summary>Length of ciphertext in bytes for this algorithm.</summary>
    public readonly UIntPtr length_ciphertext;
    
    /// <summary>Length of shared secrets in bytes for this algorithm.</summary>
    public readonly UIntPtr length_shared_secret;
    
    /// <summary>Function pointer to the native key pair generation function.</summary>
    public readonly IntPtr keypair;
    
    /// <summary>Function pointer to the native encapsulation function.</summary>
    public readonly IntPtr encaps;
    
    /// <summary>Function pointer to the native decapsulation function.</summary>
    public readonly IntPtr decaps;
    
    /// <summary>
    /// Determines whether the specified OqsKem is equal to the current OqsKem.
    /// </summary>
    /// <param name="other">The OqsKem to compare with the current OqsKem.</param>
    /// <returns>True if the specified OqsKem is equal to the current OqsKem; otherwise, false.</returns>
    public bool Equals(OqsKem other)
    {
        return method_name == other.method_name &&
               alg_version == other.alg_version &&
               claimed_nist_level == other.claimed_nist_level &&
               ind_cca == other.ind_cca &&
               length_public_key == other.length_public_key &&
               length_secret_key == other.length_secret_key &&
               length_ciphertext == other.length_ciphertext &&
               length_shared_secret == other.length_shared_secret &&
               keypair == other.keypair &&
               encaps == other.encaps &&
               decaps == other.decaps;
    }
    
    /// <summary>
    /// Determines whether the specified object is equal to the current OqsKem.
    /// </summary>
    /// <param name="obj">The object to compare with the current OqsKem.</param>
    /// <returns>True if the specified object is equal to the current OqsKem; otherwise, false.</returns>
    public override bool Equals(object? obj)
    {
        return obj is OqsKem other && Equals(other);
    }
    
    /// <summary>
    /// Returns the hash code for this OqsKem.
    /// </summary>
    /// <returns>A 32-bit signed integer hash code.</returns>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(method_name);
        hash.Add(alg_version);
        hash.Add(claimed_nist_level);
        hash.Add(ind_cca);
        hash.Add(length_public_key);
        hash.Add(length_secret_key);
        hash.Add(length_ciphertext);
        hash.Add(length_shared_secret);
        hash.Add(keypair);
        hash.Add(encaps);
        hash.Add(decaps);
        return hash.ToHashCode();
    }
    
    /// <summary>
    /// Determines whether two specified OqsKem instances are equal.
    /// </summary>
    /// <param name="left">The first OqsKem to compare.</param>
    /// <param name="right">The second OqsKem to compare.</param>
    /// <returns>True if left and right are equal; otherwise, false.</returns>
    public static bool operator ==(OqsKem left, OqsKem right)
    {
        return left.Equals(right);
    }
    
    /// <summary>
    /// Determines whether two specified OqsKem instances are not equal.
    /// </summary>
    /// <param name="left">The first OqsKem to compare.</param>
    /// <param name="right">The second OqsKem to compare.</param>
    /// <returns>True if left and right are not equal; otherwise, false.</returns>
    public static bool operator !=(OqsKem left, OqsKem right)
    {
        return !left.Equals(right);
    }
}