using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace OpenForge.Cryptography.LibOqs.SIG;

/// <summary>
/// Provides direct P/Invoke declarations for LibOQS digital signature functions.
/// This class contains low-level native method bindings and should not be used directly by application code.
/// </summary>
internal static partial class SigNative
{
    #pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public const string LibraryName = "oqs";
    #pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    [LibraryImport(LibraryName, EntryPoint = "OQS_SIG_alg_count")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int OQS_SIG_alg_count();

    [LibraryImport(LibraryName, EntryPoint = "OQS_SIG_alg_is_enabled", StringMarshalling = StringMarshalling.Utf8)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int OQS_SIG_alg_is_enabled(string method_name);

    [LibraryImport(LibraryName, EntryPoint = "OQS_SIG_supports_ctx_str", StringMarshalling = StringMarshalling.Utf8)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int OQS_SIG_supports_ctx_str(string alg_name);

    [LibraryImport(LibraryName, EntryPoint = "OQS_SIG_alg_identifier")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr OQS_SIG_alg_identifier(UIntPtr i);

    [LibraryImport(LibraryName, EntryPoint = "OQS_SIG_new", StringMarshalling = StringMarshalling.Utf8)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr OQS_SIG_new(string method_name);

    [LibraryImport(LibraryName, EntryPoint = "OQS_SIG_free")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void OQS_SIG_free(IntPtr sig);

    [LibraryImport(LibraryName, EntryPoint = "OQS_SIG_keypair")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int OQS_SIG_keypair(IntPtr sig, byte* public_key, byte* secret_key);

    [LibraryImport(LibraryName, EntryPoint = "OQS_SIG_sign")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int OQS_SIG_sign(IntPtr sig, byte* signature, ref UIntPtr signature_len, byte* message, UIntPtr message_len, byte* secret_key);

    [LibraryImport(LibraryName, EntryPoint = "OQS_SIG_sign_with_ctx_str")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int OQS_SIG_sign_with_ctx_str(IntPtr sig, byte* signature, ref UIntPtr signature_len, byte* message, UIntPtr message_len, byte* ctx_str, UIntPtr ctx_str_len, byte* secret_key);

    [LibraryImport(LibraryName, EntryPoint = "OQS_SIG_verify")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int OQS_SIG_verify(IntPtr sig, byte* message, UIntPtr message_len, byte* signature, UIntPtr signature_len, byte* public_key);

    [LibraryImport(LibraryName, EntryPoint = "OQS_SIG_verify_with_ctx_str")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int OQS_SIG_verify_with_ctx_str(IntPtr sig, byte* message, UIntPtr message_len, byte* signature, UIntPtr signature_len, byte* ctx_str, UIntPtr ctx_str_len, byte* public_key);
}

/// <summary>
/// Native structure representing LibOQS digital signature algorithm information and function pointers.
/// This structure mirrors the OQS_SIG struct from the LibOQS C library.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public readonly struct OqsSig : IEquatable<OqsSig>
{
    /// <summary>Pointer to the algorithm method name string.</summary>
    public readonly IntPtr method_name;
    
    /// <summary>Pointer to the algorithm version string.</summary>
    public readonly IntPtr alg_version;
    
    /// <summary>NIST security level claimed by this algorithm (1, 2, 3, or 5).</summary>
    public readonly byte claimed_nist_level;
    
    /// <summary>Indicates whether the algorithm provides EUF-CMA security (0 = false, non-zero = true).</summary>
    public readonly byte euf_cma;
    
    /// <summary>Indicates whether the algorithm provides SUF-CMA security (0 = false, non-zero = true).</summary>
    public readonly byte suf_cma;
    
    /// <summary>Indicates whether the algorithm supports signing with a context string (0 = false, non-zero = true).</summary>
    public readonly byte sig_with_ctx_support;
    
    /// <summary>Length of public keys in bytes for this algorithm.</summary>
    public readonly UIntPtr length_public_key;
    
    /// <summary>Length of secret keys in bytes for this algorithm.</summary>
    public readonly UIntPtr length_secret_key;
    
    /// <summary>Maximum length of signatures in bytes for this algorithm.</summary>
    public readonly UIntPtr length_signature;
    
    /// <summary>Function pointer to the native key pair generation function.</summary>
    public readonly IntPtr keypair;
    
    /// <summary>Function pointer to the native signing function.</summary>
    public readonly IntPtr sign;
    
    /// <summary>Function pointer to the native signing with context function.</summary>
    public readonly IntPtr sign_with_ctx_str;
    
    /// <summary>Function pointer to the native verification function.</summary>
    public readonly IntPtr verify;
    
    /// <summary>Function pointer to the native verification with context function.</summary>
    public readonly IntPtr verify_with_ctx_str;
    
    /// <summary>
    /// Determines whether the specified OqsSig is equal to the current OqsSig.
    /// </summary>
    /// <param name="other">The OqsSig to compare with the current OqsSig.</param>
    /// <returns>True if the specified OqsSig is equal to the current OqsSig; otherwise, false.</returns>
    public bool Equals(OqsSig other)
    {
        return method_name == other.method_name &&
               alg_version == other.alg_version &&
               claimed_nist_level == other.claimed_nist_level &&
               euf_cma == other.euf_cma &&
               suf_cma == other.suf_cma &&
               sig_with_ctx_support == other.sig_with_ctx_support &&
               length_public_key == other.length_public_key &&
               length_secret_key == other.length_secret_key &&
               length_signature == other.length_signature &&
               keypair == other.keypair &&
               sign == other.sign &&
               sign_with_ctx_str == other.sign_with_ctx_str &&
               verify == other.verify &&
               verify_with_ctx_str == other.verify_with_ctx_str;
    }
    
    /// <summary>
    /// Determines whether the specified object is equal to the current OqsSig.
    /// </summary>
    /// <param name="obj">The object to compare with the current OqsSig.</param>
    /// <returns>True if the specified object is equal to the current OqsSig; otherwise, false.</returns>
    public override bool Equals(object? obj)
    {
        return obj is OqsSig other && Equals(other);
    }
    
    /// <summary>
    /// Returns the hash code for this OqsSig.
    /// </summary>
    /// <returns>A 32-bit signed integer hash code.</returns>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(method_name);
        hash.Add(alg_version);
        hash.Add(claimed_nist_level);
        hash.Add(euf_cma);
        hash.Add(suf_cma);
        hash.Add(sig_with_ctx_support);
        hash.Add(length_public_key);
        hash.Add(length_secret_key);
        hash.Add(length_signature);
        hash.Add(keypair);
        hash.Add(sign);
        hash.Add(sign_with_ctx_str);
        hash.Add(verify);
        hash.Add(verify_with_ctx_str);
        return hash.ToHashCode();
    }
    
    /// <summary>
    /// Determines whether two specified OqsSig instances are equal.
    /// </summary>
    /// <param name="left">The first OqsSig to compare.</param>
    /// <param name="right">The second OqsSig to compare.</param>
    /// <returns>True if left and right are equal; otherwise, false.</returns>
    public static bool operator ==(OqsSig left, OqsSig right)
    {
        return left.Equals(right);
    }
    
    /// <summary>
    /// Determines whether two specified OqsSig instances are not equal.
    /// </summary>
    /// <param name="left">The first OqsSig to compare.</param>
    /// <param name="right">The second OqsSig to compare.</param>
    /// <returns>True if left and right are not equal; otherwise, false.</returns>
    public static bool operator !=(OqsSig left, OqsSig right)
    {
        return !left.Equals(right);
    }
}