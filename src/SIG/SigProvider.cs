using System.Runtime.InteropServices;
using OpenForge.Cryptography.LibOqs.Core;

namespace OpenForge.Cryptography.LibOqs.SIG;

/// <summary>
/// Provides internal access to LibOQS digital signature algorithms.
/// This class serves as the core provider and factory for signature operations, acting as the bridge
/// between the public `Sig` API and the low-level `SigNative` P/Invoke calls. It is responsible
/// for creating and managing native signature instances and ensuring the native library resolver is registered.
/// </summary>
internal static partial class SigProvider
{
    static SigProvider()
    {
        NativeLibraryLoader.Register(typeof(SigNative).Assembly);
    }
    /// <summary>
    /// Gets the total number of digital signature algorithms available in LibOQS.
    /// </summary>
    /// <value>The total count of signature algorithms, including both enabled and disabled ones.</value>
    public static int AlgorithmCount
    {
        get
        {
            OqsCore.Initialize();
            return SigNative.OQS_SIG_alg_count();
        }
    }

    /// <summary>
    /// Determines whether a specific digital signature algorithm is enabled and available for use.
    /// </summary>
    /// <param name="algorithmName">The name of the signature algorithm to check.</param>
    /// <returns>True if the algorithm is enabled and can be used, false otherwise.</returns>
    /// <exception cref="ArgumentException">Thrown if algorithmName is null, empty, or whitespace.</exception>
    public static bool IsAlgorithmEnabled(string algorithmName)
    {
        CryptographyValidation.ValidateAlgorithmName(algorithmName);
        
        OqsCore.Initialize();
        return SigNative.OQS_SIG_alg_is_enabled(algorithmName) != 0;
    }

    /// <summary>
    /// Gets the algorithm identifier for a digital signature algorithm at the specified index.
    /// </summary>
    /// <param name="index">The zero-based index of the algorithm.</param>
    /// <returns>The algorithm identifier string.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the index is negative or invalid.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the algorithm identifier could not be retrieved.</exception>
    public static string GetAlgorithmIdentifier(int index)
    {
        if (index < 0)
            throw new ArgumentOutOfRangeException(nameof(index), "Index must be non-negative");

        var count = AlgorithmCount;
        if (index >= count)
            throw new ArgumentOutOfRangeException(nameof(index), $"Invalid algorithm index {index}. Must be less than {count}");

        var ptr = SigNative.OQS_SIG_alg_identifier((nuint)index);
        CryptographyValidation.ValidatePointer(ptr, nameof(SigNative.OQS_SIG_alg_identifier));

        return Marshal.PtrToStringAnsi(ptr) ?? throw new InvalidOperationException("Failed to retrieve algorithm identifier");
    }

    /// <summary>
    /// Gets all digital signature algorithms that are currently supported and enabled.
    /// </summary>
    /// <returns>An enumerable of algorithm identifier strings for enabled signature algorithms.</returns>
    public static IEnumerable<string> GetSupportedAlgorithms()
    {
        var count = AlgorithmCount;
        for (int i = 0; i < count; i++)
        {
            var identifier = GetAlgorithmIdentifier(i);
            if (IsAlgorithmEnabled(identifier))
                yield return identifier;
        }
    }

    /// <summary>
    /// Creates a new digital signature instance for the specified algorithm.
    /// The returned instance must be disposed to free native resources.
    /// </summary>
    /// <param name="algorithmName">The name of the signature algorithm to use.</param>
    /// <returns>A SigInstance that can perform digital signature operations.</returns>
    /// <exception cref="ArgumentException">Thrown if algorithmName is null, empty, or whitespace.</exception>
    /// <exception cref="NotSupportedException">Thrown if the algorithm is not enabled or supported.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the signature instance could not be created.</exception>
    public static SigInstance Create(string algorithmName)
    {
        CryptographyValidation.ValidateAlgorithmName(algorithmName);
        
        OqsCore.Initialize();
        
        var isSupported = IsAlgorithmEnabled(algorithmName);
        CryptographyValidation.ValidateAlgorithmSupport(isSupported, algorithmName);

        var handle = SigNative.OQS_SIG_new(algorithmName);
        CryptographyValidation.ValidateNativeHandle(handle, algorithmName);

        return new SigInstance(handle, algorithmName);
    }
}

/// <summary>
/// Represents a digital signature instance for performing cryptographic signing and verification operations.
/// This class provides methods for key generation, message signing, and signature verification.
/// </summary>
public sealed class SigInstance : IDisposable
{
    private IntPtr _handle;
    private readonly string _algorithmName;
    private bool _disposed;

    internal SigInstance(IntPtr handle, string algorithmName)
    {
        _handle = handle;
        _algorithmName = algorithmName;
    }

    /// <summary>
    /// Gets the name of the digital signature algorithm used by this instance.
    /// </summary>
    /// <value>The algorithm identifier string.</value>
    public string AlgorithmName => _algorithmName;

    /// <summary>
    /// Determines whether this signature algorithm supports context strings for domain separation.
    /// Context strings allow the same keys to be used safely in different contexts.
    /// </summary>
    /// <returns>True if the algorithm supports context strings, false otherwise.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the instance has been disposed.</exception>
    public bool SupportsContextString()
    {
        ThrowIfDisposed();
        OqsCore.Initialize();
        return SigNative.OQS_SIG_supports_ctx_str(_algorithmName) != 0;
    }

    /// <summary>
    /// Gets detailed information about the signature algorithm including key sizes and security parameters.
    /// </summary>
    /// <returns>An OqsSig structure containing algorithm details.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the instance has been disposed.</exception>
    public unsafe OqsSig GetAlgorithmInfo()
    {
        ThrowIfDisposed();
        return Marshal.PtrToStructure<OqsSig>(_handle);
    }

    /// <summary>
    /// Generates a new cryptographic key pair using secure random number generation.
    /// The returned SigKeyPair should be disposed to securely clear the secret key.
    /// </summary>
    /// <returns>A SigKeyPair containing the public and secret keys.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if key pair generation fails.</exception>
    public unsafe SigKeyPair GenerateKeyPair()
    {
        ThrowIfDisposed();
        
        var info = GetAlgorithmInfo();
        var publicKey = new byte[info.length_public_key];
        var secretKey = new byte[info.length_secret_key];

        fixed (byte* publicKeyPtr = publicKey)
        fixed (byte* secretKeyPtr = secretKey)
        {
            var result = SigNative.OQS_SIG_keypair(_handle, publicKeyPtr, secretKeyPtr);
            CryptographyValidation.ValidateOperationResult(result, "generate key pair", _algorithmName);

            return new SigKeyPair(publicKey, secretKey);
        }
    }

    /// <summary>
    /// Signs a message using the provided secret key, creating a digital signature.
    /// The signature can be verified using the corresponding public key.
    /// </summary>
    /// <param name="message">The message to sign.</param>
    /// <param name="secretKey">The secret key for signing.</param>
    /// <returns>The digital signature bytes.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the instance has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if the secret key has an invalid length.</exception>
    /// <exception cref="InvalidOperationException">Thrown if signing fails.</exception>
    public unsafe byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> secretKey)
    {
        ThrowIfDisposed();
        
        var info = GetAlgorithmInfo();
        SecurityUtilities.ValidateParameterLength(secretKey, (int)info.length_secret_key, nameof(secretKey));

        var signature = new byte[info.length_signature];
        var signatureLen = (nuint)signature.Length;

        fixed (byte* signaturePtr = signature)
        fixed (byte* messagePtr = message)
        fixed (byte* secretKeyPtr = secretKey)
        {
            var result = SigNative.OQS_SIG_sign(_handle, signaturePtr, ref signatureLen, messagePtr, (nuint)message.Length, secretKeyPtr);
            CryptographyValidation.ValidateOperationResult(result, "sign message", _algorithmName);

            if (signatureLen < (nuint)signature.Length)
            {
                var actualSignature = new byte[signatureLen];
                try
                {
                    Array.Copy(signature, actualSignature, (int)signatureLen);
                }
                finally
                {
                    SecureMemory.SecureClear(signature);
                }
                return actualSignature;
            }

            return signature;
        }
    }

    /// <summary>
    /// Verifies a digital signature against the original message using the signer's public key.
    /// </summary>
    /// <param name="message">The original message that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <returns>True if the signature is valid for the message and public key, false otherwise.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the instance has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if the public key has an invalid length.</exception>
    public unsafe bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        ThrowIfDisposed();
        
        var info = GetAlgorithmInfo();
        SecurityUtilities.ValidateParameterLength(publicKey, (int)info.length_public_key, nameof(publicKey));

        fixed (byte* messagePtr = message)
        fixed (byte* signaturePtr = signature)
        fixed (byte* publicKeyPtr = publicKey)
        {
            var result = SigNative.OQS_SIG_verify(_handle, messagePtr, (nuint)message.Length, signaturePtr, (nuint)signature.Length, publicKeyPtr);
            return result == 0;
        }
    }

    /// <summary>
    /// Signs a message with a context string using the signature algorithm.
    /// This provides domain separation for signatures in different contexts.
    /// </summary>
    /// <param name="message">The message to sign.</param>
    /// <param name="contextString">The context string for domain separation.</param>
    /// <param name="secretKey">The secret key for signing.</param>
    /// <returns>The signature bytes.</returns>
    /// <exception cref="NotSupportedException">Thrown if the algorithm doesn't support context strings.</exception>
    /// <exception cref="InvalidOperationException">Thrown if signing fails.</exception>
    public unsafe byte[] SignWithContext(ReadOnlySpan<byte> message, ReadOnlySpan<byte> contextString, ReadOnlySpan<byte> secretKey)
    {
        ThrowIfDisposed();
        
        var supportsContext = SupportsContextString();
        CryptographyValidation.ValidateContextStringSupport(supportsContext, _algorithmName);
        
        var info = GetAlgorithmInfo();
        SecurityUtilities.ValidateParameterLength(secretKey, (int)info.length_secret_key, nameof(secretKey));

        var signature = new byte[info.length_signature];
        var signatureLen = (nuint)signature.Length;

        fixed (byte* signaturePtr = signature)
        fixed (byte* messagePtr = message)
        fixed (byte* contextPtr = contextString)
        fixed (byte* secretKeyPtr = secretKey)
        {
            var result = SigNative.OQS_SIG_sign_with_ctx_str(_handle, signaturePtr, ref signatureLen, messagePtr, (nuint)message.Length, contextPtr, (nuint)contextString.Length, secretKeyPtr);
            CryptographyValidation.ValidateOperationResult(result, "sign message with context", _algorithmName);

            if (signatureLen < (nuint)signature.Length)
            {
                var actualSignature = new byte[signatureLen];
                try
                {
                    Array.Copy(signature, actualSignature, (int)signatureLen);
                }
                finally
                {
                    SecureMemory.SecureClear(signature);
                }
                return actualSignature;
            }

            return signature;
        }
    }

    /// <summary>
    /// Verifies a signature with a context string using the signature algorithm.
    /// This provides domain separation for signatures in different contexts.
    /// </summary>
    /// <param name="message">The original message that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="contextString">The context string used during signing.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    /// <exception cref="NotSupportedException">Thrown if the algorithm doesn't support context strings.</exception>
    public unsafe bool VerifyWithContext(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> contextString, ReadOnlySpan<byte> publicKey)
    {
        ThrowIfDisposed();
        
        if (!SupportsContextString())
            throw new NotSupportedException($"Algorithm '{_algorithmName}' does not support context strings");
        
        var info = GetAlgorithmInfo();
        SecurityUtilities.ValidateParameterLength(publicKey, (int)info.length_public_key, nameof(publicKey));

        fixed (byte* messagePtr = message)
        fixed (byte* signaturePtr = signature)
        fixed (byte* contextPtr = contextString)
        fixed (byte* publicKeyPtr = publicKey)
        {
            var result = SigNative.OQS_SIG_verify_with_ctx_str(_handle, messagePtr, (nuint)message.Length, signaturePtr, (nuint)signature.Length, contextPtr, (nuint)contextString.Length, publicKeyPtr);
            return result == 0;
        }
    }

    /// <summary>
    /// Disposes the signature instance and releases all associated native resources.
    /// After disposal, this instance cannot be used for further operations.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    #pragma warning disable IDE0060 // Remove unused parameter
    private void Dispose(bool disposing)
    #pragma warning restore IDE0060 // Remove unused parameter
    {
        if (!_disposed)
        {
            if (_handle != IntPtr.Zero)
            {
                SigNative.OQS_SIG_free(_handle);
                _handle = IntPtr.Zero;
            }
            _disposed = true;
        }
    }

    /// <summary>
    /// Finalizer that ensures native resources are cleaned up if Dispose was not called.
    /// </summary>
    ~SigInstance()
    {
        Dispose(false);
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}

/// <summary>
/// Represents a digital signature key pair consisting of a public key and a secret key.
/// The secret key is securely cleared when the SigKeyPair is disposed.
/// </summary>
/// <param name="PublicKey">The public key that can be shared for signature verification operations.</param>
/// <param name="SecretKey">The secret key that must be kept private for signing operations.</param>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Cryptographic data requires byte arrays for performance and interoperability")]
public readonly record struct SigKeyPair(byte[] PublicKey, byte[] SecretKey) : IDisposable
{
    /// <summary>
    /// Securely clears the secret key from memory to prevent information leakage.
    /// The public key does not need secure clearing as it is not sensitive.
    /// </summary>
    public void Dispose()
    {
        SecureMemory.SecureClear(SecretKey);
    }
}