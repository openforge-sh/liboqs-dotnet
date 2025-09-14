using System.Runtime.InteropServices;
using OpenForge.Cryptography.LibOqs.Core;

namespace OpenForge.Cryptography.LibOqs.KEM;

/// <summary>
/// Provides internal access to LibOQS Key Encapsulation Mechanism (KEM) algorithms.
/// This class serves as the core provider and factory for KEM operations, acting as the bridge
/// between the public `Kem` API and the low-level `KemNative` P/Invoke calls. It is responsible
/// for creating and managing native KEM instances and ensuring the native library resolver is registered.
/// </summary>
internal static partial class KemProvider
{
    static KemProvider()
    {
        NativeLibraryLoader.Register(typeof(KemNative).Assembly);
    }
    /// <summary>
    /// Gets the total number of KEM algorithms available in LibOQS.
    /// </summary>
    /// <value>The total count of KEM algorithms, including both enabled and disabled ones.</value>
    public static int AlgorithmCount
    {
        get
        {
            OqsCore.Initialize();
            return KemNative.OQS_KEM_alg_count();
        }
    }

    /// <summary>
    /// Determines whether a specific KEM algorithm is enabled and available for use.
    /// </summary>
    /// <param name="algorithmName">The name of the KEM algorithm to check.</param>
    /// <returns>True if the algorithm is enabled and can be used, false otherwise.</returns>
    /// <exception cref="ArgumentException">Thrown if algorithmName is null, empty, or whitespace.</exception>
    public static bool IsAlgorithmEnabled(string algorithmName)
    {
        CryptographyValidation.ValidateAlgorithmName(algorithmName);
        
        OqsCore.Initialize();
        return KemNative.OQS_KEM_alg_is_enabled(algorithmName) != 0;
    }

    /// <summary>
    /// Gets the algorithm identifier for a KEM algorithm at the specified index.
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

        var ptr = KemNative.OQS_KEM_alg_identifier((nuint)index);
        CryptographyValidation.ValidatePointer(ptr, nameof(KemNative.OQS_KEM_alg_identifier));

        return Marshal.PtrToStringAnsi(ptr) ?? throw new InvalidOperationException("Failed to retrieve algorithm identifier");
    }

    /// <summary>
    /// Gets all KEM algorithms that are currently supported and enabled.
    /// </summary>
    /// <returns>An enumerable of algorithm identifier strings for enabled KEM algorithms.</returns>
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
    /// Creates a new KEM instance for the specified algorithm.
    /// The returned instance must be disposed to free native resources.
    /// </summary>
    /// <param name="algorithmName">The name of the KEM algorithm to use.</param>
    /// <returns>A KemInstance that can perform KEM operations.</returns>
    /// <exception cref="ArgumentException">Thrown if algorithmName is null, empty, or whitespace.</exception>
    /// <exception cref="NotSupportedException">Thrown if the algorithm is not enabled or supported.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the KEM instance could not be created.</exception>
    public static KemInstance Create(string algorithmName)
    {
        CryptographyValidation.ValidateAlgorithmName(algorithmName);
        
        OqsCore.Initialize();
        
        var isSupported = IsAlgorithmEnabled(algorithmName);
        CryptographyValidation.ValidateAlgorithmSupport(isSupported, algorithmName);

        var handle = KemNative.OQS_KEM_new(algorithmName);
        CryptographyValidation.ValidateNativeHandle(handle, algorithmName);

        return new KemInstance(handle, algorithmName);
    }
}

/// <summary>
/// Represents a Key Encapsulation Mechanism (KEM) instance for performing cryptographic operations.
/// This class provides methods for key generation, encapsulation, and decapsulation.
/// </summary>
public sealed class KemInstance : IDisposable
{
    private IntPtr _handle;
    private readonly string _algorithmName;
    private bool _disposed;

    internal KemInstance(IntPtr handle, string algorithmName)
    {
        _handle = handle;
        _algorithmName = algorithmName;
    }

    /// <summary>
    /// Gets the name of the KEM algorithm used by this instance.
    /// </summary>
    /// <value>The algorithm identifier string.</value>
    public string AlgorithmName => _algorithmName;

    /// <summary>
    /// Gets detailed information about the KEM algorithm including key sizes and security parameters.
    /// </summary>
    /// <returns>An OqsKem structure containing algorithm details.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the instance has been disposed.</exception>
    public unsafe OqsKem GetAlgorithmInfo()
    {
        ThrowIfDisposed();
        return Marshal.PtrToStructure<OqsKem>(_handle);
    }

    /// <summary>
    /// Generates a new cryptographic key pair using secure random number generation.
    /// The returned KeyPair should be disposed to securely clear the secret key.
    /// </summary>
    /// <returns>A KeyPair containing the public and secret keys.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if key pair generation fails.</exception>
    public unsafe KeyPair GenerateKeyPair()
    {
        ThrowIfDisposed();
        
        var info = GetAlgorithmInfo();
        var publicKey = new byte[info.length_public_key];
        var secretKey = new byte[info.length_secret_key];

        fixed (byte* publicKeyPtr = publicKey)
        fixed (byte* secretKeyPtr = secretKey)
        {
            var result = KemNative.OQS_KEM_keypair(_handle, publicKeyPtr, secretKeyPtr);
            CryptographyValidation.ValidateOperationResult(result, "generate key pair", _algorithmName);

            return new KeyPair(publicKey, secretKey);
        }
    }

    /// <summary>
    /// Generates a deterministic keypair using the provided seed.
    /// This is primarily useful for testing and reproducible cryptographic operations.
    /// </summary>
    /// <param name="seed">The 48-byte seed for deterministic key generation.</param>
    /// <returns>A keypair generated deterministically from the seed.</returns>
    /// <exception cref="ArgumentException">Thrown if seed is not exactly 48 bytes.</exception>
    /// <exception cref="InvalidOperationException">Thrown if key generation fails.</exception>
    public unsafe KeyPair GenerateDeterministicKeyPair(ReadOnlySpan<byte> seed)
    {
        ThrowIfDisposed();
        
        SecurityUtilities.ValidateParameterLength(seed, 48, nameof(seed));

        var info = GetAlgorithmInfo();
        var publicKey = new byte[info.length_public_key];
        var secretKey = new byte[info.length_secret_key];

        fixed (byte* publicKeyPtr = publicKey)
        fixed (byte* secretKeyPtr = secretKey)
        fixed (byte* seedPtr = seed)
        {
            var result = KemNative.OQS_KEM_keypair_derand(_handle, publicKeyPtr, secretKeyPtr, seedPtr);
            CryptographyValidation.ValidateOperationResult(result, "generate deterministic key pair", _algorithmName);

            return new KeyPair(publicKey, secretKey);
        }
    }

    /// <summary>
    /// Encapsulates a shared secret using the recipient's public key.
    /// This generates a ciphertext and a shared secret that can be used for symmetric encryption.
    /// </summary>
    /// <param name="publicKey">The recipient's public key for encapsulation.</param>
    /// <returns>An EncapsulationResult containing the ciphertext and shared secret.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the instance has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if the public key has an invalid length.</exception>
    /// <exception cref="InvalidOperationException">Thrown if encapsulation fails.</exception>
    public unsafe EncapsulationResult Encapsulate(ReadOnlySpan<byte> publicKey)
    {
        ThrowIfDisposed();
        
        var info = GetAlgorithmInfo();
        SecurityUtilities.ValidateParameterLength(publicKey, (int)info.length_public_key, nameof(publicKey));

        var ciphertext = new byte[info.length_ciphertext];
        var sharedSecret = new byte[info.length_shared_secret];

        fixed (byte* ciphertextPtr = ciphertext)
        fixed (byte* sharedSecretPtr = sharedSecret)
        fixed (byte* publicKeyPtr = publicKey)
        {
            var result = KemNative.OQS_KEM_encaps(_handle, ciphertextPtr, sharedSecretPtr, publicKeyPtr);
            CryptographyValidation.ValidateOperationResult(result, "encapsulate", _algorithmName);

            return new EncapsulationResult(ciphertext, sharedSecret);
        }
    }

    /// <summary>
    /// Performs deterministic encapsulation using the provided seed.
    /// This is primarily useful for testing and reproducible cryptographic operations.
    /// </summary>
    /// <param name="publicKey">The public key to encapsulate against.</param>
    /// <param name="seed">The 48-byte seed for deterministic encapsulation.</param>
    /// <returns>The encapsulation result containing ciphertext and shared secret.</returns>
    /// <exception cref="ArgumentException">Thrown if parameters have invalid lengths.</exception>
    /// <exception cref="InvalidOperationException">Thrown if encapsulation fails.</exception>
    public unsafe EncapsulationResult EncapsulateDeterministic(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> seed)
    {
        ThrowIfDisposed();
        
        var info = GetAlgorithmInfo();
        SecurityUtilities.ValidateParameterLength(publicKey, (int)info.length_public_key, nameof(publicKey));
        SecurityUtilities.ValidateParameterLength(seed, 48, nameof(seed));

        var ciphertext = new byte[info.length_ciphertext];
        var sharedSecret = new byte[info.length_shared_secret];

        fixed (byte* ciphertextPtr = ciphertext)
        fixed (byte* sharedSecretPtr = sharedSecret)
        fixed (byte* publicKeyPtr = publicKey)
        fixed (byte* seedPtr = seed)
        {
            var result = KemNative.OQS_KEM_encaps_derand(_handle, ciphertextPtr, sharedSecretPtr, publicKeyPtr, seedPtr);
            CryptographyValidation.ValidateOperationResult(result, "perform deterministic encapsulation", _algorithmName);

            return new EncapsulationResult(ciphertext, sharedSecret);
        }
    }

    /// <summary>
    /// Decapsulates a shared secret from the ciphertext using the recipient's secret key.
    /// This recovers the same shared secret that was generated during encapsulation.
    /// </summary>
    /// <param name="ciphertext">The ciphertext produced by encapsulation.</param>
    /// <param name="secretKey">The recipient's secret key for decapsulation.</param>
    /// <returns>The recovered shared secret that matches the one from encapsulation.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the instance has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if parameters have invalid lengths.</exception>
    /// <exception cref="InvalidOperationException">Thrown if decapsulation fails.</exception>
    public unsafe byte[] Decapsulate(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> secretKey)
    {
        ThrowIfDisposed();
        
        var info = GetAlgorithmInfo();
        SecurityUtilities.ValidateParameterLength(ciphertext, (int)info.length_ciphertext, nameof(ciphertext));
        SecurityUtilities.ValidateParameterLength(secretKey, (int)info.length_secret_key, nameof(secretKey));

        var sharedSecret = new byte[info.length_shared_secret];

        fixed (byte* sharedSecretPtr = sharedSecret)
        fixed (byte* ciphertextPtr = ciphertext)
        fixed (byte* secretKeyPtr = secretKey)
        {
            var result = KemNative.OQS_KEM_decaps(_handle, sharedSecretPtr, ciphertextPtr, secretKeyPtr);
            CryptographyValidation.ValidateOperationResult(result, "decapsulate", _algorithmName);

            return sharedSecret;
        }
    }

    /// <summary>
    /// Disposes the KEM instance and releases all associated native resources.
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
                KemNative.OQS_KEM_free(_handle);
                _handle = IntPtr.Zero;
            }
            _disposed = true;
        }
    }

    /// <summary>
    /// Finalizer that ensures native resources are cleaned up if Dispose was not called.
    /// </summary>
    ~KemInstance()
    {
        Dispose(false);
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}

/// <summary>
/// Represents a cryptographic key pair consisting of a public key and a secret key.
/// The secret key is securely cleared when the KeyPair is disposed.
/// </summary>
/// <param name="PublicKey">The public key that can be shared for encapsulation operations.</param>
/// <param name="SecretKey">The secret key that must be kept private for decapsulation operations.</param>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Cryptographic data requires byte arrays for performance and interoperability")]
public readonly record struct KeyPair(byte[] PublicKey, byte[] SecretKey) : IDisposable
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

/// <summary>
/// Represents the result of a KEM encapsulation operation, containing both the ciphertext and shared secret.
/// The shared secret is securely cleared when the EncapsulationResult is disposed.
/// </summary>
/// <param name="Ciphertext">The ciphertext that will be sent to the recipient for decapsulation.</param>
/// <param name="SharedSecret">The shared secret that should be used for symmetric encryption operations.</param>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Cryptographic data requires byte arrays for performance and interoperability")]
public readonly record struct EncapsulationResult(byte[] Ciphertext, byte[] SharedSecret) : IDisposable
{
    /// <summary>
    /// Securely clears the shared secret from memory to prevent information leakage.
    /// The ciphertext does not need secure clearing as it is not sensitive.
    /// </summary>
    public void Dispose()
    {
        SecureMemory.SecureClear(SharedSecret);
    }
}