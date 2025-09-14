using OpenForge.Cryptography.LibOqs.Core;

namespace OpenForge.Cryptography.LibOqs.SIG;

/// <summary>
/// High-level wrapper for LibOQS digital signature operations.
/// This class provides a user-friendly interface for post-quantum digital signature operations.
/// Digital signatures provide authentication, integrity, and non-repudiation.
/// </summary>
public sealed class Sig : IDisposable
{
    private readonly SigInstance _sigInstance;
    private readonly string _algorithmName;
    private bool _disposed;

    /// <summary>
    /// Gets the name of the digital signature algorithm used by this instance.
    /// </summary>
    /// <value>The algorithm identifier string.</value>
    public string AlgorithmName => _algorithmName;
    
    /// <summary>
    /// Gets the length of public keys in bytes for this signature algorithm.
    /// </summary>
    /// <value>The public key length in bytes.</value>
    public int PublicKeyLength { get; private set; }
    
    /// <summary>
    /// Gets the length of secret keys in bytes for this signature algorithm.
    /// </summary>
    /// <value>The secret key length in bytes.</value>
    public int SecretKeyLength { get; private set; }
    
    /// <summary>
    /// Gets the maximum length of signatures in bytes for this signature algorithm.
    /// </summary>
    /// <value>The signature length in bytes.</value>
    public int SignatureLength { get; private set; }
    
    /// <summary>
    /// Gets the NIST security level claimed by this signature algorithm.
    /// </summary>
    /// <value>The NIST security level (1, 2, 3, or 5).</value>
    public byte ClaimedNistLevel { get; private set; }
    
    /// <summary>
    /// Gets a value indicating whether this signature algorithm provides EUF-CMA security.
    /// EUF-CMA (Existential Unforgeability under Chosen Message Attack) is the standard security requirement for signatures.
    /// </summary>
    /// <value>True if the algorithm provides EUF-CMA security, false otherwise.</value>
    public bool IsEufCma { get; private set; }


    /// <summary>
    /// Initializes a new instance of the Signature class with the specified algorithm.
    /// </summary>
    /// <param name="algorithmName">The name of the digital signature algorithm to use.</param>
    /// <exception cref="ArgumentNullException">Thrown if algorithmName is null.</exception>
    /// <exception cref="NotSupportedException">Thrown if the algorithm is not supported or enabled.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the signature instance could not be created.</exception>
    public Sig(string algorithmName)
    {
        _algorithmName = algorithmName ?? throw new ArgumentNullException(nameof(algorithmName));
        
        AlgorithmConstants.CheckForDeprecationWarning(algorithmName, "Signature constructor");
        
        _sigInstance = SigProvider.Create(algorithmName);
        
        var sigInfo = _sigInstance.GetAlgorithmInfo();
        PublicKeyLength = (int)sigInfo.length_public_key;
        SecretKeyLength = (int)sigInfo.length_secret_key;
        SignatureLength = (int)sigInfo.length_signature;
        ClaimedNistLevel = sigInfo.claimed_nist_level;
        IsEufCma = sigInfo.euf_cma != 0;
    }

    /// <summary>
    /// Generates a new cryptographic key pair for this signature algorithm.
    /// The secret key should be kept private and securely stored.
    /// </summary>
    /// <returns>A tuple containing the public key and secret key as byte arrays.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if this instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if key pair generation fails.</exception>
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        ThrowIfDisposed();
        
        var keyPair = _sigInstance.GenerateKeyPair();
        return (keyPair.PublicKey, keyPair.SecretKey);
    }

    /// <summary>
    /// Signs a message using the provided secret key, creating a digital signature.
    /// The signature can be verified using the corresponding public key.
    /// </summary>
    /// <param name="message">The message to sign.</param>
    /// <param name="secretKey">The secret key for signing.</param>
    /// <returns>The digital signature bytes.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if this instance has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if message or secretKey is null.</exception>
    /// <exception cref="ArgumentException">Thrown if the secret key has an invalid length.</exception>
    /// <exception cref="InvalidOperationException">Thrown if signing fails.</exception>
    public byte[] Sign(byte[] message, byte[] secretKey)
    {
        ThrowIfDisposed();
        
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(secretKey);
        
        return _sigInstance.Sign(message, secretKey);
    }

    /// <summary>
    /// Verifies a digital signature against the original message using the signer's public key.
    /// </summary>
    /// <param name="message">The original message that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <returns>True if the signature is valid for the message and public key, false otherwise.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if this instance has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown if the public key has an invalid length.</exception>
    public bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        ThrowIfDisposed();
        
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(publicKey);
        
        return _sigInstance.Verify(message, signature, publicKey);
    }

    /// <summary>
    /// Gets all digital signature algorithms that are currently supported and enabled in LibOQS.
    /// </summary>
    /// <returns>An array of algorithm identifier strings for supported signature algorithms.</returns>
    public static string[] GetSupportedAlgorithms()
    {
        return SigProvider.GetSupportedAlgorithms().ToArray();
    }

    /// <summary>
    /// Determines whether a specific digital signature algorithm is supported and available for use.
    /// </summary>
    /// <param name="algorithmName">The name of the signature algorithm to check.</param>
    /// <returns>True if the algorithm is supported and enabled, false otherwise.</returns>
    public static bool IsAlgorithmSupported(string algorithmName)
    {
        if (string.IsNullOrEmpty(algorithmName))
            return false;
        
        return SigProvider.IsAlgorithmEnabled(algorithmName);
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    /// <summary>
    /// Disposes the signature instance and releases all associated resources.
    /// After disposal, this instance cannot be used for further operations.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        
        _sigInstance?.Dispose();
        _disposed = true;
    }
}