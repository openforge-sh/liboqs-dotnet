using OpenForge.Cryptography.LibOqs.Core;

namespace OpenForge.Cryptography.LibOqs.KEM;

/// <summary>
/// High-level wrapper for LibOQS Key Encapsulation Mechanism (KEM) operations.
/// This class provides a user-friendly interface for post-quantum key exchange operations.
/// KEM algorithms are used to securely establish shared secrets between parties.
/// </summary>
public sealed class Kem : IDisposable
{
    private readonly KemInstance _kemInstance;
    private readonly string _algorithmName;
    private bool _disposed;

    /// <summary>
    /// Gets the name of the KEM algorithm used by this instance.
    /// </summary>
    /// <value>The algorithm identifier string.</value>
    public string AlgorithmName => _algorithmName;
    
    /// <summary>
    /// Gets the length of public keys in bytes for this KEM algorithm.
    /// </summary>
    /// <value>The public key length in bytes.</value>
    public int PublicKeyLength { get; private set; }
    
    /// <summary>
    /// Gets the length of secret keys in bytes for this KEM algorithm.
    /// </summary>
    /// <value>The secret key length in bytes.</value>
    public int SecretKeyLength { get; private set; }
    
    /// <summary>
    /// Gets the length of ciphertext in bytes for this KEM algorithm.
    /// </summary>
    /// <value>The ciphertext length in bytes.</value>
    public int CiphertextLength { get; private set; }
    
    /// <summary>
    /// Gets the length of shared secrets in bytes for this KEM algorithm.
    /// </summary>
    /// <value>The shared secret length in bytes.</value>
    public int SharedSecretLength { get; private set; }
    
    /// <summary>
    /// Gets the NIST security level claimed by this KEM algorithm.
    /// </summary>
    /// <value>The NIST security level (1, 2, 3, or 5).</value>
    public byte ClaimedNistLevel { get; private set; }
    
    /// <summary>
    /// Gets a value indicating whether this KEM algorithm provides IND-CCA security.
    /// IND-CCA (Indistinguishability under Chosen Ciphertext Attack) is the standard security requirement for KEMs.
    /// </summary>
    /// <value>True if the algorithm provides IND-CCA security, false otherwise.</value>
    public bool IsIndCca { get; private set; }


    /// <summary>
    /// Initializes a new instance of the KEM class with the specified algorithm.
    /// </summary>
    /// <param name="algorithmName">The name of the KEM algorithm to use.</param>
    /// <exception cref="ArgumentNullException">Thrown if algorithmName is null.</exception>
    /// <exception cref="NotSupportedException">Thrown if the algorithm is not supported or enabled.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the KEM instance could not be created.</exception>
    public Kem(string algorithmName)
    {
        ArgumentNullException.ThrowIfNull(algorithmName);
        _algorithmName = algorithmName;
        
        AlgorithmConstants.CheckForDeprecationWarning(algorithmName, "KEM constructor");
        
        _kemInstance = KemProvider.Create(algorithmName);
        
        var kemInfo = _kemInstance.GetAlgorithmInfo();
        PublicKeyLength = (int)kemInfo.length_public_key;
        SecretKeyLength = (int)kemInfo.length_secret_key;
        CiphertextLength = (int)kemInfo.length_ciphertext;
        SharedSecretLength = (int)kemInfo.length_shared_secret;
        ClaimedNistLevel = kemInfo.claimed_nist_level;
        IsIndCca = kemInfo.ind_cca != 0;
    }

    /// <summary>
    /// Generates a new cryptographic key pair for this KEM algorithm.
    /// The secret key should be kept private and securely stored.
    /// </summary>
    /// <returns>A tuple containing the public key and secret key as byte arrays.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if this instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if key pair generation fails.</exception>
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        ThrowIfDisposed();
        
        var keyPair = _kemInstance.GenerateKeyPair();
        return (keyPair.PublicKey, keyPair.SecretKey);
    }

    /// <summary>
    /// Encapsulates a shared secret using the recipient's public key.
    /// This creates both a ciphertext to send to the recipient and a shared secret for symmetric encryption.
    /// </summary>
    /// <param name="publicKey">The recipient's public key.</param>
    /// <returns>A tuple containing the ciphertext to send and the shared secret to use.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if this instance has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if publicKey is null.</exception>
    /// <exception cref="ArgumentException">Thrown if the public key has an invalid length.</exception>
    /// <exception cref="InvalidOperationException">Thrown if encapsulation fails.</exception>
    public (byte[] ciphertext, byte[] sharedSecret) Encapsulate(byte[] publicKey)
    {
        ThrowIfDisposed();
        
        ArgumentNullException.ThrowIfNull(publicKey);
        
        var result = _kemInstance.Encapsulate(publicKey);
        return (result.Ciphertext, result.SharedSecret);
    }

    /// <summary>
    /// Decapsulates the shared secret from the ciphertext using the recipient's secret key.
    /// This recovers the same shared secret that was generated during encapsulation.
    /// </summary>
    /// <param name="ciphertext">The ciphertext received from the sender.</param>
    /// <param name="secretKey">The recipient's secret key.</param>
    /// <returns>The shared secret that matches the one from encapsulation.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if this instance has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if ciphertext or secretKey is null.</exception>
    /// <exception cref="ArgumentException">Thrown if parameters have invalid lengths.</exception>
    /// <exception cref="InvalidOperationException">Thrown if decapsulation fails.</exception>
    public byte[] Decapsulate(byte[] ciphertext, byte[] secretKey)
    {
        ThrowIfDisposed();
        
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(secretKey);
        
        return _kemInstance.Decapsulate(ciphertext, secretKey);
    }

    /// <summary>
    /// Gets all KEM algorithms that are currently supported and enabled in LibOQS.
    /// </summary>
    /// <returns>An array of algorithm identifier strings for supported KEM algorithms.</returns>
    public static string[] GetSupportedAlgorithms()
    {
        return KemProvider.GetSupportedAlgorithms().ToArray();
    }

    /// <summary>
    /// Determines whether a specific KEM algorithm is supported and available for use.
    /// </summary>
    /// <param name="algorithmName">The name of the KEM algorithm to check.</param>
    /// <returns>True if the algorithm is supported and enabled, false otherwise.</returns>
    public static bool IsAlgorithmSupported(string algorithmName)
    {
        if (string.IsNullOrEmpty(algorithmName))
            return false;
        
        return KemProvider.IsAlgorithmEnabled(algorithmName);
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    /// <summary>
    /// Disposes the KEM instance and releases all associated resources.
    /// After disposal, this instance cannot be used for further operations.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        
        _kemInstance?.Dispose();
        _disposed = true;
    }
}