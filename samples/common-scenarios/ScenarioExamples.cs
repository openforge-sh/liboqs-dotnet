using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OpenForge.Cryptography.LibOqs.KEM;
using OpenForge.Cryptography.LibOqs.SIG;

namespace OpenForge.Cryptography.LibOqs.Samples.CommonScenarios;

/// <summary>
/// Demonstrates practical post-quantum cryptography usage in common real-world scenarios.
/// </summary>
internal static class ScenarioExamples
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    /// <summary>
    /// Example 1: File encryption using post-quantum key encapsulation.
    /// </summary>
    public static void FileEncryption()
    {
        Console.WriteLine("=== File Encryption Scenario ===\n");
        
        Console.WriteLine("This example shows how to encrypt files using post-quantum cryptography.");
        Console.WriteLine("We use ML-KEM for key encapsulation and AES for the actual file encryption.\n");
        
        // Step 1: Generate recipient's key pair
        using var kem = new Kem("ML-KEM-768");
        var (recipientPublicKey, recipientSecretKey) = kem.GenerateKeyPair();
        
        Console.WriteLine("1. Generated recipient key pair");
        Console.WriteLine($"   Public key: {recipientPublicKey.Length} bytes (share with sender)");
        Console.WriteLine($"   Secret key: {recipientSecretKey.Length} bytes (keep private)");
        Console.WriteLine();
        
        // Step 2: Sender encrypts a file
        var originalData = "This is sensitive file content that needs post-quantum protection.\nIt could be any binary data, documents, or application data."u8.ToArray();
        
        Console.WriteLine("2. Encrypting file data...");
        Console.WriteLine($"   Original data: {originalData.Length} bytes");
        
        // Use KEM to create shared secret for symmetric encryption
        var (ciphertext, sharedSecret) = kem.Encapsulate(recipientPublicKey);
        
        // In production, use proper AEAD encryption like AES-GCM with the shared secret as key derivation input
        // This example shows the concept - replace with System.Security.Cryptography.Aes for real applications
        var encryptedData = EncryptWithSharedSecret(originalData, sharedSecret);
        
        Console.WriteLine($"   Encrypted data: {encryptedData.Length} bytes");
        Console.WriteLine($"   KEM ciphertext: {ciphertext.Length} bytes (send with encrypted file)");
        Console.WriteLine();
        
        // Step 3: Recipient decrypts the file
        Console.WriteLine("3. Decrypting file data...");
        
        // Recipient uses their secret key to recover the shared secret
        var recoveredSharedSecret = kem.Decapsulate(ciphertext, recipientSecretKey);
        
        // Verify shared secrets match
        var secretsMatch = sharedSecret.AsSpan().SequenceEqual(recoveredSharedSecret);
        Console.WriteLine($"   Shared secret recovery: {(secretsMatch ? "✓ Success" : "✗ Failed")}");
        
        // Decrypt the data using the recovered shared secret
        var decryptedData = DecryptWithSharedSecret(encryptedData, recoveredSharedSecret);
        
        var dataMatches = originalData.AsSpan().SequenceEqual(decryptedData);
        Console.WriteLine($"   Data recovery: {(dataMatches ? "✓ Success" : "✗ Failed")}");
        Console.WriteLine($"   Decrypted: \"{Encoding.UTF8.GetString(decryptedData)[..50]}...\"");
        Console.WriteLine();
        
        Console.WriteLine("Real-world implementation notes:");
        Console.WriteLine("• This example uses AES-GCM for authenticated encryption");
        Console.WriteLine("• Shared secret should be used with proper key derivation (HKDF)");
        Console.WriteLine("• Store KEM ciphertext alongside the encrypted file");
        Console.WriteLine("• Consider chunked encryption for very large files");
        Console.WriteLine("• Always validate ciphertext integrity before decryption");
    }
    internal static readonly string[] value =
            [
                "All cryptographic systems must use NIST-approved post-quantum algorithms",
                "ML-KEM-768 is approved for key encapsulation",
                "ML-DSA-65 is approved for digital signatures",
                "Migration must be completed by 2026"
            ];

    /// <summary>
    /// Example 2: Document signing for authenticity and integrity.
    /// </summary>
    public static void DocumentSigning()
    {
        Console.WriteLine("=== Document Signing Scenario ===\n");
        
        Console.WriteLine("This example shows how to digitally sign documents for authenticity.");
        Console.WriteLine("The signature proves the document came from the signer and wasn't modified.\n");
        
        // Step 1: Create a document to sign
        var document = JsonSerializer.Serialize(new
        {
            Title = "Post-Quantum Security Policy",
            Version = "1.0",
            Date = DateTime.UtcNow.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
            Content = value
        }, JsonOptions);
        
        var documentBytes = Encoding.UTF8.GetBytes(document);
        
        Console.WriteLine("1. Document to sign:");
        Console.WriteLine($"   Length: {documentBytes.Length} bytes");
        Console.WriteLine($"   Preview: {document[..100]}...");
        Console.WriteLine();
        
        // Step 2: Signer creates digital signature
        using var sig = new Sig("ML-DSA-65");
        var (signerPublicKey, signerSecretKey) = sig.GenerateKeyPair();
        
        Console.WriteLine("2. Creating digital signature...");
        Console.WriteLine($"   Signer public key: {signerPublicKey.Length} bytes");
        Console.WriteLine($"   Algorithm: {sig.AlgorithmName} (NIST Level {sig.ClaimedNistLevel})");
        
        var signature = sig.Sign(documentBytes, signerSecretKey);
        Console.WriteLine($"   Signature: {signature.Length} bytes");
        Console.WriteLine();
        
        // Step 3: Verification by recipient
        Console.WriteLine("3. Verifying signature...");
        var isValid = sig.Verify(documentBytes, signature, signerPublicKey);
        Console.WriteLine($"   Original document: {(isValid ? "✓ Authentic" : "✗ Invalid")}");
        
        // Step 4: Test tampering detection
        Console.WriteLine();
        Console.WriteLine("4. Testing tampering detection...");
        
        // Slightly modify the document
        var tamperedDocument = document.Replace("2026", "2025", StringComparison.Ordinal);
        var tamperedBytes = Encoding.UTF8.GetBytes(tamperedDocument);
        
        var isTamperedValid = sig.Verify(tamperedBytes, signature, signerPublicKey);
        Console.WriteLine($"   Tampered document: {(isTamperedValid ? "✗ Not detected!" : "✓ Correctly rejected")}");
        Console.WriteLine();
        
        Console.WriteLine("Signed document package would include:");
        Console.WriteLine($"• Original document: {documentBytes.Length} bytes");
        Console.WriteLine($"• Digital signature: {signature.Length} bytes");
        Console.WriteLine($"• Signer public key: {signerPublicKey.Length} bytes");
        Console.WriteLine($"• Algorithm identifier: {sig.AlgorithmName}");
        Console.WriteLine();
        
        Console.WriteLine("Real-world considerations:");
        Console.WriteLine("• Store public key in trusted certificate or key registry");
        Console.WriteLine("• Include timestamp to prevent replay attacks");
        Console.WriteLine("• Consider certificate chains for organizational trust");
        Console.WriteLine("• Hash large documents before signing for efficiency");
    }

    /// <summary>
    /// Example 3: API authentication and data protection.
    /// </summary>
    public static void ApiSecurity()
    {
        Console.WriteLine("=== API Security Scenario ===\n");
        
        Console.WriteLine("This example shows post-quantum authentication for REST API calls.");
        Console.WriteLine("Each request is signed to prove identity and prevent tampering.\n");
        
        // Step 1: Client setup
        using var clientSig = new Sig("ML-DSA-44"); // Faster for API calls
        var (clientPublicKey, clientSecretKey) = clientSig.GenerateKeyPair();
        
        Console.WriteLine("1. Client setup:");
        Console.WriteLine($"   Client ID: client-12345");
        Console.WriteLine($"   Public key: {clientPublicKey.Length} bytes (registered with server)");
        Console.WriteLine($"   Algorithm: {clientSig.AlgorithmName}");
        Console.WriteLine();
        
        // Step 2: Create API request
        var apiRequest = new
        {
            Method = "POST",
            Path = "/api/v1/users",
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ClientId = "client-12345",
            Data = new
            {
                Name = "John Doe",
                Email = "john@example.com",
                Role = "User"
            }
        };
        
        var requestJson = JsonSerializer.Serialize(apiRequest);
        var requestBytes = Encoding.UTF8.GetBytes(requestJson);
        
        Console.WriteLine("2. API request:");
        Console.WriteLine($"   {requestJson}");
        Console.WriteLine($"   Request size: {requestBytes.Length} bytes");
        Console.WriteLine();
        
        // Step 3: Sign the request
        Console.WriteLine("3. Signing API request...");
        var requestSignature = clientSig.Sign(requestBytes, clientSecretKey);
        
        Console.WriteLine($"   Signature: {requestSignature.Length} bytes");
        Console.WriteLine($"   Header: X-Signature: {Convert.ToBase64String(requestSignature)[..32]}...");
        Console.WriteLine();
        
        // Step 4: Server verification (simulated)
        Console.WriteLine("4. Server verification...");
        Console.WriteLine("   Server looks up client public key from registry...");
        
        // Server verifies the signature
        var isAuthenticated = clientSig.Verify(requestBytes, requestSignature, clientPublicKey);
        Console.WriteLine($"   Authentication: {(isAuthenticated ? "✓ Valid client" : "✗ Rejected")}");
        
        // Check timestamp to prevent replay attacks
        var requestTime = DateTimeOffset.FromUnixTimeSeconds(apiRequest.Timestamp);
        var timeDiff = DateTimeOffset.UtcNow - requestTime;
        var isTimestampValid = timeDiff.TotalMinutes < 5; // 5-minute window
        
        Console.WriteLine($"   Timestamp: {(isTimestampValid ? "✓ Fresh request" : "✗ Too old")}");
        Console.WriteLine();
        
        if (isAuthenticated && isTimestampValid)
        {
            Console.WriteLine("5. Request processing:");
            Console.WriteLine("   ✓ Client authenticated successfully");
            Console.WriteLine("   ✓ Request integrity verified");
            Console.WriteLine("   ✓ Timestamp within acceptable window");
            Console.WriteLine("   → Processing user creation...");
        }
        else
        {
            Console.WriteLine("5. Request rejected:");
            Console.WriteLine("   ✗ Authentication or timestamp validation failed");
        }
        Console.WriteLine();
        
        Console.WriteLine("API security implementation:");
        Console.WriteLine("• Client signs: HTTP method + path + timestamp + body");
        Console.WriteLine("• Server validates signature using registered public key");
        Console.WriteLine("• Timestamp prevents replay attacks");
        Console.WriteLine("• Each client has unique key pair for accountability");
        Console.WriteLine();
        
        Console.WriteLine("Real-world considerations:");
        Console.WriteLine("• Use HTTPS for transport security");
        Console.WriteLine("• Implement proper key management and rotation");
        Console.WriteLine("• Consider rate limiting per client key");
        Console.WriteLine("• Log all authentication attempts for security monitoring");
    }

    /// <summary>
    /// Example 4: Database field encryption for sensitive data.
    /// </summary>
    public static void DatabaseFieldEncryption()
    {
        Console.WriteLine("=== Database Field Encryption Scenario ===\n");
        
        Console.WriteLine("This example shows how to encrypt sensitive database fields.");
        Console.WriteLine("Personal information is protected even if the database is compromised.\n");
        
        // Step 1: Application master key (would be stored securely)
        using var kem = new Kem("ML-KEM-768");
        var (masterPublicKey, masterSecretKey) = kem.GenerateKeyPair();
        
        Console.WriteLine("1. Master key setup (done once):");
        Console.WriteLine($"   Master public key: {masterPublicKey.Length} bytes");
        Console.WriteLine("   Master secret key: stored in secure key management system");
        Console.WriteLine();
        
        // Step 2: Encrypt user record fields
        var userData = new
        {
            Id = 12345,
            Username = "jdoe",
            Email = "john.doe@company.com",
            SSN = "123-45-6789",
            CreditCard = "4111-1111-1111-1111",
            Salary = "$85,000"
        };
        
        Console.WriteLine("2. User data to protect:");
        Console.WriteLine($"   ID: {userData.Id} (not encrypted - used for queries)");
        Console.WriteLine($"   Username: {userData.Username} (not encrypted - used for login)");
        Console.WriteLine($"   Email: {userData.Email} (encrypted)");
        Console.WriteLine($"   SSN: {userData.SSN} (encrypted)");
        Console.WriteLine($"   Credit Card: {userData.CreditCard} (encrypted)");
        Console.WriteLine($"   Salary: {userData.Salary} (encrypted)");
        Console.WriteLine();
        
        // Encrypt sensitive fields
        Console.WriteLine("3. Encrypting sensitive fields...");
        
        var encryptedFields = new
        {
            Email = EncryptField(userData.Email, masterPublicKey, kem),
            SSN = EncryptField(userData.SSN, masterPublicKey, kem),
            CreditCard = EncryptField(userData.CreditCard, masterPublicKey, kem),
            Salary = EncryptField(userData.Salary, masterPublicKey, kem)
        };
        
        Console.WriteLine($"   Encrypted email: {encryptedFields.Email.CipherText.Length} bytes + {encryptedFields.Email.KemCiphertext.Length} bytes KEM");
        Console.WriteLine($"   Encrypted SSN: {encryptedFields.SSN.CipherText.Length} bytes + {encryptedFields.SSN.KemCiphertext.Length} bytes KEM");
        Console.WriteLine($"   Encrypted CC: {encryptedFields.CreditCard.CipherText.Length} bytes + {encryptedFields.CreditCard.KemCiphertext.Length} bytes KEM");
        Console.WriteLine($"   Encrypted salary: {encryptedFields.Salary.CipherText.Length} bytes + {encryptedFields.Salary.KemCiphertext.Length} bytes KEM");
        Console.WriteLine();
        
        // Step 4: Store in database (simulated)
        Console.WriteLine("4. Database storage (simulated SQL):");
        Console.WriteLine("   INSERT INTO users (id, username, email_cipher, email_kem, ssn_cipher, ssn_kem, ...)");
        Console.WriteLine($"   VALUES ({userData.Id}, '{userData.Username}',");
        Console.WriteLine($"          '{Convert.ToBase64String(encryptedFields.Email.CipherText)[..20]}...',");
        Console.WriteLine($"          '{Convert.ToBase64String(encryptedFields.Email.KemCiphertext)[..20]}...', ...)");
        Console.WriteLine();
        
        // Step 5: Decrypt fields when reading
        Console.WriteLine("5. Decrypting fields when reading from database...");
        
        var decryptedEmail = DecryptField(encryptedFields.Email, masterSecretKey, kem);
        var decryptedSSN = DecryptField(encryptedFields.SSN, masterSecretKey, kem);
        
        Console.WriteLine($"   Original email: {userData.Email}");
        Console.WriteLine($"   Decrypted email: {decryptedEmail}");
        Console.WriteLine($"   Match: {(userData.Email == decryptedEmail ? "✓" : "✗")}");
        Console.WriteLine();
        Console.WriteLine($"   Original SSN: {userData.SSN}");
        Console.WriteLine($"   Decrypted SSN: {decryptedSSN}");
        Console.WriteLine($"   Match: {(userData.SSN == decryptedSSN ? "✓" : "✗")}");
        Console.WriteLine();
        
        Console.WriteLine("Database security benefits:");
        Console.WriteLine("• Sensitive data encrypted at rest");
        Console.WriteLine("• Database breach doesn't expose personal information");
        Console.WriteLine("• Application controls access through key management");
        Console.WriteLine("• Post-quantum security protects against future threats");
        Console.WriteLine();
        
        Console.WriteLine("Implementation considerations:");
        Console.WriteLine("• Use proper key management system (Azure Key Vault, AWS KMS, etc.)");
        Console.WriteLine("• Consider searchable encryption for query requirements");
        Console.WriteLine("• Separate encryption keys per data type or tenant");
        Console.WriteLine("• Regular key rotation and secure backup procedures");
    }

    // Helper methods for field encryption using secure AES-GCM
    private static (byte[] CipherText, byte[] KemCiphertext) EncryptField(string data, byte[] publicKey, Kem kem)
    {
        var (kemCiphertext, sharedSecret) = kem.Encapsulate(publicKey);
        var dataBytes = Encoding.UTF8.GetBytes(data);
        var ciphertext = EncryptWithSharedSecret(dataBytes, sharedSecret);
        
        return (ciphertext, kemCiphertext);
    }
    
    private static string DecryptField((byte[] CipherText, byte[] KemCiphertext) encrypted, byte[] secretKey, Kem kem)
    {
        var sharedSecret = kem.Decapsulate(encrypted.KemCiphertext, secretKey);
        var plaintext = DecryptWithSharedSecret(encrypted.CipherText, sharedSecret);
        
        return Encoding.UTF8.GetString(plaintext);
    }
    
    // Secure encryption using AES-GCM with the shared secret
    private static byte[] EncryptWithSharedSecret(byte[] plaintext, byte[] sharedSecret)
    {
        using var aes = Aes.Create();
        
        // Use first 32 bytes of shared secret as AES key (or use HKDF for proper key derivation)
        var key = new byte[32];
        Array.Copy(sharedSecret, 0, key, 0, Math.Min(32, sharedSecret.Length));
        
        // Generate random IV
        var iv = new byte[12]; // AES-GCM typically uses 12-byte IV
        RandomNumberGenerator.Fill(iv);
        
        using var gcm = new AesGcm(key, 16);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16]; // AES-GCM authentication tag
        
        gcm.Encrypt(iv, plaintext, ciphertext, tag);
        
        // Combine IV + ciphertext + tag for storage/transmission
        var result = new byte[iv.Length + ciphertext.Length + tag.Length];
        Array.Copy(iv, 0, result, 0, iv.Length);
        Array.Copy(ciphertext, 0, result, iv.Length, ciphertext.Length);
        Array.Copy(tag, 0, result, iv.Length + ciphertext.Length, tag.Length);
        
        return result;
    }
    
    private static byte[] DecryptWithSharedSecret(byte[] encryptedData, byte[] sharedSecret)
    {
        // Use first 32 bytes of shared secret as AES key
        var key = new byte[32];
        Array.Copy(sharedSecret, 0, key, 0, Math.Min(32, sharedSecret.Length));
        
        // Extract IV, ciphertext, and tag from encrypted data
        var iv = encryptedData[0..12];
        var tag = encryptedData[^16..];
        var ciphertext = encryptedData[12..^16];
        
        using var gcm = new AesGcm(key, 16);
        var plaintext = new byte[ciphertext.Length];
        
        gcm.Decrypt(iv, ciphertext, tag, plaintext);
        
        return plaintext;
    }

    /// <summary>
    /// Runs all common scenario examples.
    /// </summary>
    public static void RunAllScenarios()
    {
        var examples = new Action[]
        {
            FileEncryption,
            DocumentSigning,
            ApiSecurity,
            DatabaseFieldEncryption
        };

        foreach (var example in examples)
        {
            example();
            Console.WriteLine(new string('=', 70));
            Console.WriteLine();
        }
    }
}