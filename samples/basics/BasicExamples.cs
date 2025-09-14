using System.Text;
using OpenForge.Cryptography.LibOqs.SIG;
using OpenForge.Cryptography.LibOqs.KEM;

namespace OpenForge.Cryptography.LibOqs.Samples.Basics;

/// <summary>
/// Demonstrates fundamental usage of OpenForge.Cryptography.LibOqs.
/// These examples cover the essential concepts every user should understand.
/// </summary>
internal static class BasicExamples
{
    /// <summary>
    /// Example 1: Basic KEM (Key Encapsulation Mechanism) usage.
    /// </summary>
    public static void BasicKemUsage()
    {
        Console.WriteLine("=== Basic KEM Usage ===\n");
        
        // Choose ML-KEM-768 for balanced security and performance
        using var kem = new Kem("ML-KEM-768");
        
        Console.WriteLine($"Algorithm: {kem.AlgorithmName}");
        Console.WriteLine($"Security Level: NIST Level {kem.ClaimedNistLevel}");
        Console.WriteLine();
        
        // Step 1: Generate a key pair
        Console.WriteLine("1. Generating key pair...");
        var (publicKey, secretKey) = kem.GenerateKeyPair();
        
        Console.WriteLine($"   Public key:  {publicKey.Length} bytes");
        Console.WriteLine($"   Secret key:  {secretKey.Length} bytes");
        Console.WriteLine();
        
        // Step 2: Encapsulate (encrypt) to create shared secret
        Console.WriteLine("2. Encapsulating shared secret...");
        var (ciphertext, sharedSecret1) = kem.Encapsulate(publicKey);
        
        Console.WriteLine($"   Ciphertext:    {ciphertext.Length} bytes");
        Console.WriteLine($"   Shared secret: {sharedSecret1.Length} bytes");
        Console.WriteLine();
        
        // Step 3: Decapsulate (decrypt) to recover shared secret
        Console.WriteLine("3. Decapsulating shared secret...");
        var sharedSecret2 = kem.Decapsulate(ciphertext, secretKey);
        
        // Step 4: Verify the shared secrets match
        var match = sharedSecret1.AsSpan().SequenceEqual(sharedSecret2);
        Console.WriteLine($"   Secrets match: {(match ? "✓ Yes" : "✗ No")}");
        Console.WriteLine();
        
        Console.WriteLine("✅ Basic KEM operation completed successfully!");
        Console.WriteLine("The shared secret can now be used for symmetric encryption.");
    }

    /// <summary>
    /// Example 2: Basic digital signature usage.
    /// </summary>
    public static void BasicSignatureUsage()
    {
        Console.WriteLine("=== Basic Digital Signature Usage ===\n");
        
        // Choose ML-DSA-65 for balanced security and performance
        using var sig = new Sig("ML-DSA-65");
        
        Console.WriteLine($"Algorithm: {sig.AlgorithmName}");
        Console.WriteLine($"Security Level: NIST Level {sig.ClaimedNistLevel}");
        Console.WriteLine();
        
        // Step 1: Generate a key pair
        Console.WriteLine("1. Generating key pair...");
        var (publicKey, secretKey) = sig.GenerateKeyPair();
        
        Console.WriteLine($"   Public key: {publicKey.Length} bytes");
        Console.WriteLine($"   Secret key: {secretKey.Length} bytes");
        Console.WriteLine();
        
        // Step 2: Create a message to sign
        var message = Encoding.UTF8.GetBytes("Hello, Post-Quantum World! This message is signed with ML-DSA-65.");
        Console.WriteLine("2. Signing message...");
        Console.WriteLine($"   Message: \"{Encoding.UTF8.GetString(message)}\"");
        Console.WriteLine($"   Message length: {message.Length} bytes");
        Console.WriteLine();
        
        // Step 3: Sign the message
        var signature = sig.Sign(message, secretKey);
        Console.WriteLine($"   Signature: {signature.Length} bytes");
        Console.WriteLine();
        
        // Step 4: Verify the signature
        Console.WriteLine("3. Verifying signature...");
        var isValid = sig.Verify(message, signature, publicKey);
        Console.WriteLine($"   Signature valid: {(isValid ? "✓ Yes" : "✗ No")}");
        Console.WriteLine();
        
        // Step 5: Test with tampered message
        Console.WriteLine("4. Testing with tampered message...");
        var tamperedMessage = Encoding.UTF8.GetBytes("Hello, Post-Quantum World! This message has been tampered with.");
        var isTamperedValid = sig.Verify(tamperedMessage, signature, publicKey);
        Console.WriteLine($"   Tampered message valid: {(isTamperedValid ? "✓ Yes" : "✗ No")}");
        Console.WriteLine();
        
        Console.WriteLine("✅ Basic signature operation completed successfully!");
        Console.WriteLine("Digital signatures provide authentication and non-repudiation.");
    }

    /// <summary>
    /// Example 3: Algorithm discovery and comparison.
    /// </summary>
    public static void AlgorithmDiscovery()
    {
        Console.WriteLine("=== Algorithm Discovery ===\n");
        
        // Discover available KEM algorithms
        Console.WriteLine("Available KEM Algorithms:");
        var kemAlgorithms = Kem.GetSupportedAlgorithms();
        var nistKemAlgorithms = kemAlgorithms.Where(a => a.StartsWith("ML-KEM", StringComparison.Ordinal)).ToArray();
        
        Console.WriteLine("Algorithm     | Pub Key | Sec Key | Cipher | Shared | Level");
        Console.WriteLine("--------------|---------|---------|--------|--------|-------");
        
        foreach (var algorithm in nistKemAlgorithms)
        {
            try
            {
                using var kem = new Kem(algorithm);
                Console.WriteLine($"{algorithm,-13} | {kem.PublicKeyLength,7} | {kem.SecretKeyLength,7} | " +
                                $"{kem.CiphertextLength,6} | {kem.SharedSecretLength,6} | {kem.ClaimedNistLevel,5}");
            }
            catch (ArgumentException)
            {
                Console.WriteLine($"{algorithm,-13} | (not available on this platform)");
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine($"{algorithm,-13} | (not available on this platform)");
            }
        }
        Console.WriteLine();
        
        // Discover available signature algorithms
        Console.WriteLine("Available Signature Algorithms:");
        var sigAlgorithms = Sig.GetSupportedAlgorithms();
        var nistSigAlgorithms = sigAlgorithms.Where(a => a.StartsWith("ML-DSA", StringComparison.Ordinal)).ToArray();
        
        Console.WriteLine("Algorithm     | Pub Key | Sec Key | Max Sig | Level");
        Console.WriteLine("--------------|---------|---------|---------|-------");
        
        foreach (var algorithm in nistSigAlgorithms)
        {
            try
            {
                using var sig = new Sig(algorithm);
                Console.WriteLine($"{algorithm,-13} | {sig.PublicKeyLength,7} | {sig.SecretKeyLength,7} | " +
                                $"{sig.SignatureLength,7} | {sig.ClaimedNistLevel,5}");
            }
            catch (ArgumentException)
            {
                Console.WriteLine($"{algorithm,-13} | (not available on this platform)");
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine($"{algorithm,-13} | (not available on this platform)");
            }
        }
        Console.WriteLine();
        
        Console.WriteLine("Algorithm Selection Guide:");
        Console.WriteLine("• ML-KEM-512 + ML-DSA-44: Fastest, smallest (Level 1-2)");
        Console.WriteLine("• ML-KEM-768 + ML-DSA-65: Balanced choice (Level 3) ⭐");
        Console.WriteLine("• ML-KEM-1024 + ML-DSA-87: Maximum security (Level 5)");
    }

    /// <summary>
    /// Example 4: Error handling and validation.
    /// </summary>
    public static void ErrorHandling()
    {
        Console.WriteLine("=== Error Handling Best Practices ===\n");
        
        // Test 1: Invalid algorithm name
        Console.WriteLine("1. Testing invalid algorithm name...");
        try
        {
            using var kem = new Kem("Invalid-Algorithm");
            Console.WriteLine("   ✗ Should have thrown an exception!");
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"   ✓ Caught expected exception: {ex.Message}");
        }
        catch (InvalidOperationException ex)
        {
            Console.WriteLine($"   ✓ Caught expected exception: {ex.Message}");
        }
        Console.WriteLine();
        
        // Test 2: Invalid key size for operations
        Console.WriteLine("2. Testing invalid key sizes...");
        try
        {
            using var kem = new Kem("ML-KEM-768");
            var invalidPublicKey = new byte[100]; // Wrong size
            kem.Encapsulate(invalidPublicKey);
            Console.WriteLine("   ✗ Should have thrown an exception!");
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"   ✓ Caught expected exception: {ex.Message}");
        }
        catch (InvalidOperationException ex)
        {
            Console.WriteLine($"   ✓ Caught expected exception: {ex.Message}");
        }
        Console.WriteLine();
        
        // Test 3: Proper validation
        Console.WriteLine("3. Proper validation example...");
        try
        {
            using var sig = new Sig("ML-DSA-65");
            
            // Check if algorithm is available
            if (!Sig.IsAlgorithmSupported("ML-DSA-65"))
            {
                Console.WriteLine("   ✗ ML-DSA-65 not supported on this platform");
                return;
            }
            
            var (publicKey, secretKey) = sig.GenerateKeyPair();
            
            // Validate key lengths
            if (publicKey.Length != sig.PublicKeyLength)
            {
                Console.WriteLine("   ✗ Public key length mismatch");
                return;
            }
            
            if (secretKey.Length != sig.SecretKeyLength)
            {
                Console.WriteLine("   ✗ Secret key length mismatch");
                return;
            }
            
            Console.WriteLine("   ✓ All validations passed");
            Console.WriteLine($"   ✓ Generated valid key pair for {sig.AlgorithmName}");
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"   ✗ Argument error: {ex.Message}");
        }
        catch (InvalidOperationException ex)
        {
            Console.WriteLine($"   ✗ Operation error: {ex.Message}");
        }
        Console.WriteLine();
        
        Console.WriteLine("Best Practices:");
        Console.WriteLine("• Always validate algorithm support before use");
        Console.WriteLine("• Use specific exception types (ArgumentException, InvalidOperationException)");
        Console.WriteLine("• Check key lengths match expected values");
        Console.WriteLine("• Handle platform-specific algorithm availability");
    }

    /// <summary>
    /// Example 5: Memory and performance considerations.
    /// </summary>
    public static void MemoryAndPerformance()
    {
        Console.WriteLine("=== Memory and Performance Considerations ===\n");
        
        Console.WriteLine("Key Size Comparison (bytes):");
        Console.WriteLine("Algorithm     | Total Keys | vs RSA-2048 | vs ECDSA P-256");
        Console.WriteLine("--------------|------------|-------------|----------------");
        
        // RSA-2048 baseline: ~512 bytes total, ECDSA P-256: ~64 bytes total
        var rsaTotal = 512;
        var ecdsaTotal = 64;
        
        var kemAlgorithms = new[] { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
        foreach (var algorithm in kemAlgorithms)
        {
            try
            {
                using var kem = new Kem(algorithm);
                var total = kem.PublicKeyLength + kem.SecretKeyLength;
                var vsRsa = total / (double)rsaTotal;
                var vsEcdsa = total / (double)ecdsaTotal;
                
                Console.WriteLine($"{algorithm,-13} | {total,10:N0} | {vsRsa,9:F1}x | {vsEcdsa,12:F1}x");
            }
            catch (ArgumentException)
            {
                Console.WriteLine($"{algorithm,-13} | (not available)");
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine($"{algorithm,-13} | (not available)");
            }
        }
        Console.WriteLine();
        
        Console.WriteLine("Performance Tips:");
        Console.WriteLine("• Reuse Kem/Signature instances when possible (they're disposable)");
        Console.WriteLine("• Keys are larger than classical crypto - plan storage accordingly");
        Console.WriteLine("• ML-KEM-512 offers best performance, ML-KEM-1024 best security");
        Console.WriteLine("• Operations are generally fast - key generation is the slowest part");
        Console.WriteLine();
        
        Console.WriteLine("Memory Management:");
        Console.WriteLine("• Use 'using' statements for automatic cleanup");
        Console.WriteLine("• Keys are byte arrays - they can be securely cleared if needed");
        Console.WriteLine("• Library handles native memory management automatically");
        Console.WriteLine("• Thread-safe for concurrent operations with different instances");
    }

    /// <summary>
    /// Runs all basic examples.
    /// </summary>
    public static void RunAllExamples()
    {
        var examples = new Action[]
        {
            BasicKemUsage,
            BasicSignatureUsage,
            AlgorithmDiscovery,
            ErrorHandling,
            MemoryAndPerformance
        };

        foreach (var example in examples)
        {
            example();
            Console.WriteLine(new string('=', 70));
            Console.WriteLine();
        }
    }
}