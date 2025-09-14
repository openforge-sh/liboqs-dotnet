using System.Text;
using OpenForge.Cryptography.LibOqs.KEM;
using OpenForge.Cryptography.LibOqs.SIG;

namespace OpenForge.Cryptography.LibOqs.Samples.Testing;

/// <summary>
/// Demonstrates validation and testing techniques for post-quantum cryptographic operations.
/// </summary>
#pragma warning disable S1192
internal static class ValidationExamples
{
    /// <summary>
    /// Example 1: Algorithm consistency validation.
    /// </summary>
    public static void AlgorithmConsistency()
    {
        Console.WriteLine("=== Algorithm Consistency Validation ===\n");
        
        Console.WriteLine("Validating algorithm properties match specifications:");
        Console.WriteLine();
        
        // NIST ML-KEM specifications
        var expectedKemSizes = new[]
        {
            ("ML-KEM-512", PublicKey: 800, SecretKey: 1632, Ciphertext: 768, SharedSecret: 32, Level: 1),
            ("ML-KEM-768", PublicKey: 1184, SecretKey: 2400, Ciphertext: 1088, SharedSecret: 32, Level: 3),
            ("ML-KEM-1024", PublicKey: 1568, SecretKey: 3168, Ciphertext: 1568, SharedSecret: 32, Level: 5)
        };
        
        Console.WriteLine("KEM Algorithm Validation:");
        Console.WriteLine("Algorithm     | Status | Pub Key | Sec Key | Cipher | Shared | Level");
        Console.WriteLine("--------------|--------|---------|---------|--------|--------|-------");
        
        foreach (var (name, expectedPub, expectedSec, expectedCipher, expectedShared, expectedLevel) in expectedKemSizes)
        {
            try
            {
                using var kem = new Kem(name);
                
                var pubMatch = kem.PublicKeyLength == expectedPub;
                var secMatch = kem.SecretKeyLength == expectedSec;
                var cipherMatch = kem.CiphertextLength == expectedCipher;
                var sharedMatch = kem.SharedSecretLength == expectedShared;
                var levelMatch = kem.ClaimedNistLevel == expectedLevel;
                
                var allMatch = pubMatch && secMatch && cipherMatch && sharedMatch && levelMatch;
                var status = allMatch ? "✓ PASS" : "✗ FAIL";
                
                Console.WriteLine($"{name,-13} | {status,-6} | {kem.PublicKeyLength,7} | {kem.SecretKeyLength,7} | " +
                                $"{kem.CiphertextLength,6} | {kem.SharedSecretLength,6} | {kem.ClaimedNistLevel,5}");
                
                if (!allMatch)
                {
                    if (!pubMatch) Console.WriteLine($"    ✗ Public key: expected {expectedPub}, got {kem.PublicKeyLength}");
                    if (!secMatch) Console.WriteLine($"    ✗ Secret key: expected {expectedSec}, got {kem.SecretKeyLength}");
                    if (!cipherMatch) Console.WriteLine($"    ✗ Ciphertext: expected {expectedCipher}, got {kem.CiphertextLength}");
                    if (!sharedMatch) Console.WriteLine($"    ✗ Shared secret: expected {expectedShared}, got {kem.SharedSecretLength}");
                    if (!levelMatch) Console.WriteLine($"    ✗ Security level: expected {expectedLevel}, got {kem.ClaimedNistLevel}");
                }
            }
            catch (ArgumentException)
            {
                Console.WriteLine($"{name,-13} | SKIP   | (algorithm not available)");
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine($"{name,-13} | SKIP   | (algorithm not available)");
            }
        }
        Console.WriteLine();
        
        // NIST ML-DSA specifications  
        var expectedSigSizes = new[]
        {
            ("ML-DSA-44", PublicKey: 1312, SecretKey: 2560, MaxSignature: 2420, Level: 2),
            ("ML-DSA-65", PublicKey: 1952, SecretKey: 4032, MaxSignature: 3309, Level: 3),
            ("ML-DSA-87", PublicKey: 2592, SecretKey: 4896, MaxSignature: 4627, Level: 5)
        };
        
        Console.WriteLine("Signature Algorithm Validation:");
        Console.WriteLine("Algorithm     | Status | Pub Key | Sec Key | Max Sig | Level");
        Console.WriteLine("--------------|--------|---------|---------|---------|-------");
        
        foreach (var (name, expectedPub, expectedSec, expectedSig, expectedLevel) in expectedSigSizes)
        {
            try
            {
                using var sig = new Sig(name);
                
                var pubMatch = sig.PublicKeyLength == expectedPub;
                var secMatch = sig.SecretKeyLength == expectedSec;
                var sigMatch = sig.SignatureLength == expectedSig;
                var levelMatch = sig.ClaimedNistLevel == expectedLevel;
                
                var allMatch = pubMatch && secMatch && sigMatch && levelMatch;
                var status = allMatch ? "✓ PASS" : "✗ FAIL";
                
                Console.WriteLine($"{name,-13} | {status,-6} | {sig.PublicKeyLength,7} | {sig.SecretKeyLength,7} | " +
                                $"{sig.SignatureLength,7} | {sig.ClaimedNistLevel,5}");
                
                if (!allMatch)
                {
                    if (!pubMatch) Console.WriteLine($"    ✗ Public key: expected {expectedPub}, got {sig.PublicKeyLength}");
                    if (!secMatch) Console.WriteLine($"    ✗ Secret key: expected {expectedSec}, got {sig.SecretKeyLength}");
                    if (!sigMatch) Console.WriteLine($"    ✗ Max signature: expected {expectedSig}, got {sig.SignatureLength}");
                    if (!levelMatch) Console.WriteLine($"    ✗ Security level: expected {expectedLevel}, got {sig.ClaimedNistLevel}");
                }
            }
            catch (ArgumentException)
            {
                Console.WriteLine($"{name,-13} | SKIP   | (algorithm not available)");
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine($"{name,-13} | SKIP   | (algorithm not available)");
            }
        }
    }

    /// <summary>
    /// Example 2: Functional correctness validation.
    /// </summary>
    public static void FunctionalCorrectness()
    {
        Console.WriteLine("=== Functional Correctness Validation ===\n");
        
        Console.WriteLine("Testing KEM correctness (shared secrets must match):");
        
        var kemAlgorithms = new[] { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
        foreach (var algorithm in kemAlgorithms)
        {
            try
            {
                Console.Write($"  {algorithm,-13}: ");
                
                using var kem = new Kem(algorithm);
                var passed = 0;
                var total = 10;
                
                for (int i = 0; i < total; i++)
                {
                    var (publicKey, secretKey) = kem.GenerateKeyPair();
                    var (ciphertext, sharedSecret1) = kem.Encapsulate(publicKey);
                    var sharedSecret2 = kem.Decapsulate(ciphertext, secretKey);
                    
                    if (sharedSecret1.AsSpan().SequenceEqual(sharedSecret2))
                        passed++;
                }
                
                var status = passed == total ? "✓ PASS" : "✗ FAIL";
                Console.WriteLine($"{status} ({passed}/{total} tests passed)");
            }
            catch (ArgumentException)
            {
                Console.WriteLine("SKIP (not available)");
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine("SKIP (not available)");
            }
        }
        Console.WriteLine();
        
        Console.WriteLine("Testing Signature correctness (signatures must verify):");
        
        var sigAlgorithms = new[] { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
        var testMessage = Encoding.UTF8.GetBytes("Test message for signature validation");
        
        foreach (var algorithm in sigAlgorithms)
        {
            try
            {
                Console.Write($"  {algorithm,-13}: ");
                
                using var sig = new Sig(algorithm);
                var passed = 0;
                var total = 10;
                
                for (int i = 0; i < total; i++)
                {
                    var (publicKey, secretKey) = sig.GenerateKeyPair();
                    var signature = sig.Sign(testMessage, secretKey);
                    var isValid = sig.Verify(testMessage, signature, publicKey);
                    
                    if (isValid)
                        passed++;
                }
                
                var status = passed == total ? "✓ PASS" : "✗ FAIL";
                Console.WriteLine($"{status} ({passed}/{total} tests passed)");
            }
            catch (ArgumentException)
            {
                Console.WriteLine("SKIP (not available)");
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine("SKIP (not available)");
            }
        }
    }

    /// <summary>
    /// Example 3: Edge case and error condition testing.
    /// </summary>
    public static void EdgeCaseValidation()
    {
        Console.WriteLine("=== Edge Case Validation ===\n");
        
        Console.WriteLine("Testing error conditions and edge cases:");
        Console.WriteLine();
        
        // Test 1: Invalid algorithm names
        Console.WriteLine("1. Invalid algorithm names:");
        var invalidNames = new[] { "", "Invalid-Algo", "ML-KEM-999", "Classical-RSA" };
        
        foreach (var name in invalidNames)
        {
            try
            {
                using var kem = new Kem(name);
                Console.WriteLine($"   ✗ {name}: Should have failed!");
            }
            catch (ArgumentException)
            {
                Console.WriteLine($"   ✓ {name}: Correctly rejected");
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine($"   ✓ {name}: Correctly rejected");
            }
        }
        Console.WriteLine();
        
        // Test 2: Invalid key sizes
        Console.WriteLine("2. Invalid key sizes:");
        try
        {
            using var kem = new Kem("ML-KEM-768");
            
            // Test with wrong public key size
            var wrongPublicKey = new byte[100];
            try
            {
                kem.Encapsulate(wrongPublicKey);
                Console.WriteLine("   ✗ Wrong public key size: Should have failed!");
            }
            catch (ArgumentException)
            {
                Console.WriteLine("   ✓ Wrong public key size: Correctly rejected");
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine("   ✓ Wrong public key size: Correctly rejected");
            }
            
            // Test with wrong secret key size
            var (validPublicKey, _) = kem.GenerateKeyPair();
            var (validCiphertext, _) = kem.Encapsulate(validPublicKey);
            var wrongSecretKey = new byte[100];
            
            try
            {
                kem.Decapsulate(validCiphertext, wrongSecretKey);
                Console.WriteLine("   ✗ Wrong secret key size: Should have failed!");
            }
            catch (ArgumentException)
            {
                Console.WriteLine("   ✓ Wrong secret key size: Correctly rejected");
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine("   ✓ Wrong secret key size: Correctly rejected");
            }
        }
        catch (ArgumentException)
        {
            Console.WriteLine("   SKIP: ML-KEM-768 not available");
        }
        catch (InvalidOperationException)
        {
            Console.WriteLine("   SKIP: ML-KEM-768 not available");
        }
        Console.WriteLine();
        
        // Test 3: Empty/null inputs
        Console.WriteLine("3. Empty and null inputs:");
        try
        {
            using var sig = new Sig("ML-DSA-65");
            var (publicKey, secretKey) = sig.GenerateKeyPair();
            
            // Test with empty message
            var emptyMessage = Array.Empty<byte>();
            try
            {
                var emptySignature = sig.Sign(emptyMessage, secretKey);
                var isValid = sig.Verify(emptyMessage, emptySignature, publicKey);
                Console.WriteLine($"   ✓ Empty message: Handled correctly (valid: {isValid})");
            }
            catch (ArgumentException)
            {
                Console.WriteLine("   ✓ Empty message: Correctly rejected");
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine("   ✓ Empty message: Correctly rejected");
            }
            
            // Test signature tampering detection
            var testMessage = Encoding.UTF8.GetBytes("Original message");
            var signature = sig.Sign(testMessage, secretKey);
            
            // Tamper with signature
            if (signature.Length > 0)
            {
                signature[0] ^= 0x01; // Flip a bit
                var isTamperedValid = sig.Verify(testMessage, signature, publicKey);
                Console.WriteLine($"   ✓ Tampered signature: {(isTamperedValid ? "✗ Not detected!" : "✓ Correctly rejected")}");
            }
        }
        catch (ArgumentException)
        {
            Console.WriteLine("   SKIP: ML-DSA-65 not available");
        }
        catch (InvalidOperationException)
        {
            Console.WriteLine("   SKIP: ML-DSA-65 not available");
        }
    }

    /// <summary>
    /// Example 4: Performance consistency validation.
    /// </summary>
    public static void PerformanceValidation()
    {
        Console.WriteLine("=== Performance Consistency Validation ===\n");
        
        Console.WriteLine("Validating performance is within expected ranges:");
        Console.WriteLine("(Note: Actual performance varies by platform)");
        Console.WriteLine();
        
        var testIterations = 25; // Smaller test for quick validation
        
        // KEM performance validation
        Console.WriteLine("KEM Performance Validation:");
        Console.WriteLine("Algorithm     | Ops/sec | Status | Notes");
        Console.WriteLine("--------------|---------|--------|------------------");
        
        var kemAlgorithms = new[] { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
        foreach (var algorithm in kemAlgorithms)
        {
            try
            {
                using var kem = new Kem(algorithm);
                var (publicKey, secretKey) = kem.GenerateKeyPair();
                
                var sw = System.Diagnostics.Stopwatch.StartNew();
                for (int i = 0; i < testIterations; i++)
                {
                    var (ciphertext, _) = kem.Encapsulate(publicKey);
                    kem.Decapsulate(ciphertext, secretKey);
                }
                sw.Stop();
                
                var opsPerSec = testIterations / sw.Elapsed.TotalSeconds;
                
                // Reasonable performance thresholds (very conservative)
                var minExpectedOps = algorithm switch
                {
                    "ML-KEM-512" => 50,   // Should be faster
                    "ML-KEM-768" => 30,   // Balanced
                    "ML-KEM-1024" => 20,  // Slower but secure
                    _ => 10
                };
                
                var status = opsPerSec >= minExpectedOps ? "✓ PASS" : "⚠ SLOW";
                var note = opsPerSec >= minExpectedOps ? "Within range" : "Below threshold";
                
                Console.WriteLine($"{algorithm,-13} | {opsPerSec,7:F0} | {status,-6} | {note}");
            }
            catch (ArgumentException)
            {
                Console.WriteLine($"{algorithm,-13} | {"N/A",7} | {"SKIP",6} | Not available");
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine($"{algorithm,-13} | {"N/A",7} | {"SKIP",6} | Not available");
            }
        }
        Console.WriteLine();
        
        Console.WriteLine("Performance Notes:");
        Console.WriteLine("• Performance varies significantly by platform and CPU");
        Console.WriteLine("• These are conservative thresholds for basic validation");
        Console.WriteLine("• Focus on correctness first, optimize performance second");
        Console.WriteLine("• Use dedicated benchmarking tools for detailed analysis");
    }

    /// <summary>
    /// Runs all validation examples.
    /// </summary>
    public static void RunAllValidation()
    {
        var examples = new Action[]
        {
            AlgorithmConsistency,
            FunctionalCorrectness,
            EdgeCaseValidation,
            PerformanceValidation
        };

        foreach (var example in examples)
        {
            example();
            Console.WriteLine(new string('=', 70));
            Console.WriteLine();
        }
    }
}

#pragma warning restore S1192