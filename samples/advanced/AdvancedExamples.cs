using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using OpenForge.Cryptography.LibOqs.KEM;
using OpenForge.Cryptography.LibOqs.SIG;
using OpenForge.Cryptography.LibOqs.Core;

namespace OpenForge.Cryptography.LibOqs.Samples.Advanced;

/// <summary>
/// Advanced examples demonstrating complex post-quantum cryptography scenarios.
/// </summary>
internal static class AdvancedExamples
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    /// <summary>
    /// Example 1: Algorithm selection guidance and comparison.
    /// </summary>
    public static void AlgorithmSelection()
    {
        Console.WriteLine("=== Algorithm Selection Guidance ===\n");
        
        Console.WriteLine("NIST Standardized Algorithms (Recommended):");
        Console.WriteLine();
        
        // KEM algorithms comparison
        var kemOptions = new[]
        {
            new { Name = "ML-KEM-512", Security = "Level 1", PublicKey = 800, SecretKey = 1632, Ciphertext = 768, UseCase = "IoT, Mobile" },
            new { Name = "ML-KEM-768", Security = "Level 3", PublicKey = 1184, SecretKey = 2400, Ciphertext = 1088, UseCase = "General Purpose" },
            new { Name = "ML-KEM-1024", Security = "Level 5", PublicKey = 1568, SecretKey = 3168, Ciphertext = 1568, UseCase = "High Security" }
        };
        
        Console.WriteLine("Key Encapsulation Mechanisms (KEM):");
        Console.WriteLine("Algorithm   | Security | Pub Key | Sec Key | Cipher | Best For");
        Console.WriteLine("------------|----------|---------|---------|--------|------------------");
        
        foreach (var kem in kemOptions)
        {
            Console.WriteLine($"{kem.Name,-11} | {kem.Security,-8} | {kem.PublicKey,7} | {kem.SecretKey,7} | " +
                            $"{kem.Ciphertext,6} | {kem.UseCase}");
        }
        Console.WriteLine();
        
        // Signature algorithms comparison
        var sigOptions = new[]
        {
            new { Name = "ML-DSA-44", Security = "Level 2", PublicKey = 1312, SecretKey = 2560, Signature = 2420, UseCase = "High Performance" },
            new { Name = "ML-DSA-65", Security = "Level 3", PublicKey = 1952, SecretKey = 4032, Signature = 3309, UseCase = "Balanced" },
            new { Name = "ML-DSA-87", Security = "Level 5", PublicKey = 2592, SecretKey = 4896, Signature = 4627, UseCase = "Maximum Security" }
        };
        
        Console.WriteLine("Digital Signature Algorithms:");
        Console.WriteLine("Algorithm   | Security | Pub Key | Sec Key | Sig    | Best For");
        Console.WriteLine("------------|----------|---------|---------|--------|------------------");
        
        foreach (var sig in sigOptions)
        {
            Console.WriteLine($"{sig.Name,-11} | {sig.Security,-8} | {sig.PublicKey,7} | {sig.SecretKey,7} | " +
                            $"{sig.Signature,6} | {sig.UseCase}");
        }
        Console.WriteLine();
        
        Console.WriteLine("Selection Guidelines:");
        Console.WriteLine("📊 **Performance Priority**: ML-KEM-512 + ML-DSA-44");
        Console.WriteLine("   • Fastest operations, smallest keys");
        Console.WriteLine("   • Suitable for high-throughput systems");
        Console.WriteLine("   • Good for resource-constrained environments");
        Console.WriteLine();
        Console.WriteLine("⚖️  **Balanced Approach**: ML-KEM-768 + ML-DSA-65");
        Console.WriteLine("   • NIST security level 3 (192-bit classical security)");
        Console.WriteLine("   • Recommended for most enterprise applications");
        Console.WriteLine("   • Good performance/security tradeoff");
        Console.WriteLine();
        Console.WriteLine("🔒 **Maximum Security**: ML-KEM-1024 + ML-DSA-87");
        Console.WriteLine("   • Highest NIST security level (256-bit classical security)");
        Console.WriteLine("   • For long-term data protection");
        Console.WriteLine("   • Government and critical infrastructure");
        
        // Show deprecated algorithms
        Console.WriteLine();
        Console.WriteLine("⚠️  **Deprecated Algorithms** (DO NOT USE):");
        var deprecatedAlgorithms = new[]
        {
            "Rainbow-I-Classic", "Rainbow-III-Classic", "Rainbow-V-Classic",
            "SIDH-p434", "SIDH-p503", "SIDH-p610", "SIDH-p751",
            "SIKE-p434", "SIKE-p503", "SIKE-p610", "SIKE-p751"
        };
        
        foreach (var alg in deprecatedAlgorithms.Take(4))
        {
            Console.WriteLine($"   ✗ {alg} - Broken by cryptanalysis");
        }
        Console.WriteLine("   • Use NIST standardized ML-KEM/ML-DSA instead");
    }

    /// <summary>
    /// Example 2: Performance benchmarking and analysis.
    /// </summary>
    public static void PerformanceBenchmarking()
    {
        Console.WriteLine("=== Performance Benchmarking ===\n");
        
        Console.WriteLine("Comparing Classical vs Post-Quantum Performance");
        Console.WriteLine("(Note: Actual performance varies by platform)\n");
        
        // Platform info
        Console.WriteLine($"Platform: {GetOSDescription()} on {RuntimeInformation.ProcessArchitecture}");
        Console.WriteLine($"Processor Count: {Environment.ProcessorCount}");
        Console.WriteLine($".NET Version: {Environment.Version}");
        Console.WriteLine();
        
        // Test ML-DSA-65 performance
        using (var sig = new Sig("ML-DSA-65"))
        {
            var message = new byte[32];
            var (publicKey, secretKey) = sig.GenerateKeyPair();
            
            var testIterations = 50;
            
            // Measure signing
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < testIterations; i++)
            {
                sig.Sign(message, secretKey);
            }
            sw.Stop();
            var signOps = testIterations / sw.Elapsed.TotalSeconds;
            
            // Measure verification
            var testSig = sig.Sign(message, secretKey);
            sw.Restart();
            for (int i = 0; i < testIterations; i++)
            {
                sig.Verify(message, testSig, publicKey);
            }
            sw.Stop();
            var verifyOps = testIterations / sw.Elapsed.TotalSeconds;
            
            Console.WriteLine("🔬 Post-Quantum Performance (Live Test):");
            Console.WriteLine($"• ML-DSA-65 Sign:     ~{signOps:F0} ops/sec");
            Console.WriteLine($"• ML-DSA-65 Verify:   ~{verifyOps:F0} ops/sec");
        }
        
        // Test ML-KEM-768 performance
        using (var kem = new Kem("ML-KEM-768"))
        {
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            var testIterations = 50;
            
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < testIterations; i++)
            {
                var (ciphertext, _) = kem.Encapsulate(publicKey);
                kem.Decapsulate(ciphertext, secretKey);
            }
            sw.Stop();
            var kemOps = (testIterations * 2) / sw.Elapsed.TotalSeconds; // 2 ops per iteration
            
            Console.WriteLine($"• ML-KEM-768 KEM:     ~{kemOps:F0} ops/sec");
        }
        Console.WriteLine();
        
        Console.WriteLine("📈 Performance Impact Summary:");
        Console.WriteLine("• **Signing**: 2-10x slower than ECDSA but often faster than RSA-2048");
        Console.WriteLine("• **Verification**: 1-3x slower than ECDSA, usually faster than RSA");
        Console.WriteLine("• **Key Exchange**: 2-5x slower than ECDH but more predictable");
        Console.WriteLine();
        
        Console.WriteLine("🎯 Optimization Strategies:");
        Console.WriteLine("1. **Algorithm Choice**: ML-DSA-44 for performance-critical applications");
        Console.WriteLine("2. **Caching**: Reuse key pairs when possible");
        Console.WriteLine("3. **Batching**: Process multiple operations together");
        Console.WriteLine("4. **Hardware**: Utilize CPU-specific optimizations");
        Console.WriteLine("5. **Architecture**: Consider async operations for I/O bound scenarios");
    }

    /// <summary>
    /// Example 3: Cross-platform deployment and compatibility.
    /// </summary>
    public static void CrossPlatformDeployment()
    {
        Console.WriteLine("=== Cross-Platform Deployment ===\n");
        
        // Display current platform info
        Console.WriteLine("Current Platform:");
        Console.WriteLine($"  OS: {GetOSDescription()}");
        Console.WriteLine($"  Architecture: {RuntimeInformation.ProcessArchitecture}");
        Console.WriteLine($"  .NET Version: {Environment.Version}");
        Console.WriteLine($"  64-bit Process: {Environment.Is64BitProcess}");
        Console.WriteLine();

        // Test library initialization
        Console.WriteLine("LibOqs Initialization:");
        try
        {
            var version = OqsCore.GetVersion();
            Console.WriteLine($"  ✓ LibOqs Version: {version}");
        }
        catch (InvalidOperationException ex)
        {
            Console.WriteLine($"  ✗ Failed to initialize: {ex.Message}");
            return;
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"  ✗ Failed to initialize: {ex.Message}");
            return;
        }
        Console.WriteLine();

        // Test basic functionality to prove cross-platform compatibility
        Console.WriteLine("Cross-Platform Functionality Test:");
        try
        {
            using var kem = new Kem("ML-KEM-768");
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            var (ciphertext, sharedSecret1) = kem.Encapsulate(publicKey);
            var sharedSecret2 = kem.Decapsulate(ciphertext, secretKey);
            var match = sharedSecret1.AsSpan().SequenceEqual(sharedSecret2);
            
            Console.WriteLine($"  ✓ ML-KEM-768: Key sizes {publicKey.Length + secretKey.Length:N0} bytes, secrets match: {match}");
        }
        catch (InvalidOperationException ex)
        {
            Console.WriteLine($"  ✗ ML-KEM-768 failed: {ex.Message}");
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"  ✗ ML-KEM-768 failed: {ex.Message}");
        }
        
        var os = GetOSType();
        Console.WriteLine();
        Console.WriteLine($"Deployment Guidance for {os}:");
        
        switch (os)
        {
            case "Windows":
                Console.WriteLine("• Native library (liboqs.dll) automatically included");
                Console.WriteLine("• Supports Windows 10+ on x64 and ARM64");
                Console.WriteLine("• Example: dotnet publish -c Release -r win-x64");
                break;
                
            case "Linux":
                Console.WriteLine("• Supports glibc and musl (Alpine) distributions");
                Console.WriteLine("• Works in Docker containers and Kubernetes");
                Console.WriteLine("• Example: dotnet publish -c Release -r linux-x64");
                break;
                
            case "macOS":
                Console.WriteLine("• Native Apple Silicon (ARM64) support");
                Console.WriteLine("• Code signing may be required for distribution");
                Console.WriteLine("• Example: dotnet publish -c Release -r osx-arm64");
                break;
                
            default:
                Console.WriteLine("• Check documentation for platform requirements");
                break;
        }
        
        Console.WriteLine();
        Console.WriteLine("Universal Best Practices:");
        Console.WriteLine("• Always test on target platform before deployment");
        Console.WriteLine("• Use platform-specific publish profiles");
        Console.WriteLine("• Monitor memory usage for embedded/IoT scenarios");
        Console.WriteLine("• Consider containers for consistent deployment");
    }

    /// <summary>
    /// Example 4: Interoperability with other cryptographic libraries.
    /// </summary>
    public static void Interoperability()
    {
        Console.WriteLine("=== Interoperability Scenarios ===\n");
        
        using var kem = new Kem("ML-KEM-768");
        var (publicKey, secretKey) = kem.GenerateKeyPair();
        
        Console.WriteLine("Raw Key Material Compatibility:");
        Console.WriteLine($"  Public key: {publicKey.Length} bytes");
        Console.WriteLine($"  Secret key: {secretKey.Length} bytes");
        Console.WriteLine($"  Format: Raw binary (liboqs native format)");
        Console.WriteLine();
        
        // Demonstrate that keys work as expected
        var (ciphertext, sharedSecret1) = kem.Encapsulate(publicKey);
        var sharedSecret2 = kem.Decapsulate(ciphertext, secretKey);
        var match = sharedSecret1.AsSpan().SequenceEqual(sharedSecret2);
        
        Console.WriteLine("Validation:");
        Console.WriteLine($"  ✓ Encapsulation/Decapsulation: {(match ? "Success" : "Failed")}");
        Console.WriteLine($"  ✓ Shared secret: {sharedSecret1.Length} bytes");
        Console.WriteLine();
        
        Console.WriteLine("Cross-Implementation Compatibility:");
        Console.WriteLine("• **Raw Format**: Direct compatibility with liboqs C library");
        Console.WriteLine("• **Language Bindings**: Python oqs-python, Go liboqs, etc.");
        Console.WriteLine("• **Standards**: NIST FIPS 203 (ML-KEM) compliant");
        Console.WriteLine("• **Encoding**: Raw binary - no ASN.1/DER by default");
        Console.WriteLine();
        
        // Serialization examples
        Console.WriteLine("Serialization Options:");
        Console.WriteLine("1. **Raw Binary** (current):");
        Console.WriteLine($"   {Convert.ToHexString(publicKey)[..32]}...");
        Console.WriteLine("   ✓ Minimal overhead, direct liboqs compatibility");
        Console.WriteLine();
        
        Console.WriteLine("2. **Base64 Encoding**:");
        var publicKeyB64 = Convert.ToBase64String(publicKey);
        Console.WriteLine($"   {publicKeyB64[..32]}...");
        Console.WriteLine("   ✓ Text-safe, JSON/XML integration");
        Console.WriteLine();
        
        Console.WriteLine("3. **JSON Wrapper**:");
        var keyInfo = JsonSerializer.Serialize(new
        {
            algorithm = "ML-KEM-768",
            keyType = "public",
            keyData = Convert.ToBase64String(publicKey),
            length = publicKey.Length
        }, JsonOptions);
        Console.WriteLine($"   {keyInfo[..100]}...");
        Console.WriteLine("   ✓ Self-describing, metadata included");
        Console.WriteLine();
        
        Console.WriteLine("Integration Recommendations:");
        Console.WriteLine("• Use raw binary for direct liboqs compatibility");
        Console.WriteLine("• Add Base64 encoding for REST APIs and config files");
        Console.WriteLine("• Document algorithm versions clearly");
        Console.WriteLine("• Test with target systems before deployment");
    }

    /// <summary>
    /// Example 5: Migration strategies from classical to post-quantum cryptography.
    /// </summary>
    public static void MigrationStrategies()
    {
        Console.WriteLine("=== Migration Strategy Planning ===\n");
        
        Console.WriteLine("Step 1: Cryptographic Inventory");
        Console.WriteLine("Identify all current cryptographic usage in your systems.\n");
        
        // Simulate discovering existing cryptographic usage
        var cryptoInventory = new[]
        {
            new { Component = "Web API Authentication", Algorithm = "RSA-2048", Usage = "JWT Signing", Risk = "High", Priority = 1 },
            new { Component = "Database Encryption", Algorithm = "AES-256", Usage = "Data at Rest", Risk = "Low", Priority = 3 },
            new { Component = "TLS Connections", Algorithm = "ECDSA P-256", Usage = "Server Certificates", Risk = "High", Priority = 1 },
            new { Component = "File Signatures", Algorithm = "RSA-2048", Usage = "Code Signing", Risk = "Medium", Priority = 2 },
            new { Component = "VPN Tunnels", Algorithm = "ECDH P-256", Usage = "Key Exchange", Risk = "High", Priority = 1 },
            new { Component = "Email Security", Algorithm = "RSA-1024", Usage = "S/MIME", Risk = "Critical", Priority = 1 }
        };
        
        Console.WriteLine("Current Cryptographic Inventory:");
        Console.WriteLine("Component                | Algorithm    | Usage           | Risk     | Priority");
        Console.WriteLine("-------------------------|--------------|-----------------|----------|----------");
        
        foreach (var item in cryptoInventory)
        {
            Console.WriteLine($"{item.Component,-24} | {item.Algorithm,-12} | {item.Usage,-15} | {item.Risk,-8} | {item.Priority}");
        }
        Console.WriteLine();
        
        // Migration phases
        Console.WriteLine("Migration Timeline:");
        Console.WriteLine("📅 **Phase 1** (Months 1-6): Deploy hybrid signatures");
        Console.WriteLine("   • Implement both classical and PQ in parallel");
        Console.WriteLine("   • Start with non-critical systems for testing");
        Console.WriteLine();
        Console.WriteLine("📅 **Phase 2** (Months 6-12): Require PQ in new systems");
        Console.WriteLine("   • All new deployments use post-quantum algorithms");
        Console.WriteLine("   • Monitor performance and compatibility");
        Console.WriteLine();
        Console.WriteLine("📅 **Phase 3** (Months 12-18): Migrate existing systems");
        Console.WriteLine("   • Systematic replacement of classical algorithms");
        Console.WriteLine("   • Maintain rollback capabilities");
        Console.WriteLine();
        Console.WriteLine("📅 **Phase 4** (Months 18-24): Complete transition");
        Console.WriteLine("   • Deprecate classical algorithms");
        Console.WriteLine("   • Full post-quantum security");
        Console.WriteLine();
        
        // Demonstrate hybrid approach
        Console.WriteLine("Hybrid Implementation Example:");
        var message = Encoding.UTF8.GetBytes("Important document requiring hybrid protection");
        
        using var pqSig = new Sig("ML-DSA-44");
        var (pqPublicKey, pqSecretKey) = pqSig.GenerateKeyPair();
        var pqSignature = pqSig.Sign(message, pqSecretKey);
        var pqValid = pqSig.Verify(message, pqSignature, pqPublicKey);
        
        Console.WriteLine($"Post-Quantum Signature: {pqSignature.Length} bytes, Valid: {(pqValid ? "✓" : "✗")}");
        Console.WriteLine("Classical Signature: (simulated RSA signature), Valid: ✓");
        Console.WriteLine($"Hybrid Result: {(pqValid ? "✓ BOTH VALID" : "✗ VALIDATION FAILED")}");
        Console.WriteLine();
        
        Console.WriteLine("🎯 Best Practices:");
        Console.WriteLine("• Start small with non-critical systems");
        Console.WriteLine("• Monitor performance continuously");
        Console.WriteLine("• Plan for rollback scenarios");
        Console.WriteLine("• Test interoperability early");
        Console.WriteLine("• Document all changes thoroughly");
        Console.WriteLine("• Train teams on new algorithms");
    }

    /// <summary>
    /// Example 6: Advanced signature features and security practices.
    /// </summary>
    public static void AdvancedSignatureFeatures()
    {
        Console.WriteLine("=== Advanced Signature Features ===\n");
        
        Console.WriteLine("Demonstrating advanced signature techniques and security practices...\n");
        
        // Show available ML-DSA algorithms
        var supportedAlgorithms = Sig.GetSupportedAlgorithms()
            .Where(alg => alg.StartsWith("ML-DSA", StringComparison.Ordinal))
            .ToArray();
        
        Console.WriteLine("Available ML-DSA Algorithms:");
        Console.WriteLine("Algorithm     | Pub Key | Sec Key | Max Sig | Level | Status");
        Console.WriteLine("--------------|---------|---------|---------|-------|--------");
        
        string? testAlgorithm = null;
        foreach (var algorithm in supportedAlgorithms)
        {
            try
            {
                using var sig = new Sig(algorithm);
                Console.WriteLine($"{algorithm,-13} | {sig.PublicKeyLength,7} | {sig.SecretKeyLength,7} | {sig.SignatureLength,7} | {sig.ClaimedNistLevel,5} | Available");
                
                if (testAlgorithm == null)
                {
                    testAlgorithm = algorithm;
                }
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
        
        if (testAlgorithm != null)
        {
            Console.WriteLine($"📝 Advanced Signature Example using {testAlgorithm}:");
            
            using var sig = new Sig(testAlgorithm);
            var (publicKey, secretKey) = sig.GenerateKeyPair();
            
            // Demonstrate multiple signature operations
            var documents = new[]
            {
                "Contract Agreement v1.0"u8.ToArray(),
                "Financial Statement Q4 2024"u8.ToArray(),
                "Security Policy Update"u8.ToArray()
            };
            
            Console.WriteLine("   Signing multiple documents:");
            var signatures = new List<(byte[] doc, byte[] sig)>();
            
            foreach (var doc in documents)
            {
                var signature = sig.Sign(doc, secretKey);
                signatures.Add((doc, signature));
                
                var docText = Encoding.UTF8.GetString(doc);
                Console.WriteLine($"   • \"{docText}\": {signature.Length} bytes signature");
            }
            Console.WriteLine();
            
            // Batch verification
            Console.WriteLine("   Batch verification results:");
            var allValid = true;
            
            foreach (var (doc, signature) in signatures)
            {
                var isValid = sig.Verify(doc, signature, publicKey);
                var docText = Encoding.UTF8.GetString(doc);
                Console.WriteLine($"   • \"{docText}\": {(isValid ? "✓ Valid" : "✗ Invalid")}");
                
                if (!isValid) allValid = false;
            }
            
            Console.WriteLine($"   Batch result: {(allValid ? "✓ All signatures valid" : "✗ Some signatures invalid")}");
            Console.WriteLine();
            
            // Demonstrate signature uniqueness (signatures should be different even for same message)
            Console.WriteLine("   Signature uniqueness test:");
            var testMessage = "Test message for uniqueness"u8.ToArray();
            var sig1 = sig.Sign(testMessage, secretKey);
            var sig2 = sig.Sign(testMessage, secretKey);
            
            var signaturesMatch = sig1.AsSpan().SequenceEqual(sig2);
            Console.WriteLine($"   Same message, two signatures match: {(signaturesMatch ? "✗ Unexpected" : "✓ Expected (randomized)")}");
            Console.WriteLine($"   Signature 1: {sig1.Length} bytes");
            Console.WriteLine($"   Signature 2: {sig2.Length} bytes");
            Console.WriteLine($"   Both valid: {(sig.Verify(testMessage, sig1, publicKey) && sig.Verify(testMessage, sig2, publicKey) ? "✓ Yes" : "✗ No")}");
        }
        else
        {
            Console.WriteLine("⚠️  No ML-DSA algorithms found on this platform.");
            Console.WriteLine("ML-DSA algorithms provide NIST-standardized post-quantum signatures.");
        }
        
        Console.WriteLine();
        Console.WriteLine("🔐 Security Best Practices:");
        Console.WriteLine("• Use different key pairs for different purposes");
        Console.WriteLine("• Implement proper key lifecycle management");
        Console.WriteLine("• Validate all inputs before cryptographic operations");
        Console.WriteLine("• Monitor signature verification failures");
        Console.WriteLine("• Use secure random number generation for key generation");
        Console.WriteLine();
        
        Console.WriteLine("🎯 Performance Considerations:");
        Console.WriteLine("• ML-DSA-44: Fastest signing and verification");
        Console.WriteLine("• ML-DSA-65: Balanced performance and security");
        Console.WriteLine("• ML-DSA-87: Maximum security, slower operations");
        Console.WriteLine("• Batch operations when possible for better throughput");
        Console.WriteLine("• Cache public keys for repeated verification");
    }

    /// <summary>
    /// Runs all advanced examples.
    /// </summary>
    public static void RunAllExamples()
    {
        var examples = new Action[]
        {
            AlgorithmSelection,
            PerformanceBenchmarking,
            CrossPlatformDeployment,
            Interoperability,
            MigrationStrategies,
            AdvancedSignatureFeatures
        };

        foreach (var example in examples)
        {
            example();
            Console.WriteLine(new string('=', 70));
            Console.WriteLine();
        }
    }

    private static string GetOSDescription()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return $"Windows {Environment.OSVersion.Version}";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return "Linux";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return "macOS";
        return "Unknown OS";
    }

    private static string GetOSType()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return "Windows";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return "Linux";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return "macOS";
        return "Unknown";
    }
}