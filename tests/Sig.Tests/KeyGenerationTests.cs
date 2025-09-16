using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Core;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.SIG.Tests;

[Collection("LibOqs Collection")]
public sealed class KeyGenerationTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void GenerateKeyPair_ShouldReturnValidKeys()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        var (publicKey, secretKey) = sig.GenerateKeyPair();

        publicKey.Should().NotBeNull();
        secretKey.Should().NotBeNull();
        publicKey.Length.Should().Be(sig.PublicKeyLength);
        secretKey.Length.Should().Be(sig.SecretKeyLength);
    }

    [Fact]
    public void GenerateKeyPair_ShouldProduceUniqueKeys()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        const int keyPairCount = 10;
        var publicKeys = new List<byte[]>();
        var secretKeys = new List<byte[]>();

        for (int i = 0; i < keyPairCount; i++)
        {
            var (publicKey, secretKey) = sig.GenerateKeyPair();
            publicKeys.Add(publicKey);
            secretKeys.Add(secretKey);
        }

        publicKeys.Should().OnlyHaveUniqueItems();

        secretKeys.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void GenerateKeyPair_ShouldNotProduceAllZeroKeys()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        foreach (var algorithm in algorithms.Take(5)) // Test first 5 for performance
        {
            using var sig = new Sig(algorithm);
            var (publicKey, secretKey) = sig.GenerateKeyPair();

                publicKey.Should().NotBeEquivalentTo(new byte[publicKey.Length],
                $"{algorithm} public key should not be all zeros");
            secretKey.Should().NotBeEquivalentTo(new byte[secretKey.Length],
                $"{algorithm} secret key should not be all zeros");
        }
    }

    [Fact]
    public void GenerateKeyPair_ForAllAlgorithms_ShouldProduceValidKeySizes()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var sampleAlgorithms = algorithms.Take(10);

        foreach (var algorithm in sampleAlgorithms)
        {
            using var sig = new Sig(algorithm);
            var (publicKey, secretKey) = sig.GenerateKeyPair();

            publicKey.Length.Should().Be(sig.PublicKeyLength,
                $"{algorithm} public key should match expected length");
            secretKey.Length.Should().Be(sig.SecretKeyLength,
                $"{algorithm} secret key should match expected length");

            publicKey.Length.Should().BeGreaterThan(0,
                $"{algorithm} public key should have positive length");
            secretKey.Length.Should().BeGreaterThan(0,
                $"{algorithm} secret key should have positive length");

            publicKey.Length.Should().BeGreaterThanOrEqualTo(32,
                $"{algorithm} public key should be at least 32 bytes");
            secretKey.Length.Should().BeGreaterThanOrEqualTo(32,
                $"{algorithm} secret key should be at least 32 bytes");
        }
    }

    [Fact]
    public void GenerateKeyPair_ShouldBeConsistentWithProperties()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        const int iterations = 5;
        for (int i = 0; i < iterations; i++)
        {
            var (publicKey, secretKey) = sig.GenerateKeyPair();

            publicKey.Length.Should().Be(sig.PublicKeyLength,
                $"Iteration {i}: public key length should match property");
            secretKey.Length.Should().Be(sig.SecretKeyLength,
                $"Iteration {i}: secret key length should match property");
        }
    }

    [Fact]
    public void GenerateKeyPair_WithDisposedInstance_ShouldThrow()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        var sig = new Sig(algorithm);

        // Generate a key pair successfully first
        var (publicKey, secretKey) = sig.GenerateKeyPair();
        publicKey.Should().NotBeNull();
        secretKey.Should().NotBeNull();

        // Dispose the instance
        sig.Dispose();

        // Attempt to generate key pair with disposed instance
        var action = () => sig.GenerateKeyPair();
        action.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void KeyPair_ShouldWorkWithSigningVerification()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        foreach (var algorithm in algorithms.Take(5)) // Test first 5 for performance
        {
            using var sig = new Sig(algorithm);

            // Generate key pair
            var (publicKey, secretKey) = sig.GenerateKeyPair();

            // Use the keys for signing/verification
            var message = new byte[128];
            RandomNumberGenerator.Fill(message);

            var signature = sig.Sign(message, secretKey);
            var isValid = sig.Verify(message, signature, publicKey);

            isValid.Should().BeTrue(
                $"{algorithm} should correctly verify signature with generated keys");
        }
    }

    [Fact]
    public void KeyPair_CrossInstanceCompatibility()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];

        // Generate key pair with first instance
        byte[] publicKey;
        byte[] secretKey;
        using (var sig1 = new Sig(algorithm))
        {
            (publicKey, secretKey) = sig1.GenerateKeyPair();
        }

        // Use keys with different instances
        var message = new byte[256];
        RandomNumberGenerator.Fill(message);

        using var sig2 = new Sig(algorithm);
        using var sig3 = new Sig(algorithm);

        var signature = sig2.Sign(message, secretKey);
        var isValid = sig3.Verify(message, signature, publicKey);

        isValid.Should().BeTrue(
            "Keys should work across different instances of same algorithm");
    }

    [Fact]
    public void KeyPair_InvalidKeySizes_ShouldFailGracefully()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        // Create invalid keys (wrong sizes)
        var invalidPublicKey = new byte[sig.PublicKeyLength / 2]; // Too short
        var invalidSecretKey = new byte[sig.SecretKeyLength * 2]; // Too long
        RandomNumberGenerator.Fill(invalidPublicKey);
        RandomNumberGenerator.Fill(invalidSecretKey);

        var message = new byte[128];
        RandomNumberGenerator.Fill(message);

        // Signing with invalid secret key should fail
        var signAction = () => sig.Sign(message, invalidSecretKey);
        signAction.Should().Throw<ArgumentException>();

        // Generate valid signature for verification test
        var (_, validSecretKey) = sig.GenerateKeyPair();
        var validSignature = sig.Sign(message, validSecretKey);

        // Verification with invalid public key should fail
        var verifyAction = () => sig.Verify(message, validSignature, invalidPublicKey);
        verifyAction.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void KeyPair_ShouldHaveHighEntropy()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        const int keyPairCount = 10;
        var publicKeys = new List<byte[]>();
        var secretKeys = new List<byte[]>();

        for (int i = 0; i < keyPairCount; i++)
        {
            var (publicKey, secretKey) = sig.GenerateKeyPair();
            publicKeys.Add(publicKey);
            secretKeys.Add(secretKey);
        }

        // Calculate simple entropy check - count unique bytes in first 100 bytes
        foreach (var publicKey in publicKeys)
        {
            var sampleSize = Math.Min(100, publicKey.Length);
            var uniqueBytes = publicKey.Take(sampleSize).Distinct().Count();

            // Should have high byte diversity (at least 25% unique bytes in sample for public keys)
            uniqueBytes.Should().BeGreaterThan(sampleSize * 25 / 100,
                "Public key should have reasonable entropy");
        }

        foreach (var secretKey in secretKeys)
        {
            var sampleSize = Math.Min(100, secretKey.Length);
            var uniqueBytes = secretKey.Take(sampleSize).Distinct().Count();

            // Should have high byte diversity (at least 30% unique bytes in sample for secret keys)
            uniqueBytes.Should().BeGreaterThan(sampleSize * 30 / 100,
                "Secret key should have high entropy");
        }
    }

    [Theory]
    [InlineData(SignatureAlgorithms.ML_DSA_44)]
    [InlineData(SignatureAlgorithms.ML_DSA_65)]
    [InlineData(SignatureAlgorithms.ML_DSA_87)]
    [InlineData(SignatureAlgorithms.Dilithium2)]
    [InlineData(SignatureAlgorithms.Dilithium3)]
    [InlineData(SignatureAlgorithms.Dilithium5)]
    public void CommonAlgorithms_KeyPairGeneration(string algorithm)
    {
        if (!Sig.IsAlgorithmSupported(algorithm))
            return; // Skip if not supported in this build

        using var sig = new Sig(algorithm);

        // Generate multiple key pairs to verify consistency
        const int iterations = 3;
        for (int i = 0; i < iterations; i++)
        {
            var (publicKey, secretKey) = sig.GenerateKeyPair();

            publicKey.Should().NotBeNull();
            secretKey.Should().NotBeNull();
            publicKey.Length.Should().Be(sig.PublicKeyLength);
            secretKey.Length.Should().Be(sig.SecretKeyLength);

            // Test that keys work correctly
            var message = new byte[128];
            RandomNumberGenerator.Fill(message);

            var signature = sig.Sign(message, secretKey);
            var isValid = sig.Verify(message, signature, publicKey);
            isValid.Should().BeTrue();
        }
    }

    [Fact]
    public async Task KeyPairGeneration_ConcurrentOperations()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        const int taskCount = 5;
        const int operationsPerTask = 10;
        var tasks = new List<Task<List<(byte[] publicKey, byte[] secretKey)>>>();

        for (int t = 0; t < taskCount; t++)
        {
            tasks.Add(Task.Run(() =>
            {
                var results = new List<(byte[] publicKey, byte[] secretKey)>();
                for (int i = 0; i < operationsPerTask; i++)
                {
                    var keyPair = sig.GenerateKeyPair();
                    results.Add(keyPair);
                }
                return results;
            }, TestContext.Current.CancellationToken));
        }

        var allResults = await Task.WhenAll(tasks);

        // Verify all generated key pairs
        var allKeyPairs = allResults.SelectMany(r => r).ToList();
        allKeyPairs.Should().HaveCount(taskCount * operationsPerTask);

        // All key pairs should be valid
        foreach (var (publicKey, secretKey) in allKeyPairs)
        {
            publicKey.Should().NotBeNull();
            secretKey.Should().NotBeNull();
            publicKey.Length.Should().Be(sig.PublicKeyLength);
            secretKey.Length.Should().Be(sig.SecretKeyLength);
        }

        var allPublicKeys = allKeyPairs.Select(kp => kp.publicKey).ToList();
        allPublicKeys.Should().OnlyHaveUniqueItems();

        var allSecretKeys = allKeyPairs.Select(kp => kp.secretKey).ToList();
        allSecretKeys.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void KeyPair_SignatureCompatibility_AcrossDifferentMessageTypes()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        var (publicKey, secretKey) = sig.GenerateKeyPair();

        // Test various message types and sizes
        var testMessages = new List<byte[]>
        {
            Array.Empty<byte>(),                    // Empty message
            new byte[1],                            // Single byte
            new byte[16],                           // Small message
            new byte[64],                           // Medium message
            new byte[256],                          // Larger message
            new byte[1024],                         // Large message
            new byte[4096]                          // Very large message
        };

        // Fill non-empty messages with random data
        for (int i = 1; i < testMessages.Count; i++)
        {
            RandomNumberGenerator.Fill(testMessages[i]);
        }

        // Test that the same key pair works for all message types
        foreach (var message in testMessages)
        {
            var signature = sig.Sign(message, secretKey);
            signature.Should().NotBeNull(
                $"Should be able to sign message of length {message.Length}");

            var isValid = sig.Verify(message, signature, publicKey);
            isValid.Should().BeTrue(
                $"Should verify signature for message of length {message.Length}");
        }
    }

    [Fact]
    public void KeyPair_ShouldMaintainConsistentSizeAcrossGenerations()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        foreach (var algorithm in algorithms.Take(5)) // Test sample for performance
        {
            using var sig = new Sig(algorithm);

            const int iterations = 50;
            var publicKeySizes = new List<int>();
            var secretKeySizes = new List<int>();

            for (int i = 0; i < iterations; i++)
            {
                var (publicKey, secretKey) = sig.GenerateKeyPair();
                publicKeySizes.Add(publicKey.Length);
                secretKeySizes.Add(secretKey.Length);
            }

            // All public keys should have the same size
            publicKeySizes.Should().AllSatisfy(size => size.Should().Be(sig.PublicKeyLength),
                $"{algorithm} should generate consistent public key sizes");

            // All secret keys should have the same size
            secretKeySizes.Should().AllSatisfy(size => size.Should().Be(sig.SecretKeyLength),
                $"{algorithm} should generate consistent secret key sizes");
        }
    }

    [Fact]
    public void KeyPair_GeneratedKeysProperties_ShouldBeValidForSigning()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        // Generate a fresh key pair
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        // Keys should have expected properties
        publicKey.Should().NotBeNull();
        secretKey.Should().NotBeNull();
        publicKey.Length.Should().Be(sig.PublicKeyLength);
        secretKey.Length.Should().Be(sig.SecretKeyLength);

        // Keys should not be identical (this would indicate a serious bug)
        if (sig.PublicKeyLength == sig.SecretKeyLength)
        {
            publicKey.Should().NotBeEquivalentTo(secretKey,
                "Public and secret keys should be different even if same length");
        }

        // Test multiple signing operations with the same key pair
        const int signOperations = 20;
        var testMessage = new byte[128];
        RandomNumberGenerator.Fill(testMessage);

        var signatures = new List<byte[]>();
        for (int i = 0; i < signOperations; i++)
        {
            var signature = sig.Sign(testMessage, secretKey);
            signatures.Add(signature);

            var isValid = sig.Verify(testMessage, signature, publicKey);
            isValid.Should().BeTrue($"Signature {i} should be valid");
        }

        // For deterministic signature schemes, signatures should be identical
        // For probabilistic schemes, they might be different
        // We'll just verify they all validate correctly (already done above)
        signatures.Should().AllSatisfy(signature => signature.Should().NotBeNull());
    }

#pragma warning restore S1144
}