using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Core;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.KEM.Tests;

[Collection("LibOqs Collection")]
public sealed class KeyPairTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void GenerateKeyPair_ShouldReturnValidKeys()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, secretKey) = kem.GenerateKeyPair();

        publicKey.Should().NotBeNull();
        secretKey.Should().NotBeNull();
        publicKey.Length.Should().Be(kem.PublicKeyLength);
        secretKey.Length.Should().Be(kem.SecretKeyLength);
    }

    [Fact]
    public void GenerateKeyPair_ShouldProduceUniqueKeys()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        const int keyPairCount = 10;
        var publicKeys = new List<byte[]>();
        var secretKeys = new List<byte[]>();

        for (int i = 0; i < keyPairCount; i++)
        {
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            publicKeys.Add(publicKey);
            secretKeys.Add(secretKey);
        }

        publicKeys.Should().OnlyHaveUniqueItems();
        secretKeys.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void GenerateKeyPair_ShouldNotProduceAllZeroKeys()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        foreach (var algorithm in algorithms.Take(5)) // Test first 5 for performance
        {
            using var kem = new Kem(algorithm);
            var (publicKey, secretKey) = kem.GenerateKeyPair();

            // Keys should not be all zeros
            publicKey.Should().NotBeEquivalentTo(new byte[publicKey.Length],
                $"{algorithm} public key should not be all zeros");
            secretKey.Should().NotBeEquivalentTo(new byte[secretKey.Length],
                $"{algorithm} secret key should not be all zeros");
        }
    }

    [Fact]
    public void GenerateKeyPair_ForAllAlgorithms_ShouldProduceValidKeySizes()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var sampleAlgorithms = algorithms.Take(10); // Sample to avoid long test runtime

        foreach (var algorithm in sampleAlgorithms)
        {
            using var kem = new Kem(algorithm);
            var (publicKey, secretKey) = kem.GenerateKeyPair();

            publicKey.Length.Should().Be(kem.PublicKeyLength,
                $"{algorithm} public key should match expected length");
            secretKey.Length.Should().Be(kem.SecretKeyLength,
                $"{algorithm} secret key should match expected length");

            // Verify keys have reasonable sizes
            publicKey.Length.Should().BeGreaterThan(0,
                $"{algorithm} public key should have positive length");
            secretKey.Length.Should().BeGreaterThan(0,
                $"{algorithm} secret key should have positive length");

            // Most quantum-resistant algorithms have larger keys
            publicKey.Length.Should().BeGreaterThanOrEqualTo(32,
                $"{algorithm} public key should be at least 32 bytes");
            secretKey.Length.Should().BeGreaterThanOrEqualTo(32,
                $"{algorithm} secret key should be at least 32 bytes");
        }
    }

    [Fact]
    public void GenerateKeyPair_ShouldBeConsistentWithProperties()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        const int iterations = 5;
        for (int i = 0; i < iterations; i++)
        {
            var (publicKey, secretKey) = kem.GenerateKeyPair();

            publicKey.Length.Should().Be(kem.PublicKeyLength,
                $"Iteration {i}: public key length should match property");
            secretKey.Length.Should().Be(kem.SecretKeyLength,
                $"Iteration {i}: secret key length should match property");
        }
    }

    [Fact]
    public void GenerateKeyPair_WithDisposedInstance_ShouldThrow()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        var kem = new Kem(algorithm);

        // Generate a key pair successfully first
        var (publicKey, secretKey) = kem.GenerateKeyPair();
        publicKey.Should().NotBeNull();
        secretKey.Should().NotBeNull();

        // Dispose the instance
        kem.Dispose();

        // Attempt to generate key pair with disposed instance
        var action = () => kem.GenerateKeyPair();
        action.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void KeyPair_ShouldWorkWithEncapsulationDecapsulation()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        foreach (var algorithm in algorithms.Take(5)) // Test first 5 for performance
        {
            using var kem = new Kem(algorithm);

            var (publicKey, secretKey) = kem.GenerateKeyPair();

            // Use the keys for encapsulation/decapsulation
            var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
            var recoveredSecret = kem.Decapsulate(ciphertext, secretKey);

            recoveredSecret.Should().BeEquivalentTo(sharedSecret,
                $"{algorithm} should correctly recover shared secret");
        }
    }

    [Fact]
    public void KeyPair_CrossInstanceCompatibility()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];

        byte[] publicKey;
        byte[] secretKey;
        using (var kem1 = new Kem(algorithm))
        {
            (publicKey, secretKey) = kem1.GenerateKeyPair();
        }

        using var kem2 = new Kem(algorithm);
        var (ciphertext, sharedSecret) = kem2.Encapsulate(publicKey);

        using var kem3 = new Kem(algorithm);
        var recoveredSecret = kem3.Decapsulate(ciphertext, secretKey);
        recoveredSecret.Should().BeEquivalentTo(sharedSecret,
            "Keys should work across different instances of same algorithm");
    }

    [Fact]
    public void KeyPair_InvalidKeySizes_ShouldFailGracefully()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var invalidPublicKey = new byte[kem.PublicKeyLength / 2]; // Too short
        var invalidSecretKey = new byte[kem.SecretKeyLength * 2]; // Too long
        RandomNumberGenerator.Fill(invalidPublicKey);
        RandomNumberGenerator.Fill(invalidSecretKey);

        // Encapsulation with invalid public key should fail
        var encapsulateAction = () => kem.Encapsulate(invalidPublicKey);
        encapsulateAction.Should().Throw<ArgumentException>();

        // Generate valid ciphertext for decapsulation test
        var (validPublicKey, _) = kem.GenerateKeyPair();
        var (ciphertext, _) = kem.Encapsulate(validPublicKey);

        // Decapsulation with invalid secret key should fail
        var decapsulateAction = () => kem.Decapsulate(ciphertext, invalidSecretKey);
        decapsulateAction.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void KeyPair_ShouldHaveHighEntropy()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        const int keyPairCount = 10;
        var publicKeys = new List<byte[]>();
        var secretKeys = new List<byte[]>();

        for (int i = 0; i < keyPairCount; i++)
        {
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            publicKeys.Add(publicKey);
            secretKeys.Add(secretKey);
        }

        // Calculate simple entropy check - count unique bytes in first 100 bytes
        foreach (var publicKey in publicKeys)
        {
            var sampleSize = Math.Min(100, publicKey.Length);
            var uniqueBytes = publicKey.Take(sampleSize).Distinct().Count();

            // Should have high byte diversity (at least 30% unique bytes in sample)
            uniqueBytes.Should().BeGreaterThan(sampleSize * 30 / 100,
                "Public key should have high entropy");
        }

        foreach (var secretKey in secretKeys)
        {
            var sampleSize = Math.Min(100, secretKey.Length);
            var uniqueBytes = secretKey.Take(sampleSize).Distinct().Count();

            // Should have high byte diversity (at least 30% unique bytes in sample)
            uniqueBytes.Should().BeGreaterThan(sampleSize * 30 / 100,
                "Secret key should have high entropy");
        }
    }

    [Theory]
    [InlineData(KemAlgorithms.ML_KEM_512)]
    [InlineData(KemAlgorithms.ML_KEM_768)]
    [InlineData(KemAlgorithms.ML_KEM_1024)]
    public void NISTStandardizedAlgorithms_KeyPairGeneration(string algorithm)
    {
        if (!Kem.IsAlgorithmSupported(algorithm))
            return; // Skip if not supported in this build

        using var kem = new Kem(algorithm);

        const int iterations = 3;
        for (int i = 0; i < iterations; i++)
        {
            var (publicKey, secretKey) = kem.GenerateKeyPair();

            publicKey.Should().NotBeNull();
            secretKey.Should().NotBeNull();
            publicKey.Length.Should().Be(kem.PublicKeyLength);
            secretKey.Length.Should().Be(kem.SecretKeyLength);

            // Test that keys work correctly
            var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
            var recoveredSecret = kem.Decapsulate(ciphertext, secretKey);
            recoveredSecret.Should().BeEquivalentTo(sharedSecret);
        }
    }

    [Fact]
    public async Task KeyPairGeneration_ConcurrentOperations()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

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
                    var keyPair = kem.GenerateKeyPair();
                    results.Add(keyPair);
                }
                return results;
            }, TestContext.Current.CancellationToken));
        }

        var allResults = await Task.WhenAll(tasks);

        var allKeyPairs = allResults.SelectMany(r => r).ToList();
        allKeyPairs.Should().HaveCount(taskCount * operationsPerTask);

        foreach (var (publicKey, secretKey) in allKeyPairs)
        {
            publicKey.Should().NotBeNull();
            secretKey.Should().NotBeNull();
            publicKey.Length.Should().Be(kem.PublicKeyLength);
            secretKey.Length.Should().Be(kem.SecretKeyLength);
        }

        var allPublicKeys = allKeyPairs.Select(kp => kp.publicKey).ToList();
        allPublicKeys.Should().OnlyHaveUniqueItems();
    }

#pragma warning restore S1144
}