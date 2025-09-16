using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.KEM.Tests;

[Collection("LibOqs Collection")]
public sealed class DecapsulationTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void Decapsulate_WithValidInputs_ShouldRecoverSharedSecret()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, secretKey) = kem.GenerateKeyPair();
        var (ciphertext, originalSecret) = kem.Encapsulate(publicKey);

        var recoveredSecret = kem.Decapsulate(ciphertext, secretKey);

        recoveredSecret.Should().BeEquivalentTo(originalSecret);
        recoveredSecret.Length.Should().Be(kem.SharedSecretLength);
    }

    [Fact]
    public void Decapsulate_WithInvalidCiphertextSize_ShouldThrowArgumentException()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (_, secretKey) = kem.GenerateKeyPair();
        var wrongSizeCiphertext = new byte[kem.CiphertextLength + 1];
        RandomNumberGenerator.Fill(wrongSizeCiphertext);

        var action = () => kem.Decapsulate(wrongSizeCiphertext, secretKey);
        action.Should().Throw<ArgumentException>()
            .WithMessage("*ciphertext*");
    }

    [Fact]
    public void Decapsulate_WithEmptyCiphertext_ShouldThrowArgumentException()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (_, secretKey) = kem.GenerateKeyPair();
        var emptyCiphertext = Array.Empty<byte>();

        var action = () => kem.Decapsulate(emptyCiphertext, secretKey);
        action.Should().Throw<ArgumentException>()
            .WithMessage("*ciphertext*");
    }

    [Fact]
    public void Decapsulate_WithEmptySecretKey_ShouldThrowArgumentException()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, _) = kem.GenerateKeyPair();
        var (ciphertext, _) = kem.Encapsulate(publicKey);
        var emptySecretKey = Array.Empty<byte>();

        var action = () => kem.Decapsulate(ciphertext, emptySecretKey);
        action.Should().Throw<ArgumentException>()
            .WithMessage("*secret*");
    }

    [Fact]
    public void Decapsulate_WithInvalidSecretKeySize_ShouldThrowArgumentException()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, _) = kem.GenerateKeyPair();
        var (ciphertext, _) = kem.Encapsulate(publicKey);
        var wrongSizeSecretKey = new byte[kem.SecretKeyLength + 1];
        RandomNumberGenerator.Fill(wrongSizeSecretKey);

        var action = () => kem.Decapsulate(ciphertext, wrongSizeSecretKey);
        action.Should().Throw<ArgumentException>()
            .WithMessage("*secret*");
    }


    [Fact]
    public void Decapsulate_WithCorruptedCiphertext_ShouldProduceDifferentSecret()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, secretKey) = kem.GenerateKeyPair();
        var (ciphertext, originalSecret) = kem.Encapsulate(publicKey);

        var corruptedCiphertext = ciphertext.ToArray();
        corruptedCiphertext[0] ^= 0x01; // Flip one bit

        var corruptedSecret = kem.Decapsulate(corruptedCiphertext, secretKey);

        // The corrupted ciphertext should produce a different shared secret
        corruptedSecret.Should().NotBeEquivalentTo(originalSecret,
            "Corrupted ciphertext should not produce the same shared secret");
        corruptedSecret.Length.Should().Be(kem.SharedSecretLength);
    }

    [Fact]
    public void Decapsulate_WithWrongSecretKey_ShouldProduceDifferentSecret()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey1, _) = kem.GenerateKeyPair();
        var (_, secretKey2) = kem.GenerateKeyPair();
        var (ciphertext, originalSecret) = kem.Encapsulate(publicKey1);

        var wrongSecret = kem.Decapsulate(ciphertext, secretKey2);

        wrongSecret.Should().NotBeEquivalentTo(originalSecret,
            "Wrong secret key should not produce the same shared secret");
        wrongSecret.Length.Should().Be(kem.SharedSecretLength);
    }

    [Fact]
    public void Decapsulate_SameInputs_ShouldProduceSameResult()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, secretKey) = kem.GenerateKeyPair();
        var (ciphertext, _) = kem.Encapsulate(publicKey);

        var secret1 = kem.Decapsulate(ciphertext, secretKey);
        var secret2 = kem.Decapsulate(ciphertext, secretKey);

        secret1.Should().BeEquivalentTo(secret2,
            "Same inputs should always produce the same shared secret");
    }

    [Fact]
    public void Decapsulate_WithZeroCiphertext_ShouldStillProduce()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (_, secretKey) = kem.GenerateKeyPair();
        var zeroCiphertext = new byte[kem.CiphertextLength];

        var action = () => kem.Decapsulate(zeroCiphertext, secretKey);
        action.Should().NotThrow("Decapsulation should work with zero ciphertext");

        var result = kem.Decapsulate(zeroCiphertext, secretKey);
        result.Should().NotBeNull();
        result.Length.Should().Be(kem.SharedSecretLength);
    }

    [Fact]
    public void Decapsulate_AfterDispose_ShouldThrowObjectDisposedException()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        var kem = new Kem(algorithm);
        var (publicKey, secretKey) = kem.GenerateKeyPair();
        var (ciphertext, _) = kem.Encapsulate(publicKey);

        kem.Dispose();

        var action = () => kem.Decapsulate(ciphertext, secretKey);
        action.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Decapsulate_AllSupportedAlgorithms_ShouldWork()
    {
        var algorithms = Kem.GetSupportedAlgorithms();

        foreach (var algorithm in algorithms)
        {
            using var kem = new Kem(algorithm);
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            var (ciphertext, originalSecret) = kem.Encapsulate(publicKey);

            var action = () => kem.Decapsulate(ciphertext, secretKey);
            action.Should().NotThrow($"Decapsulation should work for {algorithm}");

            var recoveredSecret = kem.Decapsulate(ciphertext, secretKey);
            recoveredSecret.Should().BeEquivalentTo(originalSecret,
                $"{algorithm} should recover the correct shared secret");
        }
    }

    [Fact]
    public void Decapsulate_MultipleTimesWithSameInputs_ProducesSameResult()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, secretKey) = kem.GenerateKeyPair();
        var (ciphertext, _) = kem.Encapsulate(publicKey);

        const int iterations = 10;
        var secrets = new List<byte[]>();

        for (int i = 0; i < iterations; i++)
        {
            var secret = kem.Decapsulate(ciphertext, secretKey);
            secrets.Add(secret);
        }

        for (int i = 1; i < iterations; i++)
        {
            secrets[i].Should().BeEquivalentTo(secrets[0],
                "Decapsulation should be deterministic");
        }
    }

    [Fact]
    public void Decapsulate_RandomCorruption_ShouldNotCrash()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, secretKey) = kem.GenerateKeyPair();
        var (originalCiphertext, _) = kem.Encapsulate(publicKey);

        // Use deterministic corruption for reproducibility
        for (int attempt = 0; attempt < 10; attempt++)
        {
            var corruptedCiphertext = originalCiphertext.ToArray();

            // Deterministically corrupt some bytes based on attempt number
            for (int i = 0; i < Math.Min(5, corruptedCiphertext.Length); i++)
            {
                int position = (attempt * 7 + i * 3) % corruptedCiphertext.Length;
                corruptedCiphertext[position] = (byte)((attempt * 17 + i * 13) % 256);
            }

            var action = () => kem.Decapsulate(corruptedCiphertext, secretKey);
            action.Should().NotThrow($"Decapsulation should not crash with corrupted ciphertext (attempt {attempt})");

            var result = kem.Decapsulate(corruptedCiphertext, secretKey);
            result.Should().NotBeNull();
            result.Length.Should().Be(kem.SharedSecretLength);
        }
    }

    [Fact]
    public void Decapsulate_Performance_ShouldCompleteInReasonableTime()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);
        var (publicKey, secretKey) = kem.GenerateKeyPair();
        var (ciphertext, _) = kem.Encapsulate(publicKey);

        const int iterations = 100;
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        for (int i = 0; i < iterations; i++)
        {
            var _ = kem.Decapsulate(ciphertext, secretKey);
        }

        stopwatch.Stop();

        // Should complete 100 decapsulations in less than 10 seconds
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(10000,
            $"{algorithm} should perform {iterations} decapsulations in reasonable time");
    }

    [Fact]
    public void Decapsulate_CrossKeyValidation_ShouldFailGracefully()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        if (algorithms.Length < 2)
            return; // Skip if not enough algorithms

        var algorithm1 = algorithms[0];
        var algorithm2 = algorithms[1];

        using var kem1 = new Kem(algorithm1);
        using var kem2 = new Kem(algorithm2);

        var (publicKey1, secretKey1) = kem1.GenerateKeyPair();
        var (ciphertext1, _) = kem1.Encapsulate(publicKey1);

        // Try to use algorithm2's instance with algorithm1's data
        if (kem1.CiphertextLength == kem2.CiphertextLength &&
            kem1.SecretKeyLength == kem2.SecretKeyLength)
        {
            // If sizes match, operation should complete but produce different result
            var crossResult = kem2.Decapsulate(ciphertext1, secretKey1);
            crossResult.Should().NotBeNull();
        }
        else
        {
            // If sizes don't match, should throw ArgumentException
            var action = () => kem2.Decapsulate(ciphertext1, secretKey1);
            action.Should().Throw<ArgumentException>();
        }
    }

#pragma warning restore S1144
}