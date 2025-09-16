using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.KEM.Tests;

[Collection("LibOqs Collection")]
public sealed class EncapsulationTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void Encapsulate_WithValidPublicKey_ShouldProduceCorrectSizes()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, _) = kem.GenerateKeyPair();
        var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);

        ciphertext.Length.Should().Be(kem.CiphertextLength);
        sharedSecret.Length.Should().Be(kem.SharedSecretLength);
    }

    [Fact]
    public void Encapsulate_WithInvalidPublicKeySize_ShouldThrowArgumentException()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var wrongSizePublicKey = new byte[kem.PublicKeyLength + 1];
        RandomNumberGenerator.Fill(wrongSizePublicKey);

        var action = () => kem.Encapsulate(wrongSizePublicKey);
        action.Should().Throw<ArgumentException>()
            .WithMessage("*public*");
    }

    [Fact]
    public void Encapsulate_WithEmptyPublicKey_ShouldThrowArgumentException()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var emptyPublicKey = Array.Empty<byte>();
        var action = () => kem.Encapsulate(emptyPublicKey);
        
        action.Should().Throw<ArgumentException>()
            .WithMessage("*public*");
    }

    [Fact]
    public void Encapsulate_WithNullPublicKey_ShouldThrowArgumentNullException()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var action = () => kem.Encapsulate(null!);
        
        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("publicKey");
    }

    [Fact]
    public void Encapsulate_WithZeroPublicKey_ShouldStillWork()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        // Even with all zeros, encapsulation should work (though insecure)
        var zeroPublicKey = new byte[kem.PublicKeyLength];
        var (ciphertext, sharedSecret) = kem.Encapsulate(zeroPublicKey);

        ciphertext.Should().NotBeNull();
        sharedSecret.Should().NotBeNull();
        ciphertext.Length.Should().Be(kem.CiphertextLength);
        sharedSecret.Length.Should().Be(kem.SharedSecretLength);
    }

    [Fact]
    public void Encapsulate_MultipleTimesWithSameKey_ProducesDifferentResults()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, _) = kem.GenerateKeyPair();

        const int iterations = 10;
        var ciphertexts = new List<byte[]>();
        var sharedSecrets = new List<byte[]>();

        for (int i = 0; i < iterations; i++)
        {
            var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
            ciphertexts.Add(ciphertext);
            sharedSecrets.Add(sharedSecret);
        }

        for (int i = 0; i < iterations - 1; i++)
        {
            for (int j = i + 1; j < iterations; j++)
            {
                ciphertexts[i].Should().NotBeEquivalentTo(ciphertexts[j],
                    "Each encapsulation should produce a unique ciphertext");
                sharedSecrets[i].Should().NotBeEquivalentTo(sharedSecrets[j],
                    "Each encapsulation should produce a unique shared secret");
            }
        }
    }

    [Fact]
    public void Encapsulate_WithDifferentPublicKeys_ProducesDifferentResults()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey1, _) = kem.GenerateKeyPair();
        var (publicKey2, _) = kem.GenerateKeyPair();

        var (ciphertext1, sharedSecret1) = kem.Encapsulate(publicKey1);
        var (ciphertext2, sharedSecret2) = kem.Encapsulate(publicKey2);

        ciphertext1.Should().NotBeEquivalentTo(ciphertext2);
        sharedSecret1.Should().NotBeEquivalentTo(sharedSecret2);
    }

    [Fact]
    public void Encapsulate_SharedSecretShouldBeRandom()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, _) = kem.GenerateKeyPair();
        var (_, sharedSecret) = kem.Encapsulate(publicKey);

        // Shared secret should not be all zeros
        sharedSecret.Should().NotBeEquivalentTo(new byte[sharedSecret.Length],
            "Shared secret should contain random data");

        // Check for sufficient entropy (at least half the bytes should be non-zero)
        var nonZeroCount = sharedSecret.Count(b => b != 0);
        nonZeroCount.Should().BeGreaterThan(sharedSecret.Length / 2,
            "Shared secret should have sufficient entropy");
    }

    [Fact]
    public void Encapsulate_CiphertextShouldBeRandom()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, _) = kem.GenerateKeyPair();
        var (ciphertext, _) = kem.Encapsulate(publicKey);

        // Ciphertext should not be all zeros
        ciphertext.Should().NotBeEquivalentTo(new byte[ciphertext.Length],
            "Ciphertext should contain random data");

        // Check for sufficient entropy
        var nonZeroCount = ciphertext.Count(b => b != 0);
        nonZeroCount.Should().BeGreaterThan(ciphertext.Length / 2,
            "Ciphertext should have sufficient entropy");
    }

    [Fact]
    public void Encapsulate_AfterDispose_ShouldThrowObjectDisposedException()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        var kem = new Kem(algorithm);
        var (publicKey, _) = kem.GenerateKeyPair();

        kem.Dispose();

        var action = () => kem.Encapsulate(publicKey);
        action.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Encapsulate_AllSupportedAlgorithms_ShouldWork()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();

            foreach (var algorithm in algorithms)
            {
                TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
                {
                    using var kem = new Kem(algorithm);
                    var (publicKey, _) = kem.GenerateKeyPair();

                    var action = () => kem.Encapsulate(publicKey);
                    action.Should().NotThrow($"Encapsulation should work for {algorithm}");

                    var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
                    ciphertext.Length.Should().Be(kem.CiphertextLength,
                        $"{algorithm} ciphertext should have correct length");
                    sharedSecret.Length.Should().Be(kem.SharedSecretLength,
                        $"{algorithm} shared secret should have correct length");
                });
            }
        });
    }

    [Fact]
    public void Encapsulate_WithCorruptedPublicKey_ShouldStillProduce()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            var algorithm = algorithms[0];
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {
                using var kem = new Kem(algorithm);

                var (publicKey, _) = kem.GenerateKeyPair();

                var corruptedPublicKey = publicKey.ToArray();
                for (int i = 0; i < Math.Min(10, corruptedPublicKey.Length); i++)
                {
                    corruptedPublicKey[i] ^= 0xFF;
                }

                // Encapsulation should still work (but decapsulation would fail)
                var action = () => kem.Encapsulate(corruptedPublicKey);
                action.Should().NotThrow("Encapsulation should work even with corrupted public key");

                var (ciphertext, sharedSecret) = kem.Encapsulate(corruptedPublicKey);
                ciphertext.Should().NotBeNull();
                sharedSecret.Should().NotBeNull();
            });
        });
    }

    [Fact]
    public void Encapsulate_Performance_ShouldCompleteInReasonableTime()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);
        var (publicKey, _) = kem.GenerateKeyPair();

        const int iterations = 100;
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        for (int i = 0; i < iterations; i++)
        {
            var (_, _) = kem.Encapsulate(publicKey);
        }

        stopwatch.Stop();

        // Should complete 100 encapsulations in less than 10 seconds
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(10000,
            $"{algorithm} should perform {iterations} encapsulations in reasonable time");
    }

#pragma warning restore S1144
}