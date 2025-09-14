using System.Collections.Concurrent;
using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.SIG.Tests;

[Collection("LibOqs Collection")]
public sealed class SigningAndVerificationTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void Sign_WithValidInputs_ShouldReturnSignature()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (_, secretKey) = sig.GenerateKeyPair();

        var message = new byte[128];
        RandomNumberGenerator.Fill(message);

        var signature = sig.Sign(message, secretKey);

        signature.Should().NotBeNull();
        signature.Should().NotBeEmpty();
        signature.Length.Should().BeLessThanOrEqualTo(sig.SignatureLength);
    }

    [Fact]
    public void Sign_WithNullMessage_ShouldThrowArgumentNullException()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (_, secretKey) = sig.GenerateKeyPair();

        var action = () => sig.Sign(null!, secretKey);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("message");
    }

    [Fact]
    public void Sign_WithNullSecretKey_ShouldThrowArgumentNullException()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var message = new byte[128];
        RandomNumberGenerator.Fill(message);

        var action = () => sig.Sign(message, null!);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("secretKey");
    }

    [Fact]
    public void Sign_WithEmptyMessage_ShouldWork()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var emptyMessage = Array.Empty<byte>();
        var signature = sig.Sign(emptyMessage, secretKey);

        signature.Should().NotBeNull();
        signature.Should().NotBeEmpty();

        var isValid = sig.Verify(emptyMessage, signature, publicKey);
        isValid.Should().BeTrue();
    }

    [Fact]
    public void Sign_WithInvalidSecretKeySize_ShouldThrow()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        var message = new byte[64];
        RandomNumberGenerator.Fill(message);

        var invalidSecretKey = new byte[sig.SecretKeyLength / 2];
        RandomNumberGenerator.Fill(invalidSecretKey);

        var action = () => sig.Sign(message, invalidSecretKey);
        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Sign_MultipleTimesWithSameInputs_ShouldProduceConsistentResults()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var message = new byte[128];
        RandomNumberGenerator.Fill(message);

        const int iterations = 10;
        var signatures = new List<byte[]>();

        for (int i = 0; i < iterations; i++)
        {
            var signature = sig.Sign(message, secretKey);
            signatures.Add(signature);
        }

        foreach (var signature in signatures)
        {
            var isValid = sig.Verify(message, signature, publicKey);
            isValid.Should().BeTrue("All signatures should be valid");
        }

        signatures.Should().AllSatisfy(s => s.Should().NotBeNull());
    }

    [Fact]
    public void Verify_WithValidSignature_ShouldReturnTrue()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var message = new byte[256];
        RandomNumberGenerator.Fill(message);

        var signature = sig.Sign(message, secretKey);
        var isValid = sig.Verify(message, signature, publicKey);

        isValid.Should().BeTrue();
    }

    [Fact]
    public void Verify_WithNullMessage_ShouldThrowArgumentNullException()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, _) = sig.GenerateKeyPair();
        var signature = new byte[100];

        var action = () => sig.Verify(null!, signature, publicKey);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("message");
    }

    [Fact]
    public void Verify_WithNullSignature_ShouldThrowArgumentNullException()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, _) = sig.GenerateKeyPair();
        var message = new byte[128];

        var action = () => sig.Verify(message, null!, publicKey);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("signature");
    }

    [Fact]
    public void Verify_WithNullPublicKey_ShouldThrowArgumentNullException()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var message = new byte[128];
        var signature = new byte[100];

        var action = () => sig.Verify(message, signature, null!);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("publicKey");
    }

    [Fact]
    public void Verify_WithModifiedMessage_ShouldReturnFalse()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var originalMessage = new byte[128];
        RandomNumberGenerator.Fill(originalMessage);
        var signature = sig.Sign(originalMessage, secretKey);

        // Modify the message
        var modifiedMessage = (byte[])originalMessage.Clone();
        modifiedMessage[0] ^= 0xFF;

        var isValid = sig.Verify(modifiedMessage, signature, publicKey);
        isValid.Should().BeFalse();
    }

    [Fact]
    public void Verify_WithModifiedSignature_ShouldReturnFalse()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var message = new byte[128];
        RandomNumberGenerator.Fill(message);
        var originalSignature = sig.Sign(message, secretKey);

        // Modify the signature
        var modifiedSignature = (byte[])originalSignature.Clone();
        modifiedSignature[0] ^= 0xFF;

        var isValid = sig.Verify(message, modifiedSignature, publicKey);
        isValid.Should().BeFalse();
    }

    [Fact]
    public void Verify_WithWrongPublicKey_ShouldReturnFalse()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        var (_, secretKey1) = sig.GenerateKeyPair();
        var (publicKey2, _) = sig.GenerateKeyPair();

        var message = new byte[128];
        RandomNumberGenerator.Fill(message);
        var signature = sig.Sign(message, secretKey1);

        var isValid = sig.Verify(message, signature, publicKey2);
        isValid.Should().BeFalse();
    }

    [Fact]
    public void Verify_WithInvalidPublicKeySize_ShouldThrow()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (_, secretKey) = sig.GenerateKeyPair();

        var message = new byte[64];
        RandomNumberGenerator.Fill(message);
        var signature = sig.Sign(message, secretKey);

        var invalidPublicKey = new byte[sig.PublicKeyLength / 2];
        RandomNumberGenerator.Fill(invalidPublicKey);

        var action = () => sig.Verify(message, signature, invalidPublicKey);
        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void SignAndVerify_VariousMessageSizes_ShouldWork()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var messageSizes = new[] { 0, 1, 16, 64, 256, 1024, 4096 };

        foreach (var messageSize in messageSizes)
        {
            var message = new byte[messageSize];
            if (messageSize > 0)
            {
                RandomNumberGenerator.Fill(message);
            }

            var signature = sig.Sign(message, secretKey);
            var isValid = sig.Verify(message, signature, publicKey);

            isValid.Should().BeTrue($"Should work with message size {messageSize}");
        }
    }

    [Fact]
    public void SignAndVerify_LargeMessages_ShouldWork()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        // Test with various large message sizes
        var largeSizes = new[] { 8192, 16384, 32768, 65536 };

        foreach (var size in largeSizes)
        {
            var largeMessage = new byte[size];
            RandomNumberGenerator.Fill(largeMessage);

            var signature = sig.Sign(largeMessage, secretKey);
            var isValid = sig.Verify(largeMessage, signature, publicKey);

            isValid.Should().BeTrue($"Should work with large message size {size}");
        }
    }

    [Fact]
    public void SignAndVerify_RepeatedMessages_ShouldWork()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        // Test with messages containing repeated patterns
        var repeatedMessages = new[]
        {
            Enumerable.Repeat((byte)0x00, 1000).ToArray(),
            [.. Enumerable.Repeat((byte)0xFF, 1000)],
            [.. Enumerable.Repeat((byte)0xAA, 1000)],
            [.. Enumerable.Range(0, 256).Select(i => (byte)i)], // 0-255 pattern
            [.. Enumerable.Range(0, 1000).Select(i => (byte)(i % 256))] // Repeating 0-255
        };

        foreach (var message in repeatedMessages)
        {
            var signature = sig.Sign(message, secretKey);
            var isValid = sig.Verify(message, signature, publicKey);

            isValid.Should().BeTrue("Should work with repeated pattern messages");
        }
    }

    [Fact]
    public void SignAndVerify_MultipleKeyPairs_ShouldBeIndependent()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        const int keyPairCount = 5;
        var keyPairs = new List<(byte[] publicKey, byte[] secretKey)>();

        // Generate multiple key pairs
        for (int i = 0; i < keyPairCount; i++)
        {
            keyPairs.Add(sig.GenerateKeyPair());
        }

        // Test that signatures from one key pair don't verify with another
        var message = new byte[128];
        RandomNumberGenerator.Fill(message);

        for (int i = 0; i < keyPairCount; i++)
        {
            var signature = sig.Sign(message, keyPairs[i].secretKey);

            // Should verify with correct public key
            var correctVerify = sig.Verify(message, signature, keyPairs[i].publicKey);
            correctVerify.Should().BeTrue($"Key pair {i} should verify its own signature");

            // Should NOT verify with other public keys
            for (int j = 0; j < keyPairCount; j++)
            {
                if (i != j)
                {
                    var wrongVerify = sig.Verify(message, signature, keyPairs[j].publicKey);
                    wrongVerify.Should().BeFalse($"Key pair {i} signature should not verify with key pair {j} public key");
                }
            }
        }
    }

    [Fact]
    public async Task SignAndVerify_ConcurrentOperations_ShouldBeThreadSafe()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        const int threadCount = 5;
        const int operationsPerThread = 20;
        var results = new ConcurrentBag<bool>();

        var tasks = new List<Task>();
        for (int t = 0; t < threadCount; t++)
        {
            tasks.Add(Task.Run(() =>
            {
                for (int op = 0; op < operationsPerThread; op++)
                {
                    var message = new byte[128];
                    RandomNumberGenerator.Fill(message);

                    var signature = sig.Sign(message, secretKey);
                    var isValid = sig.Verify(message, signature, publicKey);

                    results.Add(isValid);
                }
            }, TestContext.Current.CancellationToken));
        }

        await Task.WhenAll(tasks);

        // All operations should have succeeded
        results.Should().HaveCount(threadCount * operationsPerThread);
        results.Should().AllSatisfy(result => result.Should().BeTrue());
    }

    [Fact]
    public void SignAndVerify_WithDisposedInstance_ShouldThrow()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var message = new byte[64];
        RandomNumberGenerator.Fill(message);
        var signature = sig.Sign(message, secretKey);

        // Dispose the instance
        sig.Dispose();

        // All operations should throw ObjectDisposedException
        var signAction = () => sig.Sign(message, secretKey);
        signAction.Should().Throw<ObjectDisposedException>();

        var verifyAction = () => sig.Verify(message, signature, publicKey);
        verifyAction.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Signature_ConsistencyAcrossInstances()
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

        var message = new byte[256];
        RandomNumberGenerator.Fill(message);

        byte[] signature;
        using var sig2 = new Sig(algorithm);
        using var sig3 = new Sig(algorithm);

        // Sign with second instance
        signature = sig2.Sign(message, secretKey);

        // Verify with third instance
        var isValid = sig3.Verify(message, signature, publicKey);
        isValid.Should().BeTrue("Signature should be valid across different instances");
    }

    [Fact]
    public void SignatureLength_ShouldNotExceedDeclaredMaximum()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        foreach (var algorithm in algorithms.Take(5)) // Test sample for performance
        {
            using var sig = new Sig(algorithm);
            var (_, secretKey) = sig.GenerateKeyPair();

            // Test with various message sizes
            var messageSizes = new[] { 0, 1, 64, 256, 1024 };

            foreach (var size in messageSizes)
            {
                var message = new byte[size];
                if (size > 0)
                {
                    RandomNumberGenerator.Fill(message);
                }

                var signature = sig.Sign(message, secretKey);

                signature.Length.Should().BeLessThanOrEqualTo(sig.SignatureLength,
                    $"{algorithm} signature length should not exceed SignatureLength property for message size {size}");
            }
        }
    }

#pragma warning restore S1144
}