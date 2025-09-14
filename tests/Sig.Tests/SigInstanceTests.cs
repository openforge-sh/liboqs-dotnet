using System.Collections.Concurrent;
using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.SIG.Tests;

[Collection("LibOqs Collection")]
public sealed class SigInstanceTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void Constructor_WithValidAlgorithm_ShouldCreateInstance()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        sig.Should().NotBeNull();
        sig.AlgorithmName.Should().Be(algorithm);
        sig.PublicKeyLength.Should().BeGreaterThan(0);
        sig.SecretKeyLength.Should().BeGreaterThan(0);
        sig.SignatureLength.Should().BeGreaterThan(0);
        sig.ClaimedNistLevel.Should().BeInRange(1, 5);
    }

    [Fact]
    public void Constructor_WithNullAlgorithm_ShouldThrowArgumentException()
    {
        var action = () => new Sig(null!);
        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("algorithmName");
    }

    [Fact]
    public void Constructor_WithEmptyAlgorithm_ShouldThrowArgumentException()
    {
        var action = () => new Sig("");
        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Constructor_WithWhitespaceAlgorithm_ShouldThrowArgumentException()
    {
        var action = () => new Sig("   ");
        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Constructor_WithInvalidAlgorithm_ShouldThrowException()
    {
        var action = () => new Sig("NonExistentAlgorithm");
        action.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void Instance_Properties_ShouldBeConsistent()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        foreach (var algorithm in algorithms.Take(5))
        {
            using var sig = new Sig(algorithm);

            sig.AlgorithmName.Should().Be(algorithm);
            sig.PublicKeyLength.Should().BeGreaterThan(0);
            sig.SecretKeyLength.Should().BeGreaterThan(0);
            sig.SignatureLength.Should().BeGreaterThan(0);
            sig.ClaimedNistLevel.Should().BeInRange(1, 5);
        }
    }

    [Fact]
    public void Instance_MultipleCreations_ShouldHaveConsistentProperties()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];

        using var sig1 = new Sig(algorithm);
        using var sig2 = new Sig(algorithm);
        using var sig3 = new Sig(algorithm);

        sig2.AlgorithmName.Should().Be(sig1.AlgorithmName);
        sig2.PublicKeyLength.Should().Be(sig1.PublicKeyLength);
        sig2.SecretKeyLength.Should().Be(sig1.SecretKeyLength);
        sig2.SignatureLength.Should().Be(sig1.SignatureLength);
        sig2.ClaimedNistLevel.Should().Be(sig1.ClaimedNistLevel);
        sig2.IsEufCma.Should().Be(sig1.IsEufCma);

        sig3.AlgorithmName.Should().Be(sig1.AlgorithmName);
        sig3.PublicKeyLength.Should().Be(sig1.PublicKeyLength);
        sig3.SecretKeyLength.Should().Be(sig1.SecretKeyLength);
        sig3.SignatureLength.Should().Be(sig1.SignatureLength);
        sig3.ClaimedNistLevel.Should().Be(sig1.ClaimedNistLevel);
        sig3.IsEufCma.Should().Be(sig1.IsEufCma);
    }

    [Fact]
    public void Instance_GenerateKeyPair_ShouldProduceValidKeys()
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

        // Keys should not be all zeros
        publicKey.Should().NotBeEquivalentTo(new byte[publicKey.Length]);
        secretKey.Should().NotBeEquivalentTo(new byte[secretKey.Length]);
    }

    [Fact]
    public void Instance_GenerateKeyPair_MultipleInvocations_ShouldProduceDifferentKeys()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        const int keyPairCount = 5;
        var keyPairs = new List<(byte[] publicKey, byte[] secretKey)>();

        for (int i = 0; i < keyPairCount; i++)
        {
            var (publicKey, secretKey) = sig.GenerateKeyPair();
            keyPairs.Add((publicKey, secretKey));
        }

        // All public keys should be different
        for (int i = 0; i < keyPairCount - 1; i++)
        {
            for (int j = i + 1; j < keyPairCount; j++)
            {
                keyPairs[i].publicKey.Should().NotBeEquivalentTo(keyPairs[j].publicKey,
                    $"Public key {i} should be different from public key {j}");
                keyPairs[i].secretKey.Should().NotBeEquivalentTo(keyPairs[j].secretKey,
                    $"Secret key {i} should be different from secret key {j}");
            }
        }
    }

    [Fact]
    public void Instance_FullSignatureLifecycle_ShouldWork()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        // Generate key pair
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        // Create a test message
        var message = new byte[256];
        RandomNumberGenerator.Fill(message);

        // Sign
        var signature = sig.Sign(message, secretKey);
        signature.Should().NotBeNull();
        signature.Length.Should().BeLessThanOrEqualTo(sig.SignatureLength);

        // Verify
        var isValid = sig.Verify(message, signature, publicKey);
        isValid.Should().BeTrue();
    }

    [Fact]
    public void Instance_StateIsolation_BetweenOperations()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        const int operationCount = 10;
        var results = new List<(byte[] publicKey, byte[] secretKey, byte[] message, byte[] signature, bool verified)>();

        // Perform multiple independent operations
        for (int i = 0; i < operationCount; i++)
        {
            var (publicKey, secretKey) = sig.GenerateKeyPair();

            var message = new byte[128];
            RandomNumberGenerator.Fill(message);

            var signature = sig.Sign(message, secretKey);
            var verified = sig.Verify(message, signature, publicKey);

            results.Add((publicKey, secretKey, message, signature, verified));
        }

        // Verify all operations are independent and successful
        for (int i = 0; i < operationCount; i++)
        {
            var (publicKey, secretKey, _, signature, verified) = results[i];

            publicKey.Length.Should().Be(sig.PublicKeyLength, $"Operation {i} should have correct public key length");
            secretKey.Length.Should().Be(sig.SecretKeyLength, $"Operation {i} should have correct secret key length");
            signature.Length.Should().BeLessThanOrEqualTo(sig.SignatureLength, $"Operation {i} should have correct signature length");
            verified.Should().BeTrue($"Operation {i} should verify correctly");
        }

        // Verify all results are unique
        for (int i = 0; i < operationCount - 1; i++)
        {
            for (int j = i + 1; j < operationCount; j++)
            {
                results[i].signature.Should().NotBeEquivalentTo(results[j].signature,
                    $"Signature {i} should be different from signature {j}");
            }
        }
    }

    [Fact]
    public void Instance_Dispose_ShouldRenderInstanceUnusable()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        var sig = new Sig(algorithm);

        // Use the instance successfully
        var (publicKey, secretKey) = sig.GenerateKeyPair();
        var message = new byte[32];
        RandomNumberGenerator.Fill(message);
        var signature = sig.Sign(message, secretKey);

        // Dispose the instance
        sig.Dispose();

        // All operations should now throw ObjectDisposedException
        var generateAction = () => sig.GenerateKeyPair();
        generateAction.Should().Throw<ObjectDisposedException>();

        var signAction = () => sig.Sign(message, secretKey);
        signAction.Should().Throw<ObjectDisposedException>();

        var verifyAction = () => sig.Verify(message, signature, publicKey);
        verifyAction.Should().Throw<ObjectDisposedException>();

        // Properties should still be accessible (common .NET pattern)
        var algorithmName = sig.AlgorithmName;
        algorithmName.Should().Be(algorithm);
    }

    [Fact]
    public void Instance_MultipleDispose_ShouldNotThrow()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        var sig = new Sig(algorithm);

        // Multiple dispose calls should be safe
        sig.Dispose();
        var action = () => sig.Dispose();
        action.Should().NotThrow();

        // Additional dispose calls should also be safe
        sig.Dispose();
        sig.Dispose();
    }

    [Fact]
    public void Instance_UsingStatement_ShouldDisposeCorrectly()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        Sig? sigReference = null;

        // Create and use instance in using statement
        using (var sig = new Sig(algorithm))
        {
            sigReference = sig;
            var (publicKey, secretKey) = sig.GenerateKeyPair();
            var message = new byte[64];
            RandomNumberGenerator.Fill(message);
            var signature = sig.Sign(message, secretKey);
            var isValid = sig.Verify(message, signature, publicKey);

            isValid.Should().BeTrue();
        }

        // Instance should be disposed after using block
        sigReference.Should().NotBeNull();
        var action = () => sigReference!.GenerateKeyPair();
        action.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public async Task Instance_ConcurrentAccess_ShouldBeThreadSafe()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        const int threadCount = 5;
        const int operationsPerThread = 10;
        var tasks = new List<Task>();
        var results = new ConcurrentBag<(byte[] message, byte[] signature, bool verified)>();
        var exceptions = new ConcurrentBag<ObjectDisposedException>();

        var (sharedPublicKey, sharedSecretKey) = sig.GenerateKeyPair();

        for (int t = 0; t < threadCount; t++)
        {
            tasks.Add(Task.Run(() =>
            {
                try
                {
                    for (int op = 0; op < operationsPerThread; op++)
                    {
                        var message = new byte[64];
                        RandomNumberGenerator.Fill(message);

                        var signature = sig.Sign(message, sharedSecretKey);
                        var verified = sig.Verify(message, signature, sharedPublicKey);

                        results.Add((message, signature, verified));
                    }
                }
                catch (ObjectDisposedException ex)
                {
                    // Only catch ObjectDisposedException which could occur during concurrent access
                    exceptions.Add(ex);
                }
            }, TestContext.Current.CancellationToken));
        }

        await Task.WhenAll(tasks);

        // Should have no exceptions
        exceptions.Should().BeEmpty();

        // Should have all results
        results.Should().HaveCount(threadCount * operationsPerThread);

        // All results should be valid
        foreach (var (message, signature, verified) in results)
        {
            message.Should().NotBeNull();
            signature.Should().NotBeNull();
            verified.Should().BeTrue();
        }
    }

    [Fact]
    public void Instance_MemoryUsage_ShouldBeReasonable()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];

        // Measure memory before
        #pragma warning disable S1215
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var memoryBefore = GC.GetTotalMemory(false);

        // Create and use multiple instances
        const int instanceCount = 100;
        for (int i = 0; i < instanceCount; i++)
        {
            using var sig = new Sig(algorithm);
            var (publicKey, secretKey) = sig.GenerateKeyPair();
            var message = new byte[128];
            RandomNumberGenerator.Fill(message);
            var signature = sig.Sign(message, secretKey);
            sig.Verify(message, signature, publicKey);
        }

        // Force garbage collection
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var memoryAfter = GC.GetTotalMemory(false);
        #pragma warning restore S1215

        // Memory growth should be reasonable (less than 100MB for 100 instances)
        var memoryGrowth = memoryAfter - memoryBefore;
        memoryGrowth.Should().BeLessThan(100 * 1024 * 1024,
            $"Memory growth of {memoryGrowth:N0} bytes for {instanceCount} instances seems excessive");
    }

    [Fact]
    public void Instance_LongRunningOperations_ShouldMaintainStability()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        const int operationCount = 1000;
        var (publicKey, secretKey) = sig.GenerateKeyPair();
        var successCount = 0;

        for (int i = 0; i < operationCount; i++)
        {
            try
            {
                var message = new byte[64];
                RandomNumberGenerator.Fill(message);

                var signature = sig.Sign(message, secretKey);
                var isValid = sig.Verify(message, signature, publicKey);

                if (isValid)
                {
                    successCount++;
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Operation {i} failed: {ex.Message}", ex);
            }
        }

        successCount.Should().Be(operationCount, "All operations should succeed");
    }

#pragma warning restore S1144
}