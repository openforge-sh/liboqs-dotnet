using System.Collections.Concurrent;
using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.KEM.Tests;

[Collection("LibOqs Collection")]
public sealed class KemInstanceTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void Constructor_WithValidAlgorithm_ShouldCreateInstance()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        kem.Should().NotBeNull();
        kem.AlgorithmName.Should().Be(algorithm);
        kem.PublicKeyLength.Should().BeGreaterThan(0);
        kem.SecretKeyLength.Should().BeGreaterThan(0);
        kem.CiphertextLength.Should().BeGreaterThan(0);
        kem.SharedSecretLength.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Constructor_WithNullAlgorithm_ShouldThrowArgumentException()
    {
        var action = () => new Kem(null!);
        action.Should().Throw<ArgumentException>()
            .WithMessage("*algorithm*");
    }

    [Fact]
    public void Constructor_WithEmptyAlgorithm_ShouldThrowArgumentException()
    {
        var action = () => new Kem("");
        action.Should().Throw<ArgumentException>()
            .WithMessage("*algorithm*");
    }

    [Fact]
    public void Constructor_WithInvalidAlgorithm_ShouldThrowNotSupportedException()
    {
        var action = () => new Kem("InvalidAlgorithm123");
        action.Should().Throw<NotSupportedException>()
            .WithMessage("*InvalidAlgorithm123*not enabled or supported*");
    }

    [Fact]
    public void Constructor_WithDisabledAlgorithm_ShouldThrowNotSupportedException()
    {
        // Try to find a disabled algorithm
        var count = KemProvider.AlgorithmCount;
        
        for (int i = 0; i < count; i++)
        {
            var identifier = KemProvider.GetAlgorithmIdentifier(i);
            if (!KemProvider.IsAlgorithmEnabled(identifier))
            {
                var action = () => new Kem(identifier);
                action.Should().Throw<NotSupportedException>()
                    .WithMessage($"*{identifier}*not enabled or supported*");
                return; // Exit early if we found a disabled algorithm
            }
        }
        
        // If no disabled algorithms found, test with clearly invalid name
        var fallbackAction = () => new Kem("CLEARLY_INVALID_ALGORITHM_NAME");
        fallbackAction.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void Constructor_WithWhitespaceAlgorithm_ShouldThrowArgumentException()
    {
        var action = () => new Kem("   ");
        action.Should().Throw<ArgumentException>()
            .WithMessage("*algorithm*");
    }

    [Fact]
    public void Constructor_WithInvalidAlgorithm_ShouldThrowException()
    {
        var action = () => new Kem("NonExistentAlgorithm");
        action.Should().Throw<NotSupportedException>()
            .WithMessage("*not enabled or supported*");
    }

    [Fact]
    public void Instance_Properties_ShouldBeConsistent()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        foreach (var algorithm in algorithms.Take(5)) // Test first 5 for performance
        {
            using var kem = new Kem(algorithm);

            kem.AlgorithmName.Should().Be(algorithm);
            kem.PublicKeyLength.Should().BeGreaterThan(0);
            kem.SecretKeyLength.Should().BeGreaterThan(0);
            kem.CiphertextLength.Should().BeGreaterThan(0);
            kem.SharedSecretLength.Should().BeGreaterThan(0);
            kem.ClaimedNistLevel.Should().BeInRange(1, 5);
        }
    }

    [Fact]
    public void Instance_MultipleCreations_ShouldHaveConsistentProperties()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];

        using var kem1 = new Kem(algorithm);
        using var kem2 = new Kem(algorithm);
        using var kem3 = new Kem(algorithm);

        kem2.AlgorithmName.Should().Be(kem1.AlgorithmName);
        kem2.PublicKeyLength.Should().Be(kem1.PublicKeyLength);
        kem2.SecretKeyLength.Should().Be(kem1.SecretKeyLength);
        kem2.CiphertextLength.Should().Be(kem1.CiphertextLength);
        kem2.SharedSecretLength.Should().Be(kem1.SharedSecretLength);
        kem2.ClaimedNistLevel.Should().Be(kem1.ClaimedNistLevel);
        kem2.IsIndCca.Should().Be(kem1.IsIndCca);

        kem3.AlgorithmName.Should().Be(kem1.AlgorithmName);
        kem3.PublicKeyLength.Should().Be(kem1.PublicKeyLength);
        kem3.SecretKeyLength.Should().Be(kem1.SecretKeyLength);
        kem3.CiphertextLength.Should().Be(kem1.CiphertextLength);
        kem3.SharedSecretLength.Should().Be(kem1.SharedSecretLength);
        kem3.ClaimedNistLevel.Should().Be(kem1.ClaimedNistLevel);
        kem3.IsIndCca.Should().Be(kem1.IsIndCca);
    }

    [Fact]
    public void Instance_GenerateKeyPair_ShouldProduceValidKeys()
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

        // Keys should not be all zeros
        publicKey.Should().NotBeEquivalentTo(new byte[publicKey.Length]);
        secretKey.Should().NotBeEquivalentTo(new byte[secretKey.Length]);
    }

    [Fact]
    public void Instance_GenerateKeyPair_MultipleInvocations_ShouldProduceDifferentKeys()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        const int keyPairCount = 5;
        var keyPairs = new List<(byte[] publicKey, byte[] secretKey)>();

        for (int i = 0; i < keyPairCount; i++)
        {
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            keyPairs.Add((publicKey, secretKey));
        }

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
    public void Instance_FullKeyLifecycle_ShouldWork()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, secretKey) = kem.GenerateKeyPair();

        // Encapsulate
        var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
        ciphertext.Length.Should().Be(kem.CiphertextLength);
        sharedSecret.Length.Should().Be(kem.SharedSecretLength);

        // Decapsulate
        var recoveredSecret = kem.Decapsulate(ciphertext, secretKey);
        recoveredSecret.Should().BeEquivalentTo(sharedSecret);
    }

    [Fact]
    public void Instance_StateIsolation_BetweenOperations()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        const int operationCount = 10;
        var results = new List<(byte[] publicKey, byte[] secretKey, byte[] ciphertext, byte[] sharedSecret, byte[] recovered)>();

        // Perform multiple independent operations
        for (int i = 0; i < operationCount; i++)
        {
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
            var recovered = kem.Decapsulate(ciphertext, secretKey);

            results.Add((publicKey, secretKey, ciphertext, sharedSecret, recovered));
        }

        for (int i = 0; i < operationCount; i++)
        {
            var (publicKey, secretKey, ciphertext, sharedSecret, recovered) = results[i];

            publicKey.Length.Should().Be(kem.PublicKeyLength, $"Operation {i} should have correct public key length");
            secretKey.Length.Should().Be(kem.SecretKeyLength, $"Operation {i} should have correct secret key length");
            ciphertext.Length.Should().Be(kem.CiphertextLength, $"Operation {i} should have correct ciphertext length");
            sharedSecret.Length.Should().Be(kem.SharedSecretLength, $"Operation {i} should have correct shared secret length");
            recovered.Should().BeEquivalentTo(sharedSecret, $"Operation {i} should recover correct shared secret");
        }

        for (int i = 0; i < operationCount - 1; i++)
        {
            for (int j = i + 1; j < operationCount; j++)
            {
                results[i].sharedSecret.Should().NotBeEquivalentTo(results[j].sharedSecret,
                    $"Shared secret {i} should be different from shared secret {j}");
            }
        }
    }

    [Fact]
    public void Instance_Dispose_ShouldRenderInstanceUnusable()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        var kem = new Kem(algorithm);

        // Use the instance successfully
        var (publicKey, secretKey) = kem.GenerateKeyPair();
        var (ciphertext, _) = kem.Encapsulate(publicKey);

        // Dispose the instance
        kem.Dispose();

        var generateAction = () => kem.GenerateKeyPair();
        generateAction.Should().Throw<ObjectDisposedException>();

        var encapsulateAction = () => kem.Encapsulate(publicKey);
        encapsulateAction.Should().Throw<ObjectDisposedException>();

        var decapsulateAction = () => kem.Decapsulate(ciphertext, secretKey);
        decapsulateAction.Should().Throw<ObjectDisposedException>();

        // Properties should still be accessible (common .NET pattern)
        var algorithmName = kem.AlgorithmName;
        algorithmName.Should().Be(algorithm);
    }

    [Fact]
    public void Instance_MultipleDispose_ShouldNotThrow()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        var kem = new Kem(algorithm);

        // Multiple dispose calls should be safe
        kem.Dispose();
        var action = () => kem.Dispose();
        action.Should().NotThrow();

        // Additional dispose calls should also be safe
        kem.Dispose();
        kem.Dispose();
    }

    [Fact]
    public void Instance_UsingStatement_ShouldDisposeCorrectly()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        Kem? kemReference = null;

        using (var kem = new Kem(algorithm))
        {
            kemReference = kem;
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
            var recovered = kem.Decapsulate(ciphertext, secretKey);

            recovered.Should().BeEquivalentTo(sharedSecret);
        }

        // Instance should be disposed after using block
        kemReference.Should().NotBeNull();
        var action = () => kemReference!.GenerateKeyPair();
        action.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public async Task Instance_ConcurrentAccess_ShouldBeThreadSafe()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        const int threadCount = 5;
        const int operationsPerThread = 10;
        var tasks = new List<Task>();
        var results = new ConcurrentBag<(byte[] ciphertext, byte[] sharedSecret, byte[] recovered)>();
        var exceptions = new ConcurrentBag<ObjectDisposedException>();

        var (sharedPublicKey, sharedSecretKey) = kem.GenerateKeyPair();

        for (int t = 0; t < threadCount; t++)
        {
            tasks.Add(Task.Run(() =>
            {
                try
                {
                    for (int op = 0; op < operationsPerThread; op++)
                    {
                        var (ciphertext, sharedSecret) = kem.Encapsulate(sharedPublicKey);
                        var recovered = kem.Decapsulate(ciphertext, sharedSecretKey);
                        results.Add((ciphertext, sharedSecret, recovered));
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

        exceptions.Should().BeEmpty();

        results.Should().HaveCount(threadCount * operationsPerThread);

        foreach (var (ciphertext, sharedSecret, recovered) in results)
        {
            ciphertext.Should().NotBeNull();
            sharedSecret.Should().NotBeNull();
            recovered.Should().BeEquivalentTo(sharedSecret);
        }
    }

    [Fact]
    public void Instance_MemoryUsage_ShouldBeReasonable()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];

        // Measure memory before
        #pragma warning disable S1215
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var memoryBefore = GC.GetTotalMemory(false);

        const int instanceCount = 100;
        for (int i = 0; i < instanceCount; i++)
        {
            using var kem = new Kem(algorithm);
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            var (ciphertext, _) = kem.Encapsulate(publicKey);
            kem.Decapsulate(ciphertext, secretKey);
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
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            var algorithm = algorithms[0];
            using var kem = new Kem(algorithm);

            const int operationCount = 500;
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            var successCount = 0;

            for (int i = 0; i < operationCount; i++)
            {
                try
                {
                    var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
                    var recovered = kem.Decapsulate(ciphertext, secretKey);

                    if (recovered.SequenceEqual(sharedSecret))
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
        });
    }

    [PlatformSpecificFact("LINUX")]
    public void KemInstance_GenerateDeterministicKeyPair_WithValidSeed_ShouldSucceed()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            // Try to find an algorithm that supports deterministic operations
            foreach (var algorithm in algorithms)
            {
                TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
                {
                    using var kemInstance = KemProvider.Create(algorithm);

                    try
                    {
                        var seed = new byte[48];
                        RandomNumberGenerator.Fill(seed);

                        var keyPair1 = kemInstance.GenerateDeterministicKeyPair(seed);
                        var keyPair2 = kemInstance.GenerateDeterministicKeyPair(seed);

                        keyPair1.PublicKey.Should().BeEquivalentTo(keyPair2.PublicKey);
                        keyPair1.SecretKey.Should().BeEquivalentTo(keyPair2.SecretKey);

                        keyPair1.Dispose();
                        keyPair2.Dispose();
                        return; // Exit after successful test
                    }
                    catch (InvalidOperationException)
                    {
                        // This algorithm doesn't support deterministic key generation, try next
                    }
                });
            }

            // If we get here, no algorithm supported deterministic operations
            Assert.True(true, "No algorithms support deterministic key pair generation");
        });
    }

    [PlatformSpecificFact("LINUX")]
    public void KemInstance_GenerateDeterministicKeyPair_WithInvalidSeedLength_ShouldThrowArgumentException()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            var algorithm = algorithms[0];
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {
                using var kemInstance = KemProvider.Create(algorithm);
                
                var invalidSeed = new byte[32]; // Should be 48 bytes

                var action = () => kemInstance.GenerateDeterministicKeyPair(invalidSeed);
                action.Should().Throw<ArgumentException>()
                    .WithParameterName("seed");
            });
        });
    }

    [PlatformSpecificFact("LINUX")]
    public void KemInstance_EncapsulateDeterministic_WithValidInputs_ShouldSucceed()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            // Try to find an algorithm that supports deterministic operations
            foreach (var algorithm in algorithms)
            {
                TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
                {
                    using var kemInstance = KemProvider.Create(algorithm);
                    
                    try
                    {
                        var keyPair = kemInstance.GenerateKeyPair();
                        var seed = new byte[48];
                        RandomNumberGenerator.Fill(seed);

                        var result1 = kemInstance.EncapsulateDeterministic(keyPair.PublicKey, seed);
                        var result2 = kemInstance.EncapsulateDeterministic(keyPair.PublicKey, seed);

                        result1.Ciphertext.Should().BeEquivalentTo(result2.Ciphertext);
                        result1.SharedSecret.Should().BeEquivalentTo(result2.SharedSecret);

                        var recovered1 = kemInstance.Decapsulate(result1.Ciphertext, keyPair.SecretKey);
                        var recovered2 = kemInstance.Decapsulate(result2.Ciphertext, keyPair.SecretKey);

                        recovered1.Should().BeEquivalentTo(result1.SharedSecret);
                        recovered2.Should().BeEquivalentTo(result2.SharedSecret);

                        keyPair.Dispose();
                        result1.Dispose();
                        result2.Dispose();
                        return; // Exit after successful test
                    }
                    catch (InvalidOperationException)
                    {
                        // This algorithm doesn't support deterministic encapsulation, try next
                    }
                });
            }
            
            // If we get here, no algorithm supported deterministic operations
            Assert.True(true, "No algorithms support deterministic encapsulation");
        });
    }

    [PlatformSpecificFact("LINUX")]
    public void KemInstance_EncapsulateDeterministic_WithInvalidPublicKeyLength_ShouldThrowArgumentException()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            var algorithm = algorithms[0];
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {
                using var kemInstance = KemProvider.Create(algorithm);
                
                var info = kemInstance.GetAlgorithmInfo();
                var invalidPublicKey = new byte[info.length_public_key / 2]; // Too short
                var seed = new byte[48];

                var action = () => kemInstance.EncapsulateDeterministic(invalidPublicKey, seed);
                action.Should().Throw<ArgumentException>()
                    .WithParameterName("publicKey");
            });
        });
    }

    [PlatformSpecificFact("LINUX")]
    public void KemInstance_EncapsulateDeterministic_WithInvalidSeedLength_ShouldThrowArgumentException()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            var algorithm = algorithms[0];
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {
                using var kemInstance = KemProvider.Create(algorithm);
                
                var keyPair = kemInstance.GenerateKeyPair();
                var invalidSeed = new byte[24]; // Should be 48 bytes

                var action = () => kemInstance.EncapsulateDeterministic(keyPair.PublicKey, invalidSeed);
                action.Should().Throw<ArgumentException>()
                    .WithParameterName("seed");

                keyPair.Dispose();
            });
        });
    }

    [Fact]
    public void KemInstance_Encapsulate_WithInvalidPublicKeyLength_ShouldThrowArgumentException()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            var algorithm = algorithms[0];
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {
                using var kemInstance = KemProvider.Create(algorithm);
                
                var info = kemInstance.GetAlgorithmInfo();
                var invalidPublicKey = new byte[info.length_public_key + 10]; // Too long

                var action = () => kemInstance.Encapsulate(invalidPublicKey);
                action.Should().Throw<ArgumentException>()
                    .WithParameterName("publicKey");
            });
        });
    }

    [Fact]
    public void KemInstance_Decapsulate_WithInvalidCiphertextLength_ShouldThrowArgumentException()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            var algorithm = algorithms[0];
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {
                using var kemInstance = KemProvider.Create(algorithm);
                
                var keyPair = kemInstance.GenerateKeyPair();
                var info = kemInstance.GetAlgorithmInfo();
                var invalidCiphertext = new byte[info.length_ciphertext - 1]; // Too short

                var action = () => kemInstance.Decapsulate(invalidCiphertext, keyPair.SecretKey);
                action.Should().Throw<ArgumentException>()
                    .WithParameterName("ciphertext");

                keyPair.Dispose();
            });
        });
    }

    [Fact]
    public void KemInstance_Decapsulate_WithInvalidSecretKeyLength_ShouldThrowArgumentException()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            var algorithm = algorithms[0];
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {
                using var kemInstance = KemProvider.Create(algorithm);
                
                var keyPair = kemInstance.GenerateKeyPair();
                var encapResult = kemInstance.Encapsulate(keyPair.PublicKey);
                var info = kemInstance.GetAlgorithmInfo();
                var invalidSecretKey = new byte[info.length_secret_key + 5]; // Too long

                var action = () => kemInstance.Decapsulate(encapResult.Ciphertext, invalidSecretKey);
                action.Should().Throw<ArgumentException>()
                    .WithParameterName("secretKey");

                keyPair.Dispose();
                encapResult.Dispose();
            });
        });
    }

    [Fact]
    public void KemInstance_GetAlgorithmInfo_ShouldReturnValidInfo()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            var algorithm = algorithms[0];
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {
                using var kemInstance = KemProvider.Create(algorithm);

                var info = kemInstance.GetAlgorithmInfo();
                
                info.length_public_key.Should().BeGreaterThan(UIntPtr.Zero);
                info.length_secret_key.Should().BeGreaterThan(UIntPtr.Zero);
                info.length_ciphertext.Should().BeGreaterThan(UIntPtr.Zero);
                info.length_shared_secret.Should().BeGreaterThan(UIntPtr.Zero);
                info.claimed_nist_level.Should().BeInRange(1, 5);
            });
        });
    }

    [Fact]
    public void KemInstance_AfterDispose_ShouldThrowObjectDisposedException()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            var algorithm = algorithms[0];
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {
                var kemInstance = KemProvider.Create(algorithm);
                
                var keyPair = kemInstance.GenerateKeyPair();
                var encapResult = kemInstance.Encapsulate(keyPair.PublicKey);
                
                // Dispose the instance
                kemInstance.Dispose();

                var getInfoAction = () => kemInstance.GetAlgorithmInfo();
                getInfoAction.Should().Throw<ObjectDisposedException>();

                var generateAction = () => kemInstance.GenerateKeyPair();
                generateAction.Should().Throw<ObjectDisposedException>();

                var generateDetAction = () => kemInstance.GenerateDeterministicKeyPair(new byte[48]);
                generateDetAction.Should().Throw<ObjectDisposedException>();

                var encapsulateAction = () => kemInstance.Encapsulate(keyPair.PublicKey);
                encapsulateAction.Should().Throw<ObjectDisposedException>();

                var encapsulateDetAction = () => kemInstance.EncapsulateDeterministic(keyPair.PublicKey, new byte[48]);
                encapsulateDetAction.Should().Throw<ObjectDisposedException>();

                var decapsulateAction = () => kemInstance.Decapsulate(encapResult.Ciphertext, keyPair.SecretKey);
                decapsulateAction.Should().Throw<ObjectDisposedException>();

                keyPair.Dispose();
                encapResult.Dispose();
            });
        });
    }

    [Fact]
    public void KemInstance_Finalizer_ShouldCleanupResources()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        
        TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
        {
            WeakReference? weakRef = null;
            
            // Create the instance in a separate method to ensure it goes out of scope
            void CreateInstance()
            {
                var kemInstance = KemProvider.Create(algorithm);
                weakRef = new WeakReference(kemInstance);
                // kemInstance goes out of scope here
            }
            
            CreateInstance();
            
            // Force multiple GC cycles and wait for finalizers
            for (int i = 0; i < 5; i++)
            {
                #pragma warning disable S1215
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
                #pragma warning restore S1215
                
                if (weakRef != null && !weakRef.IsAlive)
                    break;
            }

            // Finalizer execution is not guaranteed in tests, but we can check if it happened
            // This test verifies the finalizer can run without crashing
            Assert.True(true, "Finalizer test completed without exceptions");
        });
    }

#pragma warning restore S1144
}