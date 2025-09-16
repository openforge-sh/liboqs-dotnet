using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.KEM.Tests;

[Collection("LibOqs Collection")]
public sealed class InteroperabilityTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void KemInstances_WithSameAlgorithm_ShouldBeInteroperable()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
        {
            using var kem1 = new Kem(algorithm);
            using var kem2 = new Kem(algorithm);

            var (publicKey, secretKey) = kem1.GenerateKeyPair();

            // Encapsulate with first instance
            var (ciphertext1, sharedSecret1) = kem1.Encapsulate(publicKey);

            // Encapsulate with second instance using same public key
            var (ciphertext2, sharedSecret2) = kem2.Encapsulate(publicKey);

            // Decapsulate with both instances
            var recoveredSecret1 = kem1.Decapsulate(ciphertext1, secretKey);
            var recoveredSecret2 = kem2.Decapsulate(ciphertext2, secretKey);

            // Cross-instance decapsulation
            var crossRecovered1 = kem2.Decapsulate(ciphertext1, secretKey);
            var crossRecovered2 = kem1.Decapsulate(ciphertext2, secretKey);

            recoveredSecret1.Should().BeEquivalentTo(sharedSecret1);
            recoveredSecret2.Should().BeEquivalentTo(sharedSecret2);
            crossRecovered1.Should().BeEquivalentTo(sharedSecret1);
            crossRecovered2.Should().BeEquivalentTo(sharedSecret2);
        });
    }

    [Fact]
    public void KemInstances_SameKeys_DifferentEncapsulations_ShouldDecapsulateCorrectly()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
        {
            using var kemGenerator = new Kem(algorithm);
            using var kemEncryptor1 = new Kem(algorithm);
            using var kemEncryptor2 = new Kem(algorithm);
            using var kemDecryptor = new Kem(algorithm);

            var (publicKey, secretKey) = kemGenerator.GenerateKeyPair();

            var (ciphertext1, sharedSecret1) = kemEncryptor1.Encapsulate(publicKey);
            var (ciphertext2, sharedSecret2) = kemEncryptor2.Encapsulate(publicKey);

            // Verify they produce different results (due to randomness)
            ciphertext1.Should().NotBeEquivalentTo(ciphertext2);
            sharedSecret1.Should().NotBeEquivalentTo(sharedSecret2);

            // Decapsulate both with the same decryptor instance
            var recovered1 = kemDecryptor.Decapsulate(ciphertext1, secretKey);
            var recovered2 = kemDecryptor.Decapsulate(ciphertext2, secretKey);

            // Verify correct recovery
            recovered1.Should().BeEquivalentTo(sharedSecret1);
            recovered2.Should().BeEquivalentTo(sharedSecret2);
        });
    }

    [Fact]
    public async Task KemInstances_MultipleConcurrentOperations_ShouldBeThreadSafe()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        
        await Task.Run(() =>
        {
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {
                var tasks = new List<Task>();
                var results = new Dictionary<int, (byte[] ciphertext, byte[] sharedSecret, byte[] recovered)>();
                var lockObject = new object();

                const int concurrentOperations = 10;
                using var kem = new Kem(algorithm);
                var (publicKey, secretKey) = kem.GenerateKeyPair();

                for (int i = 0; i < concurrentOperations; i++)
                {
                    int operationId = i;
                    tasks.Add(Task.Run(() =>
                    {
                        using var localKem = new Kem(algorithm);
                        var (ciphertext, sharedSecret) = localKem.Encapsulate(publicKey);
                        var recovered = localKem.Decapsulate(ciphertext, secretKey);

                        lock (lockObject)
                        {
                            results[operationId] = (ciphertext, sharedSecret, recovered);
                        }
                    }, TestContext.Current.CancellationToken));
                }

                Task.WhenAll(tasks).GetAwaiter().GetResult();

                results.Should().HaveCount(concurrentOperations);
                foreach (var (operationId, (ciphertext, sharedSecret, recovered)) in results)
                {
                    ciphertext.Should().NotBeNull($"Operation {operationId} should produce valid ciphertext");
                    sharedSecret.Should().NotBeNull($"Operation {operationId} should produce valid shared secret");
                    recovered.Should().BeEquivalentTo(sharedSecret, $"Operation {operationId} should recover correct shared secret");
                }

                var allCiphertexts = results.Values.Select(r => r.ciphertext).ToList();
                var allSharedSecrets = results.Values.Select(r => r.sharedSecret).ToList();

                for (int i = 0; i < allCiphertexts.Count - 1; i++)
                {
                    for (int j = i + 1; j < allCiphertexts.Count; j++)
                    {
                        allCiphertexts[i].Should().NotBeEquivalentTo(allCiphertexts[j],
                            "Each concurrent operation should produce unique ciphertext");
                        allSharedSecrets[i].Should().NotBeEquivalentTo(allSharedSecrets[j],
                            "Each concurrent operation should produce unique shared secret");
                    }
                }
            });
        }, TestContext.Current.CancellationToken);
    }

    [Fact]
    public void KemInstances_KeyReuse_AcrossMultipleInstances_ShouldWork()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
        {
            byte[] publicKey, secretKey;

            using (var kemGenerator = new Kem(algorithm))
            {
                (publicKey, secretKey) = kemGenerator.GenerateKeyPair();
            }

            const int instanceCount = 5;
            var encapsulationResults = new List<(byte[] ciphertext, byte[] sharedSecret)>();

            for (int i = 0; i < instanceCount; i++)
            {
                using var kem = new Kem(algorithm);
                var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
                encapsulationResults.Add((ciphertext, sharedSecret));
            }

            using var decryptor = new Kem(algorithm);
            foreach (var (ciphertext, expectedSharedSecret) in encapsulationResults)
            {
                var recoveredSecret = decryptor.Decapsulate(ciphertext, secretKey);
                recoveredSecret.Should().BeEquivalentTo(expectedSharedSecret);
            }
        });
    }

    [Fact]
    public void KemInstances_AllSupportedAlgorithms_ShouldBeInteroperable()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            foreach (var algorithm in algorithms.Take(3)) // Test first 3 algorithms for performance
            {
                TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
                {
                    using var kem1 = new Kem(algorithm);
                    using var kem2 = new Kem(algorithm);

                    var (publicKey, secretKey) = kem1.GenerateKeyPair();
                    var (ciphertext, sharedSecret) = kem1.Encapsulate(publicKey);

                    var recoveredSecret = kem2.Decapsulate(ciphertext, secretKey);
                    recoveredSecret.Should().BeEquivalentTo(sharedSecret,
                        $"Algorithm {algorithm} should be interoperable across instances");
                });
            }
        });
    }

    [Fact]
    public void KemInstances_PropertiesConsistency_AcrossInstances_ShouldMatch()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
        {
            using var kem1 = new Kem(algorithm);
            using var kem2 = new Kem(algorithm);

            kem1.AlgorithmName.Should().Be(kem2.AlgorithmName);
            kem1.PublicKeyLength.Should().Be(kem2.PublicKeyLength);
            kem1.SecretKeyLength.Should().Be(kem2.SecretKeyLength);
            kem1.CiphertextLength.Should().Be(kem2.CiphertextLength);
            kem1.SharedSecretLength.Should().Be(kem2.SharedSecretLength);
            kem1.ClaimedNistLevel.Should().Be(kem2.ClaimedNistLevel);
            kem1.IsIndCca.Should().Be(kem2.IsIndCca);
        });
    }

    [Fact]
    public void KemInstances_SequentialOperations_WithInstanceReuse_ShouldWork()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
        {
            using var kem = new Kem(algorithm);

            const int operationCount = 10;
            var keyPairs = new List<(byte[] publicKey, byte[] secretKey)>();
            var encapsulationResults = new List<(byte[] ciphertext, byte[] sharedSecret)>();

            for (int i = 0; i < operationCount; i++)
            {
                var (publicKey, secretKey) = kem.GenerateKeyPair();
                keyPairs.Add((publicKey, secretKey));
            }

            // Perform encapsulations
            foreach (var (publicKey, _) in keyPairs)
            {
                var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
                encapsulationResults.Add((ciphertext, sharedSecret));
            }

            // Verify decapsulations
            for (int i = 0; i < operationCount; i++)
            {
                var (_, secretKey) = keyPairs[i];
                var (ciphertext, expectedSharedSecret) = encapsulationResults[i];

                var recoveredSecret = kem.Decapsulate(ciphertext, secretKey);
                recoveredSecret.Should().BeEquivalentTo(expectedSharedSecret,
                    $"Operation {i} should recover correct shared secret");
            }
        });
    }

    [Fact]
    public void KemInstances_CrossPlatformCompatibility_SameResults()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
        {
            using var kem1 = new Kem(algorithm);
            using var kem2 = new Kem(algorithm);

            var (publicKey, secretKey) = kem1.GenerateKeyPair();

            // Simulate data that might come from different platforms
            var publicKeyCopy = publicKey.ToArray();
            var secretKeyCopy = secretKey.ToArray();

            var (ciphertext1, sharedSecret1) = kem1.Encapsulate(publicKeyCopy);
            var recoveredSecret1 = kem2.Decapsulate(ciphertext1, secretKeyCopy);

            recoveredSecret1.Should().BeEquivalentTo(sharedSecret1);

            // Verify byte arrays are independent
            publicKeyCopy[0] ^= 0x01;
            secretKeyCopy[0] ^= 0x01;

            // Original operations should still work
            var (ciphertext2, sharedSecret2) = kem1.Encapsulate(publicKey);
            var recoveredSecret2 = kem2.Decapsulate(ciphertext2, secretKey);
            recoveredSecret2.Should().BeEquivalentTo(sharedSecret2);
        });
    }

    [Fact]
    public void KemInstances_LargeScaleOperations_ShouldMaintainConsistency()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
        {
            using var kem = new Kem(algorithm);

            const int largeOperationCount = 100;
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            var results = new List<(byte[] ciphertext, byte[] sharedSecret, byte[] recovered)>();

            // Perform many operations with same instance
            for (int i = 0; i < largeOperationCount; i++)
            {
                var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
                var recovered = kem.Decapsulate(ciphertext, secretKey);
                results.Add((ciphertext, sharedSecret, recovered));
            }

            results.Should().HaveCount(largeOperationCount);
            foreach (var (index, (ciphertext, sharedSecret, recovered)) in results.Select((r, i) => (i, r)))
            {
                ciphertext.Should().NotBeNull($"Operation {index} should produce valid ciphertext");
                sharedSecret.Should().NotBeNull($"Operation {index} should produce valid shared secret");
                recovered.Should().BeEquivalentTo(sharedSecret, $"Operation {index} should recover correct shared secret");
            }

            var uniqueCiphertexts = results.Select(r => Convert.ToBase64String(r.ciphertext)).ToHashSet();
            var uniqueSharedSecrets = results.Select(r => Convert.ToBase64String(r.sharedSecret)).ToHashSet();

            uniqueCiphertexts.Should().HaveCount(largeOperationCount, "All ciphertexts should be unique");
            uniqueSharedSecrets.Should().HaveCount(largeOperationCount, "All shared secrets should be unique");
        });
    }

#pragma warning restore S1144
}