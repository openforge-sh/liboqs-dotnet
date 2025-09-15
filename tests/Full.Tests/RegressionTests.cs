using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Core;
using OpenForge.Cryptography.LibOqs.KEM;
using OpenForge.Cryptography.LibOqs.SIG;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.Tests;

[Collection("LibOqs Collection")]
public sealed class RegressionTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void EmptyMessage_SigningAndVerification_ShouldWork()
    {
        var sigAlgorithm = GetSupportedSignatureAlgorithm();
        using var sig = new Sig(sigAlgorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var emptyMessage = Array.Empty<byte>();

        var signature = sig.Sign(emptyMessage, secretKey);
        var isValid = sig.Verify(emptyMessage, signature, publicKey);

        signature.Should().NotBeNull("Empty message signature should not be null");
        signature.Should().NotBeEmpty("Empty message signature should not be empty");
        isValid.Should().BeTrue("Empty message signature should verify correctly");
    }

    [Fact]
    public void LargeMessage_SigningAndVerification_ShouldWork()
    {
        var sigAlgorithm = GetSupportedSignatureAlgorithm();
        using var sig = new Sig(sigAlgorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var largeMessage = new byte[10 * 1024 * 1024];
        RandomNumberGenerator.Fill(largeMessage);

        var signature = sig.Sign(largeMessage, secretKey);
        var isValid = sig.Verify(largeMessage, signature, publicKey);

        signature.Should().NotBeNull("Large message signature should not be null");
        isValid.Should().BeTrue("Large message signature should verify correctly");
    }

    [Fact]
    public void SingleByteMessage_AllValues_ShouldWork()
    {
        var sigAlgorithm = GetSupportedSignatureAlgorithm();
        using var sig = new Sig(sigAlgorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var criticalValues = new byte[] { 0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF };

        foreach (var value in criticalValues)
        {
            var message = new byte[] { value };
            var signature = sig.Sign(message, secretKey);
            var isValid = sig.Verify(message, signature, publicKey);

            isValid.Should().BeTrue($"Single byte message with value 0x{value:X2} should verify");
        }
    }

    [Fact]
    public void KemEncapsulation_ZeroKey_ShouldHandleGracefully()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        using var kem = new Kem(kemAlgorithm);

        var (publicKey, secretKey) = kem.GenerateKeyPair();

        var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
        var recovered = kem.Decapsulate(ciphertext, secretKey);
        recovered.Should().BeEquivalentTo(sharedSecret);

        var zeroPublicKey = new byte[publicKey.Length];
        var act = () => kem.Encapsulate(zeroPublicKey);

        try
        {
            var (zeroCiphertext, zeroSharedSecret) = act();
            zeroCiphertext.Should().NotBeNull("Zero key encapsulation should produce ciphertext");
            zeroSharedSecret.Should().NotBeNull("Zero key encapsulation should produce shared secret");
        }
        catch (ArgumentException)
        {
            // Expected for invalid keys
        }
        catch (InvalidOperationException)
        {
            // Expected for invalid operations
        }
    }

    [Fact]
    public void MultipleInstancesCreation_ShouldNotInterfere()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        const int instanceCount = 5;
        var kemInstances = new List<Kem>();
        var sigInstances = new List<Sig>();

        try
        {
            for (int i = 0; i < instanceCount; i++)
            {
                kemInstances.Add(new Kem(kemAlgorithm));
                sigInstances.Add(new Sig(sigAlgorithm));
            }

            var kemKeyPairs = new List<(byte[] pub, byte[] sec)>();
            var sigKeyPairs = new List<(byte[] pub, byte[] sec)>();

            for (int i = 0; i < instanceCount; i++)
            {
                kemKeyPairs.Add(kemInstances[i].GenerateKeyPair());
                sigKeyPairs.Add(sigInstances[i].GenerateKeyPair());
            }

            var message = "Independent instance test"u8.ToArray();

            for (int i = 0; i < instanceCount; i++)
            {
                var (kemPub, kemSec) = kemKeyPairs[i];
                var (sigPub, sigSec) = sigKeyPairs[i];

                var (ciphertext, sharedSecret) = kemInstances[i].Encapsulate(kemPub);
                var recovered = kemInstances[i].Decapsulate(ciphertext, kemSec);
                recovered.Should().BeEquivalentTo(sharedSecret, $"KEM instance {i} should work correctly");

                var signature = sigInstances[i].Sign(message, sigSec);
                var isValid = sigInstances[i].Verify(message, signature, sigPub);
                isValid.Should().BeTrue($"Signature instance {i} should work correctly");
            }
        }
        finally
        {
            foreach (var kem in kemInstances)
            {
                kem.Dispose();
            }
            foreach (var sig in sigInstances)
            {
                sig.Dispose();
            }
        }
    }

    [Fact]
    public void RepeatedOperations_SameSeed_ShouldProduceDifferentResults()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        using var kem = new Kem(kemAlgorithm);
        using var sig = new Sig(sigAlgorithm);

        var kemPublicKeys = new List<byte[]>();
        var sigPublicKeys = new List<byte[]>();

        for (int i = 0; i < 10; i++)
        {
            var (kemPub, _) = kem.GenerateKeyPair();
            var (sigPub, _) = sig.GenerateKeyPair();
            kemPublicKeys.Add(kemPub);
            sigPublicKeys.Add(sigPub);
        }

        for (int i = 0; i < kemPublicKeys.Count - 1; i++)
        {
            for (int j = i + 1; j < kemPublicKeys.Count; j++)
            {
                kemPublicKeys[i].Should().NotBeEquivalentTo(kemPublicKeys[j],
                    $"KEM public keys {i} and {j} should be different");
                sigPublicKeys[i].Should().NotBeEquivalentTo(sigPublicKeys[j],
                    $"Signature public keys {i} and {j} should be different");
            }
        }
    }

    [Fact]
    public void MessageBoundaryValues_ShouldHandleCorrectly()
    {
        var sigAlgorithm = GetSupportedSignatureAlgorithm();
        using var sig = new Sig(sigAlgorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var boundarySizes = new[] {
            0, 1, 15, 16, 17,
            63, 64, 65,
            255, 256, 257,
            511, 512, 513,
            1023, 1024, 1025,
            4095, 4096, 4097,
            8191, 8192, 8193
        };

        foreach (var size in boundarySizes)
        {
            var message = new byte[size];
            if (size > 0)
            {
                RandomNumberGenerator.Fill(message);
            }

            var signature = sig.Sign(message, secretKey);
            var isValid = sig.Verify(message, signature, publicKey);

            isValid.Should().BeTrue($"Message of size {size} should sign and verify correctly");
        }
    }

    [Fact]
    public void ConcurrentDispose_ShouldNotCrash()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        const int instanceCount = 20;
        var instances = new List<IDisposable>();

        for (int i = 0; i < instanceCount; i++)
        {
            instances.Add(new Kem(kemAlgorithm));
            instances.Add(new Sig(sigAlgorithm));
        }

        Parallel.ForEach(instances, instance =>
        {
            instance.Dispose();
        });

        instances.Clear();
    }

    [Fact]
    public void SequentialKeyGeneration_ShouldMaintainQuality()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        using var kem = new Kem(kemAlgorithm);
        using var sig = new Sig(sigAlgorithm);

        const int keyCount = 100;
        var kemKeys = new List<byte[]>();
        var sigKeys = new List<byte[]>();

        for (int i = 0; i < keyCount; i++)
        {
            var (kemPub, _) = kem.GenerateKeyPair();
            var (sigPub, _) = sig.GenerateKeyPair();
            kemKeys.Add(kemPub);
            sigKeys.Add(sigPub);
        }

        var kemHashes = kemKeys.Select(k => SHA256.HashData(k)).ToArray();
        var sigHashes = sigKeys.Select(k => SHA256.HashData(k)).ToArray();

        kemHashes.Should().OnlyHaveUniqueItems("KEM key hashes should all be unique");
        sigHashes.Should().OnlyHaveUniqueItems("Signature key hashes should all be unique");
    }

    [Fact]
    public void AlgorithmName_Consistency_ShouldBeStable()
    {
        var kemAlgorithms = Kem.GetSupportedAlgorithms();
        var sigAlgorithms = Sig.GetSupportedAlgorithms();

        kemAlgorithms.Should().NotBeEmpty("KEM algorithms should be available");
        sigAlgorithms.Should().NotBeEmpty("Signature algorithms should be available");

        foreach (var algorithm in kemAlgorithms)
        {
            using var kem = new Kem(algorithm);
            kem.AlgorithmName.Should().Be(algorithm, "Algorithm name should match requested algorithm");
            kem.AlgorithmName.Should().NotBeNullOrWhiteSpace("Algorithm name should not be empty");
        }

        foreach (var algorithm in sigAlgorithms)
        {
            using var sig = new Sig(algorithm);
            sig.AlgorithmName.Should().Be(algorithm, "Algorithm name should match requested algorithm");
            sig.AlgorithmName.Should().NotBeNullOrWhiteSpace("Algorithm name should not be empty");
        }
    }

    [Fact]
    public void KeySizes_Consistency_ShouldBeReasonable()
    {
        var kemAlgorithms = Kem.GetSupportedAlgorithms();
        var sigAlgorithms = Sig.GetSupportedAlgorithms();

        foreach (var algorithm in kemAlgorithms)
        {
            using var kem = new Kem(algorithm);

            kem.PublicKeyLength.Should().BePositive($"{algorithm} public key length should be positive");
            kem.SecretKeyLength.Should().BePositive($"{algorithm} secret key length should be positive");
            kem.CiphertextLength.Should().BePositive($"{algorithm} ciphertext length should be positive");
            kem.SharedSecretLength.Should().BePositive($"{algorithm} shared secret length should be positive");

            kem.PublicKeyLength.Should().BeInRange(16, 5_000_000, $"{algorithm} public key size should be reasonable");
            kem.SecretKeyLength.Should().BeInRange(16, 5_000_000, $"{algorithm} secret key size should be reasonable");
            kem.CiphertextLength.Should().BeInRange(16, 5_000_000, $"{algorithm} ciphertext size should be reasonable");
            kem.SharedSecretLength.Should().BeInRange(16, 1024, $"{algorithm} shared secret size should be reasonable");
        }

        foreach (var algorithm in sigAlgorithms)
        {
            using var sig = new Sig(algorithm);

            sig.PublicKeyLength.Should().BePositive($"{algorithm} public key length should be positive");
            sig.SecretKeyLength.Should().BePositive($"{algorithm} secret key length should be positive");

            sig.PublicKeyLength.Should().BeInRange(16, 5_000_000, $"{algorithm} public key size should be reasonable");
            sig.SecretKeyLength.Should().BeInRange(16, 5_000_000, $"{algorithm} secret key size should be reasonable");
        }
    }

    [Fact]
    public void MemoryManagement_RepeatedOperations_ShouldNotLeak()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();
        var baseline = TimingUtils.GetSystemBaseline();

        // Use environment-aware iteration count and memory threshold
        var iterations = baseline.Environment switch
        {
            TimingUtils.EnvironmentType.CI => 250,           // Reduced for CI
            TimingUtils.EnvironmentType.LocalSlow => 350,    // Reduced for slow systems
            TimingUtils.EnvironmentType.LocalFast => 500,    // Original count for fast systems
            _ => 350
        };

        var maxMemoryGrowthMB = baseline.Environment switch
        {
            TimingUtils.EnvironmentType.CI => 50,            // More lenient for CI (50MB)
            TimingUtils.EnvironmentType.LocalSlow => 25,     // Somewhat lenient for slow systems (25MB)
            TimingUtils.EnvironmentType.LocalFast => 5,      // Original threshold for fast systems (5MB)
            _ => 25
        };

        #pragma warning disable S1215
        // Stabilize system and force clean GC state
        TimingUtils.StabilizeSystem();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var initialMemory = GC.GetTotalMemory(false);

        for (int i = 0; i < iterations; i++)
        {
            using var kem = new Kem(kemAlgorithm);
            using var sig = new Sig(sigAlgorithm);

            var (kemPub, kemSec) = kem.GenerateKeyPair();
            var (sigPub, sigSec) = sig.GenerateKeyPair();

            var message = new byte[128];
            RandomNumberGenerator.Fill(message);

            var signature = sig.Sign(message, sigSec);
            var (ciphertext, sharedSecret) = kem.Encapsulate(kemPub);

            var isValid = sig.Verify(message, signature, sigPub);
            var recovered = kem.Decapsulate(ciphertext, kemSec);

            isValid.Should().BeTrue();
            recovered.Should().BeEquivalentTo(sharedSecret);

            // More frequent GC in CI environments to combat memory pressure
            var gcFrequency = baseline.Environment == TimingUtils.EnvironmentType.CI ? 25 : 50;
            if (i % gcFrequency == 0)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }

        // Final cleanup and measurement
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        #pragma warning restore S1215
        var finalMemory = GC.GetTotalMemory(false);

        var memoryGrowth = finalMemory - initialMemory;
        var memoryGrowthMB = memoryGrowth / 1024.0 / 1024.0;
        var maxMemoryGrowthBytes = maxMemoryGrowthMB * 1024 * 1024;

        memoryGrowth.Should().BeLessThan(maxMemoryGrowthBytes,
            $"Memory growth should be minimal for {baseline.Environment} environment, grew by {memoryGrowthMB:F1} MB (max: {maxMemoryGrowthMB} MB, iterations: {iterations})");
    }

    private static string GetSupportedKemAlgorithm()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty("At least one KEM algorithm should be supported");

        var nistAlgorithms = algorithms.Where(alg => KemAlgorithms.NISTStandardized.Contains(alg)).ToArray();
        return nistAlgorithms.Length > 0 ? nistAlgorithms[0] : algorithms[0];
    }

    private static string GetSupportedSignatureAlgorithm()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty("At least one signature algorithm should be supported");

        var nistAlgorithms = algorithms.Where(alg => SignatureAlgorithms.NISTStandardized.Contains(alg)).ToArray();
        return nistAlgorithms.Length > 0 ? nistAlgorithms[0] : algorithms[0];
    }

#pragma warning restore S1144
}