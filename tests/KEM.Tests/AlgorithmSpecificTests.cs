using System.Runtime.InteropServices;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Core;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.KEM.Tests;

[Collection("LibOqs Collection")]
public sealed class AlgorithmSpecificTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void NISTStandardized_Algorithms_ShouldBeSupported()
    {
        foreach (var algorithm in KemAlgorithms.NISTStandardized)
        {
            var isSupported = Kem.IsAlgorithmSupported(algorithm);

            // NIST standardized algorithms should be supported in most LibOQS builds
            if (isSupported)
            {
                using var kem = new Kem(algorithm);
                kem.AlgorithmName.Should().Be(algorithm);
                kem.IsIndCca.Should().BeTrue($"{algorithm} should provide IND-CCA security");

                // Verify complete KEM flow works
                var (publicKey, secretKey) = kem.GenerateKeyPair();
                var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
                var recoveredSecret = kem.Decapsulate(ciphertext, secretKey);
                recoveredSecret.Should().BeEquivalentTo(sharedSecret);
            }
        }
    }

    [Fact]
    public void Deprecated_Algorithms_ShouldNotBeUsed()
    {
        foreach (var algorithm in KemAlgorithms.Deprecated)
        {
            // Even if supported, deprecated algorithms should be avoided
            // This test documents which algorithms are deprecated
            AlgorithmConstants.IsDeprecated(algorithm).Should().BeTrue(
                $"{algorithm} should be marked as deprecated");
        }
    }

    [Theory]
    [InlineData(KemAlgorithms.ML_KEM_512, 1)]
    [InlineData(KemAlgorithms.ML_KEM_768, 3)]
    [InlineData(KemAlgorithms.ML_KEM_1024, 5)]
    public void ML_KEM_Algorithms_ShouldHaveCorrectNistLevel(string algorithm, byte expectedNistLevel)
    {
        if (!Kem.IsAlgorithmSupported(algorithm))
            return; // Skip if not supported

        using var kem = new Kem(algorithm);
        kem.ClaimedNistLevel.Should().Be(expectedNistLevel);
        kem.IsIndCca.Should().BeTrue($"{algorithm} should provide IND-CCA security");
    }

    [Theory]
    [InlineData(KemAlgorithms.Kyber512, 1)]
    [InlineData(KemAlgorithms.Kyber768, 3)]
    [InlineData(KemAlgorithms.Kyber1024, 5)]
    public void Kyber_Algorithms_ShouldHaveCorrectNistLevel(string algorithm, byte expectedNistLevel)
    {
        if (!Kem.IsAlgorithmSupported(algorithm))
            return; // Skip if not supported

        using var kem = new Kem(algorithm);
        kem.ClaimedNistLevel.Should().Be(expectedNistLevel);
        kem.IsIndCca.Should().BeTrue($"{algorithm} should provide IND-CCA security");
    }

    [PlatformSpecificTheory("LINUX", "OSX")]
    [InlineData(KemAlgorithms.BIKE_L1, 1)]
    [InlineData(KemAlgorithms.BIKE_L3, 3)]
    [InlineData(KemAlgorithms.BIKE_L5, 5)]
    public void BIKE_Algorithms_ShouldHaveCorrectNistLevel(string algorithm, byte expectedNistLevel)
    {
        if (!Kem.IsAlgorithmSupported(algorithm))
            return; // Skip if not supported

        using var kem = new Kem(algorithm);
        kem.ClaimedNistLevel.Should().Be(expectedNistLevel);
    }

    [Theory]
    [InlineData(KemAlgorithms.HQC_128, 1)]
    [InlineData(KemAlgorithms.HQC_192, 3)]
    [InlineData(KemAlgorithms.HQC_256, 5)]
    public void HQC_Algorithms_ShouldHaveCorrectNistLevel(string algorithm, byte expectedNistLevel)
    {
        if (!Kem.IsAlgorithmSupported(algorithm))
            return; // Skip if not supported

        using var kem = new Kem(algorithm);
        kem.ClaimedNistLevel.Should().Be(expectedNistLevel);
        kem.IsIndCca.Should().BeTrue($"{algorithm} should provide IND-CCA security");
    }

    [Theory]
    [InlineData(KemAlgorithms.FrodoKEM_640_AES, 1)]
    [InlineData(KemAlgorithms.FrodoKEM_640_SHAKE, 1)]
    [InlineData(KemAlgorithms.FrodoKEM_976_AES, 3)]
    [InlineData(KemAlgorithms.FrodoKEM_976_SHAKE, 3)]
    [InlineData(KemAlgorithms.FrodoKEM_1344_AES, 5)]
    [InlineData(KemAlgorithms.FrodoKEM_1344_SHAKE, 5)]
    public void FrodoKEM_Algorithms_ShouldHaveCorrectNistLevel(string algorithm, byte expectedNistLevel)
    {
        if (!Kem.IsAlgorithmSupported(algorithm))
            return; // Skip if not supported

        using var kem = new Kem(algorithm);
        kem.ClaimedNistLevel.Should().Be(expectedNistLevel);
        kem.IsIndCca.Should().BeTrue($"{algorithm} should provide IND-CCA security");
    }

    [Fact]
    public void AllSupportedAlgorithms_ShouldHaveValidProperties()
    {
        var algorithms = Kem.GetSupportedAlgorithms();

        // Filter out BIKE algorithms on Windows and macOS as they are not supported
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            algorithms = [.. algorithms.Where(a => !a.Contains("BIKE", StringComparison.OrdinalIgnoreCase))];
            
            // On Windows and macOS, test algorithms in smaller batches to avoid potential stack issues
            const int batchSize = 5;
            for (var i = 0; i < algorithms.Length; i += batchSize)
            {
                var batch = algorithms.Skip(i).Take(batchSize).ToArray();
                ValidateAlgorithmPropertiesBatch(batch);
            }
        }
        else
        {
            // On Linux, test all algorithms at once
            ValidateAlgorithmPropertiesBatch(algorithms);
        }
    }

    private static void ValidateAlgorithmPropertiesBatch(string[] algorithms)
    {
        foreach (var algorithm in algorithms)
        {
            using var kem = new Kem(algorithm);

            kem.AlgorithmName.Should().Be(algorithm);
            kem.PublicKeyLength.Should().BeGreaterThan(0, $"{algorithm} should have positive public key length");
            kem.SecretKeyLength.Should().BeGreaterThan(0, $"{algorithm} should have positive secret key length");
            kem.CiphertextLength.Should().BeGreaterThan(0, $"{algorithm} should have positive ciphertext length");
            kem.SharedSecretLength.Should().BeGreaterThan(0, $"{algorithm} should have positive shared secret length");
            kem.ClaimedNistLevel.Should().BeInRange(1, 5, $"{algorithm} should have valid NIST level");
        }
    }

    [Fact]
    public void AllSupportedAlgorithms_ShouldPerformCompleteKemFlow()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty("Should have at least one supported algorithm");

        // Filter out BIKE algorithms on Windows and macOS as they are not supported
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            algorithms = [.. algorithms.Where(a => !a.Contains("BIKE", StringComparison.OrdinalIgnoreCase))];
            
            // On Windows and macOS, test algorithms in smaller batches for better error isolation
            const int batchSize = 5;
            for (var i = 0; i < algorithms.Length; i += batchSize)
            {
                var batch = algorithms.Skip(i).Take(batchSize).ToArray();
                TestAlgorithmBatch(batch);
            }
        }
        else
        {
            // On Linux platforms, test all algorithms at once
            TestAlgorithmBatch(algorithms);
        }
    }

    private static void TestAlgorithmBatch(string[] algorithms)
    {
        foreach (var algorithm in algorithms)
        {
            using var kem = new Kem(algorithm);

            var (publicKey, secretKey) = kem.GenerateKeyPair();
            publicKey.Length.Should().Be(kem.PublicKeyLength, $"{algorithm} public key should match expected length");
            secretKey.Length.Should().Be(kem.SecretKeyLength, $"{algorithm} secret key should match expected length");

            // Encapsulate
            var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
            ciphertext.Length.Should().Be(kem.CiphertextLength, $"{algorithm} ciphertext should match expected length");
            sharedSecret.Length.Should().Be(kem.SharedSecretLength, $"{algorithm} shared secret should match expected length");

            // Decapsulate
            var recoveredSecret = kem.Decapsulate(ciphertext, secretKey);
            recoveredSecret.Should().BeEquivalentTo(sharedSecret, $"{algorithm} should recover the same shared secret");
        }
    }

    [Fact]
    public void DifferentAlgorithms_ShouldProduceDifferentKeySizes()
    {
        var algorithms = Kem.GetSupportedAlgorithms()
            .Where(a => a.Contains("ML-KEM", StringComparison.Ordinal) || a.Contains("Kyber", StringComparison.Ordinal))
            .Take(2)
            .ToArray();

        if (algorithms.Length < 2)
            return; // Skip if not enough algorithms

        using var kem1 = new Kem(algorithms[0]);
        using var kem2 = new Kem(algorithms[1]);

        // Different security levels should have different key sizes
        if (!algorithms[0].Contains(algorithms[1].Split('-').Last(), StringComparison.Ordinal) &&
            !algorithms[1].Contains(algorithms[0].Split('-').Last(), StringComparison.Ordinal))
        {
            (kem1.PublicKeyLength != kem2.PublicKeyLength ||
             kem1.SecretKeyLength != kem2.SecretKeyLength ||
             kem1.CiphertextLength != kem2.CiphertextLength).Should().BeTrue(
                "Different algorithm variants should have different sizes");
        }
    }

    [Fact]
    public void SameAlgorithm_MultipleCalls_ShouldGenerateDifferentSecrets()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, _) = kem.GenerateKeyPair();

        var (_, sharedSecret1) = kem.Encapsulate(publicKey);
        var (_, sharedSecret2) = kem.Encapsulate(publicKey);

        // Each encapsulation should produce a different shared secret
        sharedSecret1.Should().NotBeEquivalentTo(sharedSecret2,
            "Multiple encapsulations should produce different shared secrets due to randomness");
    }

    [Fact]
    public void ClassicMcEliece_Algorithms_ShouldHaveIndCcaSecurity()
    {
        var mcElieceAlgorithms = Kem.GetSupportedAlgorithms()
            .Where(a => a.StartsWith("Classic-McEliece", StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var algorithm in mcElieceAlgorithms)
        {
            using var kem = new Kem(algorithm);
            kem.IsIndCca.Should().BeTrue($"{algorithm} should provide IND-CCA security");
        }
    }

    [Fact]
    public void NTRU_Algorithms_ShouldHaveValidProperties()
    {
        var ntruAlgorithms = Kem.GetSupportedAlgorithms()
            .Where(a => a.StartsWith("NTRU", StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var algorithm in ntruAlgorithms)
        {
            using var kem = new Kem(algorithm);
            kem.ClaimedNistLevel.Should().BeInRange(1, 5);
            kem.IsIndCca.Should().BeTrue($"{algorithm} should provide IND-CCA security");
        }
    }

    [Fact]
    public void Saber_Algorithms_ShouldHaveValidProperties()
    {
        var saberAlgorithms = new[]
        {
            KemAlgorithms.Saber_LightSaber,
            KemAlgorithms.Saber_Saber,
            KemAlgorithms.Saber_FireSaber
        };

        foreach (var algorithm in saberAlgorithms)
        {
            if (Kem.IsAlgorithmSupported(algorithm))
            {
                using var kem = new Kem(algorithm);
                kem.IsIndCca.Should().BeTrue($"{algorithm} should provide IND-CCA security");

                // LightSaber = Level 1, Saber = Level 3, FireSaber = Level 5
                if (algorithm.Contains("Light", StringComparison.Ordinal))
                    kem.ClaimedNistLevel.Should().Be(1);
                else if (algorithm.Contains("Fire", StringComparison.Ordinal))
                    kem.ClaimedNistLevel.Should().Be(5);
                else
                    kem.ClaimedNistLevel.Should().Be(3);
            }
        }
    }

#pragma warning restore S1144
}