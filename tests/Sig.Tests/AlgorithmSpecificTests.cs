using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Core;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.SIG.Tests;

[Collection("LibOqs Collection")]
public sealed class AlgorithmSpecificTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void NISTStandardized_Algorithms_ShouldBeSupported()
    {
        foreach (var algorithm in SignatureAlgorithms.NISTStandardized)
        {
            var isSupported = Sig.IsAlgorithmSupported(algorithm);

            if (isSupported)
            {
                using var sig = new Sig(algorithm);
                sig.AlgorithmName.Should().Be(algorithm);
                sig.IsEufCma.Should().BeTrue($"{algorithm} should provide EUF-CMA security");

                var (publicKey, secretKey) = sig.GenerateKeyPair();
                var message = new byte[256];
                RandomNumberGenerator.Fill(message);

                var signature = sig.Sign(message, secretKey);
                var isValid = sig.Verify(message, signature, publicKey);
                isValid.Should().BeTrue();
            }
        }
    }

    [Fact]
    public void Deprecated_Algorithms_ShouldNotBeUsed()
    {
        foreach (var algorithm in SignatureAlgorithms.Deprecated)
        {
            AlgorithmConstants.IsDeprecated(algorithm).Should().BeTrue(
                $"{algorithm} should be marked as deprecated");
        }
    }

    [Theory]
    [InlineData(SignatureAlgorithms.ML_DSA_44, 2)]
    [InlineData(SignatureAlgorithms.ML_DSA_65, 3)]
    [InlineData(SignatureAlgorithms.ML_DSA_87, 5)]
    public void ML_DSA_Algorithms_ShouldHaveCorrectNistLevel(string algorithm, byte expectedNistLevel)
    {
        if (!Sig.IsAlgorithmSupported(algorithm))
            return;

        using var sig = new Sig(algorithm);
        sig.ClaimedNistLevel.Should().Be(expectedNistLevel);
        sig.IsEufCma.Should().BeTrue($"{algorithm} should provide EUF-CMA security");
    }

    [Theory]
    [InlineData(SignatureAlgorithms.Dilithium2, 2)]
    [InlineData(SignatureAlgorithms.Dilithium3, 3)]
    [InlineData(SignatureAlgorithms.Dilithium5, 5)]
    public void Dilithium_Algorithms_ShouldHaveCorrectNistLevel(string algorithm, byte expectedNistLevel)
    {
        if (!Sig.IsAlgorithmSupported(algorithm))
            return;

        using var sig = new Sig(algorithm);
        sig.ClaimedNistLevel.Should().Be(expectedNistLevel);
        sig.IsEufCma.Should().BeTrue($"{algorithm} should provide EUF-CMA security");
    }

    [Theory]
    [InlineData(SignatureAlgorithms.Falcon_512, 1)]
    [InlineData(SignatureAlgorithms.Falcon_1024, 5)]
    [InlineData(SignatureAlgorithms.Falcon_512_padded, 1)]
    [InlineData(SignatureAlgorithms.Falcon_1024_padded, 5)]
    public void Falcon_Algorithms_ShouldHaveCorrectNistLevel(string algorithm, byte expectedNistLevel)
    {
        if (!Sig.IsAlgorithmSupported(algorithm))
            return;

        using var sig = new Sig(algorithm);
        sig.ClaimedNistLevel.Should().Be(expectedNistLevel);
        sig.IsEufCma.Should().BeTrue($"{algorithm} should provide EUF-CMA security");
    }

    [Theory]
    [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHA2_128f_simple, 1)]
    [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHA2_128s_simple, 1)]
    [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHA2_192f_simple, 3)]
    [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHA2_192s_simple, 3)]
    [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHA2_256f_simple, 5)]
    [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHA2_256s_simple, 5)]
    public void SPHINCS_PLUS_SHA2_Algorithms_ShouldHaveCorrectNistLevel(string algorithm, byte expectedNistLevel)
    {
        if (!Sig.IsAlgorithmSupported(algorithm))
            return;

        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            using var sig = new Sig(algorithm);
            sig.ClaimedNistLevel.Should().Be(expectedNistLevel);
            sig.IsEufCma.Should().BeTrue($"{algorithm} should provide EUF-CMA security");
        });
    }

    [Theory]
    [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHAKE_128f_simple, 1)]
    [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHAKE_128s_simple, 1)]
    [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHAKE_192f_simple, 3)]
    [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHAKE_192s_simple, 3)]
    [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHAKE_256f_simple, 5)]
    [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHAKE_256s_simple, 5)]
    public void SPHINCS_PLUS_SHAKE_Algorithms_ShouldHaveCorrectNistLevel(string algorithm, byte expectedNistLevel)
    {
        if (!Sig.IsAlgorithmSupported(algorithm))
            return;

        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            using var sig = new Sig(algorithm);
            sig.ClaimedNistLevel.Should().Be(expectedNistLevel);
            sig.IsEufCma.Should().BeTrue($"{algorithm} should provide EUF-CMA security");
        });
    }

    [Theory]
    [InlineData(SignatureAlgorithms.MAYO_1, 1)]
    [InlineData(SignatureAlgorithms.MAYO_3, 3)]
    [InlineData(SignatureAlgorithms.MAYO_5, 5)]
    public void MAYO_Algorithms_ShouldHaveCorrectNistLevel(string algorithm, byte expectedNistLevel)
    {
        if (!Sig.IsAlgorithmSupported(algorithm))
            return;

        using var sig = new Sig(algorithm);
        sig.ClaimedNistLevel.Should().Be(expectedNistLevel);
        sig.IsEufCma.Should().BeTrue($"{algorithm} should provide EUF-CMA security");
    }

    [Fact]
    public void AllSupportedAlgorithms_ShouldHaveValidProperties()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Sig.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            foreach (var algorithm in algorithms.Take(10))
            {
                TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
                {
                    using var sig = new Sig(algorithm);

                    sig.AlgorithmName.Should().Be(algorithm);
                    sig.PublicKeyLength.Should().BeGreaterThan(0,
                        $"{algorithm} should have positive public key length");
                    sig.SecretKeyLength.Should().BeGreaterThan(0,
                        $"{algorithm} should have positive secret key length");
                    sig.SignatureLength.Should().BeGreaterThan(0,
                        $"{algorithm} should have positive signature length");
                    sig.ClaimedNistLevel.Should().BeInRange(1, 5,
                        $"{algorithm} should have valid NIST level");

                    sig.PublicKeyLength.Should().BeGreaterThanOrEqualTo(32,
                        $"{algorithm} public key should be at least 32 bytes");
                    sig.SecretKeyLength.Should().BeGreaterThanOrEqualTo(32,
                        $"{algorithm} secret key should be at least 32 bytes");
                    sig.SignatureLength.Should().BeGreaterThanOrEqualTo(32,
                        $"{algorithm} signature should be at least 32 bytes");

                    sig.IsEufCma.Should().BeTrue(
                        $"{algorithm} should provide EUF-CMA security");
                });
            }
        });
    }

    [Fact]
    public void AlgorithmFamilies_ShouldHaveConsistentBehavior()
    {
        var algorithmFamilies = new Dictionary<string, string[]>
        {
            ["ML-DSA"] = [SignatureAlgorithms.ML_DSA_44, SignatureAlgorithms.ML_DSA_65, SignatureAlgorithms.ML_DSA_87],
            ["Dilithium"] = [SignatureAlgorithms.Dilithium2, SignatureAlgorithms.Dilithium3, SignatureAlgorithms.Dilithium5],
            ["Falcon"] = [SignatureAlgorithms.Falcon_512, SignatureAlgorithms.Falcon_1024],
            ["MAYO"] = [SignatureAlgorithms.MAYO_1, SignatureAlgorithms.MAYO_3, SignatureAlgorithms.MAYO_5]
        };

        foreach (var (familyName, algorithms) in algorithmFamilies)
        {
            var supportedInFamily = algorithms.Where(Sig.IsAlgorithmSupported).ToArray();

            if (supportedInFamily.Length == 0)
                continue;

            var familyResults = new List<(string algorithm, int publicKeyLen, int secretKeyLen, int sigLen, byte nistLevel)>();

            foreach (var algorithm in supportedInFamily)
            {
                using var sig = new Sig(algorithm);
                familyResults.Add((algorithm, sig.PublicKeyLength, sig.SecretKeyLength, sig.SignatureLength, sig.ClaimedNistLevel));
            }

            familyResults = familyResults.OrderBy(r => r.nistLevel).ToList();

            for (int i = 0; i < familyResults.Count - 1; i++)
            {
                var current = familyResults[i];
                var next = familyResults[i + 1];

                if (next.nistLevel > current.nistLevel)
                {
                    next.publicKeyLen.Should().BeGreaterThan(0,
                        $"{familyName} family: {next.algorithm} should have positive public key length");
                    next.secretKeyLen.Should().BeGreaterThan(0,
                        $"{familyName} family: {next.algorithm} should have positive secret key length");
                    next.sigLen.Should().BeGreaterThan(0,
                        $"{familyName} family: {next.algorithm} should have positive signature length");
                }
            }
        }
    }

    [Fact]
    public void SignatureSize_ShouldBeReasonable()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        foreach (var algorithm in algorithms.Take(10))
        {
            using var sig = new Sig(algorithm);
            var (publicKey, secretKey) = sig.GenerateKeyPair();

            var messageSizes = new[] { 0, 1, 32, 256, 1024, 4096 };

            foreach (var messageSize in messageSizes)
            {
                var message = new byte[messageSize];
                if (messageSize > 0)
                {
                    RandomNumberGenerator.Fill(message);
                }

                var signature = sig.Sign(message, secretKey);

                signature.Length.Should().BeLessThanOrEqualTo(sig.SignatureLength,
                    $"{algorithm} signature should not exceed SignatureLength property for message size {messageSize}");

                var isValid = sig.Verify(message, signature, publicKey);
                isValid.Should().BeTrue(
                    $"{algorithm} should verify correctly for message size {messageSize}");
            }
        }
    }

    [Fact]
    public void CrossAlgorithm_KeysAndSignatures_ShouldNotBeInterchangeable()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        if (algorithms.Length < 2)
            return;

        var alg1 = algorithms[0];
        var alg2 = algorithms[1];

        using var sig1 = new Sig(alg1);
        using var sig2 = new Sig(alg2);

        var (publicKey1, secretKey1) = sig1.GenerateKeyPair();
        var (publicKey2, secretKey2) = sig2.GenerateKeyPair();

        var message = new byte[128];
        RandomNumberGenerator.Fill(message);

        var signature1 = sig1.Sign(message, secretKey1);
        var signature2 = sig2.Sign(message, secretKey2);

        if (sig1.PublicKeyLength == sig2.PublicKeyLength && sig1.SignatureLength == sig2.SignatureLength)
        {
            var wrongVerify1 = sig1.Verify(message, signature2, publicKey2);
            var wrongVerify2 = sig2.Verify(message, signature1, publicKey1);

            wrongVerify1.Should().BeFalse(
                $"{alg1} should not verify signature from {alg2}");
            wrongVerify2.Should().BeFalse(
                $"{alg2} should not verify signature from {alg1}");
        }
    }

    [Theory]
    [InlineData(SignatureAlgorithms.ML_DSA_44)]
    [InlineData(SignatureAlgorithms.ML_DSA_65)]
    [InlineData(SignatureAlgorithms.ML_DSA_87)]
    [InlineData(SignatureAlgorithms.Dilithium2)]
    [InlineData(SignatureAlgorithms.Dilithium3)]
    [InlineData(SignatureAlgorithms.Dilithium5)]
    [InlineData(SignatureAlgorithms.Falcon_512)]
    [InlineData(SignatureAlgorithms.Falcon_1024)]
    public void CommonAlgorithms_ComprehensiveTest(string algorithm)
    {
        if (!Sig.IsAlgorithmSupported(algorithm))
            return;

        using var sig = new Sig(algorithm);

        sig.AlgorithmName.Should().Be(algorithm);
        sig.PublicKeyLength.Should().BeGreaterThan(0);
        sig.SecretKeyLength.Should().BeGreaterThan(0);
        sig.SignatureLength.Should().BeGreaterThan(0);
        sig.ClaimedNistLevel.Should().BeInRange(1, 5);
        sig.IsEufCma.Should().BeTrue();

        var (publicKey, secretKey) = sig.GenerateKeyPair();
        publicKey.Length.Should().Be(sig.PublicKeyLength);
        secretKey.Length.Should().Be(sig.SecretKeyLength);

        var testMessages = new[]
        {
            [],
            "B"u8.ToArray(),
            new byte[32],
            [.. Enumerable.Range(0, 256).Select(i => (byte)i)],
        };

        RandomNumberGenerator.Fill(testMessages[2]);

        foreach (var message in testMessages)
        {
            var signature = sig.Sign(message, secretKey);
            signature.Should().NotBeNull();
            signature.Length.Should().BeLessThanOrEqualTo(sig.SignatureLength);

            var isValid = sig.Verify(message, signature, publicKey);
            isValid.Should().BeTrue($"{algorithm} should verify message of length {message.Length}");

            if (message.Length > 0)
            {
                var modifiedMessage = (byte[])message.Clone();
                modifiedMessage[0] ^= 0xFF;
                var isInvalid = sig.Verify(modifiedMessage, signature, publicKey);
                isInvalid.Should().BeFalse($"{algorithm} should not verify modified message");
            }
        }
    }

#pragma warning restore S1144
}