using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.SIG.Tests;

[Collection("LibOqs Collection")]
public class SigProviderTests(LibOqsTestFixture fixture)
{
    #pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void AlgorithmCount_ShouldReturnPositiveNumber()
    {
        var count = SigProvider.AlgorithmCount;
        count.Should().BeGreaterThan(0);
    }

    [Fact]
    public void IsAlgorithmEnabled_WithNullAlgorithmName_ShouldThrowArgumentException()
    {
        var act = () => SigProvider.IsAlgorithmEnabled(null!);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void IsAlgorithmEnabled_WithEmptyAlgorithmName_ShouldThrowArgumentException()
    {
        var act = () => SigProvider.IsAlgorithmEnabled("");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void IsAlgorithmEnabled_WithWhitespaceAlgorithmName_ShouldThrowArgumentException()
    {
        var act = () => SigProvider.IsAlgorithmEnabled("   ");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void IsAlgorithmEnabled_WithValidAlgorithm_ShouldReturnTrue()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            var result = SigProvider.IsAlgorithmEnabled(supportedAlgorithms[0]);
            result.Should().BeTrue();
        }
    }

    [Fact]
    public void IsAlgorithmEnabled_WithInvalidAlgorithm_ShouldReturnFalse()
    {
        var result = SigProvider.IsAlgorithmEnabled("NonExistentAlgorithm");
        result.Should().BeFalse();
    }

    [Fact]
    public void GetAlgorithmIdentifier_WithNegativeIndex_ShouldThrowArgumentOutOfRangeException()
    {
        var act = () => SigProvider.GetAlgorithmIdentifier(-1);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void GetAlgorithmIdentifier_WithValidIndex_ShouldReturnNonEmptyString()
    {
        var count = SigProvider.AlgorithmCount;
        if (count > 0)
        {
            var identifier = SigProvider.GetAlgorithmIdentifier(0);
            identifier.Should().NotBeNullOrEmpty();
        }
    }

    [Fact]
    public void GetAlgorithmIdentifier_WithInvalidIndex_ShouldThrowArgumentOutOfRangeException()
    {
        var count = SigProvider.AlgorithmCount;
        var act = () => SigProvider.GetAlgorithmIdentifier(count + 100);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void GetSupportedAlgorithms_ShouldReturnNonEmptyCollection()
    {
        var algorithms = SigProvider.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        foreach (var algorithm in algorithms)
        {
            algorithm.Should().NotBeNullOrEmpty();
            SigProvider.IsAlgorithmEnabled(algorithm).Should().BeTrue();
        }
    }

    [Fact]
    public void Create_WithNullAlgorithmName_ShouldThrowArgumentException()
    {
        var act = () => SigProvider.Create(null!);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Create_WithEmptyAlgorithmName_ShouldThrowArgumentException()
    {
        var act = () => SigProvider.Create("");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Create_WithWhitespaceAlgorithmName_ShouldThrowArgumentException()
    {
        var act = () => SigProvider.Create("   ");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Create_WithUnsupportedAlgorithm_ShouldThrowNotSupportedException()
    {
        var act = () => SigProvider.Create("UnsupportedAlgorithm");
        act.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void Create_WithValidAlgorithm_ShouldReturnSigInstance()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);
            sig.Should().NotBeNull();
            sig.AlgorithmName.Should().Be(supportedAlgorithms[0]);
        }
    }

    [Fact]
    public void SigInstance_AlgorithmName_ShouldReturnCorrectName()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);
            sig.AlgorithmName.Should().Be(supportedAlgorithms[0]);
        }
    }

    [Fact]
    public void SigInstance_SupportsContextString_ShouldReturnValidResult()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);
            var supportsContext = sig.SupportsContextString();
            supportsContext.Should().Be(supportsContext); // Just verify no exception
        }
    }

    [Fact]
    public void SigInstance_GetAlgorithmInfo_ShouldReturnValidInfo()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);
            var info = sig.GetAlgorithmInfo();

            info.method_name.Should().NotBe(IntPtr.Zero);
            info.length_public_key.Should().BeGreaterThan(0);
            info.length_secret_key.Should().BeGreaterThan(0);
            info.length_signature.Should().BeGreaterThan(0);
            info.claimed_nist_level.Should().BeInRange(1, 5);
        }
    }

    [Fact]
    public void SigInstance_GenerateKeyPair_ShouldCreateValidKeyPair()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);
            using var keyPair = sig.GenerateKeyPair();

            keyPair.PublicKey.Should().NotBeEmpty();
            keyPair.SecretKey.Should().NotBeEmpty();
            keyPair.PublicKey.Length.Should().BeGreaterThan(0);
            keyPair.SecretKey.Length.Should().BeGreaterThan(0);
        }
    }

    [Fact]
    public void SigInstance_GenerateKeyPair_ShouldCreateDifferentKeyPairs()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);

            using var keyPair1 = sig.GenerateKeyPair();
            using var keyPair2 = sig.GenerateKeyPair();

            keyPair1.PublicKey.Should().NotEqual(keyPair2.PublicKey);
            keyPair1.SecretKey.Should().NotEqual(keyPair2.SecretKey);
        }
    }

    [Fact]
    public void SigInstance_SignAndVerify_ShouldWorkCorrectly()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);
            using var keyPair = sig.GenerateKeyPair();

            var message = new byte[32];
            RandomNumberGenerator.Fill(message);

            var signature = sig.Sign(message, keyPair.SecretKey);
            signature.Should().NotBeEmpty();

            var isValid = sig.Verify(message, signature, keyPair.PublicKey);
            isValid.Should().BeTrue();
        }
    }

    [Fact]
    public void SigInstance_Verify_WithWrongMessage_ShouldReturnFalse()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);
            using var keyPair = sig.GenerateKeyPair();

            var message = new byte[32];
            RandomNumberGenerator.Fill(message);

            var signature = sig.Sign(message, keyPair.SecretKey);

            var wrongMessage = new byte[32];
            RandomNumberGenerator.Fill(wrongMessage);

            var isValid = sig.Verify(wrongMessage, signature, keyPair.PublicKey);
            isValid.Should().BeFalse();
        }
    }

    [Fact]
    public void SigInstance_Verify_WithWrongSignature_ShouldReturnFalse()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);
            using var keyPair = sig.GenerateKeyPair();

            var message = new byte[32];
            RandomNumberGenerator.Fill(message);

            var wrongSignature = new byte[100];
            RandomNumberGenerator.Fill(wrongSignature);

            var isValid = sig.Verify(message, wrongSignature, keyPair.PublicKey);
            isValid.Should().BeFalse();
        }
    }

    [Fact]
    public void SigInstance_Verify_WithWrongPublicKey_ShouldReturnFalse()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);
            using var keyPair1 = sig.GenerateKeyPair();
            using var keyPair2 = sig.GenerateKeyPair();

            var message = new byte[32];
            RandomNumberGenerator.Fill(message);

            var signature = sig.Sign(message, keyPair1.SecretKey);

            var isValid = sig.Verify(message, signature, keyPair2.PublicKey);
            isValid.Should().BeFalse();
        }
    }

    [Fact]
    public void SigInstance_Sign_WithInvalidSecretKeyLength_ShouldThrowArgumentException()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);

            var message = new byte[32];
            var invalidSecretKey = new byte[10]; // Wrong length

            var act = () => sig.Sign(message, invalidSecretKey);
            act.Should().Throw<ArgumentException>();
        }
    }

    [Fact]
    public void SigInstance_Verify_WithInvalidPublicKeyLength_ShouldThrowArgumentException()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);

            var message = new byte[32];
            var signature = new byte[100];
            var invalidPublicKey = new byte[10]; // Wrong length

            var act = () => sig.Verify(message, signature, invalidPublicKey);
            act.Should().Throw<ArgumentException>();
        }
    }

    [Fact]
    public void SigInstance_SignWithContext_WithUnsupportedAlgorithm_ShouldThrowNotSupportedException()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        var algorithmWithoutContext = supportedAlgorithms.FirstOrDefault(alg =>
        {
            using var tempSig = SigProvider.Create(alg);
            return !tempSig.SupportsContextString();
        });

        if (algorithmWithoutContext != null)
        {
            using var sig = SigProvider.Create(algorithmWithoutContext);
            using var keyPair = sig.GenerateKeyPair();

            var message = new byte[32];
            var context = new byte[10];

            var act = () => sig.SignWithContext(message, context, keyPair.SecretKey);
            act.Should().Throw<NotSupportedException>();
        }
    }

    [Fact]
    public void SigInstance_VerifyWithContext_WithUnsupportedAlgorithm_ShouldThrowNotSupportedException()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        var algorithmWithoutContext = supportedAlgorithms.FirstOrDefault(alg =>
        {
            using var tempSig = SigProvider.Create(alg);
            return !tempSig.SupportsContextString();
        });

        if (algorithmWithoutContext != null)
        {
            using var sig = SigProvider.Create(algorithmWithoutContext);

            var message = new byte[32];
            var signature = new byte[100];
            var context = new byte[10];
            var publicKey = new byte[100];

            var act = () => sig.VerifyWithContext(message, signature, context, publicKey);
            act.Should().Throw<NotSupportedException>();
        }
    }

    [Fact]
    public void SigInstance_SignAndVerifyWithContext_ShouldWorkCorrectly()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        var algorithmWithContext = supportedAlgorithms.FirstOrDefault(alg =>
        {
            using var tempSig = SigProvider.Create(alg);
            return tempSig.SupportsContextString();
        });

        if (algorithmWithContext != null)
        {
            using var sig = SigProvider.Create(algorithmWithContext);
            using var keyPair = sig.GenerateKeyPair();

            var message = new byte[32];
            RandomNumberGenerator.Fill(message);

            var context = "test-context"u8.ToArray();

            var signature = sig.SignWithContext(message, context, keyPair.SecretKey);
            signature.Should().NotBeEmpty();

            var isValid = sig.VerifyWithContext(message, signature, context, keyPair.PublicKey);
            isValid.Should().BeTrue();
        }
    }

    [Fact]
    public void SigInstance_VerifyWithContext_WithWrongContext_ShouldReturnFalse()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        var algorithmWithContext = supportedAlgorithms.FirstOrDefault(alg =>
        {
            using var tempSig = SigProvider.Create(alg);
            return tempSig.SupportsContextString();
        });

        if (algorithmWithContext != null)
        {
            using var sig = SigProvider.Create(algorithmWithContext);
            using var keyPair = sig.GenerateKeyPair();

            var message = new byte[32];
            RandomNumberGenerator.Fill(message);

            var context1 = "context1"u8.ToArray();
            var context2 = "context2"u8.ToArray();

            var signature = sig.SignWithContext(message, context1, keyPair.SecretKey);

            var isValid = sig.VerifyWithContext(message, signature, context2, keyPair.PublicKey);
            isValid.Should().BeFalse();
        }
    }

    [Fact]
    public void SigInstance_SignWithContext_WithInvalidSecretKeyLength_ShouldThrowArgumentException()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        var algorithmWithContext = supportedAlgorithms.FirstOrDefault(alg =>
        {
            using var tempSig = SigProvider.Create(alg);
            return tempSig.SupportsContextString();
        });

        if (algorithmWithContext != null)
        {
            using var sig = SigProvider.Create(algorithmWithContext);

            var message = new byte[32];
            var context = new byte[10];
            var invalidSecretKey = new byte[10]; // Wrong length

            var act = () => sig.SignWithContext(message, context, invalidSecretKey);
            act.Should().Throw<ArgumentException>();
        }
    }

    [Fact]
    public void SigInstance_VerifyWithContext_WithInvalidPublicKeyLength_ShouldThrowArgumentException()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        var algorithmWithContext = supportedAlgorithms.FirstOrDefault(alg =>
        {
            using var tempSig = SigProvider.Create(alg);
            return tempSig.SupportsContextString();
        });

        if (algorithmWithContext != null)
        {
            using var sig = SigProvider.Create(algorithmWithContext);

            var message = new byte[32];
            var signature = new byte[100];
            var context = new byte[10];
            var invalidPublicKey = new byte[10]; // Wrong length

            var act = () => sig.VerifyWithContext(message, signature, context, invalidPublicKey);
            act.Should().Throw<ArgumentException>();
        }
    }

    [Fact]
    public void SigInstance_AfterDisposal_ShouldThrowObjectDisposedException()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            var sig = SigProvider.Create(supportedAlgorithms[0]);
            sig.Dispose();

            var act = () => sig.SupportsContextString();
            act.Should().Throw<ObjectDisposedException>();
        }
    }

    [Fact]
    public void SigInstance_DoubleDisposal_ShouldNotThrow()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            var sig = SigProvider.Create(supportedAlgorithms[0]);
            sig.Dispose();

            var act = () => sig.Dispose();
            act.Should().NotThrow();
        }
    }

    [Fact]
    public void SigKeyPair_AfterDisposal_SecretKeyShouldBeCleared()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);
            var keyPair = sig.GenerateKeyPair();
            var secretKeyCopy = keyPair.SecretKey.ToArray();

            keyPair.Dispose();

            keyPair.SecretKey.Should().AllSatisfy(b => b.Should().Be(0));
            keyPair.SecretKey.Should().NotEqual(secretKeyCopy);
        }
    }

    [Fact]
    public void SigKeyPair_PublicKeyNotAffectedByDisposal()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);
            var keyPair = sig.GenerateKeyPair();
            var publicKeyCopy = keyPair.PublicKey.ToArray();

            keyPair.Dispose();

            keyPair.PublicKey.Should().Equal(publicKeyCopy);
        }
    }

    [Fact]
    public void SigInstance_Sign_WithEmptyMessage_ShouldWork()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);
            using var keyPair = sig.GenerateKeyPair();

            var emptyMessage = Array.Empty<byte>();

            var signature = sig.Sign(emptyMessage, keyPair.SecretKey);
            signature.Should().NotBeEmpty();

            var isValid = sig.Verify(emptyMessage, signature, keyPair.PublicKey);
            isValid.Should().BeTrue();
        }
    }

    [Fact]
    public void SigInstance_SignWithContext_WithEmptyMessage_ShouldWork()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        var algorithmWithContext = supportedAlgorithms.FirstOrDefault(alg =>
        {
            using var tempSig = SigProvider.Create(alg);
            return tempSig.SupportsContextString();
        });

        if (algorithmWithContext != null)
        {
            using var sig = SigProvider.Create(algorithmWithContext);
            using var keyPair = sig.GenerateKeyPair();

            var emptyMessage = Array.Empty<byte>();
            var context = "test"u8.ToArray();

            var signature = sig.SignWithContext(emptyMessage, context, keyPair.SecretKey);
            signature.Should().NotBeEmpty();

            var isValid = sig.VerifyWithContext(emptyMessage, signature, context, keyPair.PublicKey);
            isValid.Should().BeTrue();
        }
    }

    [Fact]
    public void SigInstance_SignWithContext_WithEmptyContext_ShouldWork()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        var algorithmWithContext = supportedAlgorithms.FirstOrDefault(alg =>
        {
            using var tempSig = SigProvider.Create(alg);
            return tempSig.SupportsContextString();
        });

        if (algorithmWithContext != null)
        {
            using var sig = SigProvider.Create(algorithmWithContext);
            using var keyPair = sig.GenerateKeyPair();

            var message = new byte[32];
            RandomNumberGenerator.Fill(message);
            var emptyContext = Array.Empty<byte>();

            var signature = sig.SignWithContext(message, emptyContext, keyPair.SecretKey);
            signature.Should().NotBeEmpty();

            var isValid = sig.VerifyWithContext(message, signature, emptyContext, keyPair.PublicKey);
            isValid.Should().BeTrue();
        }
    }

    [Fact]
    public void SigInstance_Sign_WithLargeMessage_ShouldWork()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        if (supportedAlgorithms.Count > 0)
        {
            using var sig = SigProvider.Create(supportedAlgorithms[0]);
            using var keyPair = sig.GenerateKeyPair();

            var largeMessage = new byte[1024 * 1024]; // 1MB
            RandomNumberGenerator.Fill(largeMessage);

            var signature = sig.Sign(largeMessage, keyPair.SecretKey);
            signature.Should().NotBeEmpty();

            var isValid = sig.Verify(largeMessage, signature, keyPair.PublicKey);
            isValid.Should().BeTrue();
        }
    }

    [Fact]
    public void SigInstance_SignWithContext_WithLargeMessage_ShouldWork()
    {
        var supportedAlgorithms = SigProvider.GetSupportedAlgorithms().ToList();
        var algorithmWithContext = supportedAlgorithms.FirstOrDefault(alg =>
        {
            using var tempSig = SigProvider.Create(alg);
            return tempSig.SupportsContextString();
        });

        if (algorithmWithContext != null)
        {
            using var sig = SigProvider.Create(algorithmWithContext);
            using var keyPair = sig.GenerateKeyPair();

            var largeMessage = new byte[1024 * 1024]; // 1MB
            RandomNumberGenerator.Fill(largeMessage);
            var context = "large-test"u8.ToArray();

            var signature = sig.SignWithContext(largeMessage, context, keyPair.SecretKey);
            signature.Should().NotBeEmpty();

            var isValid = sig.VerifyWithContext(largeMessage, signature, context, keyPair.PublicKey);
            isValid.Should().BeTrue();
        }
    }
}

#pragma warning restore S1144