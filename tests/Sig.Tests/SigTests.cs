using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.SIG.Tests;

[Collection("LibOqs Collection")]
public sealed class SigTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void Constructor_WithNullAlgorithmName_ShouldThrowArgumentNullException()
    {
        var action = () => new Sig(null!);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("algorithmName");
    }

    [Fact]
    public void Constructor_WithUnsupportedAlgorithm_ShouldThrowNotSupportedException()
    {
        var action = () => new Sig("NonExistentAlgorithm123");

        action.Should().Throw<NotSupportedException>()
            .WithMessage("*not enabled or supported*");
    }

    [Fact]
    public void Constructor_WithValidAlgorithm_ShouldInitializeProperties()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var sig = new Sig(algorithm);

        sig.AlgorithmName.Should().Be(algorithm);
        sig.PublicKeyLength.Should().BeGreaterThan(0);
        sig.SecretKeyLength.Should().BeGreaterThan(0);
        sig.SignatureLength.Should().BeGreaterThan(0);
        sig.ClaimedNistLevel.Should().BeInRange(1, 5);
    }

    [Fact]
    public void GetSupportedAlgorithms_ShouldReturnNonEmptyArray()
    {
        var algorithms = Sig.GetSupportedAlgorithms();

        algorithms.Should().NotBeEmpty();
        algorithms.Should().BeOfType<string[]>();
        algorithms.Should().OnlyContain(alg => !string.IsNullOrEmpty(alg));
    }

    [Fact]
    public void IsAlgorithmSupported_WithNullAlgorithm_ShouldReturnFalse()
    {
        var result = Sig.IsAlgorithmSupported(null!);

        result.Should().BeFalse();
    }

    [Fact]
    public void IsAlgorithmSupported_WithEmptyAlgorithm_ShouldReturnFalse()
    {
        var result = Sig.IsAlgorithmSupported(string.Empty);

        result.Should().BeFalse();
    }

    [Fact]
    public void IsAlgorithmSupported_WithValidAlgorithm_ShouldReturnTrue()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        if (supportedAlgorithms.Length > 0)
        {
            var result = Sig.IsAlgorithmSupported(supportedAlgorithms[0]);
            result.Should().BeTrue();
        }
    }

    [Fact]
    public void IsAlgorithmSupported_WithInvalidAlgorithm_ShouldReturnFalse()
    {
        var result = Sig.IsAlgorithmSupported("NonExistentAlgorithm");

        result.Should().BeFalse();
    }

    [Fact]
    public void GenerateKeyPair_ShouldReturnValidKeyPair()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var sig = new Sig(algorithm);

        var (publicKey, secretKey) = sig.GenerateKeyPair();

        publicKey.Should().NotBeNull();
        secretKey.Should().NotBeNull();
        publicKey.Length.Should().Be(sig.PublicKeyLength);
        secretKey.Length.Should().Be(sig.SecretKeyLength);
    }

    [Fact]
    public void GenerateKeyPair_MultipleCalls_ShouldProduceDifferentKeys()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var sig = new Sig(algorithm);

        var (publicKey1, secretKey1) = sig.GenerateKeyPair();
        var (publicKey2, secretKey2) = sig.GenerateKeyPair();

        publicKey1.Should().NotBeEquivalentTo(publicKey2);
        secretKey1.Should().NotBeEquivalentTo(secretKey2);
    }

    [Fact]
    public void Sign_WithNullMessage_ShouldThrowArgumentNullException()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var sig = new Sig(algorithm);
        var (_, secretKey) = sig.GenerateKeyPair();

        var action = () => sig.Sign(null!, secretKey);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("message");
    }

    [Fact]
    public void Sign_WithNullSecretKey_ShouldThrowArgumentNullException()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var sig = new Sig(algorithm);
        var message = new byte[32];

        var action = () => sig.Sign(message, null!);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("secretKey");
    }

    [Fact]
    public void Sign_WithValidInputs_ShouldReturnSignature()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var sig = new Sig(algorithm);
        var (_, secretKey) = sig.GenerateKeyPair();

        var message = new byte[32];
        RandomNumberGenerator.Fill(message);

        var signature = sig.Sign(message, secretKey);

        signature.Should().NotBeNull();
        signature.Should().NotBeEmpty();
        signature.Length.Should().BeLessThanOrEqualTo(sig.SignatureLength);
    }

    [Fact]
    public void Verify_WithNullMessage_ShouldThrowArgumentNullException()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, _) = sig.GenerateKeyPair();
        var signature = new byte[100];

        var action = () => sig.Verify(null!, signature, publicKey);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("message");
    }

    [Fact]
    public void GenerateKeyPair_AfterDispose_ShouldThrowObjectDisposedException()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        var sig = new Sig(algorithm);
        sig.Dispose();

        var action = () => sig.GenerateKeyPair();
        action.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Sign_AfterDispose_ShouldThrowObjectDisposedException()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        var sig = new Sig(algorithm);
        var (_, secretKey) = sig.GenerateKeyPair();
        sig.Dispose();

        var message = new byte[32];
        var action = () => sig.Sign(message, secretKey);
        action.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Verify_AfterDispose_ShouldThrowObjectDisposedException()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();
        var message = new byte[32];
        var signature = sig.Sign(message, secretKey);
        sig.Dispose();

        var action = () => sig.Verify(message, signature, publicKey);
        action.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Dispose_CalledMultipleTimes_ShouldNotThrow()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var sig = new Sig(algorithm);

        var action = () =>
        {
            sig.Dispose();
            sig.Dispose();
            sig.Dispose();
        };
        
        action.Should().NotThrow("Multiple dispose calls should be safe");
    }

    [Fact]
    public void Verify_WithNullSignature_ShouldThrowArgumentNullException()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, _) = sig.GenerateKeyPair();
        var message = new byte[32];

        var action = () => sig.Verify(message, null!, publicKey);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("signature");
    }

    [Fact]
    public void Verify_WithNullPublicKey_ShouldThrowArgumentNullException()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var sig = new Sig(algorithm);
        var message = new byte[32];
        var signature = new byte[100];

        var action = () => sig.Verify(message, signature, null!);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("publicKey");
    }

    [Fact]
    public void SignAndVerify_WithValidInputs_ShouldSucceed()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var message = new byte[32];
        RandomNumberGenerator.Fill(message);

        var signature = sig.Sign(message, secretKey);
        var isValid = sig.Verify(message, signature, publicKey);

        isValid.Should().BeTrue();
    }

    [Fact]
    public void Verify_WithWrongMessage_ShouldReturnFalse()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var message = new byte[32];
        RandomNumberGenerator.Fill(message);
        var signature = sig.Sign(message, secretKey);

        var wrongMessage = new byte[32];
        RandomNumberGenerator.Fill(wrongMessage);
        var isValid = sig.Verify(wrongMessage, signature, publicKey);

        isValid.Should().BeFalse();
    }

    [Fact]
    public void Verify_WithWrongPublicKey_ShouldReturnFalse()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var sig = new Sig(algorithm);
        var (_, secretKey1) = sig.GenerateKeyPair();
        var (publicKey2, _) = sig.GenerateKeyPair();

        var message = new byte[32];
        RandomNumberGenerator.Fill(message);
        var signature = sig.Sign(message, secretKey1);

        var isValid = sig.Verify(message, signature, publicKey2);

        isValid.Should().BeFalse();
    }

    [Fact]
    public void Sign_WithEmptyMessage_ShouldWork()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var emptyMessage = Array.Empty<byte>();
        var signature = sig.Sign(emptyMessage, secretKey);
        var isValid = sig.Verify(emptyMessage, signature, publicKey);

        isValid.Should().BeTrue();
    }

    [Fact]
    public void Dispose_ShouldNotAllowFurtherOperations()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        var sig = new Sig(algorithm);
        sig.Dispose();

        var actions = new Action[]
        {
            () => sig.GenerateKeyPair(),
            () => sig.Sign(new byte[32], new byte[100]),
            () => sig.Verify(new byte[32], new byte[100], new byte[100])
        };

        foreach (var action in actions)
        {
            action.Should().Throw<ObjectDisposedException>();
        }
    }

    [Fact]
    public void DoubleDispose_ShouldNotThrow()
    {
        var supportedAlgorithms = Sig.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        var sig = new Sig(algorithm);
        sig.Dispose();

        var action = () => sig.Dispose();

        action.Should().NotThrow();
    }

    [Theory]
    [InlineData("Dilithium2")]
    [InlineData("Dilithium3")]
    [InlineData("Dilithium5")]
    [InlineData("ML-DSA-44")]
    [InlineData("ML-DSA-65")]
    [InlineData("ML-DSA-87")]
    public void CommonAlgorithms_ShouldWorkIfEnabled(string algorithm)
    {
        if (Sig.IsAlgorithmSupported(algorithm))
        {
            using var sig = new Sig(algorithm);
            var (publicKey, secretKey) = sig.GenerateKeyPair();

            var message = new byte[32];
            RandomNumberGenerator.Fill(message);

            var signature = sig.Sign(message, secretKey);
            var isValid = sig.Verify(message, signature, publicKey);

            isValid.Should().BeTrue();
        }
    }

#pragma warning restore S1144
}