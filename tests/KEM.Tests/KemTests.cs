using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.KEM.Tests;

[Collection("LibOqs Collection")]
public sealed class KemTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void Constructor_WithNullAlgorithmName_ShouldThrowArgumentNullException()
    {
        var action = () => new Kem(null!);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("algorithmName");
    }

    [Fact]
    public void Constructor_WithUnsupportedAlgorithm_ShouldThrowNotSupportedException()
    {
        var action = () => new Kem("NonExistentAlgorithm123");

        action.Should().Throw<NotSupportedException>()
            .WithMessage("*not enabled or supported*");
    }

    [Fact]
    public void Constructor_WithValidAlgorithm_ShouldInitializeProperties()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kem = new Kem(algorithm);

        kem.AlgorithmName.Should().Be(algorithm);
        kem.PublicKeyLength.Should().BeGreaterThan(0);
        kem.SecretKeyLength.Should().BeGreaterThan(0);
        kem.CiphertextLength.Should().BeGreaterThan(0);
        kem.SharedSecretLength.Should().BeGreaterThan(0);
        kem.ClaimedNistLevel.Should().BeInRange(1, 5);
    }

    [Fact]
    public void GetSupportedAlgorithms_ShouldReturnNonEmptyArray()
    {
        var algorithms = Kem.GetSupportedAlgorithms();

        algorithms.Should().NotBeEmpty();
        algorithms.Should().BeOfType<string[]>();
        algorithms.Should().OnlyContain(alg => !string.IsNullOrEmpty(alg));
    }

    [Fact]
    public void IsAlgorithmSupported_WithNullAlgorithm_ShouldReturnFalse()
    {
        var result = Kem.IsAlgorithmSupported(null!);

        result.Should().BeFalse();
    }

    [Fact]
    public void IsAlgorithmSupported_WithEmptyAlgorithm_ShouldReturnFalse()
    {
        var result = Kem.IsAlgorithmSupported(string.Empty);

        result.Should().BeFalse();
    }

    [Fact]
    public void IsAlgorithmSupported_WithValidAlgorithm_ShouldReturnTrue()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        if (supportedAlgorithms.Length > 0)
        {
            var result = Kem.IsAlgorithmSupported(supportedAlgorithms[0]);
            result.Should().BeTrue();
        }
    }

    [Fact]
    public void IsAlgorithmSupported_WithInvalidAlgorithm_ShouldReturnFalse()
    {
        var result = Kem.IsAlgorithmSupported("NonExistentAlgorithm");

        result.Should().BeFalse();
    }

    [Fact]
    public void GenerateKeyPair_ShouldReturnValidKeyPair()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, secretKey) = kem.GenerateKeyPair();

        publicKey.Should().NotBeNull();
        secretKey.Should().NotBeNull();
        publicKey.Length.Should().Be(kem.PublicKeyLength);
        secretKey.Length.Should().Be(kem.SecretKeyLength);
    }

    [Fact]
    public void GenerateKeyPair_MultipleCalls_ShouldProduceDifferentKeys()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey1, secretKey1) = kem.GenerateKeyPair();
        var (publicKey2, secretKey2) = kem.GenerateKeyPair();

        publicKey1.Should().NotBeEquivalentTo(publicKey2);
        secretKey1.Should().NotBeEquivalentTo(secretKey2);
    }

    [Fact]
    public void Encapsulate_WithNullPublicKey_ShouldThrowArgumentNullException()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kem = new Kem(algorithm);

        var action = () => kem.Encapsulate(null!);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("publicKey");
    }

    [Fact]
    public void Encapsulate_WithValidPublicKey_ShouldReturnValidResult()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, _) = kem.GenerateKeyPair();
        var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);

        ciphertext.Should().NotBeNull();
        sharedSecret.Should().NotBeNull();
        ciphertext.Length.Should().Be(kem.CiphertextLength);
        sharedSecret.Length.Should().Be(kem.SharedSecretLength);
    }

    [Fact]
    public void Decapsulate_WithNullCiphertext_ShouldThrowArgumentNullException()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kem = new Kem(algorithm);
        var (_, secretKey) = kem.GenerateKeyPair();

        var action = () => kem.Decapsulate(null!, secretKey);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("ciphertext");
    }

    [Fact]
    public void Decapsulate_WithNullSecretKey_ShouldThrowArgumentNullException()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kem = new Kem(algorithm);
        var (publicKey, _) = kem.GenerateKeyPair();
        var (ciphertext, _) = kem.Encapsulate(publicKey);

        var action = () => kem.Decapsulate(ciphertext, null!);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("secretKey");
    }

    [Fact] 
    public void GenerateKeyPair_AfterDispose_ShouldThrowObjectDisposedException()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        var kem = new Kem(algorithm);
        kem.Dispose();

        var action = () => kem.GenerateKeyPair();
        action.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Encapsulate_AfterDispose_ShouldThrowObjectDisposedException()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        var kem = new Kem(algorithm);
        var (publicKey, _) = kem.GenerateKeyPair();
        kem.Dispose();

        var action = () => kem.Encapsulate(publicKey);
        action.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Decapsulate_AfterDispose_ShouldThrowObjectDisposedException()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        var kem = new Kem(algorithm);
        var (publicKey, secretKey) = kem.GenerateKeyPair();
        var (ciphertext, _) = kem.Encapsulate(publicKey);
        kem.Dispose();

        var action = () => kem.Decapsulate(ciphertext, secretKey);
        action.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Dispose_CalledMultipleTimes_ShouldNotThrow()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kem = new Kem(algorithm);

        var action = () =>
        {
            kem.Dispose();
            kem.Dispose();
            kem.Dispose();
        };
        
        action.Should().NotThrow("Multiple dispose calls should be safe");
    }

    [Fact]
    public void EncapsulateAndDecapsulate_ShouldRecoverSameSharedSecret()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, secretKey) = kem.GenerateKeyPair();
        var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
        var recoveredSecret = kem.Decapsulate(ciphertext, secretKey);

        recoveredSecret.Should().BeEquivalentTo(sharedSecret);
    }

    [Fact]
    public void Dispose_ShouldNotAllowFurtherOperations()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        var kem = new Kem(algorithm);
        kem.Dispose();

        var actions = new Action[]
        {
            () => kem.GenerateKeyPair(),
            () => kem.Encapsulate(new byte[100]),
            () => kem.Decapsulate(new byte[100], new byte[100])
        };

        foreach (var action in actions)
        {
            action.Should().Throw<ObjectDisposedException>();
        }
    }

    [Fact]
    public void DoubleDispose_ShouldNotThrow()
    {
        var supportedAlgorithms = Kem.GetSupportedAlgorithms();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        var kem = new Kem(algorithm);
        kem.Dispose();

        var action = () => kem.Dispose();

        action.Should().NotThrow();
    }

    [Theory]
    [InlineData("KYBER512")]
    [InlineData("KYBER768")]
    [InlineData("KYBER1024")]
    [InlineData("ML-KEM-512")]
    [InlineData("ML-KEM-768")]
    [InlineData("ML-KEM-1024")]
    public void CommonAlgorithms_ShouldWorkIfEnabled(string algorithm)
    {
        if (Kem.IsAlgorithmSupported(algorithm))
        {
            using var kem = new Kem(algorithm);
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
            var recoveredSecret = kem.Decapsulate(ciphertext, secretKey);

            recoveredSecret.Should().BeEquivalentTo(sharedSecret);
        }
    }

#pragma warning restore S1144
}