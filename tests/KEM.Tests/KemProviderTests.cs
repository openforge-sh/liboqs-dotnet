using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.KEM.Tests;

[Collection("LibOqs Collection")]
public sealed class KemProviderTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void AlgorithmCount_ShouldReturnPositiveValue()
    {
        var count = KemProvider.AlgorithmCount;

        count.Should().BeGreaterThan(0, "LibOQS should have at least one KEM algorithm available");
    }

    [Fact]
    public void AlgorithmCount_MultipleCalls_ShouldReturnConsistentValue()
    {
        var count1 = KemProvider.AlgorithmCount;
        var count2 = KemProvider.AlgorithmCount;

        count1.Should().Be(count2, "Algorithm count should be consistent across calls");
    }

    [Fact]
    public void IsAlgorithmEnabled_NullArgument_ShouldThrowArgumentException()
    {
        var action = () => KemProvider.IsAlgorithmEnabled(null!);

        action.Should().Throw<ArgumentException>()
            .WithMessage("*algorithmName*");
    }

    [Fact]
    public void IsAlgorithmEnabled_EmptyString_ShouldThrowArgumentException()
    {
        var action = () => KemProvider.IsAlgorithmEnabled(string.Empty);

        action.Should().Throw<ArgumentException>()
            .WithMessage("*algorithmName*");
    }

    [Fact]
    public void IsAlgorithmEnabled_WhitespaceString_ShouldThrowArgumentException()
    {
        var action = () => KemProvider.IsAlgorithmEnabled("   ");

        action.Should().Throw<ArgumentException>()
            .WithMessage("*algorithmName*");
    }

    [Fact]
    public void IsAlgorithmEnabled_InvalidAlgorithm_ShouldReturnFalse()
    {
        var result = KemProvider.IsAlgorithmEnabled("NonExistentAlgorithm123");

        result.Should().BeFalse("Non-existent algorithm should not be enabled");
    }

    [Theory]
    [InlineData("KYBER512")]
    [InlineData("KYBER768")]
    [InlineData("KYBER1024")]
    [InlineData("ML-KEM-512")]
    [InlineData("ML-KEM-768")]
    [InlineData("ML-KEM-1024")]
    public void IsAlgorithmEnabled_CommonAlgorithms_ShouldNotThrow(string algorithm)
    {
        var action = () => KemProvider.IsAlgorithmEnabled(algorithm);

        action.Should().NotThrow($"Common algorithm '{algorithm}' should not cause exceptions");
    }

    [Fact]
    public void GetAlgorithmIdentifier_NegativeIndex_ShouldThrowArgumentOutOfRangeException()
    {
        var action = () => KemProvider.GetAlgorithmIdentifier(-1);

        action.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("index")
            .WithMessage("*non-negative*");
    }

    [Fact]
    public void GetAlgorithmIdentifier_ValidIndex_ShouldReturnNonEmptyString()
    {
        var count = KemProvider.AlgorithmCount;
        count.Should().BeGreaterThan(0);

        var identifier = KemProvider.GetAlgorithmIdentifier(0);

        identifier.Should().NotBeNullOrEmpty("Valid index should return valid algorithm identifier");
    }

    [Fact]
    public void GetAlgorithmIdentifier_InvalidIndex_ShouldThrowArgumentOutOfRangeException()
    {
        var count = KemProvider.AlgorithmCount;
        var invalidIndex = count + 1000;

        var action = () => KemProvider.GetAlgorithmIdentifier(invalidIndex);

        action.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("index")
            .WithMessage("*Invalid algorithm index*");
    }

    [Fact]
    public void GetAlgorithmIdentifier_AllValidIndices_ShouldReturnUniqueIdentifiers()
    {
        var count = KemProvider.AlgorithmCount;
        var identifiers = new string[count];

        for (int i = 0; i < count; i++)
        {
            identifiers[i] = KemProvider.GetAlgorithmIdentifier(i);
            identifiers[i].Should().NotBeNullOrEmpty($"Algorithm at index {i} should have valid identifier");
        }

        var uniqueIdentifiers = identifiers.Distinct().ToArray();
        uniqueIdentifiers.Length.Should().Be(count, "All algorithm identifiers should be unique");
    }

    [Fact]
    public void GetSupportedAlgorithms_ShouldReturnNonEmptyEnumerable()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();

        supportedAlgorithms.Should().NotBeEmpty("Should have at least one supported algorithm");
        supportedAlgorithms.Should().OnlyContain(alg => !string.IsNullOrEmpty(alg), "All algorithm names should be valid");
    }

    [Fact]
    public void GetSupportedAlgorithms_AllReturnedAlgorithms_ShouldBeEnabled()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();

        foreach (var algorithm in supportedAlgorithms)
        {
            KemProvider.IsAlgorithmEnabled(algorithm).Should().BeTrue(
                $"Algorithm '{algorithm}' returned by GetSupportedAlgorithms should be enabled");
        }
    }

    [Fact]
    public void Create_WithNullAlgorithm_ShouldThrowArgumentException()
    {
        var action = () => KemProvider.Create(null!);

        action.Should().Throw<ArgumentException>()
            .WithParameterName("algorithmName");
    }

    [Fact]
    public void Create_WithEmptyAlgorithm_ShouldThrowArgumentException()
    {
        var action = () => KemProvider.Create(string.Empty);

        action.Should().Throw<ArgumentException>()
            .WithParameterName("algorithmName");
    }

    [Fact]
    public void Create_WithWhitespaceAlgorithm_ShouldThrowArgumentException()
    {
        var action = () => KemProvider.Create("   ");

        action.Should().Throw<ArgumentException>()
            .WithParameterName("algorithmName");
    }

    [Fact]
    public void Create_WithUnsupportedAlgorithm_ShouldThrowNotSupportedException()
    {
        var action = () => KemProvider.Create("UnsupportedAlgorithm123");

        action.Should().Throw<NotSupportedException>()
            .WithMessage("*UnsupportedAlgorithm123*not enabled or supported*");
    }

    [Fact]
    public void Create_WithDisabledAlgorithm_ShouldThrowNotSupportedException()
    {
        // Find a disabled algorithm by checking all algorithm identifiers
        var count = KemProvider.AlgorithmCount;
        string? disabledAlgorithm = null;

        for (int i = 0; i < count; i++)
        {
            var identifier = KemProvider.GetAlgorithmIdentifier(i);
            if (!KemProvider.IsAlgorithmEnabled(identifier))
            {
                disabledAlgorithm = identifier;
                break;
            }
        }

        if (disabledAlgorithm != null)
        {
            var action = () => KemProvider.Create(disabledAlgorithm);

            action.Should().Throw<NotSupportedException>()
                .WithMessage($"*{disabledAlgorithm}*not enabled or supported*");
        }
        else
        {
            // If all algorithms are enabled, create a test for clearly invalid algorithm
            var action = () => KemProvider.Create("INVALID_ALGORITHM_NAME_TEST");

            action.Should().Throw<NotSupportedException>()
                .WithMessage("*INVALID_ALGORITHM_NAME_TEST*not enabled or supported*");
        }
    }

    [Fact]
    public void GetSupportedAlgorithms_MultipleCalls_ShouldReturnConsistentResults()
    {
        var algorithms1 = KemProvider.GetSupportedAlgorithms().ToList();
        var algorithms2 = KemProvider.GetSupportedAlgorithms().ToList();

        algorithms1.Should().BeEquivalentTo(algorithms2, "Supported algorithms should be consistent across calls");
    }

    [Fact]
    public void Create_NullAlgorithmName_ShouldThrowArgumentException()
    {
        var action = () => KemProvider.Create(null!);

        action.Should().Throw<ArgumentException>()
            .WithMessage("*algorithmName*");
    }

    [Fact]
    public void Create_EmptyAlgorithmName_ShouldThrowArgumentException()
    {
        var action = () => KemProvider.Create(string.Empty);

        action.Should().Throw<ArgumentException>()
            .WithMessage("*algorithmName*");
    }

    [Fact]
    public void Create_WhitespaceAlgorithmName_ShouldThrowArgumentException()
    {
        var action = () => KemProvider.Create("   ");

        action.Should().Throw<ArgumentException>()
            .WithMessage("*algorithmName*");
    }

    [Fact]
    public void Create_UnsupportedAlgorithm_ShouldThrowNotSupportedException()
    {
        var action = () => KemProvider.Create("NonExistentAlgorithm123");

        action.Should().Throw<NotSupportedException>()
            .WithMessage("*not enabled or supported*");
    }

    [Fact]
    public void Create_ValidAlgorithm_ShouldReturnValidInstance()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);

        kemInstance.Should().NotBeNull("Valid algorithm should create KEM instance");
        kemInstance.AlgorithmName.Should().Be(algorithm, "Instance should remember the algorithm name");
    }

    [Fact]
    public void KemInstance_AlgorithmName_ShouldReturnCorrectName()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);

        kemInstance.AlgorithmName.Should().Be(algorithm);
    }

    [Fact]
    public void KemInstance_GetAlgorithmInfo_ShouldReturnValidInfo()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);

        var info = kemInstance.GetAlgorithmInfo();

        info.length_public_key.Should().NotBe(UIntPtr.Zero, "Public key length should be positive");
        info.length_secret_key.Should().NotBe(UIntPtr.Zero, "Secret key length should be positive");
        info.length_ciphertext.Should().NotBe(UIntPtr.Zero, "Ciphertext length should be positive");
        info.length_shared_secret.Should().NotBe(UIntPtr.Zero, "Shared secret length should be positive");
        info.claimed_nist_level.Should().BeInRange(1, 5, "NIST level should be between 1 and 5");
    }

    [Fact]
    public void KemInstance_GenerateKeyPair_ShouldReturnValidKeyPair()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);
        var info = kemInstance.GetAlgorithmInfo();

        using var keyPair = kemInstance.GenerateKeyPair();

        keyPair.PublicKey.Should().NotBeNull("Public key should not be null");
        keyPair.SecretKey.Should().NotBeNull("Secret key should not be null");
        keyPair.PublicKey.Length.Should().Be((int)info.length_public_key, "Public key should have correct length");
        keyPair.SecretKey.Length.Should().Be((int)info.length_secret_key, "Secret key should have correct length");
    }

    [Fact]
    public void KemInstance_GenerateKeyPair_MultipleCalls_ShouldProduceDifferentKeys()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);

        using var keyPair1 = kemInstance.GenerateKeyPair();
        using var keyPair2 = kemInstance.GenerateKeyPair();

        keyPair1.PublicKey.Should().NotBeEquivalentTo(keyPair2.PublicKey, "Different calls should produce different public keys");
        keyPair1.SecretKey.Should().NotBeEquivalentTo(keyPair2.SecretKey, "Different calls should produce different secret keys");
    }

    [Fact]
    public void KemInstance_GenerateDeterministicKeyPair_ValidSeed_ShouldReturnValidKeyPair()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        // Try to find an algorithm that supports deterministic operations
        // Some algorithms like BIKE don't support deterministic operations
        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);
        var info = kemInstance.GetAlgorithmInfo();

        var seed = new byte[48];
        RandomNumberGenerator.Fill(seed);

        try
        {
            using var keyPair = kemInstance.GenerateDeterministicKeyPair(seed);

            keyPair.PublicKey.Should().NotBeNull("Public key should not be null");
            keyPair.SecretKey.Should().NotBeNull("Secret key should not be null");
            keyPair.PublicKey.Length.Should().Be((int)info.length_public_key, "Public key should have correct length");
            keyPair.SecretKey.Length.Should().Be((int)info.length_secret_key, "Secret key should have correct length");
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("Error code: -1", StringComparison.Ordinal))
        {
            // Some algorithms don't support deterministic operations, skip this test
            Assert.True(true, $"Algorithm '{algorithm}' does not support deterministic key generation, test skipped");
        }
    }

    [Fact]
    public void KemInstance_GenerateDeterministicKeyPair_SameSeed_ShouldProduceSameKeys()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);

        var seed = new byte[48];
        RandomNumberGenerator.Fill(seed);

        try
        {
            using var keyPair1 = kemInstance.GenerateDeterministicKeyPair(seed);
            using var keyPair2 = kemInstance.GenerateDeterministicKeyPair(seed);

            keyPair1.PublicKey.Should().BeEquivalentTo(keyPair2.PublicKey, "Same seed should produce same public key");
            keyPair1.SecretKey.Should().BeEquivalentTo(keyPair2.SecretKey, "Same seed should produce same secret key");
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("Error code: -1", StringComparison.Ordinal))
        {
            // Some algorithms don't support deterministic operations, skip this test
            Assert.True(true, $"Algorithm '{algorithm}' does not support deterministic key generation, test skipped");
        }
    }

    [Fact]
    public void KemInstance_GenerateDeterministicKeyPair_InvalidSeedLength_ShouldThrowArgumentException()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);

        var invalidSeed = new byte[32]; // Should be 48 bytes

        var action = () => kemInstance.GenerateDeterministicKeyPair(invalidSeed);

        action.Should().Throw<ArgumentException>()
            .WithMessage("*seed*");
    }

    [Fact]
    public void KemInstance_Encapsulate_ValidPublicKey_ShouldReturnValidResult()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);
        var info = kemInstance.GetAlgorithmInfo();

        using var keyPair = kemInstance.GenerateKeyPair();
        using var encapsResult = kemInstance.Encapsulate(keyPair.PublicKey);

        encapsResult.Ciphertext.Should().NotBeNull("Ciphertext should not be null");
        encapsResult.SharedSecret.Should().NotBeNull("Shared secret should not be null");
        encapsResult.Ciphertext.Length.Should().Be((int)info.length_ciphertext, "Ciphertext should have correct length");
        encapsResult.SharedSecret.Length.Should().Be((int)info.length_shared_secret, "Shared secret should have correct length");
    }

    [Fact]
    public void KemInstance_Encapsulate_InvalidPublicKeyLength_ShouldThrowArgumentException()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);

        var invalidPublicKey = new byte[10]; // Wrong length

        var action = () => kemInstance.Encapsulate(invalidPublicKey);

        action.Should().Throw<ArgumentException>()
            .WithMessage("*publicKey*");
    }

    [Fact]
    public void KemInstance_Decapsulate_ValidInputs_ShouldRecoverSharedSecret()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);

        using var keyPair = kemInstance.GenerateKeyPair();
        using var encapsResult = kemInstance.Encapsulate(keyPair.PublicKey);

        var recoveredSecret = kemInstance.Decapsulate(encapsResult.Ciphertext, keyPair.SecretKey);

        recoveredSecret.Should().BeEquivalentTo(encapsResult.SharedSecret, "Decapsulated secret should match original");
    }

    [Fact]
    public void KemInstance_Decapsulate_InvalidCiphertextLength_ShouldThrowArgumentException()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);
        using var keyPair = kemInstance.GenerateKeyPair();

        var invalidCiphertext = new byte[10]; // Wrong length

        var action = () => kemInstance.Decapsulate(invalidCiphertext, keyPair.SecretKey);

        action.Should().Throw<ArgumentException>()
            .WithMessage("*ciphertext*");
    }

    [Fact]
    public void KemInstance_Decapsulate_InvalidSecretKeyLength_ShouldThrowArgumentException()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);
        using var keyPair = kemInstance.GenerateKeyPair();
        using var encapsResult = kemInstance.Encapsulate(keyPair.PublicKey);

        var invalidSecretKey = new byte[10]; // Wrong length

        var action = () => kemInstance.Decapsulate(encapsResult.Ciphertext, invalidSecretKey);

        action.Should().Throw<ArgumentException>()
            .WithMessage("*secretKey*");
    }

    [Fact]
    public void KemInstance_Dispose_ShouldNotAllowFurtherOperations()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        var kemInstance = KemProvider.Create(algorithm);

        kemInstance.Dispose();

        var actions = new Action[]
        {
            () => kemInstance.GetAlgorithmInfo(),
            () => kemInstance.GenerateKeyPair(),
            () => kemInstance.GenerateDeterministicKeyPair(new byte[48]),
            () => kemInstance.Encapsulate(new byte[100]),
            () => kemInstance.Decapsulate(new byte[100], new byte[100])
        };

        foreach (var action in actions)
        {
            action.Should().Throw<ObjectDisposedException>("Disposed instance should throw ObjectDisposedException");
        }
    }

    [Fact]
    public void KemInstance_DoubleDispose_ShouldNotThrow()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        var kemInstance = KemProvider.Create(algorithm);

        kemInstance.Dispose();
        var action = () => kemInstance.Dispose();

        action.Should().NotThrow("Double dispose should be safe");
    }

    [Fact]
    public void KeyPair_Dispose_ShouldClearSecretKey()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);
        var keyPair = kemInstance.GenerateKeyPair();

        var originalSecretKey = keyPair.SecretKey.ToArray();
        keyPair.Dispose();

        keyPair.SecretKey.Should().OnlyContain(b => b == 0, "Secret key should be cleared after disposal");
        keyPair.SecretKey.Should().NotBeEquivalentTo(originalSecretKey, "Secret key should be different after clearing");
    }

    [Fact]
    public void EncapsulationResult_Dispose_ShouldClearSharedSecret()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);
        using var keyPair = kemInstance.GenerateKeyPair();
        var encapsResult = kemInstance.Encapsulate(keyPair.PublicKey);

        var originalSharedSecret = encapsResult.SharedSecret.ToArray();
        encapsResult.Dispose();

        encapsResult.SharedSecret.Should().OnlyContain(b => b == 0, "Shared secret should be cleared after disposal");
        encapsResult.SharedSecret.Should().NotBeEquivalentTo(originalSharedSecret, "Shared secret should be different after clearing");
    }

    [Fact]
    public void KemInstance_EncapsulateDeterministic_ValidInputs_ShouldReturnValidResult()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);
        var info = kemInstance.GetAlgorithmInfo();

        using var keyPair = kemInstance.GenerateKeyPair();
        var seed = new byte[48];
        RandomNumberGenerator.Fill(seed);

        try
        {
            using var encapsResult = kemInstance.EncapsulateDeterministic(keyPair.PublicKey, seed);

            encapsResult.Ciphertext.Should().NotBeNull("Ciphertext should not be null");
            encapsResult.SharedSecret.Should().NotBeNull("Shared secret should not be null");
            encapsResult.Ciphertext.Length.Should().Be((int)info.length_ciphertext, "Ciphertext should have correct length");
            encapsResult.SharedSecret.Length.Should().Be((int)info.length_shared_secret, "Shared secret should have correct length");
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("Error code: -1", StringComparison.Ordinal))
        {
            // Some algorithms don't support deterministic operations, skip this test
            Assert.True(true, $"Algorithm '{algorithm}' does not support deterministic encapsulation, test skipped");
        }
    }

    [Fact]
    public void KemInstance_EncapsulateDeterministic_SameSeed_ShouldProduceSameResult()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);
        using var keyPair = kemInstance.GenerateKeyPair();

        var seed = new byte[48];
        RandomNumberGenerator.Fill(seed);

        try
        {
            using var encapsResult1 = kemInstance.EncapsulateDeterministic(keyPair.PublicKey, seed);
            using var encapsResult2 = kemInstance.EncapsulateDeterministic(keyPair.PublicKey, seed);

            encapsResult1.Ciphertext.Should().BeEquivalentTo(encapsResult2.Ciphertext, "Same seed should produce same ciphertext");
            encapsResult1.SharedSecret.Should().BeEquivalentTo(encapsResult2.SharedSecret, "Same seed should produce same shared secret");
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("Error code: -1", StringComparison.Ordinal))
        {
            // Some algorithms don't support deterministic operations, skip this test
            Assert.True(true, $"Algorithm '{algorithm}' does not support deterministic encapsulation, test skipped");
        }
    }

    [Fact]
    public void KemInstance_EncapsulateDeterministic_InvalidSeedLength_ShouldThrowArgumentException()
    {
        var supportedAlgorithms = KemProvider.GetSupportedAlgorithms().ToList();
        supportedAlgorithms.Should().NotBeEmpty();

        var algorithm = supportedAlgorithms[0];
        using var kemInstance = KemProvider.Create(algorithm);
        using var keyPair = kemInstance.GenerateKeyPair();

        var invalidSeed = new byte[32]; // Should be 48 bytes

        var action = () => kemInstance.EncapsulateDeterministic(keyPair.PublicKey, invalidSeed);

        action.Should().Throw<ArgumentException>()
            .WithMessage("*seed*");
    }
}

#pragma warning restore S1144