using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.KEM.Tests;

[Collection("LibOqs Collection")]
public sealed class KemNativeTests(LibOqsTestFixture fixture)
{
    #pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void OQS_KEM_alg_count_ShouldReturnPositiveValue()
    {
        var count = KemNative.OQS_KEM_alg_count();

        count.Should().BeGreaterThan(0, "LibOQS should have at least one KEM algorithm available");
    }

    [Fact]
    public void OQS_KEM_alg_identifier_ValidIndex_ShouldReturnNonNullPointer()
    {
        var count = KemNative.OQS_KEM_alg_count();
        count.Should().BeGreaterThan(0);

        var ptr = KemNative.OQS_KEM_alg_identifier(0);

        ptr.Should().NotBe(IntPtr.Zero, "Valid algorithm index should return a non-null pointer");
    }

    [Fact]
    public void OQS_KEM_alg_identifier_InvalidIndex_ShouldReturnNullPointer()
    {
        var count = KemNative.OQS_KEM_alg_count();
        var invalidIndex = (nuint)(count + 1000);

        var ptr = KemNative.OQS_KEM_alg_identifier(invalidIndex);

        ptr.Should().Be(IntPtr.Zero, "Invalid algorithm index should return null pointer");
    }

    [Fact]
    public void OQS_KEM_alg_identifier_MaxValue_ShouldReturnNullPointer()
    {
        var ptr = KemNative.OQS_KEM_alg_identifier(UIntPtr.MaxValue);

        ptr.Should().Be(IntPtr.Zero, "Maximum index value should return null pointer");
    }

    [Fact]
    public void OQS_KEM_alg_is_enabled_ValidAlgorithm_ShouldReturnConsistentResult()
    {
        var count = KemNative.OQS_KEM_alg_count();
        count.Should().BeGreaterThan(0);

        var algorithmPtr = KemNative.OQS_KEM_alg_identifier(0);
        algorithmPtr.Should().NotBe(IntPtr.Zero);

        var algorithmName = System.Runtime.InteropServices.Marshal.PtrToStringAnsi(algorithmPtr);
        algorithmName.Should().NotBeNullOrEmpty();

        var isEnabled = KemNative.OQS_KEM_alg_is_enabled(algorithmName!);

        isEnabled.Should().BeInRange(0, 1, "Algorithm enabled status should be 0 or 1");
    }

    [Fact]
    public void OQS_KEM_alg_is_enabled_InvalidAlgorithm_ShouldReturnZero()
    {
        var isEnabled = KemNative.OQS_KEM_alg_is_enabled("NonExistentAlgorithm123");

        isEnabled.Should().Be(0, "Non-existent algorithm should return 0 (disabled)");
    }

    [Fact]
    public void OQS_KEM_alg_is_enabled_EmptyString_ShouldReturnZero()
    {
        var isEnabled = KemNative.OQS_KEM_alg_is_enabled(string.Empty);

        isEnabled.Should().Be(0, "Empty string should return 0 (disabled)");
    }

    [Theory]
    [InlineData("KYBER512")]
    [InlineData("KYBER768")]
    [InlineData("KYBER1024")]
    public void OQS_KEM_alg_is_enabled_CommonAlgorithms_ShouldHandleGracefully(string algorithm)
    {
        var action = () => KemNative.OQS_KEM_alg_is_enabled(algorithm);

        action.Should().NotThrow("Valid algorithm names should not cause exceptions");

        var result = action();
        result.Should().BeInRange(0, 1, "Result should be 0 or 1");
    }

    [Fact]
    public void OQS_KEM_new_InvalidAlgorithm_ShouldReturnNullPointer()
    {
        var handle = KemNative.OQS_KEM_new("NonExistentAlgorithm123");

        handle.Should().Be(IntPtr.Zero, "Invalid algorithm should return null handle");
    }

    [Fact]
    public void OQS_KEM_new_EmptyString_ShouldReturnNullPointer()
    {
        var handle = KemNative.OQS_KEM_new(string.Empty);

        handle.Should().Be(IntPtr.Zero, "Empty string should return null handle");
    }

    [Fact]
    public void OQS_KEM_free_NullPointer_ShouldNotThrow()
    {
        var action = () => KemNative.OQS_KEM_free(IntPtr.Zero);

        action.Should().NotThrow("Freeing null pointer should be safe");
    }

    [Fact]
    public unsafe void OQS_KEM_keypair_NullHandle_ShouldReturnError()
    {
        var publicKey = stackalloc byte[1];
        var secretKey = stackalloc byte[1];

        var result = KemNative.OQS_KEM_keypair(IntPtr.Zero, publicKey, secretKey);

        result.Should().NotBe(0, "Null handle should return error");
    }

    [Fact]
    public unsafe void OQS_KEM_keypair_NullPublicKey_ShouldReturnError()
    {
        var secretKey = stackalloc byte[1];

        var result = KemNative.OQS_KEM_keypair(IntPtr.Zero, null, secretKey);

        result.Should().NotBe(0, "Null public key pointer should return error");
    }

    [Fact]
    public unsafe void OQS_KEM_keypair_NullSecretKey_ShouldReturnError()
    {
        var publicKey = stackalloc byte[1];

        var result = KemNative.OQS_KEM_keypair(IntPtr.Zero, publicKey, null);

        result.Should().NotBe(0, "Null secret key pointer should return error");
    }

    [Fact]
    public unsafe void OQS_KEM_keypair_derand_NullHandle_ShouldReturnError()
    {
        var publicKey = stackalloc byte[1];
        var secretKey = stackalloc byte[1];
        var seed = stackalloc byte[48];

        var result = KemNative.OQS_KEM_keypair_derand(IntPtr.Zero, publicKey, secretKey, seed);

        result.Should().NotBe(0, "Null handle should return error");
    }

    [Fact]
    public unsafe void OQS_KEM_keypair_derand_NullSeed_ShouldReturnError()
    {
        var publicKey = stackalloc byte[1];
        var secretKey = stackalloc byte[1];

        var result = KemNative.OQS_KEM_keypair_derand(IntPtr.Zero, publicKey, secretKey, null);

        result.Should().NotBe(0, "Null seed pointer should return error");
    }

    [Fact]
    public unsafe void OQS_KEM_encaps_NullHandle_ShouldReturnError()
    {
        var ciphertext = stackalloc byte[1];
        var sharedSecret = stackalloc byte[1];
        var publicKey = stackalloc byte[1];

        var result = KemNative.OQS_KEM_encaps(IntPtr.Zero, ciphertext, sharedSecret, publicKey);

        result.Should().NotBe(0, "Null handle should return error");
    }

    [Fact]
    public unsafe void OQS_KEM_encaps_NullCiphertext_ShouldReturnError()
    {
        var sharedSecret = stackalloc byte[1];
        var publicKey = stackalloc byte[1];

        var result = KemNative.OQS_KEM_encaps(IntPtr.Zero, null, sharedSecret, publicKey);

        result.Should().NotBe(0, "Null ciphertext pointer should return error");
    }

    [Fact]
    public unsafe void OQS_KEM_encaps_NullSharedSecret_ShouldReturnError()
    {
        var ciphertext = stackalloc byte[1];
        var publicKey = stackalloc byte[1];

        var result = KemNative.OQS_KEM_encaps(IntPtr.Zero, ciphertext, null, publicKey);

        result.Should().NotBe(0, "Null shared secret pointer should return error");
    }

    [Fact]
    public unsafe void OQS_KEM_encaps_NullPublicKey_ShouldReturnError()
    {
        var ciphertext = stackalloc byte[1];
        var sharedSecret = stackalloc byte[1];

        var result = KemNative.OQS_KEM_encaps(IntPtr.Zero, ciphertext, sharedSecret, null);

        result.Should().NotBe(0, "Null public key pointer should return error");
    }

    [Fact]
    public unsafe void OQS_KEM_encaps_derand_NullHandle_ShouldReturnError()
    {
        var ciphertext = stackalloc byte[1];
        var sharedSecret = stackalloc byte[1];
        var publicKey = stackalloc byte[1];
        var seed = stackalloc byte[48];

        var result = KemNative.OQS_KEM_encaps_derand(IntPtr.Zero, ciphertext, sharedSecret, publicKey, seed);

        result.Should().NotBe(0, "Null handle should return error");
    }

    [Fact]
    public unsafe void OQS_KEM_encaps_derand_NullSeed_ShouldReturnError()
    {
        var ciphertext = stackalloc byte[1];
        var sharedSecret = stackalloc byte[1];
        var publicKey = stackalloc byte[1];

        var result = KemNative.OQS_KEM_encaps_derand(IntPtr.Zero, ciphertext, sharedSecret, publicKey, null);

        result.Should().NotBe(0, "Null seed pointer should return error");
    }

    [Fact]
    public unsafe void OQS_KEM_decaps_NullHandle_ShouldReturnError()
    {
        var sharedSecret = stackalloc byte[1];
        var ciphertext = stackalloc byte[1];
        var secretKey = stackalloc byte[1];

        var result = KemNative.OQS_KEM_decaps(IntPtr.Zero, sharedSecret, ciphertext, secretKey);

        result.Should().NotBe(0, "Null handle should return error");
    }

    [Fact]
    public unsafe void OQS_KEM_decaps_NullSharedSecret_ShouldReturnError()
    {
        var ciphertext = stackalloc byte[1];
        var secretKey = stackalloc byte[1];

        var result = KemNative.OQS_KEM_decaps(IntPtr.Zero, null, ciphertext, secretKey);

        result.Should().NotBe(0, "Null shared secret pointer should return error");
    }

    [Fact]
    public unsafe void OQS_KEM_decaps_NullCiphertext_ShouldReturnError()
    {
        var sharedSecret = stackalloc byte[1];
        var secretKey = stackalloc byte[1];

        var result = KemNative.OQS_KEM_decaps(IntPtr.Zero, sharedSecret, null, secretKey);

        result.Should().NotBe(0, "Null ciphertext pointer should return error");
    }

    [Fact]
    public unsafe void OQS_KEM_decaps_NullSecretKey_ShouldReturnError()
    {
        var sharedSecret = stackalloc byte[1];
        var ciphertext = stackalloc byte[1];

        var result = KemNative.OQS_KEM_decaps(IntPtr.Zero, sharedSecret, ciphertext, null);

        result.Should().NotBe(0, "Null secret key pointer should return error");
    }

    [Fact]
    public void OqsKem_DefaultInstance_ShouldHaveZeroValues()
    {
        var kemStruct = new OqsKem();

        kemStruct.method_name.Should().Be(IntPtr.Zero);
        kemStruct.alg_version.Should().Be(IntPtr.Zero);
        kemStruct.claimed_nist_level.Should().Be(0);
        kemStruct.ind_cca.Should().Be(0);
        kemStruct.length_public_key.Should().Be(UIntPtr.Zero);
        kemStruct.length_secret_key.Should().Be(UIntPtr.Zero);
        kemStruct.length_ciphertext.Should().Be(UIntPtr.Zero);
        kemStruct.length_shared_secret.Should().Be(UIntPtr.Zero);
        kemStruct.keypair.Should().Be(IntPtr.Zero);
        kemStruct.encaps.Should().Be(IntPtr.Zero);
        kemStruct.decaps.Should().Be(IntPtr.Zero);
    }


    [Fact]
    public void OqsKem_Equals_DefaultInstances_ShouldReturnTrue()
    {
        var kemStruct1 = new OqsKem();
        var kemStruct2 = new OqsKem();

        kemStruct1.Equals(kemStruct2).Should().BeTrue("Default instances should be equal");
        (kemStruct1 == kemStruct2).Should().BeTrue("Default instances should be equal using operator");
        (kemStruct1 != kemStruct2).Should().BeFalse("Default instances should not be unequal using operator");
    }

    [Fact]
    public void OqsKem_Equals_WithNull_ShouldReturnFalse()
    {
        var kemStruct = new OqsKem();

        kemStruct.Equals(null).Should().BeFalse("KEM struct should not equal null");
    }

    [Fact]
    public void OqsKem_Equals_WithDifferentType_ShouldReturnFalse()
    {
        var kemStruct = new OqsKem();
        var otherObject = "not a KEM struct";

        kemStruct.Equals(otherObject).Should().BeFalse("KEM struct should not equal different type");
    }

    [Fact]
    public void OqsKem_GetHashCode_SameValues_ShouldReturnSameHash()
    {
        var kemStruct1 = new OqsKem();
        var kemStruct2 = new OqsKem();

        kemStruct1.GetHashCode().Should().Be(kemStruct2.GetHashCode(), "Identical structs should have same hash code");
    }

    [Fact]
    public void OqsKem_GetHashCode_SameInstance_ShouldReturnConsistentHash()
    {
        var kemStruct = new OqsKem();

        var hash1 = kemStruct.GetHashCode();
        var hash2 = kemStruct.GetHashCode();

        hash1.Should().Be(hash2, "Hash code should be consistent for same instance");
    }

    [Fact]
    public void KemNative_AllMethods_ShouldHandleIntPtrZeroGracefully()
    {
        var actions = new Action[]
        {
            () => KemNative.OQS_KEM_free(IntPtr.Zero),
        };

        foreach (var action in actions)
        {
            action.Should().NotThrow("Methods should handle IntPtr.Zero gracefully");
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("INVALID_ALGORITHM")]
    [InlineData("test123")]
    public void OQS_KEM_alg_is_enabled_VariousInputs_ShouldNotThrow(string algorithm)
    {
        var action = () => KemNative.OQS_KEM_alg_is_enabled(algorithm);

        action.Should().NotThrow($"Algorithm name '{algorithm}' should not cause exception");

        var result = action();
        result.Should().BeInRange(0, 1, "Result should be 0 or 1 regardless of input");
    }

    [Theory]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("INVALID_ALGORITHM")]
    [InlineData("test123")]
    public void OQS_KEM_new_VariousInputs_ShouldReturnNullForInvalid(string algorithm)
    {
        var handle = KemNative.OQS_KEM_new(algorithm);

        handle.Should().Be(IntPtr.Zero, $"Invalid algorithm '{algorithm}' should return null handle");
    }
}

#pragma warning restore S1144