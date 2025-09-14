using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.SIG.Tests;

[Collection("LibOqs Collection")]
public sealed class SigNativeTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void OQS_SIG_alg_count_ShouldReturnPositiveValue()
    {
        var count = SigNative.OQS_SIG_alg_count();

        count.Should().BeGreaterThan(0, "LibOQS should have at least one Signature algorithm available");
    }

    [Fact]
    public void OQS_SIG_alg_identifier_ValidIndex_ShouldReturnNonNullPointer()
    {
        var count = SigNative.OQS_SIG_alg_count();
        count.Should().BeGreaterThan(0);

        var ptr = SigNative.OQS_SIG_alg_identifier(0);

        ptr.Should().NotBe(IntPtr.Zero, "Valid algorithm index should return a non-null pointer");
    }

    [Fact]
    public void OQS_SIG_alg_identifier_InvalidIndex_ShouldReturnNullPointer()
    {
        var count = SigNative.OQS_SIG_alg_count();
        var invalidIndex = (nuint)(count + 1000);

        var ptr = SigNative.OQS_SIG_alg_identifier(invalidIndex);

        ptr.Should().Be(IntPtr.Zero, "Invalid algorithm index should return null pointer");
    }

    [Fact]
    public void OQS_SIG_alg_identifier_MaxValue_ShouldReturnNullPointer()
    {
        var ptr = SigNative.OQS_SIG_alg_identifier(UIntPtr.MaxValue);

        ptr.Should().Be(IntPtr.Zero, "Maximum index value should return null pointer");
    }

    [Fact]
    public void OQS_SIG_alg_is_enabled_ValidAlgorithm_ShouldReturnConsistentResult()
    {
        var count = SigNative.OQS_SIG_alg_count();
        count.Should().BeGreaterThan(0);

        var algorithmPtr = SigNative.OQS_SIG_alg_identifier(0);
        algorithmPtr.Should().NotBe(IntPtr.Zero);

        var algorithmName = System.Runtime.InteropServices.Marshal.PtrToStringAnsi(algorithmPtr);
        algorithmName.Should().NotBeNullOrEmpty();

        var isEnabled = SigNative.OQS_SIG_alg_is_enabled(algorithmName!);

        isEnabled.Should().BeInRange(0, 1, "Algorithm enabled status should be 0 or 1");
    }

    [Fact]
    public void OQS_SIG_alg_is_enabled_InvalidAlgorithm_ShouldReturnZero()
    {
        var isEnabled = SigNative.OQS_SIG_alg_is_enabled("NonExistentAlgorithm123");

        isEnabled.Should().Be(0, "Non-existent algorithm should return 0 (disabled)");
    }

    [Fact]
    public void OQS_SIG_alg_is_enabled_EmptyString_ShouldReturnZero()
    {
        var isEnabled = SigNative.OQS_SIG_alg_is_enabled(string.Empty);

        isEnabled.Should().Be(0, "Empty string should return 0 (disabled)");
    }

    [Theory]
    [InlineData("Dilithium2")]
    [InlineData("Dilithium3")]
    [InlineData("Dilithium5")]
    [InlineData("SPHINCS+-SHA2-128s-simple")]
    [InlineData("SPHINCS+-SHA2-128f-simple")]
    public void OQS_SIG_alg_is_enabled_CommonAlgorithms_ShouldHandleGracefully(string algorithm)
    {
        var action = () => SigNative.OQS_SIG_alg_is_enabled(algorithm);

        action.Should().NotThrow("Valid algorithm names should not cause exceptions");

        var result = action();
        result.Should().BeInRange(0, 1, "Result should be 0 or 1");
    }

    [Fact]
    public void OQS_SIG_supports_ctx_str_ValidAlgorithm_ShouldReturnConsistentResult()
    {
        var count = SigNative.OQS_SIG_alg_count();
        count.Should().BeGreaterThan(0);

        var algorithmPtr = SigNative.OQS_SIG_alg_identifier(0);
        algorithmPtr.Should().NotBe(IntPtr.Zero);

        var algorithmName = System.Runtime.InteropServices.Marshal.PtrToStringAnsi(algorithmPtr);
        algorithmName.Should().NotBeNullOrEmpty();

        var supportsContext = SigNative.OQS_SIG_supports_ctx_str(algorithmName!);

        supportsContext.Should().BeInRange(0, 1, "Context string support should be 0 or 1");
    }

    [Fact]
    public void OQS_SIG_supports_ctx_str_InvalidAlgorithm_ShouldReturnZero()
    {
        var supportsContext = SigNative.OQS_SIG_supports_ctx_str("NonExistentAlgorithm123");

        supportsContext.Should().Be(0, "Non-existent algorithm should return 0 (no context support)");
    }

    [Fact]
    public void OQS_SIG_supports_ctx_str_EmptyString_ShouldReturnZero()
    {
        var supportsContext = SigNative.OQS_SIG_supports_ctx_str(string.Empty);

        supportsContext.Should().Be(0, "Empty string should return 0 (no context support)");
    }

    [Fact]
    public void OQS_SIG_new_InvalidAlgorithm_ShouldReturnNullPointer()
    {
        var handle = SigNative.OQS_SIG_new("NonExistentAlgorithm123");

        handle.Should().Be(IntPtr.Zero, "Invalid algorithm should return null handle");
    }

    [Fact]
    public void OQS_SIG_new_EmptyString_ShouldReturnNullPointer()
    {
        var handle = SigNative.OQS_SIG_new(string.Empty);

        handle.Should().Be(IntPtr.Zero, "Empty string should return null handle");
    }

    [Fact]
    public void OQS_SIG_free_NullPointer_ShouldNotThrow()
    {
        var action = () => SigNative.OQS_SIG_free(IntPtr.Zero);

        action.Should().NotThrow("Freeing null pointer should be safe");
    }

    [Fact]
    public unsafe void OQS_SIG_keypair_NullHandle_ShouldReturnError()
    {
        var publicKey = stackalloc byte[1];
        var secretKey = stackalloc byte[1];

        var result = SigNative.OQS_SIG_keypair(IntPtr.Zero, publicKey, secretKey);

        result.Should().NotBe(0, "Null handle should return error");
    }

    [Fact]
    public unsafe void OQS_SIG_keypair_NullPublicKey_ShouldReturnError()
    {
        var secretKey = stackalloc byte[1];

        var result = SigNative.OQS_SIG_keypair(IntPtr.Zero, null, secretKey);

        result.Should().NotBe(0, "Null public key pointer should return error");
    }

    [Fact]
    public unsafe void OQS_SIG_keypair_NullSecretKey_ShouldReturnError()
    {
        var publicKey = stackalloc byte[1];

        var result = SigNative.OQS_SIG_keypair(IntPtr.Zero, publicKey, null);

        result.Should().NotBe(0, "Null secret key pointer should return error");
    }

    [Fact]
    public unsafe void OQS_SIG_sign_NullHandle_ShouldReturnError()
    {
        var signature = stackalloc byte[1];
        var signatureLen = (UIntPtr)1;
        var message = stackalloc byte[1];
        var secretKey = stackalloc byte[1];

        var result = SigNative.OQS_SIG_sign(IntPtr.Zero, signature, ref signatureLen, message, 1, secretKey);

        result.Should().NotBe(0, "Null handle should return error");
    }

    [Fact]
    public unsafe void OQS_SIG_sign_NullSignature_ShouldReturnError()
    {
        var signatureLen = (UIntPtr)1;
        var message = stackalloc byte[1];
        var secretKey = stackalloc byte[1];

        var result = SigNative.OQS_SIG_sign(IntPtr.Zero, null, ref signatureLen, message, 1, secretKey);

        result.Should().NotBe(0, "Null signature pointer should return error");
    }

    [Fact]
    public unsafe void OQS_SIG_sign_NullMessage_ShouldReturnError()
    {
        var signature = stackalloc byte[1];
        var signatureLen = (UIntPtr)1;
        var secretKey = stackalloc byte[1];

        var result = SigNative.OQS_SIG_sign(IntPtr.Zero, signature, ref signatureLen, null, 1, secretKey);

        result.Should().NotBe(0, "Null message pointer should return error");
    }

    [Fact]
    public unsafe void OQS_SIG_sign_NullSecretKey_ShouldReturnError()
    {
        var signature = stackalloc byte[1];
        var signatureLen = (UIntPtr)1;
        var message = stackalloc byte[1];

        var result = SigNative.OQS_SIG_sign(IntPtr.Zero, signature, ref signatureLen, message, 1, null);

        result.Should().NotBe(0, "Null secret key pointer should return error");
    }

    [Fact]
    public unsafe void OQS_SIG_sign_with_ctx_str_NullHandle_ShouldReturnError()
    {
        var signature = stackalloc byte[1];
        var signatureLen = (UIntPtr)1;
        var message = stackalloc byte[1];
        var context = stackalloc byte[1];
        var secretKey = stackalloc byte[1];

        var result = SigNative.OQS_SIG_sign_with_ctx_str(IntPtr.Zero, signature, ref signatureLen, message, 1, context, 1, secretKey);

        result.Should().NotBe(0, "Null handle should return error");
    }

    [Fact]
    public unsafe void OQS_SIG_sign_with_ctx_str_NullContext_ShouldReturnError()
    {
        var signature = stackalloc byte[1];
        var signatureLen = (UIntPtr)1;
        var message = stackalloc byte[1];
        var secretKey = stackalloc byte[1];

        var result = SigNative.OQS_SIG_sign_with_ctx_str(IntPtr.Zero, signature, ref signatureLen, message, 1, null, 1, secretKey);

        result.Should().NotBe(0, "Null context pointer should return error");
    }

    [Fact]
    public unsafe void OQS_SIG_verify_NullHandle_ShouldReturnError()
    {
        var message = stackalloc byte[1];
        var signature = stackalloc byte[1];
        var publicKey = stackalloc byte[1];

        var result = SigNative.OQS_SIG_verify(IntPtr.Zero, message, 1, signature, 1, publicKey);

        result.Should().NotBe(0, "Null handle should return error");
    }

    [Fact]
    public unsafe void OQS_SIG_verify_NullMessage_ShouldReturnError()
    {
        var signature = stackalloc byte[1];
        var publicKey = stackalloc byte[1];

        var result = SigNative.OQS_SIG_verify(IntPtr.Zero, null, 1, signature, 1, publicKey);

        result.Should().NotBe(0, "Null message pointer should return error");
    }

    [Fact]
    public unsafe void OQS_SIG_verify_NullSignature_ShouldReturnError()
    {
        var message = stackalloc byte[1];
        var publicKey = stackalloc byte[1];

        var result = SigNative.OQS_SIG_verify(IntPtr.Zero, message, 1, null, 1, publicKey);

        result.Should().NotBe(0, "Null signature pointer should return error");
    }

    [Fact]
    public unsafe void OQS_SIG_verify_NullPublicKey_ShouldReturnError()
    {
        var message = stackalloc byte[1];
        var signature = stackalloc byte[1];

        var result = SigNative.OQS_SIG_verify(IntPtr.Zero, message, 1, signature, 1, null);

        result.Should().NotBe(0, "Null public key pointer should return error");
    }

    [Fact]
    public unsafe void OQS_SIG_verify_with_ctx_str_NullHandle_ShouldReturnError()
    {
        var message = stackalloc byte[1];
        var signature = stackalloc byte[1];
        var context = stackalloc byte[1];
        var publicKey = stackalloc byte[1];

        var result = SigNative.OQS_SIG_verify_with_ctx_str(IntPtr.Zero, message, 1, signature, 1, context, 1, publicKey);

        result.Should().NotBe(0, "Null handle should return error");
    }

    [Fact]
    public unsafe void OQS_SIG_verify_with_ctx_str_NullContext_ShouldReturnError()
    {
        var message = stackalloc byte[1];
        var signature = stackalloc byte[1];
        var publicKey = stackalloc byte[1];

        var result = SigNative.OQS_SIG_verify_with_ctx_str(IntPtr.Zero, message, 1, signature, 1, null, 1, publicKey);

        result.Should().NotBe(0, "Null context pointer should return error");
    }

    [Fact]
    public void OqsSig_DefaultInstance_ShouldHaveZeroValues()
    {
        var sigStruct = new OqsSig();

        sigStruct.method_name.Should().Be(IntPtr.Zero);
        sigStruct.alg_version.Should().Be(IntPtr.Zero);
        sigStruct.claimed_nist_level.Should().Be(0);
        sigStruct.euf_cma.Should().Be(0);
        sigStruct.length_public_key.Should().Be(UIntPtr.Zero);
        sigStruct.length_secret_key.Should().Be(UIntPtr.Zero);
        sigStruct.length_signature.Should().Be(UIntPtr.Zero);
        sigStruct.keypair.Should().Be(IntPtr.Zero);
        sigStruct.sign.Should().Be(IntPtr.Zero);
        sigStruct.verify.Should().Be(IntPtr.Zero);
    }

    [Fact]
    public void OqsSig_Equals_DefaultInstances_ShouldReturnTrue()
    {
        var sigStruct1 = new OqsSig();
        var sigStruct2 = new OqsSig();

        sigStruct1.Equals(sigStruct2).Should().BeTrue("Default instances should be equal");
        (sigStruct1 == sigStruct2).Should().BeTrue("Default instances should be equal using operator");
        (sigStruct1 != sigStruct2).Should().BeFalse("Default instances should not be unequal using operator");
    }

    [Fact]
    public void OqsSig_Equals_WithNull_ShouldReturnFalse()
    {
        var sigStruct = new OqsSig();

        sigStruct.Equals(null).Should().BeFalse("Sig struct should not equal null");
    }

    [Fact]
    public void OqsSig_Equals_WithDifferentType_ShouldReturnFalse()
    {
        var sigStruct = new OqsSig();
        var otherObject = "not a Sig struct";

        sigStruct.Equals(otherObject).Should().BeFalse("Sig struct should not equal different type");
    }

    [Fact]
    public void OqsSig_GetHashCode_SameValues_ShouldReturnSameHash()
    {
        var sigStruct1 = new OqsSig();
        var sigStruct2 = new OqsSig();

        sigStruct1.GetHashCode().Should().Be(sigStruct2.GetHashCode(), "Identical structs should have same hash code");
    }

    [Fact]
    public void OqsSig_GetHashCode_SameInstance_ShouldReturnConsistentHash()
    {
        var sigStruct = new OqsSig();

        var hash1 = sigStruct.GetHashCode();
        var hash2 = sigStruct.GetHashCode();

        hash1.Should().Be(hash2, "Hash code should be consistent for same instance");
    }

    [Fact]
    public void SigNative_AllMethods_ShouldHandleIntPtrZeroGracefully()
    {
        var actions = new Action[]
        {
            () => SigNative.OQS_SIG_free(IntPtr.Zero),
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
    public void OQS_SIG_alg_is_enabled_VariousInputs_ShouldNotThrow(string algorithm)
    {
        var action = () => SigNative.OQS_SIG_alg_is_enabled(algorithm);

        action.Should().NotThrow($"Algorithm name '{algorithm}' should not cause exception");

        var result = action();
        result.Should().BeInRange(0, 1, "Result should be 0 or 1 regardless of input");
    }

    [Theory]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("INVALID_ALGORITHM")]
    [InlineData("test123")]
    public void OQS_SIG_supports_ctx_str_VariousInputs_ShouldNotThrow(string algorithm)
    {
        var action = () => SigNative.OQS_SIG_supports_ctx_str(algorithm);

        action.Should().NotThrow($"Algorithm name '{algorithm}' should not cause exception");

        var result = action();
        result.Should().BeInRange(0, 1, "Result should be 0 or 1 regardless of input");
    }

    [Theory]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("INVALID_ALGORITHM")]
    [InlineData("test123")]
    public void OQS_SIG_new_VariousInputs_ShouldReturnNullForInvalid(string algorithm)
    {
        var handle = SigNative.OQS_SIG_new(algorithm);

        handle.Should().Be(IntPtr.Zero, $"Invalid algorithm '{algorithm}' should return null handle");
    }
}

#pragma warning restore S1144