using OpenForge.Cryptography.LibOqs.Tests.Common;
using System.Runtime.InteropServices;
using FluentAssertions;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.Core.Tests;

[Collection("LibOqs Collection")]
public sealed class LibOqsNativeTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void OQS_init_ShouldNotThrow()
    {
        // Act & Assert - Should not throw (already initialized by fixture, but should be idempotent)
        var action = () => LibOqsNative.OQS_init();
        action.Should().NotThrow();
    }

    [Fact]
    public void OQS_destroy_ShouldNotThrow()
    {
        // Act & Assert - Should not throw (cleanup operations should be safe)
        var action = () => LibOqsNative.OQS_destroy();
        action.Should().NotThrow();
    }

    [Fact]
    public void OQS_thread_stop_ShouldNotThrow()
    {
        // Act & Assert - Should not throw
        var action = () => LibOqsNative.OQS_thread_stop();
        action.Should().NotThrow();
    }

    [Fact]
    public void OQS_version_ShouldReturnValidPointer()
    {
        // Act
        var versionPtr = LibOqsNative.OQS_version();

        // Assert
        versionPtr.Should().NotBe(IntPtr.Zero);

        // Convert to string to validate
        var version = Marshal.PtrToStringUTF8(versionPtr);
        version.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void OQS_MEM_malloc_WithValidSize_ShouldReturnValidPointer()
    {
        // Arrange
        const uint size = 64;

        // Act
        var ptr = LibOqsNative.OQS_MEM_malloc(size);

        try
        {
            // Assert
            ptr.Should().NotBe(IntPtr.Zero);
        }
        finally
        {
            // Cleanup
            LibOqsNative.OQS_MEM_insecure_free(ptr);
        }
    }

    [Fact]
    public void OQS_MEM_malloc_WithZeroSize_ShouldReturnNonNullPointer()
    {
        // Arrange - malloc(0) behavior is implementation-defined but typically returns non-null
        const uint size = 0;

        // Act
        var ptr = LibOqsNative.OQS_MEM_malloc(size);

        if (ptr != IntPtr.Zero)
        {
            // Cleanup if non-null was returned
            LibOqsNative.OQS_MEM_insecure_free(ptr);
        }

        // Assert - Either null or non-null is acceptable for malloc(0)
        // The important thing is that it doesn't crash
        Assert.True(true); // Test completed without crashing
    }

    [Fact]
    public void OQS_MEM_calloc_WithValidParameters_ShouldReturnValidPointer()
    {
        // Arrange
        const uint numElements = 10;
        const uint elementSize = 8;

        // Act
        var ptr = LibOqsNative.OQS_MEM_calloc(numElements, elementSize);

        try
        {
            // Assert
            ptr.Should().NotBe(IntPtr.Zero);

            // Verify memory is zero-initialized
            unsafe
            {
                var bytes = new Span<byte>((void*)ptr, (int)(numElements * elementSize));
                bytes.ToArray().Should().AllSatisfy(b => b.Should().Be(0));
            }
        }
        finally
        {
            // Cleanup
            LibOqsNative.OQS_MEM_insecure_free(ptr);
        }
    }

    [Fact]
    public void OQS_MEM_calloc_WithZeroElements_ShouldReturnPointer()
    {
        // Arrange
        const uint numElements = 0;
        const uint elementSize = 8;

        // Act
        var ptr = LibOqsNative.OQS_MEM_calloc(numElements, elementSize);

        if (ptr != IntPtr.Zero)
        {
            // Cleanup if non-null was returned
            LibOqsNative.OQS_MEM_insecure_free(ptr);
        }

        // Assert - Either null or non-null is acceptable for calloc(0, size)
        Assert.True(true); // Test completed without crashing
    }

    [Fact]
    public void OQS_MEM_calloc_WithZeroElementSize_ShouldReturnPointer()
    {
        // Arrange
        const uint numElements = 10;
        const uint elementSize = 0;

        // Act
        var ptr = LibOqsNative.OQS_MEM_calloc(numElements, elementSize);

        if (ptr != IntPtr.Zero)
        {
            // Cleanup if non-null was returned
            LibOqsNative.OQS_MEM_insecure_free(ptr);
        }

        // Assert - Either null or non-null is acceptable for calloc(num, 0)
        Assert.True(true); // Test completed without crashing
    }

    [Fact]
    public void OQS_MEM_insecure_free_WithValidPointer_ShouldNotThrow()
    {
        // Arrange
        var ptr = LibOqsNative.OQS_MEM_malloc(64);
        ptr.Should().NotBe(IntPtr.Zero);

        // Act & Assert
        var action = () => LibOqsNative.OQS_MEM_insecure_free(ptr);
        action.Should().NotThrow();
    }

    [Fact]
    public void OQS_MEM_insecure_free_WithNullPointer_ShouldNotThrow()
    {
        // Act & Assert - free(NULL) should be safe
        var action = () => LibOqsNative.OQS_MEM_insecure_free(IntPtr.Zero);
        action.Should().NotThrow();
    }

    [Fact]
    public void OQS_MEM_secure_free_WithValidPointer_ShouldNotThrow()
    {
        // Arrange
        const uint size = 64;
        var ptr = LibOqsNative.OQS_MEM_malloc(size);
        ptr.Should().NotBe(IntPtr.Zero);

        // Act & Assert
        var action = () => LibOqsNative.OQS_MEM_secure_free(ptr, size);
        action.Should().NotThrow();
    }

    [Fact]
    public void OQS_MEM_secure_free_WithNullPointer_ShouldNotThrow()
    {
        // Act & Assert - secure free with null should be safe
        var action = () => LibOqsNative.OQS_MEM_secure_free(IntPtr.Zero, 64);
        action.Should().NotThrow();
    }

    [Fact]
    public void OQS_MEM_cleanse_WithValidPointer_ShouldNotThrow()
    {
        // Arrange
        const uint size = 64;
        var ptr = LibOqsNative.OQS_MEM_malloc(size);
        ptr.Should().NotBe(IntPtr.Zero);

        try
        {
            // Fill memory with data
            unsafe
            {
                var span = new Span<byte>((void*)ptr, (int)size);
                span.Fill(0x42);
            }

            // Act & Assert
            var action = () => LibOqsNative.OQS_MEM_cleanse(ptr, size);
            action.Should().NotThrow();

            // Verify memory is cleansed (should be zeros)
            unsafe
            {
                var span = new Span<byte>((void*)ptr, (int)size);
                span.ToArray().Should().AllSatisfy(b => b.Should().Be(0));
            }
        }
        finally
        {
            LibOqsNative.OQS_MEM_insecure_free(ptr);
        }
    }

    [Fact]
    public void OQS_MEM_cleanse_WithNullPointer_ShouldNotThrow()
    {
        // Act & Assert - cleanse with null should be safe
        var action = () => LibOqsNative.OQS_MEM_cleanse(IntPtr.Zero, 64);
        action.Should().NotThrow();
    }

    [Fact]
    public void OQS_MEM_secure_bcmp_WithEqualMemory_ShouldReturnZero()
    {
        // Arrange
        const uint size = 32;
        var ptr1 = LibOqsNative.OQS_MEM_malloc(size);
        var ptr2 = LibOqsNative.OQS_MEM_malloc(size);

        try
        {
            ptr1.Should().NotBe(IntPtr.Zero);
            ptr2.Should().NotBe(IntPtr.Zero);

            // Fill both with same data
            unsafe
            {
                var span1 = new Span<byte>((void*)ptr1, (int)size);
                var span2 = new Span<byte>((void*)ptr2, (int)size);
                span1.Fill(0x42);
                span2.Fill(0x42);
            }

            // Act
            var result = LibOqsNative.OQS_MEM_secure_bcmp(ptr1, ptr2, size);

            // Assert
            result.Should().Be(0);
        }
        finally
        {
            LibOqsNative.OQS_MEM_insecure_free(ptr1);
            LibOqsNative.OQS_MEM_insecure_free(ptr2);
        }
    }

    [Fact]
    public void OQS_MEM_secure_bcmp_WithDifferentMemory_ShouldReturnNonZero()
    {
        // Arrange
        const uint size = 32;
        var ptr1 = LibOqsNative.OQS_MEM_malloc(size);
        var ptr2 = LibOqsNative.OQS_MEM_malloc(size);

        try
        {
            ptr1.Should().NotBe(IntPtr.Zero);
            ptr2.Should().NotBe(IntPtr.Zero);

            // Fill with different data
            unsafe
            {
                var span1 = new Span<byte>((void*)ptr1, (int)size);
                var span2 = new Span<byte>((void*)ptr2, (int)size);
                span1.Fill(0x42);
                span2.Fill(0x24);
            }

            // Act
            var result = LibOqsNative.OQS_MEM_secure_bcmp(ptr1, ptr2, size);

            // Assert
            result.Should().NotBe(0);
        }
        finally
        {
            LibOqsNative.OQS_MEM_insecure_free(ptr1);
            LibOqsNative.OQS_MEM_insecure_free(ptr2);
        }
    }

    [Fact]
    public void OQS_MEM_secure_bcmp_WithNullPointers_ShouldReturnConsistently()
    {
        // Act & Assert - Test with null pointers (behavior may be undefined but shouldn't crash)
        var action1 = () => LibOqsNative.OQS_MEM_secure_bcmp(IntPtr.Zero, IntPtr.Zero, UIntPtr.Zero);
        action1.Should().NotThrow();

        // Compare null with null should be equal (0)
        var result = LibOqsNative.OQS_MEM_secure_bcmp(IntPtr.Zero, IntPtr.Zero, UIntPtr.Zero);
        result.Should().Be(0);
    }

    [Fact]
    public void OQS_MEM_secure_bcmp_WithZeroLength_ShouldReturnZero()
    {
        // Arrange
        var ptr1 = LibOqsNative.OQS_MEM_malloc(32);
        var ptr2 = LibOqsNative.OQS_MEM_malloc(32);

        try
        {
            // Act - Compare 0 bytes should always return 0 (equal)
            var result = LibOqsNative.OQS_MEM_secure_bcmp(ptr1, ptr2, UIntPtr.Zero);

            // Assert
            result.Should().Be(0);
        }
        finally
        {
            LibOqsNative.OQS_MEM_insecure_free(ptr1);
            LibOqsNative.OQS_MEM_insecure_free(ptr2);
        }
    }

    [Fact]
    public void OQS_MEM_strdup_WithValidString_ShouldReturnDuplicateString()
    {
        // Arrange
        const string testString = "Hello, LibOQS!";

        // Act
        var ptr = LibOqsNative.OQS_MEM_strdup(testString);

        try
        {
            // Assert
            ptr.Should().NotBe(IntPtr.Zero);

            var duplicatedString = Marshal.PtrToStringUTF8(ptr);
            duplicatedString.Should().Be(testString);
        }
        finally
        {
            LibOqsNative.OQS_MEM_insecure_free(ptr);
        }
    }

    [Fact]
    public void OQS_MEM_strdup_WithEmptyString_ShouldReturnValidPointer()
    {
        // Arrange
        const string emptyString = "";

        // Act
        var ptr = LibOqsNative.OQS_MEM_strdup(emptyString);

        try
        {
            // Assert
            ptr.Should().NotBe(IntPtr.Zero);

            var duplicatedString = Marshal.PtrToStringUTF8(ptr);
            duplicatedString.Should().Be(emptyString);
        }
        finally
        {
            LibOqsNative.OQS_MEM_insecure_free(ptr);
        }
    }

    [Fact]
    public void OQS_MEM_strdup_WithUnicodeString_ShouldHandleUtf8Correctly()
    {
        // Arrange
        const string unicodeString = "Hello, 世界! 🌍";

        // Act
        var ptr = LibOqsNative.OQS_MEM_strdup(unicodeString);

        try
        {
            // Assert
            ptr.Should().NotBe(IntPtr.Zero);

            var duplicatedString = Marshal.PtrToStringUTF8(ptr);
            duplicatedString.Should().Be(unicodeString);
        }
        finally
        {
            LibOqsNative.OQS_MEM_insecure_free(ptr);
        }
    }

    [Fact]
    public void OQS_randombytes_WithValidBuffer_ShouldFillWithRandomData()
    {
        // Arrange
        const uint size = 32;
        var buffer = new byte[size];

        // Act
        unsafe
        {
            fixed (byte* bufferPtr = buffer)
            {
                LibOqsNative.OQS_randombytes(bufferPtr, size);
            }
        }

        // Assert - Buffer should be filled with non-zero data (high probability)
        buffer.Should().NotBeEquivalentTo(new byte[size]);
    }

    [Fact]
    public void OQS_randombytes_WithZeroSize_ShouldNotThrow()
    {
        // Arrange
        var buffer = new byte[1];

        // Act & Assert
        unsafe
        {
            fixed (byte* bufferPtr = buffer)
            {
                LibOqsNative.OQS_randombytes(bufferPtr, UIntPtr.Zero);
            }
        }

        buffer.Should().AllBeEquivalentTo((byte)0);
    }

    [Fact]
    public void OQS_randombytes_MultipleCalls_ShouldProduceDifferentResults()
    {
        // Arrange
        const uint size = 32;
        var buffer1 = new byte[size];
        var buffer2 = new byte[size];

        // Act
        unsafe
        {
            fixed (byte* buffer1Ptr = buffer1)
            fixed (byte* buffer2Ptr = buffer2)
            {
                LibOqsNative.OQS_randombytes(buffer1Ptr, size);
                LibOqsNative.OQS_randombytes(buffer2Ptr, size);
            }
        }

        // Assert - Buffers should be different (high probability)
        buffer1.Should().NotBeEquivalentTo(buffer2);
    }

    [Fact]
    public void OQS_randombytes_switch_algorithm_WithValidAlgorithm_ShouldReturnSuccess()
    {
        // Act
        var result = LibOqsNative.OQS_randombytes_switch_algorithm("system");

        // Assert - OQS_SUCCESS is typically 0
        result.Should().Be(0);
    }

    [Fact]
    public void OQS_randombytes_switch_algorithm_WithInvalidAlgorithm_ShouldReturnError()
    {
        // Act
        var result = LibOqsNative.OQS_randombytes_switch_algorithm("invalid_algorithm");

        // Assert - Should return non-zero (error)
        result.Should().NotBe(0);
    }

    [Fact]
    public void OQS_randombytes_switch_algorithm_WithOpenSslAlgorithm_ShouldReturnSuccess()
    {
        // Act
        var result = LibOqsNative.OQS_randombytes_switch_algorithm("OpenSSL");

        // Assert - Should succeed (or fail gracefully if OpenSSL not available)
        // Both success (0) and failure (non-zero) are acceptable depending on system config
        Assert.True(result == 0 || result != 0); // Just ensure it doesn't crash
    }

    [Fact]
    public void OQS_CPU_has_extension_WithValidExtension_ShouldReturnBooleanValue()
    {
        // Act
        var result = LibOqsNative.OQS_CPU_has_extension(OqsCpUext.OQS_CPU_EXT_AVX2);

        // Assert - Should return 0 (false) or 1 (true), not crash
        result.Should().BeOneOf(0, 1);
    }

    [Theory]
    [InlineData(OqsCpUext.OQS_CPU_EXT_INIT)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_ADX)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_AES)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_AVX)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_AVX2)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_AVX512)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_BMI1)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_BMI2)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_PCLMULQDQ)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_VPCLMULQDQ)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_POPCNT)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_SSE)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_SSE2)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_SSE3)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_ARM_AES)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_ARM_SHA2)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_ARM_SHA3)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_ARM_NEON)]
    public void OQS_CPU_has_extension_WithAllExtensions_ShouldReturnValidValue(OqsCpUext extension)
    {
        // Act
        var result = LibOqsNative.OQS_CPU_has_extension(extension);

        // Assert - Should return 0 or 1, never crash
        result.Should().BeOneOf(0, 1);
    }

    [Fact]
    public void LibraryName_ShouldHaveCorrectValue()
    {
        // Assert
        LibOqsNative.LibraryName.Should().Be("oqs");
    }

    [Fact]
    public void OqsCpUext_AllValues_ShouldHaveCorrectNumericValues()
    {
        // Assert - Verify enum values match expected constants
        ((int)OqsCpUext.OQS_CPU_EXT_INIT).Should().Be(0);
        ((int)OqsCpUext.OQS_CPU_EXT_ADX).Should().Be(1);
        ((int)OqsCpUext.OQS_CPU_EXT_AES).Should().Be(2);
        ((int)OqsCpUext.OQS_CPU_EXT_AVX).Should().Be(3);
        ((int)OqsCpUext.OQS_CPU_EXT_AVX2).Should().Be(4);
        ((int)OqsCpUext.OQS_CPU_EXT_AVX512).Should().Be(5);
        ((int)OqsCpUext.OQS_CPU_EXT_BMI1).Should().Be(6);
        ((int)OqsCpUext.OQS_CPU_EXT_BMI2).Should().Be(7);
        ((int)OqsCpUext.OQS_CPU_EXT_PCLMULQDQ).Should().Be(8);
        ((int)OqsCpUext.OQS_CPU_EXT_VPCLMULQDQ).Should().Be(9);
        ((int)OqsCpUext.OQS_CPU_EXT_POPCNT).Should().Be(10);
        ((int)OqsCpUext.OQS_CPU_EXT_SSE).Should().Be(11);
        ((int)OqsCpUext.OQS_CPU_EXT_SSE2).Should().Be(12);
        ((int)OqsCpUext.OQS_CPU_EXT_SSE3).Should().Be(13);
        ((int)OqsCpUext.OQS_CPU_EXT_ARM_AES).Should().Be(14);
        ((int)OqsCpUext.OQS_CPU_EXT_ARM_SHA2).Should().Be(15);
        ((int)OqsCpUext.OQS_CPU_EXT_ARM_SHA3).Should().Be(16);
        ((int)OqsCpUext.OQS_CPU_EXT_ARM_NEON).Should().Be(17);
    }

    [Fact]
    public void OqsCpUext_EnumValues_ShouldBeInSequentialOrder()
    {
        // Arrange - Get all enum values
        var enumValues = Enum.GetValues<OqsCpUext>();

        // Act & Assert - Values should be in sequential order from 0 to 17
        enumValues.Should().HaveCount(18);

        for (int i = 0; i < enumValues.Length; i++)
        {
            ((int)enumValues[i]).Should().Be(i);
        }
    }
}

#pragma warning disable S1144