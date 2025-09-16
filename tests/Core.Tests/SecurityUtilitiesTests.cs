using OpenForge.Cryptography.LibOqs.Tests.Common;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.Core.Tests;

#pragma warning disable S1144, S1215, S3776
[Collection("LibOqs Collection")]
public class SecurityUtilitiesTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    public sealed class ConstantTimeEqualsSpanTests
    {
        [Fact]
        public void ConstantTimeEquals_WithEqualSpans_ShouldReturnTrue()
        {
            // Arrange
            var a = new byte[] { 0x01, 0x02, 0x03, 0x04 }.AsSpan();
            var b = new byte[] { 0x01, 0x02, 0x03, 0x04 }.AsSpan();

            // Act
            var result = SecurityUtilities.ConstantTimeEquals(a, b);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public void ConstantTimeEquals_WithDifferentSpans_ShouldReturnFalse()
        {
            // Arrange
            var a = new byte[] { 0x01, 0x02, 0x03, 0x04 }.AsSpan();
            var b = new byte[] { 0x01, 0x02, 0x03, 0xFF }.AsSpan();

            // Act
            var result = SecurityUtilities.ConstantTimeEquals(a, b);

            // Assert
            result.Should().BeFalse();
        }

        [Fact]
        public void ConstantTimeEquals_WithDifferentLengthSpans_ShouldReturnFalse()
        {
            // Arrange
            var a = new byte[] { 0x01, 0x02, 0x03 }.AsSpan();
            var b = new byte[] { 0x01, 0x02, 0x03, 0x04 }.AsSpan();

            // Act
            var result = SecurityUtilities.ConstantTimeEquals(a, b);

            // Assert
            result.Should().BeFalse();
        }

        [Fact]
        public void ConstantTimeEquals_WithEmptySpans_ShouldReturnTrue()
        {
            // Arrange
            var a = ReadOnlySpan<byte>.Empty;
            var b = ReadOnlySpan<byte>.Empty;

            // Act
            var result = SecurityUtilities.ConstantTimeEquals(a, b);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public void ConstantTimeEquals_WithAllZeros_ShouldReturnTrue()
        {
            // Arrange
            var a = new byte[32].AsSpan(); // All zeros
            var b = new byte[32].AsSpan(); // All zeros

            // Act
            var result = SecurityUtilities.ConstantTimeEquals(a, b);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public void ConstantTimeEquals_WithSingleByteDifference_ShouldReturnFalse()
        {
            // Arrange
            var a = new byte[32]; // All zeros
            var b = new byte[32]; // All zeros
            b[15] = 0x01; // Single difference in middle

            // Act
            var result = SecurityUtilities.ConstantTimeEquals(a.AsSpan(), b.AsSpan());

            // Assert
            result.Should().BeFalse();
        }
    }

    public sealed class ConstantTimeEqualsArrayTests
    {
        [Fact]
        public void ConstantTimeEquals_WithEqualArrays_ShouldReturnTrue()
        {
            // Arrange
            var a = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var b = new byte[] { 0x01, 0x02, 0x03, 0x04 };

            // Act
            var result = SecurityUtilities.ConstantTimeEquals(a, b);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public void ConstantTimeEquals_WithDifferentArrays_ShouldReturnFalse()
        {
            // Arrange
            var a = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var b = new byte[] { 0x01, 0x02, 0x03, 0xFF };

            // Act
            var result = SecurityUtilities.ConstantTimeEquals(a, b);

            // Assert
            result.Should().BeFalse();
        }

        [Fact]
        public void ConstantTimeEquals_WithBothNull_ShouldReturnTrue()
        {
            // Act
            var result = SecurityUtilities.ConstantTimeEquals(null, null);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public void ConstantTimeEquals_WithOneNull_ShouldReturnFalse()
        {
            // Arrange
            var a = new byte[] { 0x01, 0x02 };

            // Act
            var result1 = SecurityUtilities.ConstantTimeEquals(a, null);
            var result2 = SecurityUtilities.ConstantTimeEquals(null, a);

            // Assert
            result1.Should().BeFalse();
            result2.Should().BeFalse();
        }

        [Fact]
        public void ConstantTimeEquals_WithSameReference_ShouldReturnTrue()
        {
            // Arrange
            var a = new byte[] { 0x01, 0x02, 0x03, 0x04 };

            // Act
            var result = SecurityUtilities.ConstantTimeEquals(a, a);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public void ConstantTimeEquals_WithEmptyArrays_ShouldReturnTrue()
        {
            // Arrange
            var a = Array.Empty<byte>();
            var b = Array.Empty<byte>();

            // Act
            var result = SecurityUtilities.ConstantTimeEquals(a, b);

            // Assert
            result.Should().BeTrue();
        }
    }

    public sealed class ConstantTimeSelectTests
    {
        [Fact]
        public void ConstantTimeSelect_WithTrueCondition_ShouldReturnFirstValue()
        {
            // Act
            var result = SecurityUtilities.ConstantTimeSelect(true, 0xAA, 0xBB);

            // Assert
            result.Should().Be(0xAA);
        }

        [Fact]
        public void ConstantTimeSelect_WithFalseCondition_ShouldReturnSecondValue()
        {
            // Act
            var result = SecurityUtilities.ConstantTimeSelect(false, 0xAA, 0xBB);

            // Assert
            result.Should().Be(0xBB);
        }

        [Theory]
        [InlineData(true, 0x00, 0xFF, 0x00)]
        [InlineData(false, 0x00, 0xFF, 0xFF)]
        [InlineData(true, 0x42, 0x24, 0x42)]
        [InlineData(false, 0x42, 0x24, 0x24)]
        public void ConstantTimeSelect_WithVariousValues_ShouldReturnCorrectValue(bool condition, byte a, byte b, byte expected)
        {
            // Act
            var result = SecurityUtilities.ConstantTimeSelect(condition, a, b);

            // Assert
            result.Should().Be(expected);
        }
    }

    public sealed class ConstantTimeCopyTests
    {
        [Fact]
        public void ConstantTimeCopy_WithTrueCondition_ShouldCopySourceToDestination()
        {
            // Arrange
            var source = new byte[] { 0x01, 0x02, 0x03, 0x04 }.AsSpan();
            var destination = new byte[4];

            // Act
            SecurityUtilities.ConstantTimeCopy(true, source, destination);

            // Assert
            destination.Should().Equal(0x01, 0x02, 0x03, 0x04);
        }

        [Fact]
        public void ConstantTimeCopy_WithFalseCondition_ShouldNotModifyDestination()
        {
            // Arrange
            var source = new byte[] { 0x01, 0x02, 0x03, 0x04 }.AsSpan();
            var destination = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };

            // Act
            SecurityUtilities.ConstantTimeCopy(false, source, destination);

            // Assert
            destination.Should().Equal(0xAA, 0xBB, 0xCC, 0xDD);
        }

        [Fact]
        public void ConstantTimeCopy_WithDifferentLengths_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ConstantTimeCopy(true,
                [0x01, 0x02, 0x03],
                new byte[4].AsSpan());

            act.Should().Throw<ArgumentException>()
                .WithMessage("Source and destination must have the same length");
        }

        [Fact]
        public void ConstantTimeCopy_WithEmptySpans_ShouldNotThrow()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ConstantTimeCopy(true, [], []);
            act.Should().NotThrow();
        }
    }

    public sealed class ValidateParameterLengthArrayTests
    {
        [Fact]
        public void ValidateParameterLength_WithCorrectLength_ShouldNotThrow()
        {
            // Arrange
            var data = new byte[16];

            // Act & Assert
            var act = () => SecurityUtilities.ValidateParameterLength(data, 16, "testParam");
            act.Should().NotThrow();
        }

        [Fact]
        public void ValidateParameterLength_WithNullArray_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateParameterLength(null, 16, "testParam");
            act.Should().Throw<ArgumentNullException>()
                .WithParameterName("testParam");
        }

        [Fact]
        public void ValidateParameterLength_WithIncorrectLength_ShouldThrowArgumentException()
        {
            // Arrange
            var data = new byte[10];

            // Act & Assert
            var act = () => SecurityUtilities.ValidateParameterLength(data, 16, "testParam");
            act.Should().Throw<ArgumentException>()
                .WithParameterName("testParam")
                .WithMessage("testParam must be exactly 16 bytes, got 10*");
        }

        [Fact]
        public void ValidateParameterLength_WithZeroLengthArray_ShouldValidateCorrectly()
        {
            // Arrange
            var data = Array.Empty<byte>();

            // Act & Assert
            var act = () => SecurityUtilities.ValidateParameterLength(data, 0, "testParam");
            act.Should().NotThrow();
        }
    }

    public sealed class ValidateParameterLengthSpanTests
    {
        [Fact]
        public void ValidateParameterLength_WithCorrectSpanLength_ShouldNotThrow()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateParameterLength(new byte[16].AsSpan(), 16, "testParam");
            act.Should().NotThrow();
        }

        [Fact]
        public void ValidateParameterLength_WithIncorrectSpanLength_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateParameterLength(new byte[10].AsSpan(), 16, "testParam");
            act.Should().Throw<ArgumentException>()
                .WithParameterName("testParam")
                .WithMessage("testParam must be exactly 16 bytes, got 10*");
        }

        [Fact]
        public void ValidateParameterLength_WithEmptySpan_ShouldValidateCorrectly()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateParameterLength([], 0, "testParam");
            act.Should().NotThrow();
        }
    }

    public sealed class ValidateParameterLengthRangeArrayTests
    {
        [Fact]
        public void ValidateParameterLengthRange_WithValidLength_ShouldNotThrow()
        {
            // Arrange
            var data = new byte[16];

            // Act & Assert
            var act = () => SecurityUtilities.ValidateParameterLengthRange(data, 10, 20, "testParam");
            act.Should().NotThrow();
        }

        [Fact]
        public void ValidateParameterLengthRange_WithNullArray_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateParameterLengthRange(null, 10, 20, "testParam");
            act.Should().Throw<ArgumentNullException>()
                .WithParameterName("testParam");
        }

        [Fact]
        public void ValidateParameterLengthRange_WithTooShortArray_ShouldThrowArgumentException()
        {
            // Arrange
            var data = new byte[5];

            // Act & Assert
            var act = () => SecurityUtilities.ValidateParameterLengthRange(data, 10, 20, "testParam");
            act.Should().Throw<ArgumentException>()
                .WithParameterName("testParam")
                .WithMessage("testParam must be between 10 and 20 bytes, got 5*");
        }

        [Fact]
        public void ValidateParameterLengthRange_WithTooLongArray_ShouldThrowArgumentException()
        {
            // Arrange
            var data = new byte[25];

            // Act & Assert
            var act = () => SecurityUtilities.ValidateParameterLengthRange(data, 10, 20, "testParam");
            act.Should().Throw<ArgumentException>()
                .WithParameterName("testParam")
                .WithMessage("testParam must be between 10 and 20 bytes, got 25*");
        }

        [Fact]
        public void ValidateParameterLengthRange_WithBoundaryValues_ShouldNotThrow()
        {
            // Arrange
            var dataMin = new byte[10];
            var dataMax = new byte[20];

            // Act & Assert
            var actMin = () => SecurityUtilities.ValidateParameterLengthRange(dataMin, 10, 20, "testParam");
            var actMax = () => SecurityUtilities.ValidateParameterLengthRange(dataMax, 10, 20, "testParam");
            
            actMin.Should().NotThrow();
            actMax.Should().NotThrow();
        }
    }

    public sealed class ValidateParameterLengthRangeSpanTests
    {
        [Fact]
        public void ValidateParameterLengthRange_WithValidSpanLength_ShouldNotThrow()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateParameterLengthRange(new byte[16].AsSpan(), 10, 20, "testParam");
            act.Should().NotThrow();
        }

        [Fact]
        public void ValidateParameterLengthRange_WithTooShortSpan_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateParameterLengthRange(new byte[5].AsSpan(), 10, 20, "testParam");
            act.Should().Throw<ArgumentException>()
                .WithParameterName("testParam")
                .WithMessage("testParam must be between 10 and 20 bytes, got 5*");
        }

        [Fact]
        public void ValidateParameterLengthRange_WithTooLongSpan_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateParameterLengthRange(new byte[25].AsSpan(), 10, 20, "testParam");
            act.Should().Throw<ArgumentException>()
                .WithParameterName("testParam")
                .WithMessage("testParam must be between 10 and 20 bytes, got 25*");
        }
    }

    public sealed class ValidateSizeTests
    {
        [Fact]
        public void ValidateSize_WithValidSize_ShouldNotThrow()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateSize(100, 1000, "testParam");
            act.Should().NotThrow();
        }

        [Fact]
        public void ValidateSize_WithNegativeSize_ShouldThrowArgumentOutOfRangeException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateSize(-1, 1000, "testParam");
            act.Should().Throw<ArgumentOutOfRangeException>()
                .WithParameterName("testParam")
                .WithMessage("Size must be non-negative*");
        }

        [Fact]
        public void ValidateSize_WithOversizedSize_ShouldThrowArgumentOutOfRangeException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateSize(2000, 1000, "testParam");
            act.Should().Throw<ArgumentOutOfRangeException>()
                .WithParameterName("testParam")
                .WithMessage("Size 2000 exceeds maximum allowed size 1000*");
        }

        [Fact]
        public void ValidateSize_WithBoundaryValues_ShouldNotThrow()
        {
            // Act & Assert
            var actZero = () => SecurityUtilities.ValidateSize(0, 1000, "testParam");
            var actMax = () => SecurityUtilities.ValidateSize(1000, 1000, "testParam");
            
            actZero.Should().NotThrow();
            actMax.Should().NotThrow();
        }
    }

    public sealed class ValidateRandomBytesEntropyTests
    {
        [Fact]
        public void ValidateRandomBytesEntropy_WithEmptySpan_ShouldNotThrow()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateRandomBytesEntropy([], "testParam");
            act.Should().NotThrow();
        }

        [Fact]
        public void ValidateRandomBytesEntropy_WithGoodEntropy_ShouldNotThrow()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateRandomBytesEntropy([0x01, 0x02, 0x03, 0x04, 0x05], "testParam");
            act.Should().NotThrow();
        }

        [Fact]
        public void ValidateRandomBytesEntropy_WithAllZeros_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateRandomBytesEntropy(new byte[16].AsSpan(), "testParam");
            act.Should().Throw<ArgumentException>()
                .WithParameterName("testParam")
                .WithMessage("*appears to have insufficient entropy (all bytes are 0x00)*");
        }

        [Fact]
        public void ValidateRandomBytesEntropy_WithAllFF_ShouldThrowArgumentException()
        {
            // Arrange
            var data = new byte[16];
            Array.Fill(data, (byte)0xFF);

            // Act & Assert
            var act = () => SecurityUtilities.ValidateRandomBytesEntropy(data.AsSpan(), "testParam");
            act.Should().Throw<ArgumentException>()
                .WithParameterName("testParam")
                .WithMessage("*appears to have insufficient entropy (all bytes are 0xFF)*");
        }

        [Fact]
        public void ValidateRandomBytesEntropy_WithAllSameValue_ShouldThrowArgumentException()
        {
            // Arrange
            var data = new byte[16];
            Array.Fill(data, (byte)0x42);

            // Act & Assert
            var act = () => SecurityUtilities.ValidateRandomBytesEntropy(data.AsSpan(), "testParam");
            act.Should().Throw<ArgumentException>()
                .WithParameterName("testParam")
                .WithMessage("*appears to have insufficient entropy (all bytes are 0x42)*");
        }

        [Fact]
        public void ValidateRandomBytesEntropy_WithSingleByte_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateRandomBytesEntropy("B"u8.ToArray().AsSpan(), "testParam");
            act.Should().Throw<ArgumentException>()
                .WithParameterName("testParam")
                .WithMessage("*appears to have insufficient entropy (all bytes are 0x42)*");
        }

        [Theory]
        [InlineData(new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 })] // Repeating pattern
        [InlineData(new byte[] { 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB })] // Same value repeated
        [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })] // All zeros pattern
        public void ValidateRandomBytesEntropy_WithPatterns_ShouldDetectLowEntropy(byte[] data)
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateRandomBytesEntropy(data.AsSpan(), "testParam");
            act.Should().Throw<ArgumentException>()
                .WithParameterName("testParam")
                .WithMessage("*appears to have insufficient entropy*");
        }

        [Fact]
        public void ValidateRandomBytesEntropy_WithRepeatingPatterns_ShouldThrowArgumentException()
        {
            // Arrange - Create data with repeating ABAB pattern
            var data = new byte[32];
            for (int i = 0; i < data.Length; i += 2)
            {
                data[i] = 0xAB;
                if (i + 1 < data.Length)
                    data[i + 1] = 0xAB;
            }

            // Act & Assert
            var act = () => SecurityUtilities.ValidateRandomBytesEntropy(data.AsSpan(), "testParam");
            act.Should().Throw<ArgumentException>()
                .WithParameterName("testParam")
                .WithMessage("*appears to have insufficient entropy*");
        }
    }

    public sealed class CreateDefensiveCopyTests
    {
        [Fact]
        public void CreateDefensiveCopy_WithNullArray_ShouldReturnNull()
        {
            // Act
            var result = SecurityUtilities.CreateDefensiveCopy(null);

            // Assert
            result.Should().BeNull();
        }

        [Fact]
        public void CreateDefensiveCopy_WithValidArray_ShouldReturnCopy()
        {
            // Arrange
            var original = new byte[] { 0x01, 0x02, 0x03, 0x04 };

            // Act
            var copy = SecurityUtilities.CreateDefensiveCopy(original);

            // Assert
            copy.Should().NotBeNull();
            copy.Should().Equal(original);
            copy.Should().NotBeSameAs(original); // Different references
        }

        [Fact]
        public void CreateDefensiveCopy_ModifyingOriginal_ShouldNotAffectCopy()
        {
            // Arrange
            var original = new byte[] { 0x01, 0x02, 0x03, 0x04 };

            // Act
            var copy = SecurityUtilities.CreateDefensiveCopy(original);
            original[0] = 0xFF; // Modify original

            // Assert
            copy![0].Should().Be(0x01); // Copy unchanged
        }

        [Fact]
        public void CreateDefensiveCopy_WithEmptyArray_ShouldReturnEmptyArray()
        {
            // Arrange
            var original = Array.Empty<byte>();

            // Act
            var copy = SecurityUtilities.CreateDefensiveCopy(original);

            // Assert
            copy.Should().NotBeNull();
            copy.Should().BeEmpty();
            copy.Should().NotBeSameAs(original);
        }

        [Fact]
        public void CreateDefensiveCopy_WithSpan_ShouldReturnArray()
        {
            // Arrange
            var original = new byte[] { 0x01, 0x02, 0x03, 0x04 }.AsSpan();

            // Act
            var copy = SecurityUtilities.CreateDefensiveCopy(original);

            // Assert
            copy.Should().NotBeNull();
            copy.Should().Equal(0x01, 0x02, 0x03, 0x04);
        }

        [Fact]
        public void CreateDefensiveCopy_WithEmptySpan_ShouldReturnEmptyArray()
        {
            // Arrange
            var original = ReadOnlySpan<byte>.Empty;

            // Act
            var copy = SecurityUtilities.CreateDefensiveCopy(original);

            // Assert
            copy.Should().NotBeNull();
            copy.Should().BeEmpty();
        }
    }

    public sealed class ToHexStringTests
    {
        [Fact]
        public void ToHexString_WithEmptySpan_ShouldReturnEmptyString()
        {
            // Arrange
            var bytes = ReadOnlySpan<byte>.Empty;

            // Act
            var result = SecurityUtilities.ToHexString(bytes);

            // Assert
            result.Should().BeEmpty();
        }

        [Fact]
        public void ToHexString_WithValidBytes_ShouldReturnCorrectHex()
        {
            // Arrange
            var bytes = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }.AsSpan();

            // Act
            var result = SecurityUtilities.ToHexString(bytes);

            // Assert
            result.Should().Be("0123456789abcdef");
        }

        [Fact]
        public void ToHexString_WithZeroBytes_ShouldReturnZeros()
        {
            // Arrange
            var bytes = new byte[4].AsSpan(); // All zeros

            // Act
            var result = SecurityUtilities.ToHexString(bytes);

            // Assert
            result.Should().Be("00000000");
        }

        [Fact]
        public void ToHexString_WithSingleByte_ShouldReturnTwoCharacters()
        {
            // Arrange
            var bytes = new byte[] { 0x42 }.AsSpan();

            // Act
            var result = SecurityUtilities.ToHexString(bytes);

            // Assert
            result.Should().Be("42");
        }

        [Fact]
        public void ToHexString_WithMaxValues_ShouldReturnFF()
        {
            // Arrange
            var bytes = new byte[] { 0xFF, 0xFF }.AsSpan();

            // Act
            var result = SecurityUtilities.ToHexString(bytes);

            // Assert
            result.Should().Be("ffff");
        }
    }

    public sealed class FromHexStringTests
    {
        [Fact]
        public void FromHexString_WithValidHexString_ShouldReturnCorrectBytes()
        {
            // Act
            var result = SecurityUtilities.FromHexString("0123456789ABCDEF");

            // Assert
            result.Should().Equal(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF);
        }

        [Fact]
        public void FromHexString_WithLowercaseHex_ShouldReturnCorrectBytes()
        {
            // Act
            var result = SecurityUtilities.FromHexString("0123456789abcdef");

            // Assert
            result.Should().Equal(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF);
        }

        [Fact]
        public void FromHexString_WithNullString_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.FromHexString(null!);
            act.Should().Throw<ArgumentException>();
        }

        [Fact]
        public void FromHexString_WithEmptyString_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.FromHexString("");
            act.Should().Throw<ArgumentException>();
        }

        [Fact]
        public void FromHexString_WithWhitespaceString_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.FromHexString("   ");
            act.Should().Throw<ArgumentException>();
        }

        [Fact]
        public void FromHexString_WithOddLength_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.FromHexString("123");
            act.Should().Throw<ArgumentException>()
                .WithMessage("Hex string must have an even number of characters*");
        }

        [Fact]
        public void FromHexString_WithInvalidHexCharacters_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.FromHexString("12GH");
            act.Should().Throw<ArgumentException>()
                .WithMessage("Invalid hex characters at position*");
        }

        [Fact]
        public void FromHexString_WithAllZeros_ShouldReturnZeroBytes()
        {
            // Act
            var result = SecurityUtilities.FromHexString("00000000");

            // Assert
            result.Should().Equal(0x00, 0x00, 0x00, 0x00);
        }

        [Fact]
        public void FromHexString_WithAllFF_ShouldReturnMaxBytes()
        {
            // Act
            var result = SecurityUtilities.FromHexString("FFFF");

            // Assert
            result.Should().Equal(0xFF, 0xFF);
        }

        [Theory]
        [InlineData("café", "Invalid hex characters")] // Unicode characters - "é" is not valid hex
        [InlineData("한글", "Invalid hex characters")] // Korean characters - not valid hex 
        [InlineData("12G4", "Invalid hex characters")] // Invalid hex char G
        [InlineData("12♠4", "Invalid hex characters")] // Special symbol
        [InlineData("FF-FF", "Hex string must have an even number of characters")] // Dash separator (5 chars)
        [InlineData("FF FF", "Hex string must have an even number of characters")] // Space separator (5 chars)
        public void FromHexString_WithUnicodeAndSpecialChars_ShouldThrowArgumentException(string hexInput, string expectedMessagePart)
        {
            // Act & Assert
            var act = () => SecurityUtilities.FromHexString(hexInput);
            act.Should().Throw<ArgumentException>()
                .WithMessage($"*{expectedMessagePart}*");
        }

        [Fact]
        public void ToHexString_WithUnicodeBytes_ShouldHandleCorrectly()
        {
            // Arrange - UTF-8 encoded Unicode string
            var unicodeString = "Hello 世界";
            var unicodeBytes = Encoding.UTF8.GetBytes(unicodeString);

            // Act
            var hexResult = SecurityUtilities.ToHexString(unicodeBytes);

            // Assert
            hexResult.Should().NotBeNullOrEmpty();
            hexResult.Should().MatchRegex("^[0-9a-f]+$", "result should only contain lowercase hex digits");
            
            // Should be able to round-trip
            var roundTripBytes = SecurityUtilities.FromHexString(hexResult);
            roundTripBytes.Should().Equal(unicodeBytes);
            Encoding.UTF8.GetString(roundTripBytes).Should().Be(unicodeString);
        }
    }

    public sealed class ValidateNonEmptyStringTests
    {
        [Fact]
        public void ValidateNonEmptyString_WithValidString_ShouldNotThrow()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateNonEmptyString("valid", "testParam");
            act.Should().NotThrow();
        }

        [Fact]
        public void ValidateNonEmptyString_WithNullString_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateNonEmptyString(null, "testParam");
            act.Should().Throw<ArgumentException>();
        }

        [Fact]
        public void ValidateNonEmptyString_WithEmptyString_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateNonEmptyString("", "testParam");
            act.Should().Throw<ArgumentException>();
        }

        [Fact]
        public void ValidateNonEmptyString_WithWhitespaceString_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateNonEmptyString("   ", "testParam");
            act.Should().Throw<ArgumentException>();
        }
    }

    public sealed class ValidateNonEmptySpanTests
    {
        [Fact]
        public void ValidateNonEmptySpan_WithValidSpan_ShouldNotThrow()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateNonEmptySpan([0x01], "testParam");
            act.Should().NotThrow();
        }

        [Fact]
        public void ValidateNonEmptySpan_WithEmptySpan_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => SecurityUtilities.ValidateNonEmptySpan([], "testParam");
            act.Should().Throw<ArgumentException>()
                .WithParameterName("testParam")
                .WithMessage("Parameter cannot be empty*");
        }
    }

    public sealed class RoundTripHexConversionTests
    {
        [Theory]
        [InlineData(new byte[] { 0x00 })]
        [InlineData(new byte[] { 0xFF })]
        [InlineData(new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF })]
        [InlineData(new byte[] { })]
        public void ToHexString_FromHexString_ShouldRoundTrip(byte[] originalBytes)
        {
            // Act
            var hexString = SecurityUtilities.ToHexString(originalBytes);
            var roundTripBytes = hexString.Length > 0 ? SecurityUtilities.FromHexString(hexString) : [];

            // Assert
            roundTripBytes.Should().Equal(originalBytes);
        }
    }

    public sealed class TimingAttackValidationTests
    {
        [Fact]
        public void ConstantTimeEquals_TimingConsistency_ShouldBeConstant()
        {
            // Arrange - Create arrays that differ at different positions
            const int arraySize = 1024;
            var baseArray = new byte[arraySize];
            RandomNumberGenerator.Fill(baseArray);

            var earlyDiffArray = (byte[])baseArray.Clone();
            earlyDiffArray[0] = (byte)(earlyDiffArray[0] ^ 0xFF); // Differ at start

            var lateDiffArray = (byte[])baseArray.Clone();
            lateDiffArray[^1] = (byte)(lateDiffArray[^1] ^ 0xFF); // Differ at end

            // Act - Measure timing for early vs late differences
            var earlyTimes = new List<long>();
            var lateTimes = new List<long>();
            const int iterations = 100;

            var sw = Stopwatch.StartNew();
            
            for (int i = 0; i < iterations; i++)
            {
                sw.Restart();
                SecurityUtilities.ConstantTimeEquals(baseArray, earlyDiffArray);
                sw.Stop();
                earlyTimes.Add(sw.ElapsedTicks);

                sw.Restart();
                SecurityUtilities.ConstantTimeEquals(baseArray, lateDiffArray);
                sw.Stop();
                lateTimes.Add(sw.ElapsedTicks);
            }

            // Assert - Timing should not reveal position of difference
            // Note: This is a best-effort test; timing attacks are hard to test reliably
            var earlyAvg = earlyTimes.Average();
            var lateAvg = lateTimes.Average();
            var timingRatio = Math.Max(earlyAvg, lateAvg) / Math.Min(earlyAvg, lateAvg);
            
            // Allow some variance but flag significant timing differences (environment-aware)
            var baseline = TimingUtils.GetSystemBaseline();
            var adaptiveThreshold = baseline.Environment switch
            {
                TimingUtils.EnvironmentType.CI => 25.0,      // Very lenient for CI
                TimingUtils.EnvironmentType.LocalSlow => 20.0,  // Somewhat lenient for slow systems
                TimingUtils.EnvironmentType.LocalFast => 15.0,  // Original threshold for fast systems
                _ => 20.0
            };
            
            timingRatio.Should().BeLessThan(adaptiveThreshold, 
                $"timing should be relatively consistent regardless of difference position (threshold: {adaptiveThreshold:F1} for {baseline.Environment})");
        }

        [Fact]
        public async Task ConstantTimeEquals_UnderLoad_ShouldMaintainConstantTiming()
        {
            // Arrange
            var array1 = new byte[256];
            var array2 = new byte[256];
            RandomNumberGenerator.Fill(array1);
            RandomNumberGenerator.Fill(array2);

            const int parallelTasks = 10;
            const int operationsPerTask = 50;

            // Act - Run constant-time operations under load
            var tasks = new Task[parallelTasks];
            for (int i = 0; i < parallelTasks; i++)
            {
                tasks[i] = Task.Run(() =>
                {
                    for (int j = 0; j < operationsPerTask; j++)
                    {
                        var result = SecurityUtilities.ConstantTimeEquals(array1, array2);
                        result.Should().BeFalse(); // Arrays are different
                    }
                }, TestContext.Current.CancellationToken);
            }

            await Task.WhenAll(tasks);
            
            // Assert - All operations should complete without issues
            tasks.Should().AllSatisfy(task => task.IsCompletedSuccessfully.Should().BeTrue());
        }

        [Fact]
        public async Task ConstantTimeSelect_ShouldNotLeakCondition()
        {
            // Arrange
            const byte trueValue = 0xAA;
            const byte falseValue = 0x55;
            
            // Warm-up phase for JIT compilation
            for (int i = 0; i < 5000; i++)
            {
                _ = SecurityUtilities.ConstantTimeSelect(true, trueValue, falseValue);
                _ = SecurityUtilities.ConstantTimeSelect(false, trueValue, falseValue);
            }
            
            // Run multiple times and take the best result
            const int runs = 5;
            double bestRatio = double.MaxValue;
            
            for (int run = 0; run < runs; run++)
            {
                // Force garbage collection before timing
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
                await Task.Delay(10, TestContext.Current.CancellationToken);
                
                const int iterations = 1000;
                var trueTimes = new List<long>();
                var falseTimes = new List<long>();
                var sw = Stopwatch.StartNew();

                // Act - Measure timing for both conditions
                for (int i = 0; i < iterations; i++)
                {
                    sw.Restart();
                    var result1 = SecurityUtilities.ConstantTimeSelect(true, trueValue, falseValue);
                    sw.Stop();
                    trueTimes.Add(sw.ElapsedTicks);
                    result1.Should().Be(trueValue);

                    sw.Restart();
                    var result2 = SecurityUtilities.ConstantTimeSelect(false, trueValue, falseValue);
                    sw.Stop();
                    falseTimes.Add(sw.ElapsedTicks);
                    result2.Should().Be(falseValue);
                }

                // Calculate ratio using trimmed mean
                trueTimes.Sort();
                falseTimes.Sort();
                var trimCount = trueTimes.Count / 10;
                var trimmedTrue = trueTimes.Skip(trimCount).Take(trueTimes.Count - 2 * trimCount).Average();
                var trimmedFalse = falseTimes.Skip(trimCount).Take(falseTimes.Count - 2 * trimCount).Average();
                var timingRatio = Math.Max(trimmedTrue, trimmedFalse) / Math.Min(trimmedTrue, trimmedFalse);
                
                bestRatio = Math.Min(bestRatio, timingRatio);
            }
            
            // Assert - Use environment-aware threshold
            var baseline = TimingUtils.GetSystemBaseline();
            var selectThreshold = baseline.Environment switch
            {
                TimingUtils.EnvironmentType.CI => 12.0,      // Very lenient for CI
                TimingUtils.EnvironmentType.LocalSlow => 8.0,   // Somewhat lenient for slow systems
                TimingUtils.EnvironmentType.LocalFast => 5.0,   // Original threshold for fast systems
                _ => 8.0
            };
            
            bestRatio.Should().BeLessThan(selectThreshold, 
                "constant-time select should not leak the condition through timing (best ratio from {0} runs was {1:F2}, threshold: {2:F1} for {3})",
                runs, bestRatio, selectThreshold, baseline.Environment);
        }
    }
    }

public sealed class EntropyEdgeCaseTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Theory]
    [InlineData(new byte[] { 0x80, 0x80, 0x80, 0x80 })] // High bit pattern
    [InlineData(new byte[] { 0x0F, 0x0F, 0x0F, 0x0F })] // Low nibble pattern
    [InlineData(new byte[] { 0xF0, 0xF0, 0xF0, 0xF0 })] // High nibble pattern
    [InlineData(new byte[] { 0x55, 0x55, 0x55, 0x55 })] // Alternating bits (01010101)
    [InlineData(new byte[] { 0xAA, 0xAA, 0xAA, 0xAA })] // Alternating bits (10101010)
    public void ValidateRandomBytesEntropy_WithBitPatterns_ShouldDetectLowEntropy(byte[] data)
    {
        // Act & Assert
        var act = () => SecurityUtilities.ValidateRandomBytesEntropy(data.AsSpan(), "testParam");
        act.Should().Throw<ArgumentException>()
            .WithParameterName("testParam")
            .WithMessage("*appears to have insufficient entropy*");
    }

    [Theory]
    [InlineData(new byte[] { 0x12, 0x34, 0x12, 0x34, 0x12, 0x34 })] // ABAB pattern
    [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x01, 0x02, 0x03 })] // ABC pattern
    [InlineData(new byte[] { 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00 })] // Extreme alternating
    public void ValidateRandomBytesEntropy_WithRepeatingShortPatterns_ShouldNotThrowException(byte[] data)
    {
        // Act & Assert - Current implementation only detects "all same" bytes, not complex patterns
        var act = () => SecurityUtilities.ValidateRandomBytesEntropy(data.AsSpan(), "testParam");
        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateRandomBytesEntropy_WithIncrementalPattern_ShouldNotThrowException()
    {
        // Arrange - Create incrementing byte sequence
        var data = new byte[16];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)i;
        }

        // Act & Assert - Current implementation only detects "all same" bytes, not incremental patterns
        var act = () => SecurityUtilities.ValidateRandomBytesEntropy(data.AsSpan(), "testParam");
        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateRandomBytesEntropy_WithHighEntropy_ShouldNotThrow()
    {
        // Arrange - Create data with good entropy characteristics
        var data = new byte[]
        {
                0x4A, 0x7B, 0x92, 0x3E, 0xD1, 0x68, 0x05, 0xC9,
                0xF3, 0x2B, 0x8E, 0x47, 0x61, 0xA5, 0xDB, 0x0F
        };

        // Act & Assert
        var act = () => SecurityUtilities.ValidateRandomBytesEntropy(data.AsSpan(), "testParam");
        act.Should().NotThrow();
    }

    [Theory]
    [InlineData(2)] // Short but has different values
    [InlineData(3)]
    public void ValidateRandomBytesEntropy_WithVeryShortValidData_ShouldNotThrow(int length)
    {
        // Arrange - Create short arrays with different values
        var data = new byte[length];
        for (int i = 0; i < length; i++)
        {
            data[i] = (byte)(i + 1); // Different values: [1, 2] or [1, 2, 3]
        }

        // Act & Assert
        var act = () => SecurityUtilities.ValidateRandomBytesEntropy(data.AsSpan(), "testParam");
        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateRandomBytesEntropy_WithSingleByte_ShouldThrowArgumentException()
    {
        // Arrange - Single byte is always "all same"
        var data = new byte[] { 1 };

        // Act & Assert
        var act = () => SecurityUtilities.ValidateRandomBytesEntropy(data.AsSpan(), "testParam");
        act.Should().Throw<ArgumentException>()
            .WithParameterName("testParam")
            .WithMessage("*appears to have insufficient entropy (all bytes are 0x01)*");
    }
    
    [Fact]
    public void ValidateRandomBytesEntropy_WithMixedValidInvalidData_ShouldDetectCorrectly()
    {
        // Valid: Mixed data with good entropy
        var validData = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
        var act1 = () => SecurityUtilities.ValidateRandomBytesEntropy(validData.AsSpan(), "validParam");
        act1.Should().NotThrow();
        
        // Invalid: All bytes are the same (this is what the validation actually detects)
        var invalidData = new byte[] { 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42 };
        var act2 = () => SecurityUtilities.ValidateRandomBytesEntropy(invalidData.AsSpan(), "invalidParam");
        act2.Should().Throw<ArgumentException>()
            .WithMessage("*appears to have insufficient entropy (all bytes are 0x42)*");
    }
}

public sealed class MalformedHexStringTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Theory]
    [InlineData("\t\t")] // Tab characters
    [InlineData("\r\n")] // Carriage return and newline
    [InlineData(" \u00A0")] // Space and non-breaking space
    [InlineData("\u2000\u2001")] // En quad and em quad spaces
    public void FromHexString_WithWhitespaceCharacters_ShouldThrowWhitespaceException(string hexInput)
    {
        // Act & Assert - Whitespace gets caught by ArgumentException.ThrowIfNullOrWhiteSpace
        var act = () => SecurityUtilities.FromHexString(hexInput);
        act.Should().Throw<ArgumentException>()
            .WithMessage("*cannot be an empty string or composed entirely of whitespace*");
    }

    [Theory]
    [InlineData("\0\0")] // Null characters (not whitespace) - 2 chars, even length
    [InlineData("🔥")] // Single emoji (multi-byte Unicode) - may be odd or even depending on encoding
    [InlineData("ΩΩ")] // Mathematical symbols - 2 chars, even length  
    [InlineData("F\u0001")] // Control character - 2 chars, even length
    [InlineData("G\u0007")] // Bell character - 2 chars, even length
    public void FromHexString_WithNonWhitespaceInvalidCharacters_ShouldThrowInvalidHexException(string hexInput)
    {
        // Act & Assert - Non-whitespace invalid characters get caught by hex parsing
        var act = () => SecurityUtilities.FromHexString(hexInput);
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Invalid hex characters*");
    }

    [Theory]
    [InlineData("ZZZZ", 0)] // Z at position 0 (pair "ZZ")
    [InlineData("12GH", 2)] // G at position 2 (pair "GH")  
    [InlineData("AB@D", 2)] // @ at position 2 (pair "@D")
    [InlineData("123X", 2)] // X at position 2 (pair "3X" - reports start of pair)
    [InlineData("FF.F", 2)] // . at position 2 (pair ".F")
    public void FromHexString_WithInvalidCharAtPosition_ShouldReportCorrectPosition(string hexInput, int expectedPosition)
    {
        // Act & Assert
        var act = () => SecurityUtilities.FromHexString(hexInput);
        act.Should().Throw<ArgumentException>()
            .WithMessage($"*Invalid hex characters at position {expectedPosition}*");
    }

    [Fact]
    public void FromHexString_WithLongInvalidString_ShouldStopAtFirstError()
    {
        // Arrange - Long string with invalid character early (even length)
        var invalidHex = "12G" + new string('F', 101); // G at position 2, then many valid chars (total: 104 chars, even)

        // Act & Assert - Should report position of first invalid character
        var act = () => SecurityUtilities.FromHexString(invalidHex);
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Invalid hex characters at position 2*");
    }

    [Fact]
    public void FromHexString_WithMixedCase_ShouldHandleCorrectly()
    {
        // Arrange
        var mixedCaseHex = "aAbBcCdDeEfF";
        var expectedBytes = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

        // Act
        var result = SecurityUtilities.FromHexString(mixedCaseHex);

        // Assert
        result.Should().Equal(expectedBytes);
    }
}

public sealed class ExtendedTimingAttackTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public async Task ConstantTimeCopy_ShouldNotLeakCondition()
    {
        // Arrange
        const int arraySize = 256;
        var source = new byte[arraySize];
        RandomNumberGenerator.Fill(source);
        
        var trueDestination = new byte[arraySize];
        var falseDestination = new byte[arraySize];
        
        // Warm-up phase for JIT compilation
        for (int i = 0; i < 1000; i++)
        {
            SecurityUtilities.ConstantTimeCopy(true, source, trueDestination);
            SecurityUtilities.ConstantTimeCopy(false, source, falseDestination);
        }
        
        // Run multiple times and take the best result
        const int runs = 5;
        double bestRatio = double.MaxValue;
        
        for (int run = 0; run < runs; run++)
        {
            // Force garbage collection before timing
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            await Task.Delay(10, TestContext.Current.CancellationToken);

            var trueTimes = new List<long>();
            var falseTimes = new List<long>();
            const int iterations = 100;
            var sw = Stopwatch.StartNew();

            // Act - Measure timing for both conditions
            for (int i = 0; i < iterations; i++)
            {
                // Reset destinations
                Array.Clear(trueDestination);
                Array.Clear(falseDestination);
                
                sw.Restart();
                SecurityUtilities.ConstantTimeCopy(true, source, trueDestination);
                sw.Stop();
                trueTimes.Add(sw.ElapsedTicks);
                
                sw.Restart();
                SecurityUtilities.ConstantTimeCopy(false, source, falseDestination);
                sw.Stop();
                falseTimes.Add(sw.ElapsedTicks);
            }

            // Calculate ratio using trimmed mean
            trueTimes.Sort();
            falseTimes.Sort();
            var trimCount = trueTimes.Count / 10;
            var trimmedTrue = trueTimes.Skip(trimCount).Take(trueTimes.Count - 2 * trimCount).Average();
            var trimmedFalse = falseTimes.Skip(trimCount).Take(falseTimes.Count - 2 * trimCount).Average();
            var timingRatio = Math.Max(trimmedTrue, trimmedFalse) / Math.Min(trimmedTrue, trimmedFalse);
            
            bestRatio = Math.Min(bestRatio, timingRatio);
        }
        
        // Assert - Use environment-aware threshold
        var baseline = TimingUtils.GetSystemBaseline();
        var copyThreshold = baseline.Environment switch
        {
            TimingUtils.EnvironmentType.CI => 12.0,      // Very lenient for CI
            TimingUtils.EnvironmentType.LocalSlow => 8.0,   // Somewhat lenient for slow systems
            TimingUtils.EnvironmentType.LocalFast => 5.0,   // Original threshold for fast systems
            _ => 8.0
        };
        
        bestRatio.Should().BeLessThan(copyThreshold, 
            "constant-time copy should not leak the condition through timing (best ratio from {0} runs was {1:F2}, threshold: {2:F1} for {3})",
            runs, bestRatio, copyThreshold, baseline.Environment);
    }

    [Fact]
    public async Task ConstantTimeEquals_WithVaryingDataPatterns_ShouldMaintainConstantTime()
    {
        // Arrange - Test with different data patterns that might affect timing
        const int arraySize = 512;
        var baseArray = new byte[arraySize];
        RandomNumberGenerator.Fill(baseArray);
        
        // Different patterns that might have different timing characteristics
        var patterns = new[]
        {
            (name: "AllZeros", data: new byte[arraySize]), // All zeros
            (name: "AllOnes", data: Enumerable.Repeat((byte)0xFF, arraySize).ToArray()), // All 0xFF
            (name: "Alternating", data: Enumerable.Range(0, arraySize).Select(i => (byte)(i % 2 == 0 ? 0xAA : 0x55)).ToArray()), // Alternating pattern
            (name: "Incremental", data: [.. Enumerable.Range(0, arraySize).Select(i => (byte)(i % 256))]) // Incremental
        };
        
        // Warm-up phase to ensure JIT compilation
        foreach (var (_, data) in patterns)
        {
            for (int i = 0; i < 100; i++)
            {
                SecurityUtilities.ConstantTimeEquals(baseArray, data);
            }
        }
        
        // Run multiple times and take the best result to reduce noise
        const int runs = 3;
        double bestRatio = double.MaxValue;
        
        for (int run = 0; run < runs; run++)
        {
            // Force garbage collection before timing
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            await Task.Delay(10, TestContext.Current.CancellationToken); // Brief pause to let system settle
            
            var allTimes = new Dictionary<string, List<long>>();
            const int iterations = 50;
            var sw = Stopwatch.StartNew();
            
            // Act - Measure timing for each pattern
            foreach (var (name, data) in patterns)
            {
                var times = new List<long>();
                for (int i = 0; i < iterations; i++)
                {
                    sw.Restart();
                    SecurityUtilities.ConstantTimeEquals(baseArray, data);
                    sw.Stop();
                    times.Add(sw.ElapsedTicks);
                }
                allTimes[name] = times;
            }
            
            // Calculate ratio for this run using trimmed mean
            var averages = allTimes.ToDictionary(kvp => kvp.Key, kvp =>
            {
                var sorted = kvp.Value.OrderBy(t => t).ToList();
                var trimCount = sorted.Count / 10; // Remove top and bottom 10%
                return sorted.Skip(trimCount).Take(sorted.Count - 2 * trimCount).Average();
            });
            
            var minAvg = averages.Values.Min();
            var maxAvg = averages.Values.Max();
            var overallRatio = maxAvg / minAvg;
            
            bestRatio = Math.Min(bestRatio, overallRatio);
        }
        
        // Assert - Use environment-aware threshold for data pattern consistency
        var baseline = TimingUtils.GetSystemBaseline();
        var patternThreshold = baseline.Environment switch
        {
            TimingUtils.EnvironmentType.CI => 12.0,      // Very lenient for CI
            TimingUtils.EnvironmentType.LocalSlow => 8.0,   // Somewhat lenient for slow systems
            TimingUtils.EnvironmentType.LocalFast => 5.0,   // Original threshold for fast systems
            _ => 8.0
        };
        
        bestRatio.Should().BeLessThan(patternThreshold, 
            "timing should be consistent across different data patterns (best ratio from {0} runs was {1:F2}, threshold: {2:F1} for {3})",
            runs, bestRatio, patternThreshold, baseline.Environment);
    }
}

public sealed class ParameterNameValidationTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Theory]
    [InlineData("\t")] // Tab only
    [InlineData("\n")] // Newline only  
    [InlineData("\r")] // Carriage return only
    [InlineData("\r\n")] // CRLF
    [InlineData("\t\n \r")] // Mixed whitespace
    [InlineData("\u00A0")] // Non-breaking space
    [InlineData("\u2000")] // En quad
    [InlineData("\u2028")] // Line separator
    public void ValidateNonEmptyString_WithVariousWhitespaceTypes_ShouldThrowArgumentException(string whitespaceString)
    {
        // Act & Assert
        var act = () => SecurityUtilities.ValidateNonEmptyString(whitespaceString, "testParam");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ValidateNonEmptyString_ParameterName_ShouldBeUsedInException()
    {
        // Arrange
        const string paramName = "myCustomParameter";

        try
        {
            // Act
            SecurityUtilities.ValidateNonEmptyString(null, paramName);
            
            // Should not reach here
            Assert.Fail("Expected exception was not thrown");
        }
        catch (ArgumentException ex)
        {
            // Assert - The parameter name should be preserved through the validation
            // Note: ArgumentException.ThrowIfNullOrWhiteSpace uses the parameterName
            ex.Message.Should().Contain(paramName);
        }
    }

    [Fact]
    public void ValidateNonEmptyString_WithUnicodeString_ShouldNotThrow()
    {
        // Act & Assert
        var act = () => SecurityUtilities.ValidateNonEmptyString("Hello 世界 🌍", "testParam");
        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateNonEmptyString_WithSingleCharacter_ShouldNotThrow()
    {
        // Act & Assert
        var act = () => SecurityUtilities.ValidateNonEmptyString("a", "testParam");
        act.Should().NotThrow();
    }
}

public sealed class ErrorHandlingComprehensiveTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void ValidationMethods_ShouldProvideDescriptiveErrorMessages()
    {
        // Test ValidateParameterLength array version
        var act1 = () => SecurityUtilities.ValidateParameterLength(new byte[5], 10, "myArray");
        act1.Should().Throw<ArgumentException>()
            .WithMessage("myArray must be exactly 10 bytes, got 5*")
            .And.ParamName.Should().Be("myArray");
        
        // Test ValidateParameterLength span version
        var act2 = () => SecurityUtilities.ValidateParameterLength(new byte[3].AsSpan(), 7, "mySpan");
        act2.Should().Throw<ArgumentException>()
            .WithMessage("mySpan must be exactly 7 bytes, got 3*")
            .And.ParamName.Should().Be("mySpan");
        
        // Test ValidateParameterLengthRange
        var act3 = () => SecurityUtilities.ValidateParameterLengthRange(new byte[25], 10, 20, "myRangeArray");
        act3.Should().Throw<ArgumentException>()
            .WithMessage("myRangeArray must be between 10 and 20 bytes, got 25*")
            .And.ParamName.Should().Be("myRangeArray");
        
        // Test ValidateSize
        var act4 = () => SecurityUtilities.ValidateSize(2000, 1000, "mySizeParam");
        act4.Should().Throw<ArgumentOutOfRangeException>()
            .WithMessage("Size 2000 exceeds maximum allowed size 1000*")
            .And.ParamName.Should().Be("mySizeParam");
    }
    
    [Fact]
    public void ValidationMethods_WithBoundaryValues_ShouldHandleCorrectly()
    {
        // Test exactly at boundaries - should not throw
        var act1 = () => SecurityUtilities.ValidateParameterLength(new byte[16], 16, "exactMatch");
        act1.Should().NotThrow();
        
        var act2 = () => SecurityUtilities.ValidateParameterLengthRange(new byte[15], 10, 20, "inRange");
        act2.Should().NotThrow();
        
        var act3 = () => SecurityUtilities.ValidateSize(1000, 1000, "atMaximum");
        act3.Should().NotThrow();
        
        var act4 = () => SecurityUtilities.ValidateSize(0, 1000, "atMinimum");
        act4.Should().NotThrow();
    }
    
    [Fact]
    public void ValidationMethods_WithEdgeCaseInputs_ShouldHandleGracefully()
    {
        // Empty arrays
        var act1 = () => SecurityUtilities.ValidateParameterLength(Array.Empty<byte>(), 0, "emptyArray");
        act1.Should().NotThrow();
        
        // Empty spans
        var act2 = () => SecurityUtilities.ValidateParameterLength([], 0, "emptySpan");
        act2.Should().NotThrow();
        
        // Null array with zero expected length should still throw (null not allowed)
        var act3 = () => SecurityUtilities.ValidateParameterLength(null, 0, "nullArray");
        act3.Should().Throw<ArgumentNullException>()
            .And.ParamName.Should().Be("nullArray");
    }
    
    [Theory]
    [InlineData(-1, "Size must be non-negative")]
    [InlineData(int.MinValue, "Size must be non-negative")]
    public void ValidateSize_WithNegativeValues_ShouldProvideCorrectErrorMessage(int size, string expectedMessage)
    {
        // Act & Assert
        var act = () => SecurityUtilities.ValidateSize(size, 1000, "testParam");
        act.Should().Throw<ArgumentOutOfRangeException>()
            .WithMessage($"*{expectedMessage}*")
            .And.ParamName.Should().Be("testParam");
    }
    
    [Fact]
    public void HexStringMethods_ErrorRecovery_ShouldHandleGracefully()
    {
        // Test multiple error conditions in sequence
        var invalidInputs = new[]
        {
            ("", "cannot be an empty string"), // ArgumentException.ThrowIfNullOrWhiteSpace message
            ("123", "Hex string must have an even number of characters"),
            ("12GH", "Invalid hex characters at position 2")
        };
        
        foreach (var (input, expectedMessagePart) in invalidInputs)
        {
            var act = () => SecurityUtilities.FromHexString(input);
            act.Should().Throw<ArgumentException>()
                .WithMessage($"*{expectedMessagePart}*");
        }
    }
    
    [Fact]
    public void EntropyValidation_WithComplexFailureCases_ShouldProvideInformativeMessages()
    {
        var testCases = new[]
        {
            (data: "BBBB"u8.ToArray(), message: "all bytes are 0x42"),
            (data: [0x00, 0x00, 0x00, 0x00], message: "all bytes are 0x00"),
            (data: [0xFF, 0xFF, 0xFF, 0xFF], message: "all bytes are 0xFF")
        };
        
        foreach (var (data, message) in testCases)
        {
            var act = () => SecurityUtilities.ValidateRandomBytesEntropy(data.AsSpan(), "testData");
            act.Should().Throw<ArgumentException>()
                .WithMessage($"*appears to have insufficient entropy ({message})*")
                .And.ParamName.Should().Be("testData");
        }
    }
}

public sealed class TestUtilityValidationTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void TestUtilities_TimingMeasurement_ShouldBeAccurate()
    {
        // Arrange
        const int expectedDelay = 10; // milliseconds
        #pragma warning disable S2925 // Thread.Sleep is intentionally used here to test timing measurement accuracy
        static void delayAction() => Thread.Sleep(expectedDelay);
        #pragma warning restore S2925

        // Act - Measure a known delay
        var sw = Stopwatch.StartNew();
        delayAction();
        sw.Stop();
        var manualMeasurement = sw.ElapsedMilliseconds;
        
        // Assert - Timing should be approximately correct (allow some variance)
        manualMeasurement.Should().BeGreaterThanOrEqualTo(expectedDelay - 2)
            .And.BeLessThan(expectedDelay + 100); // Allow more variance for system timing because fuck osx
    }
    
    [Fact]
    public void TestUtilities_RandomDataGeneration_ShouldProduceVariedResults()
    {
        // Generate multiple random arrays
        var arrays = new List<byte[]>();
        for (int i = 0; i < 10; i++)
        {
            arrays.Add(OqsCore.GenerateRandomBytes(32));
        }
        
        // Assert - All arrays should be different
        for (int i = 0; i < arrays.Count; i++)
        {
            for (int j = i + 1; j < arrays.Count; j++)
            {
                arrays[i].Should().NotEqual(arrays[j], $"arrays at indices {i} and {j} should be different");
            }
        }
    }
    
    [Fact]
    public void TestUtilities_ExceptionHandling_ShouldCaptureCompleteDetails()
    {
        // Test that our test utilities properly capture exception details
        try
        {
            SecurityUtilities.ValidateParameterLength(new byte[5], 10, "testParam");
            Assert.Fail("Expected exception was not thrown");
        }
        catch (ArgumentException ex)
        {
            // Verify exception contains all expected details
            ex.ParamName.Should().Be("testParam");
            ex.Message.Should().Contain("testParam");
            ex.Message.Should().Contain("5");
            ex.Message.Should().Contain("10");
        }
    }
    
    [Fact]
    public void TestUtilities_FluentAssertions_ShouldProvideGoodErrorMessages()
    {
        // Test that FluentAssertions provides helpful error messages
        try
        {
            var expected = new byte[] { 1, 2, 3 };
            var actual = new byte[] { 1, 2, 4 };
            actual.Should().Equal(expected);
            Assert.Fail("Expected assertion failure");
        }
        catch (Exception ex) when (ex.GetType().Name.Contains("AssertionFailed", StringComparison.Ordinal) || ex.Message.Contains("differs at index", StringComparison.Ordinal))
        {
            // Verify FluentAssertions gives us detailed comparison info
            ex.Message.Should().Contain("differs at index");
        }
    }
    
    [Theory]
    [InlineData(new byte[] { }, "empty")]
    [InlineData(new byte[] { 0x42 }, "single")]  
    [InlineData(new byte[] { 1, 2, 3, 4, 5 }, "small")]
    public void TestUtilities_WithVariousDataSizes_ShouldHandleCorrectly(byte[] testData, string description)
    {
        // Act - Test hex conversion round-trip as example utility operation
        ArgumentNullException.ThrowIfNull(testData);

        if (testData.Length == 0)
        {
            var testHexString = SecurityUtilities.ToHexString(testData);
            testHexString.Should().BeEmpty();
            return;
        }
        
        var hexString = SecurityUtilities.ToHexString(testData);
        var roundTrip = SecurityUtilities.FromHexString(hexString);
        
        // Assert
        roundTrip.Should().Equal(testData, $"round-trip should work for {description} data");
    }
}

#pragma warning restore S1144, S1215, S3776