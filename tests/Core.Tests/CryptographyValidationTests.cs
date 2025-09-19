using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Core;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.Core.Tests;

[Collection("LibOqs Collection")]
public sealed class CryptographyValidationTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void ValidateAlgorithmName_WithValidName_ShouldNotThrow()
    {
        var action = () => CryptographyValidation.ValidateAlgorithmName("ValidAlgorithm");
        action.Should().NotThrow();
    }

    [Fact]
    public void ValidateAlgorithmName_WithNull_ShouldThrowArgumentException()
    {
        var action = () => CryptographyValidation.ValidateAlgorithmName(null);
        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ValidateAlgorithmName_WithEmpty_ShouldThrowArgumentException()
    {
        var action = () => CryptographyValidation.ValidateAlgorithmName("");
        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ValidateAlgorithmName_WithWhitespace_ShouldThrowArgumentException()
    {
        var action = () => CryptographyValidation.ValidateAlgorithmName("   ");
        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ValidateAlgorithmSupport_WithSupported_ShouldNotThrow()
    {
        var action = () => CryptographyValidation.ValidateAlgorithmSupport(true, "TestAlgorithm");
        action.Should().NotThrow();
    }

    [Fact]
    public void ValidateAlgorithmSupport_WithUnsupported_ShouldThrowNotSupportedException()
    {
        var action = () => CryptographyValidation.ValidateAlgorithmSupport(false, "TestAlgorithm");
        action.Should().Throw<NotSupportedException>()
            .WithMessage("*TestAlgorithm*not enabled or supported*");
    }

    [Fact]
    public void ValidateNativeHandle_WithValidHandle_ShouldNotThrow()
    {
        var handle = new IntPtr(123);
        var action = () => CryptographyValidation.ValidateNativeHandle(handle, "TestAlgorithm");
        action.Should().NotThrow();
    }

    [Fact]
    public void ValidateNativeHandle_WithNullHandle_ShouldThrowInvalidOperationException()
    {
        var action = () => CryptographyValidation.ValidateNativeHandle(IntPtr.Zero, "TestAlgorithm");
        action.Should().Throw<InvalidOperationException>()
            .WithMessage("*Failed to create instance for algorithm 'TestAlgorithm'*");
    }

    [Fact]
    public void ValidateOperationResult_Int_WithSuccess_ShouldNotThrow()
    {
        var action = () => CryptographyValidation.ValidateOperationResult(0, "test operation", "TestAlgorithm");
        action.Should().NotThrow();
    }

    [Fact]
    public void ValidateOperationResult_Int_WithFailure_ShouldThrowInvalidOperationException()
    {
        var action = () => CryptographyValidation.ValidateOperationResult(1, "test operation", "TestAlgorithm");
        action.Should().Throw<InvalidOperationException>()
            .WithMessage("*Failed to test operation for algorithm 'TestAlgorithm'. Error code: 1*");
    }

    [Fact]
    public void ValidateOperationResult_Int_WithFailureAndAdditionalInfo_ShouldThrowInvalidOperationException()
    {
        var action = () => CryptographyValidation.ValidateOperationResult(-1, "test operation", "TestAlgorithm", "Additional context");
        action.Should().Throw<InvalidOperationException>()
            .WithMessage("*Failed to test operation for algorithm 'TestAlgorithm'. Error code: -1. Additional context*");
    }

    [Fact]
    public void ValidateOperationResult_UInt_WithSuccess_ShouldNotThrow()
    {
        var action = () => CryptographyValidation.ValidateOperationResult(0u, "test operation", "TestAlgorithm");
        action.Should().NotThrow();
    }

    [Fact]
    public void ValidateOperationResult_UInt_WithFailure_ShouldThrowInvalidOperationException()
    {
        var action = () => CryptographyValidation.ValidateOperationResult(1u, "test operation", "TestAlgorithm");
        action.Should().Throw<InvalidOperationException>()
            .WithMessage("*Failed to test operation for algorithm 'TestAlgorithm'. Error code: 1*");
    }

    [Fact]
    public void ValidateOperationResult_UInt_WithFailureAndAdditionalInfo_ShouldThrowInvalidOperationException()
    {
        var action = () => CryptographyValidation.ValidateOperationResult(99u, "test operation", "TestAlgorithm", "Additional context");
        action.Should().Throw<InvalidOperationException>()
            .WithMessage("*Failed to test operation for algorithm 'TestAlgorithm'. Error code: 99. Additional context*");
    }

    [Fact]
    public void ValidateNonNegativeIndex_WithValidIndex_ShouldNotThrow()
    {
        var action = () => CryptographyValidation.ValidateNonNegativeIndex(5);
        action.Should().NotThrow();
    }

    [Fact]
    public void ValidateNonNegativeIndex_WithZero_ShouldNotThrow()
    {
        var action = () => CryptographyValidation.ValidateNonNegativeIndex(0);
        action.Should().NotThrow();
    }

    [Fact]
    public void ValidateNonNegativeIndex_WithNegativeIndex_ShouldThrowArgumentOutOfRangeException()
    {
        var action = () => CryptographyValidation.ValidateNonNegativeIndex(-1);
        action.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("index")
            .WithMessage("*Index must be non-negative*");
    }

    [Fact]
    public void ValidateNonNegativeIndex_WithCustomParameterName_ShouldThrowArgumentOutOfRangeException()
    {
        var action = () => CryptographyValidation.ValidateNonNegativeIndex(-5, "customIndex");
        action.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("customIndex")
            .WithMessage("*Index must be non-negative*");
    }

    [Fact]
    public void ValidatePointer_WithValidPointer_ShouldNotThrow()
    {
        var ptr = new IntPtr(123);
        var action = () => CryptographyValidation.ValidatePointer(ptr, "test operation");
        action.Should().NotThrow();
    }

    [Fact]
    public void ValidatePointer_WithNullPointer_ShouldThrowArgumentOutOfRangeException()
    {
        var action = () => CryptographyValidation.ValidatePointer(IntPtr.Zero, "test operation");
        action.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("test operation")
            .WithMessage("*Invalid pointer returned from operation*");
    }

    [Fact]
    public void ValidateContextStringSupport_WithSupported_ShouldNotThrow()
    {
        var action = () => CryptographyValidation.ValidateContextStringSupport(true, "TestAlgorithm");
        action.Should().NotThrow();
    }

    [Fact]
    public void ValidateContextStringSupport_WithUnsupported_ShouldThrowNotSupportedException()
    {
        var action = () => CryptographyValidation.ValidateContextStringSupport(false, "TestAlgorithm");
        action.Should().Throw<NotSupportedException>()
            .WithMessage("*Algorithm 'TestAlgorithm' does not support context strings*");
    }

#pragma warning restore S1144
}