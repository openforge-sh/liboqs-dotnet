using OpenForge.Cryptography.LibOqs.Tests.Common;
using FluentAssertions;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.Core.Tests;

public sealed class TestExecutionHelpersTests
{
    [Theory]
    [InlineData("Classic-McEliece-348864", true)]
    [InlineData("Classic-McEliece-6960119", true)]
    [InlineData("HQC-128", true)]
    [InlineData("HQC-192", true)]
    [InlineData("HQC-256", true)]
    [InlineData("SPHINCS-PLUS-SHA2-128s-simple", true)]
    [InlineData("SPHINCS-PLUS-SHAKE-256f-simple", true)]
    [InlineData("ML-KEM-512", false)]
    [InlineData("ML-KEM-768", false)]
    [InlineData("Kyber512", false)]
    [InlineData("Dilithium2", false)]
    [InlineData("Falcon-512", false)]
    [InlineData("MAYO-1", false)]
    public void RequiresLargeStack_ShouldIdentifyCorrectAlgorithms(string algorithm, bool expected)
    {
        var result = TestExecutionHelpers.RequiresLargeStack(algorithm);
        result.Should().Be(expected);
    }

    [Fact]
    public void RequiresLargeStack_ShouldBeCaseInsensitive()
    {
        TestExecutionHelpers.RequiresLargeStack("classic-mceliece-348864").Should().BeTrue();
        TestExecutionHelpers.RequiresLargeStack("CLASSIC-MCELIECE-348864").Should().BeTrue();
        TestExecutionHelpers.RequiresLargeStack("hqc-128").Should().BeTrue();
        TestExecutionHelpers.RequiresLargeStack("sphincs-plus-sha2-128s-simple").Should().BeTrue();
    }

    [Fact]
    public void RequiresLargeStack_ShouldThrowForNullOrEmpty()
    {
        var act1 = () => TestExecutionHelpers.RequiresLargeStack(null!);
        var act2 = () => TestExecutionHelpers.RequiresLargeStack("");
        var act3 = () => TestExecutionHelpers.RequiresLargeStack("   ");

        act1.Should().Throw<ArgumentException>();
        act2.Should().Throw<ArgumentException>();
        act3.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ExecuteWithLargeStack_ShouldExecuteAction()
    {
        var executed = false;
        TestExecutionHelpers.ExecuteWithLargeStack(() => executed = true);
        executed.Should().BeTrue();
    }

    [Fact]
    public void ExecuteWithLargeStack_ShouldReturnValue()
    {
        var result = TestExecutionHelpers.ExecuteWithLargeStack(() => 42);
        result.Should().Be(42);
    }

    [Fact]
    public void ExecuteWithLargeStack_ShouldPropagateExceptions()
    {
        var testException = new InvalidOperationException("Test exception");
        
        var act1 = () => TestExecutionHelpers.ExecuteWithLargeStack(() => throw testException);
        var act2 = () => TestExecutionHelpers.ExecuteWithLargeStack<int>(() => throw testException);

        act1.Should().Throw<InvalidOperationException>().WithMessage("Test exception");
        act2.Should().Throw<InvalidOperationException>().WithMessage("Test exception");
    }

    [Fact]
    public void ConditionallyExecuteWithLargeStack_ShouldExecuteAction()
    {
        var executed = false;
        TestExecutionHelpers.ConditionallyExecuteWithLargeStack("ML-KEM-512", () => executed = true);
        executed.Should().BeTrue();
    }

    [Fact]
    public void ConditionallyExecuteWithLargeStack_ShouldThrowForNullInputs()
    {
        var act1 = () => TestExecutionHelpers.ConditionallyExecuteWithLargeStack(null!, () => { });
        var act2 = () => TestExecutionHelpers.ConditionallyExecuteWithLargeStack("ML-KEM-512", null!);

        act1.Should().Throw<ArgumentException>();
        act2.Should().Throw<ArgumentNullException>();
    }
}