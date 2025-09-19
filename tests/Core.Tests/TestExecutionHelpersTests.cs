using OpenForge.Cryptography.LibOqs.Tests.Common;
using FluentAssertions;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.Core.Tests;

public sealed class TestExecutionHelpersTests
{
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