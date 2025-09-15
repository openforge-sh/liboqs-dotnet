using System.Runtime.InteropServices;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.Core.Tests;

public sealed class TestBaseTests
{
    public sealed class TestableTestBase(ITestOutputHelper output) : TestBase(output)
    {
        public bool IsDisposed { get; private set; }

        protected override void Dispose(bool disposing)
        {
            IsDisposed = true;
            base.Dispose(disposing);
        }
    }

    public sealed class ConstructorTests : IDisposable
    {
        private readonly StringWriter _stringWriter = new();
        private readonly TestOutputHelper _testOutputHelper;

        public ConstructorTests()
        {
            _testOutputHelper = new TestOutputHelper(_stringWriter);
        }

        [Fact]
        public void Constructor_WithValidOutput_ShouldStoreOutput()
        {
            // Act
            using var testBase = new TestableTestBase(_testOutputHelper);

            // Assert
            testBase.Output.Should().BeSameAs(_testOutputHelper);
        }

        [Fact]
        public void Constructor_WithNullOutput_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            var act = () => new TestableTestBase(null!);
            act.Should().Throw<ArgumentNullException>()
               .WithParameterName("output");
        }

        public void Dispose()
        {
            _testOutputHelper.Dispose();
            _stringWriter.Dispose();
        }
    }

    public sealed class PlatformPropertyTests : IDisposable
    {
        private readonly StringWriter _stringWriter = new();
        private readonly TestOutputHelper _testOutputHelper;

        public PlatformPropertyTests()
        {
            _testOutputHelper = new TestOutputHelper(_stringWriter);
        }

        [Fact]
        public void CurrentPlatform_ShouldReturnValidPlatform()
        {
            // Act
            var platform = TestBase.CurrentPlatform;

            // Assert
            platform.Should().BeOneOf(OSPlatform.Windows, OSPlatform.Linux, OSPlatform.OSX);
        }

        [Fact]
        public void CurrentPlatform_ShouldMatchRuntimeInformation()
        {
            // Arrange
            var expectedPlatform = GetExpectedPlatform();

            // Act
            var actualPlatform = TestBase.CurrentPlatform;

            // Assert
            actualPlatform.Should().Be(expectedPlatform);
        }

        private static OSPlatform GetExpectedPlatform()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return OSPlatform.Windows;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return OSPlatform.Linux;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                return OSPlatform.OSX;

            throw new PlatformNotSupportedException("Unsupported platform");
        }

        public void Dispose()
        {
            _testOutputHelper.Dispose();
            _stringWriter.Dispose();
        }
    }

    public sealed class ArchitecturePropertyTests : IDisposable
    {
        private readonly StringWriter _stringWriter = new();
        private readonly TestOutputHelper _testOutputHelper;

        public ArchitecturePropertyTests()
        {
            _testOutputHelper = new TestOutputHelper(_stringWriter);
        }

        [Fact]
        public void CurrentArchitecture_ShouldReturnValidArchitecture()
        {
            // Act
            var architecture = TestBase.CurrentArchitecture;

            // Assert
            architecture.Should().BeOneOf(
                Architecture.X86, Architecture.X64,
                Architecture.Arm, Architecture.Arm64,
                Architecture.Wasm, Architecture.S390x,
                Architecture.LoongArch64, Architecture.Armv6,
                Architecture.Ppc64le
            );
        }

        [Fact]
        public void CurrentArchitecture_ShouldMatchRuntimeInformation()
        {
            // Act
            var actualArchitecture = TestBase.CurrentArchitecture;

            // Assert
            actualArchitecture.Should().Be(RuntimeInformation.OSArchitecture);
        }

        public void Dispose()
        {
            _testOutputHelper.Dispose();
            _stringWriter.Dispose();
        }
    }

    public sealed class LoggingTests : IDisposable
    {
        private readonly StringWriter _stringWriter = new();
        private readonly TestOutputHelper _testOutputHelper;

        public LoggingTests()
        {
            _testOutputHelper = new TestOutputHelper(_stringWriter);
        }

        [Fact]
        public void Log_WithSimpleMessage_ShouldWriteToOutput()
        {
            // Arrange
            using var testBase = new TestableTestBase(_testOutputHelper);
            const string message = "Test message";

            // Act
            testBase.Log(message);

            // Assert
            var output = _stringWriter.ToString();
            output.Should().Contain(message);
            output.Should().MatchRegex(@"\[\d{2}:\d{2}:\d{2}\.\d{3}\] Test message");
        }

        [Fact]
        public void Log_WithFormattedMessage_ShouldWriteFormattedToOutput()
        {
            // Arrange
            using var testBase = new TestableTestBase(_testOutputHelper);
            const string format = "Test {0} with {1}";
            const string arg1 = "message";
            const int arg2 = 42;

            // Act
            testBase.Log(format, arg1, arg2);

            // Assert
            var output = _stringWriter.ToString();
            output.Should().Contain("Test message with 42");
            output.Should().MatchRegex(@"\[\d{2}:\d{2}:\d{2}\.\d{3}\] Test message with 42");
        }

        [Fact]
        public void Log_WithNoArguments_ShouldWriteFormatString()
        {
            // Arrange
            using var testBase = new TestableTestBase(_testOutputHelper);
            const string format = "Simple message";

            // Act
            testBase.Log(format);

            // Assert
            var output = _stringWriter.ToString();
            output.Should().Contain("Simple message");
        }

        [Fact]
        public void Log_WithNullMessage_ShouldHandleGracefully()
        {
            // Arrange
            using var testBase = new TestableTestBase(_testOutputHelper);

            // Act & Assert
            var act = () => testBase.Log(null!);
            act.Should().NotThrow();
        }

        public void Dispose()
        {
            _testOutputHelper.Dispose();
            _stringWriter.Dispose();
        }
    }

    public sealed class DisposalTests : IDisposable
    {
        private readonly StringWriter _stringWriter = new();
        private readonly TestOutputHelper _testOutputHelper;

        public DisposalTests()
        {
            _testOutputHelper = new TestOutputHelper(_stringWriter);
        }

        [Fact]
        public void Dispose_ShouldCallDisposeWithTrue()
        {
            // Arrange
            var testBase = new TestableTestBase(_testOutputHelper);

            // Act
            testBase.Dispose();

            // Assert
            testBase.IsDisposed.Should().BeTrue();
        }

        [Fact]
        public void Dispose_CalledMultipleTimes_ShouldNotThrow()
        {
            // Arrange
            var testBase = new TestableTestBase(_testOutputHelper);

            // Act & Assert
            testBase.Dispose();
            var act = () => testBase.Dispose();
            act.Should().NotThrow();
        }

        [Fact]
        public void Using_ShouldDisposeCorrectly()
        {
            // Arrange & Act
            TestableTestBase? testBase;
            using (testBase = new TestableTestBase(_testOutputHelper))
            {
                testBase.IsDisposed.Should().BeFalse();
            }

            // Assert
            testBase.IsDisposed.Should().BeTrue();
        }

        public void Dispose()
        {
            _testOutputHelper.Dispose();
            _stringWriter.Dispose();
        }
    }

    private sealed class TestOutputHelper : ITestOutputHelper, IDisposable
    {
        private readonly StringWriter _writer;

        public TestOutputHelper(StringWriter writer)
        {
            _writer = writer;
        }

        public string Output => _writer.ToString();

        public void WriteLine(string message)
        {
            _writer.WriteLine(message);
        }

        public void WriteLine(string format, params object[] args)
        {
            _writer.WriteLine(format, args);
        }

        public void Write(string message)
        {
            _writer.Write(message);
        }

        public void Write(string format, params object[] args)
        {
            _writer.Write(format, args);
        }

        public void Dispose()
        {
            // Writer is disposed by the test class
        }
    }
}
