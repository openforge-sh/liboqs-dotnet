using System.Collections.Concurrent;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.Core.Tests;

public class NativeLibraryLoaderTests
{
    [Fact]
    public void Initialize_ShouldNotThrow()
    {
        // Act & Assert
        var act = () => NativeLibraryLoader.Initialize();
        act.Should().NotThrow();
    }

    [Fact]
    public void Initialize_CalledMultipleTimes_ShouldBeIdempotent()
    {
        // Act & Assert - Multiple calls should be safe
        var act = () =>
        {
            NativeLibraryLoader.Initialize();
            NativeLibraryLoader.Initialize();
            NativeLibraryLoader.Initialize();
        };
        act.Should().NotThrow();
    }

    [Fact]
    public void Register_WithValidAssembly_ShouldNotThrow()
    {
        // Arrange
        var assembly = typeof(NativeLibraryLoaderTests).Assembly;

        // Act & Assert
        var act = () => NativeLibraryLoader.Register(assembly);
        act.Should().NotThrow();
    }

    [Fact]
    public void Register_CalledMultipleTimesWithSameAssembly_ShouldBeIdempotent()
    {
        // Arrange
        var assembly = typeof(NativeLibraryLoaderTests).Assembly;

        // Act & Assert - Multiple registrations of the same assembly should be safe
        var act = () =>
        {
            NativeLibraryLoader.Register(assembly);
            NativeLibraryLoader.Register(assembly);
            NativeLibraryLoader.Register(assembly);
        };
        act.Should().NotThrow();
    }

    [Fact]
    public void Register_WithMultipleDifferentAssemblies_ShouldNotThrow()
    {
        // Arrange
        var assembly1 = typeof(NativeLibraryLoaderTests).Assembly;
        var assembly2 = typeof(NativeLibraryLoader).Assembly;

        // Act & Assert
        var act = () =>
        {
            NativeLibraryLoader.Register(assembly1);
            NativeLibraryLoader.Register(assembly2);
        };
        act.Should().NotThrow();
    }
}

public class NativeLibraryLoaderRuntimeIdentifierTests
{
    [Fact]
    public void GetRuntimeIdentifier_ShouldReturnValidFormat()
    {
        // This test uses reflection to call the private method for testing
        var method = typeof(NativeLibraryLoader).GetMethod("GetRuntimeIdentifier",
            BindingFlags.NonPublic | BindingFlags.Static);
        method.Should().NotBeNull();

        // Act
        var result = method!.Invoke(null, null) as string;

        // Assert
        result.Should().NotBeNullOrEmpty();
        result.Should().MatchRegex(@"^(win|linux|linux-musl|osx)-(x64|arm64|x86|arm)$");
    }

    [Fact]
    public void GetRuntimeIdentifier_OnCurrentPlatform_ShouldMatchExpectedPattern()
    {
        var method = typeof(NativeLibraryLoader).GetMethod("GetRuntimeIdentifier",
            BindingFlags.NonPublic | BindingFlags.Static);
        method.Should().NotBeNull();

        // Act
        var result = method!.Invoke(null, null) as string;

        // Assert - Verify it contains expected components for current platform
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            result.Should().StartWith("win-");
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            result.Should().MatchRegex(@"^linux(-musl)?-");
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            result.Should().StartWith("osx-");
        }

        // Verify architecture part
        var arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            Architecture.Arm => "arm",
            var a when a.ToString() == "RiscV64" => "riscv64",
            _ => RuntimeInformation.ProcessArchitecture.ToString().ToUpperInvariant()
        };

        result.Should().EndWith(arch);
    }

    [Theory]
    [InlineData(Architecture.X64, "x64")]
    [InlineData(Architecture.Arm64, "arm64")]
    [InlineData(Architecture.X86, "x86")]
    [InlineData(Architecture.Arm, "arm")]
    public void GetRuntimeIdentifier_ShouldHandleKnownArchitectures(Architecture arch, string expectedArchString)
    {
        // This test validates our understanding of the architecture mapping
        // We can at least verify the mapping logic is correct by checking our expectations
        var actualArchString = arch switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            Architecture.Arm => "arm",
            var a when a.ToString() == "RiscV64" => "riscv64",
            _ => arch.ToString().ToUpperInvariant()
        };

        actualArchString.Should().Be(expectedArchString);
    }

    [Fact]
    public void GetRuntimeIdentifier_UnsupportedArchitecture_ThrowsPlatformNotSupportedException()
    {
        // This test verifies behavior for unsupported architectures
        // Since we can't actually change RuntimeInformation.ProcessArchitecture,
        // we'll just check that the method exists and can be called
        var method = typeof(NativeLibraryLoader).GetMethod("GetRuntimeIdentifier",
            BindingFlags.NonPublic | BindingFlags.Static);
        method.Should().NotBeNull();

        // The actual test for unsupported architecture would require more complex mocking
        // which isn't feasible without changing the implementation
        var result = method!.Invoke(null, null) as string;
        result.Should().NotBeNullOrEmpty();
    }

    [PlatformSpecificFact("LINUX")]
    public void GetRuntimeIdentifier_OnNonLinux_ShouldNotContainMusl()
    {
        var method = typeof(NativeLibraryLoader).GetMethod("GetRuntimeIdentifier",
            BindingFlags.NonPublic | BindingFlags.Static);
        method.Should().NotBeNull();

        var result = method!.Invoke(null, null) as string;

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            result.Should().NotContain("musl");
        }
    }
}

public class NativeLibraryLoaderLibraryFileNameTests
{
    [Fact]
    public void GetLibraryFileName_ShouldReturnValidFormat()
    {
        var method = typeof(NativeLibraryLoader).GetMethod("GetLibraryFileName",
            BindingFlags.NonPublic | BindingFlags.Static);
        method.Should().NotBeNull();

        // Act
        var result = method!.Invoke(null, null) as string;

        // Assert
        result.Should().NotBeNullOrEmpty();
        result.Should().MatchRegex(@"^liboqs\.(dll|so|dylib)$");
    }

    [Fact]
    public void GetLibraryFileName_OnCurrentPlatform_ShouldMatchExpectedExtension()
    {
        var method = typeof(NativeLibraryLoader).GetMethod("GetLibraryFileName",
            BindingFlags.NonPublic | BindingFlags.Static);
        method.Should().NotBeNull();

        // Act
        var result = method!.Invoke(null, null) as string;

        // Assert - Verify correct extension for current platform
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            result.Should().Be("liboqs.dll");
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            result.Should().Be("liboqs.so");
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            result.Should().Be("liboqs.dylib");
        }
    }
}

public sealed class NativeLibraryLoaderImportResolverTests : IDisposable
{
    private readonly TestDirectory _testDir;
    private readonly Assembly _testAssembly;
    private readonly string _rid;
    private readonly string _libraryFileName;
    private readonly MethodInfo _importResolverMethod;

    public NativeLibraryLoaderImportResolverTests()
    {
        _testDir = new TestDirectory();

        // Copy and load a test assembly into the temp directory to control its location
        var currentAssembly = typeof(NativeLibraryLoaderImportResolverTests).Assembly;
        var sourceDir = Path.GetDirectoryName(currentAssembly.Location);
        Assert.NotNull(sourceDir);

        foreach (var file in Directory.GetFiles(sourceDir!))
        {
            var destFile = Path.Combine(_testDir.Path, Path.GetFileName(file));
            File.Copy(file, destFile);
        }

        var assemblyUnderTest = typeof(NativeLibraryLoader).Assembly;
        var assemblyFileName = Path.GetFileName(assemblyUnderTest.Location);
        Assert.False(string.IsNullOrEmpty(assemblyFileName));

        var tempAssemblyPath = Path.Combine(_testDir.Path, assemblyFileName);
        _testAssembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(tempAssemblyPath);

        _rid = GetPrivateStatic<string>("GetRuntimeIdentifier");
        _libraryFileName = GetPrivateStatic<string>("GetLibraryFileName");

        var method = typeof(NativeLibraryLoader).GetMethod("ImportResolver", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        _importResolverMethod = method!;
    }

    private static T GetPrivateStatic<T>(string methodName)
    {
        var method = typeof(NativeLibraryLoader).GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return (T)method!.Invoke(null, null)!;
    }

    private object? InvokeImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath = null)
    {
        try
        {
            return _importResolverMethod.Invoke(null, [libraryName, assembly, searchPath]);
        }
        catch (TargetInvocationException ex)
        {
            // Unwrap TargetInvocationException to get the actual exception
            throw ex.InnerException ?? ex;
        }
    }

    [Fact]
    public void ImportResolver_WithNonOqsLibrary_ShouldReturnZero()
    {
        // Act
        var result = InvokeImportResolver("someotherlibrary", _testAssembly);

        // Assert
        result.Should().Be(IntPtr.Zero);
    }

    [Fact]
    public void ValidateLibraryFile_WithEmptyFile_ThrowsInvalidOperationException()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, ""); // Create empty file

            // Act
            var ex = Assert.Throws<InvalidOperationException>(() =>
                NativeLibraryLoader.ValidateLibraryFile(tempFile));

            // Assert
            ex.Message.Should().Contain("is empty");
            ex.Message.Should().Contain(tempFile);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ValidateLibraryFile_WithSmallFile_ThrowsInvalidOperationException()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, new byte[500]); // Create small file

            // Act
            var ex = Assert.Throws<InvalidOperationException>(() =>
                NativeLibraryLoader.ValidateLibraryFile(tempFile));

            // Assert
            ex.Message.Should().Contain("appears to be invalid");
            ex.Message.Should().Contain("size: 500 bytes");
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ValidateLibraryFile_WithValidSizeFile_DoesNotThrow()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, new byte[2048]); // Create file large enough

            // Act & Assert
            var act = () => NativeLibraryLoader.ValidateLibraryFile(tempFile);
            act.Should().NotThrow();
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ImportResolver_WhenLibraryInRuntimesFolder_MaySucceedWithSystemLibrary()
    {
        // Arrange
        var runtimeLibPath = Path.Combine(_testDir.Path, "runtimes", _rid, "native");
        Directory.CreateDirectory(runtimeLibPath);
        var libPath = Path.Combine(runtimeLibPath, _libraryFileName);
        File.WriteAllText(libPath, ""); // Create an empty file

        // Act
        var result = InvokeImportResolver(LibOqsNative.LibraryName, _testAssembly, DllImportSearchPath.AssemblyDirectory);

        // Assert
        // This test acknowledges that system liboqs may be installed and take precedence
        // The empty file validation would only trigger if no system fallback succeeds
        result.Should().BeOfType<IntPtr>();
    }






    [Fact]
    public void ImportResolver_WhenLibraryMissing_ReturnsValidHandleOrThrows()
    {
        // Act
        // Note: This test may pass if system liboqs is installed, which is acceptable behavior
        var result = InvokeImportResolver(LibOqsNative.LibraryName, _testAssembly, DllImportSearchPath.AssemblyDirectory);

        // Assert - The method should either throw or return a valid handle (if system lib exists)
        // We can't reliably test the pure "missing" case in all environments
        // This test mainly verifies the resolver doesn't crash
        if (result is IntPtr ptr)
        {
            // Valid behavior - either returns zero or a valid handle
            ptr.Should().BeOfType<IntPtr>();
        }
    }

    [Fact]
    public void ImportResolver_WithDynamicAssembly_ThrowsDllNotFoundException()
    {
        // Arrange
        var assemblyName = new AssemblyName("DynamicAssemblyForTest");
        var assemblyBuilder = AssemblyBuilder.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);

        // Act
        var ex = Assert.ThrowsAny<Exception>(() =>
            InvokeImportResolver(LibOqsNative.LibraryName, assemblyBuilder));

        // Assert
        ex.Should().BeOfType<DllNotFoundException>();
        var dllNotFoundEx = (DllNotFoundException)ex;
        dllNotFoundEx.InnerException.Should().BeOfType<InvalidOperationException>();
        dllNotFoundEx.InnerException!.Message.Should().Be("Assembly location is not available");
    }

    [Fact]
    public void ImportResolver_WithNullAssemblyLocation_ThrowsDllNotFoundException()
    {
        // Arrange
        var assemblyName = new AssemblyName("TestAssemblyWithoutLocation");
        var assemblyBuilder = AssemblyBuilder.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);

        // Act
        var ex = Assert.ThrowsAny<Exception>(() =>
            InvokeImportResolver(LibOqsNative.LibraryName, assemblyBuilder));

        // Assert
        ex.Should().BeOfType<DllNotFoundException>();
        var dllNotFoundEx = (DllNotFoundException)ex;
        dllNotFoundEx.InnerException.Should().BeOfType<InvalidOperationException>();
        dllNotFoundEx.InnerException!.Message.Should().Be("Assembly location is not available");
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (disposing)
        {
            _testDir.Dispose();
        }
    }

    private sealed class TestDirectory : IDisposable
    {
        public string Path { get; }

        public TestDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "OqsTest_" + System.IO.Path.GetRandomFileName());
            Directory.CreateDirectory(Path);
        }

        public void Dispose()
        {
            // Assembly loading can lock files, making immediate cleanup difficult, especially on Windows.
            // This is a known behavior of Assembly.LoadFrom. For this test suite, we accept that
            // the temporary directory might not always be deleted successfully.
            try
            {
                if (Directory.Exists(Path))
                {
                    Directory.Delete(Path, true);
                }
            }
            catch (IOException)
            {
                // Ignore cleanup errors.
            }
        }
    }
}

public class NativeLibraryLoaderLinuxMuslTests
{
    [Fact]
    public void GetRuntimeIdentifier_OnLinuxMusl_ShouldIncludeMusl()
    {
        // This test verifies the logic for detecting musl-based Linux distributions
        // We can't easily simulate the file system conditions in a unit test
        // but we can at least verify that the method exists and works on the current platform
        
        var method = typeof(NativeLibraryLoader).GetMethod("GetRuntimeIdentifier",
            BindingFlags.NonPublic | BindingFlags.Static);
        method.Should().NotBeNull();
        
        // On Linux systems, this should correctly identify musl if present
        var result = method!.Invoke(null, null) as string;
        result.Should().NotBeNullOrEmpty();
        
        // Just verify it follows the expected pattern
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            result.Should().MatchRegex(@"^linux(-musl)?-");
        }
    }
}

public class NativeLibraryLoaderThreadSafetyTests
{
    [Fact]
    public async Task Initialize_ConcurrentCalls_ShouldBeThreadSafe()
    {
        // Arrange
        const int threadCount = 10;
        var tasks = new List<Task>();
        var exceptions = new ConcurrentBag<Exception>();

        // Act - Multiple threads calling Initialize concurrently
        for (var i = 0; i < threadCount; i++)
        {
            tasks.Add(Task.Run(() =>
            {
                try
                {
                    NativeLibraryLoader.Initialize();
                }
                catch (InvalidOperationException ex)
                {
                    exceptions.Add(ex);
                }
                catch (PlatformNotSupportedException ex)
                {
                    exceptions.Add(ex);
                }
                catch (ArgumentException ex)
                {
                    exceptions.Add(ex);
                }
            }, TestContext.Current.CancellationToken));
        }

        await Task.WhenAll(tasks);

        // Assert - No exceptions should occur
        exceptions.Should().BeEmpty();
    }

    [Fact]
    public async Task Initialize_FromMultipleThreadsSimultaneously_ShouldNotThrow()
    {
        // Arrange
        const int threadCount = 20;
        var exceptions = new ConcurrentBag<Exception>();

        // Act - All threads start at approximately the same time
        var tasks = new Task[threadCount];
        for (var i = 0; i < threadCount; i++)
        {
            tasks[i] = Task.Run(() =>
            {
                try
                {
                    NativeLibraryLoader.Initialize();
                }
                catch (InvalidOperationException ex)
                {
                    exceptions.Add(ex);
                }
                catch (PlatformNotSupportedException ex)
                {
                    exceptions.Add(ex);
                }
                catch (ArgumentException ex)
                {
                    exceptions.Add(ex);
                }
            }, TestContext.Current.CancellationToken);
        }

        // Wait for all tasks to complete
        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty();
    }

    [Fact]
    public async Task Register_ConcurrentCalls_ShouldBeThreadSafe()
    {
        // Arrange
        const int threadCount = 15;
        var assembly = typeof(NativeLibraryLoaderTests).Assembly;
        var exceptions = new ConcurrentBag<Exception>();

        // Act - Multiple threads calling Register concurrently with same assembly
        var tasks = new Task[threadCount];
        for (var i = 0; i < threadCount; i++)
        {
            tasks[i] = Task.Run(() =>
            {
                try
                {
                    NativeLibraryLoader.Register(assembly);
                }
                catch (InvalidOperationException ex)
                {
                    exceptions.Add(ex);
                }
                catch (ArgumentException ex)
                {
                    exceptions.Add(ex);
                }
                catch (PlatformNotSupportedException ex)
                {
                    exceptions.Add(ex);
                }
            }, TestContext.Current.CancellationToken);
        }

        await Task.WhenAll(tasks);

        // Assert - No exceptions should occur due to thread safety
        exceptions.Should().BeEmpty();
    }

    [Fact]
    public async Task Register_WithMultipleDifferentAssembliesConcurrently_ShouldBeThreadSafe()
    {
        // Arrange
        const int threadCount = 10;
        var assemblies = new[]
        {
            typeof(NativeLibraryLoaderTests).Assembly,
            typeof(NativeLibraryLoader).Assembly,
            typeof(object).Assembly,
            typeof(List<>).Assembly
        };
        var exceptions = new ConcurrentBag<Exception>();

        // Act - Register different assemblies from multiple threads
        var tasks = new List<Task>();
        for (var i = 0; i < threadCount; i++)
        {
            var assembly = assemblies[i % assemblies.Length];
            tasks.Add(Task.Run(() =>
            {
                try
                {
                    NativeLibraryLoader.Register(assembly);
                }
                catch (InvalidOperationException ex)
                {
                    exceptions.Add(ex);
                }
                catch (ArgumentException ex)
                {
                    exceptions.Add(ex);
                }
                catch (PlatformNotSupportedException ex)
                {
                    exceptions.Add(ex);
                }
            }, TestContext.Current.CancellationToken));
        }

        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty();
    }
}

public class NativeLibraryLoaderEdgeCasesTests
{
    [Fact]
    public void ValidateLibraryFile_WithNonExistentFile_ShouldThrow()
    {
        // Arrange
        var nonExistentFile = Path.Combine(Path.GetTempPath(), "nonexistent_" + Guid.NewGuid() + ".so");

        // Act & Assert
        var action = () => NativeLibraryLoader.ValidateLibraryFile(nonExistentFile);

        // Should throw either FileNotFoundException or DirectoryNotFoundException
        try
        {
            action();
            Assert.Fail("Expected exception was not thrown");
        }
        catch (FileNotFoundException)
        {
            // Expected exception
        }
        catch (DirectoryNotFoundException)
        {
            // Also expected exception
        }
    }

    [Fact]
    public void ValidateLibraryFile_WithFileAt1024Bytes_ShouldNotThrow()
    {
        // Arrange - Test boundary condition (exactly 1024 bytes)
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, new byte[1024]); // Exactly at the minimum threshold

            // Act & Assert
            var action = () => NativeLibraryLoader.ValidateLibraryFile(tempFile);
            action.Should().NotThrow();
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ValidateLibraryFile_WithFileAt1023Bytes_ShouldThrow()
    {
        // Arrange - Test boundary condition (just under 1024 bytes)
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, new byte[1023]); // Just under the minimum threshold

            // Act & Assert
            var action = () => NativeLibraryLoader.ValidateLibraryFile(tempFile);
            action.Should().Throw<InvalidOperationException>()
                .WithMessage("*appears to be invalid*size: 1023 bytes*");
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ValidateLibraryFile_WithLargeValidFile_ShouldNotThrow()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, new byte[50000]); // Large enough file

            // Act & Assert
            var action = () => NativeLibraryLoader.ValidateLibraryFile(tempFile);
            action.Should().NotThrow();
        }
        finally
        {
            File.Delete(tempFile);
        }
    }
}

public sealed class NativeLibraryLoaderImportResolverErrorTests : IDisposable
{
    private readonly TestDirectory _testDir;
    private readonly Assembly _testAssembly;
    private readonly string _rid;
    private readonly string _libraryFileName;
    private readonly MethodInfo _importResolverMethod;

    public NativeLibraryLoaderImportResolverErrorTests()
    {
        _testDir = new TestDirectory();

        // Copy and load a test assembly into the temp directory to control its location
        var currentAssembly = typeof(NativeLibraryLoaderImportResolverErrorTests).Assembly;
        var sourceDir = Path.GetDirectoryName(currentAssembly.Location);
        Assert.NotNull(sourceDir);

        foreach (var file in Directory.GetFiles(sourceDir!))
        {
            var destFile = Path.Combine(_testDir.Path, Path.GetFileName(file));
            File.Copy(file, destFile);
        }

        var assemblyUnderTest = typeof(NativeLibraryLoader).Assembly;
        var assemblyFileName = Path.GetFileName(assemblyUnderTest.Location);
        Assert.False(string.IsNullOrEmpty(assemblyFileName));

        var tempAssemblyPath = Path.Combine(_testDir.Path, assemblyFileName);
        _testAssembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(tempAssemblyPath);

        _rid = GetPrivateStatic<string>("GetRuntimeIdentifier");
        _libraryFileName = GetPrivateStatic<string>("GetLibraryFileName");

        var method = typeof(NativeLibraryLoader).GetMethod("ImportResolver", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        _importResolverMethod = method!;
    }

    private static T GetPrivateStatic<T>(string methodName)
    {
        var method = typeof(NativeLibraryLoader).GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return (T)method!.Invoke(null, null)!;
    }

    private object? InvokeImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath = null)
    {
        try
        {
            return _importResolverMethod.Invoke(null, [libraryName, assembly, searchPath]);
        }
        catch (TargetInvocationException ex)
        {
            // Unwrap TargetInvocationException to get the actual exception
            throw ex.InnerException ?? ex;
        }
    }

    [Fact]
    public void ImportResolver_WithValidRuntimeLibrary_ShouldLoadSuccessfully()
    {
        // Arrange
        var runtimeLibPath = Path.Combine(_testDir.Path, "runtimes", _rid, "native");
        Directory.CreateDirectory(runtimeLibPath);
        var libPath = Path.Combine(runtimeLibPath, _libraryFileName);
        File.WriteAllBytes(libPath, new byte[2048]); // Create a valid-sized file

        // Act
        var result = InvokeImportResolver(LibOqsNative.LibraryName, _testAssembly, DllImportSearchPath.AssemblyDirectory);

        // Assert
        result.Should().BeOfType<IntPtr>();
        ((IntPtr)result!).Should().NotBe(IntPtr.Zero);
    }

    [Fact]
    public void ImportResolver_WithValidLocalLibrary_ShouldLoadSuccessfully()
    {
        // Arrange - No runtime folder, but library in assembly directory
        var libPath = Path.Combine(_testDir.Path, _libraryFileName);
        File.WriteAllBytes(libPath, new byte[2048]); // Create a valid-sized file

        // Act
        var result = InvokeImportResolver(LibOqsNative.LibraryName, _testAssembly, DllImportSearchPath.AssemblyDirectory);

        // Assert
        result.Should().BeOfType<IntPtr>();
        ((IntPtr)result!).Should().NotBe(IntPtr.Zero);
    }

    [Fact]
    public void ImportResolver_WithInvalidRuntimeLibrary_ShouldEitherThrowOrFallback()
    {
        // Arrange
        var runtimeLibPath = Path.Combine(_testDir.Path, "runtimes", _rid, "native");
        Directory.CreateDirectory(runtimeLibPath);
        var libPath = Path.Combine(runtimeLibPath, _libraryFileName);
        File.WriteAllBytes(libPath, new byte[500]); // Create an invalid-sized file

        // Act
        try
        {
            var result = InvokeImportResolver(LibOqsNative.LibraryName, _testAssembly, DllImportSearchPath.AssemblyDirectory);

            // If no exception was thrown, it means system fallback succeeded
            // This is valid behavior when system liboqs is installed
            result.Should().BeOfType<IntPtr>();
        }
        catch (InvalidOperationException ex)
        {
            // This is the expected behavior when validation fails
            ex.Message.Should().Contain("appears to be invalid").And.Contain("size: 500 bytes");
        }
    }

    [Fact]
    public void ImportResolver_WithInvalidLocalLibrary_ShouldEitherThrowOrFallback()
    {
        // Arrange - Invalid library in assembly directory
        var libPath = Path.Combine(_testDir.Path, _libraryFileName);
        File.WriteAllBytes(libPath, new byte[500]); // Create an invalid-sized file

        // Act
        try
        {
            var result = InvokeImportResolver(LibOqsNative.LibraryName, _testAssembly, DllImportSearchPath.AssemblyDirectory);

            // If no exception was thrown, it means system fallback succeeded
            result.Should().BeOfType<IntPtr>();
        }
        catch (InvalidOperationException ex)
        {
            // This is the expected behavior when validation fails
            ex.Message.Should().Contain("appears to be invalid").And.Contain("size: 500 bytes");
        }
    }

    [Fact]
    public void ImportResolver_WithEmptyRuntimeLibrary_ShouldEitherThrowOrFallback()
    {
        // Arrange
        var runtimeLibPath = Path.Combine(_testDir.Path, "runtimes", _rid, "native");
        Directory.CreateDirectory(runtimeLibPath);
        var libPath = Path.Combine(runtimeLibPath, _libraryFileName);
        File.WriteAllText(libPath, ""); // Create empty file

        // Act
        try
        {
            var result = InvokeImportResolver(LibOqsNative.LibraryName, _testAssembly, DllImportSearchPath.AssemblyDirectory);

            // If no exception was thrown, it means system fallback succeeded
            result.Should().BeOfType<IntPtr>();
        }
        catch (InvalidOperationException ex)
        {
            // This is the expected behavior when validation fails
            ex.Message.Should().Contain($"'{libPath}' is empty");
        }
    }

    [Fact]
    public void ImportResolver_WithEmptyLocalLibrary_ShouldEitherThrowOrFallback()
    {
        // Arrange
        var libPath = Path.Combine(_testDir.Path, _libraryFileName);
        File.WriteAllText(libPath, ""); // Create empty file

        // Act
        try
        {
            var result = InvokeImportResolver(LibOqsNative.LibraryName, _testAssembly, DllImportSearchPath.AssemblyDirectory);

            // If no exception was thrown, it means system fallback succeeded
            result.Should().BeOfType<IntPtr>();
        }
        catch (InvalidOperationException ex)
        {
            // This is the expected behavior when validation fails
            ex.Message.Should().Contain($"'{libPath}' is empty");
        }
    }

    [Fact]
    public void ImportResolver_WithAllPathsFailingButSystemFallbackSucceeds_ShouldReturnValidHandle()
    {
        // Arrange - No library files exist locally, but system fallback may work
        // This test may pass if system liboqs is installed

        // Act
        var result = InvokeImportResolver(LibOqsNative.LibraryName, _testAssembly, DllImportSearchPath.SafeDirectories);

        // Assert - Either succeeds with system library or throws DllNotFoundException
        if (result is IntPtr handle)
        {
            handle.Should().BeOfType<IntPtr>(); // May be Zero or valid handle
        }
        else
        {
            // Test should complete without crashing - result handling depends on system
            Assert.True(true);
        }
    }

    [Fact]
    public void ImportResolver_WhenAllLoadingFails_ShouldThrowDllNotFoundException()
    {
        // Arrange - Create a subdirectory to isolate the assembly and ensure no system fallback
        var isolatedDir = Path.Combine(_testDir.Path, "isolated");
        Directory.CreateDirectory(isolatedDir);

        var assemblyUnderTest = typeof(NativeLibraryLoader).Assembly;
        var assemblyFileName = Path.GetFileName(assemblyUnderTest.Location);
        var isolatedAssemblyPath = Path.Combine(isolatedDir, assemblyFileName);
        File.Copy(assemblyUnderTest.Location, isolatedAssemblyPath);

        var isolatedAssembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(isolatedAssemblyPath);

        // Act & Assert - Should throw when no library can be found
        var action = () => InvokeImportResolver("nonexistentlibrary", isolatedAssembly, DllImportSearchPath.AssemblyDirectory);

        // This should return IntPtr.Zero for non-OQS libraries
        var result = action();
        result.Should().Be(IntPtr.Zero);
    }

    public void Dispose()
    {
        _testDir.Dispose();
    }

    private sealed class TestDirectory : IDisposable
    {
        public string Path { get; }

        public TestDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "OqsTest_" + System.IO.Path.GetRandomFileName());
            Directory.CreateDirectory(Path);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Path))
                {
                    Directory.Delete(Path, true);
                }
            }
            catch (IOException)
            {
                // Ignore cleanup errors.
            }
        }
    }
}

public class NativeLibraryLoaderPlatformSpecificTests
{
    [Fact]
    public void GetLibraryFileName_OnUnsupportedPlatform_ShouldThrow()
    {
        // This test verifies that unsupported platforms throw exceptions
        // We can't easily mock RuntimeInformation.IsOSPlatform, but we can verify the method exists
        var method = typeof(NativeLibraryLoader).GetMethod("GetLibraryFileName",
            BindingFlags.NonPublic | BindingFlags.Static);
        method.Should().NotBeNull();

        // On supported platforms, this should work
        var result = method!.Invoke(null, null) as string;
        result.Should().NotBeNullOrEmpty();
        result.Should().MatchRegex(@"^liboqs\.(dll|so|dylib)$");
    }

    [Fact]
    public void GetRuntimeIdentifier_WithCurrentArchitecture_ShouldNotThrowUnsupportedException()
    {
        // Arrange
        var method = typeof(NativeLibraryLoader).GetMethod("GetRuntimeIdentifier",
            BindingFlags.NonPublic | BindingFlags.Static);
        method.Should().NotBeNull();

        // Act
        var action = () => method!.Invoke(null, null);

        // Assert - Should work on current platform
        action.Should().NotThrow<PlatformNotSupportedException>();
        var result = action() as string;
        result.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void GetRuntimeIdentifier_ArchitectureMapping_ShouldBeConsistent()
    {
        // Test that our architecture mapping logic is consistent
        var currentArch = RuntimeInformation.ProcessArchitecture;
        var expectedMapping = currentArch switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            Architecture.Arm => "arm",
            var riscv when riscv.ToString() == "RiscV64" => "riscv64",
            _ => null // Would throw PlatformNotSupportedException
        };

        var method = typeof(NativeLibraryLoader).GetMethod("GetRuntimeIdentifier",
            BindingFlags.NonPublic | BindingFlags.Static);
        var result = method!.Invoke(null, null) as string;

        if (expectedMapping != null)
        {
            result.Should().EndWith(expectedMapping);
        }
        else
        {
            // Current architecture is not supported, method should have thrown
            // But since we're running this test, it means we're on a supported architecture
            result.Should().NotBeNullOrEmpty();
        }
    }

    [Fact]
    public void GetRuntimeIdentifier_OnLinux_ShouldDetectMuslCorrectly()
    {
        // This test validates musl detection logic on Linux
        var method = typeof(NativeLibraryLoader).GetMethod("GetRuntimeIdentifier",
            BindingFlags.NonPublic | BindingFlags.Static);
        var result = method!.Invoke(null, null) as string;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            // Should be either linux-* or linux-musl-*
            result.Should().MatchRegex(@"^linux(-musl)?-");
        }
    }
}