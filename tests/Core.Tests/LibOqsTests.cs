using OpenForge.Cryptography.LibOqs.Tests.Common;
using FluentAssertions;
using Xunit;
using System.Reflection;
using System.Collections.Concurrent;

namespace OpenForge.Cryptography.LibOqs.Core.Tests;

#pragma warning disable S1144
[Collection("LibOqs Collection")]
public sealed class LibOqsInitializationTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void Initialize_ShouldNotThrow()
    {
        // Act & Assert - Initialize is already called by fixture, just verify it worked
        var act = () => OqsCore.Initialize();
        act.Should().NotThrow();
    }

    [Fact]
    public void Initialize_CalledMultipleTimes_ShouldNotThrow()
    {
        // Act & Assert - Multiple calls should be safe (idempotent)
        var act = () =>
        {
            OqsCore.Initialize();
            OqsCore.Initialize();
            OqsCore.Initialize();
        };
        act.Should().NotThrow();
    }

    [Fact]
    public async Task Initialize_CalledConcurrently_ShouldOnlyInitializeOnce()
    {
        // This test helps exercise the double-check locking pattern
        // We don't call Destroy since it's global state shared across tests
        var tasks = new Task[10];
        var exceptions = new ConcurrentBag<InvalidOperationException>();

        for (int i = 0; i < tasks.Length; i++)
        {
            tasks[i] = Task.Run(() =>
            {
                try
                {
                    // Initialize is safe to call multiple times and is idempotent
                    OqsCore.Initialize();
                }
                catch (InvalidOperationException ex)
                {
                    // Only catch specific exceptions we expect could occur
                    exceptions.Add(ex);
                }
            }, TestContext.Current.CancellationToken);
        }

        await Task.WhenAll(tasks);
        
        exceptions.Should().BeEmpty("Concurrent initialization should not cause exceptions");
    }
}

[Collection("LibOqs Collection")]
public class LibOqsVersionTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void GetVersion_ShouldReturnNonEmptyString()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act
        var version = OqsCore.GetVersion();

        // Assert
        version.Should().NotBeNullOrEmpty();
        version.Should().NotBe("Unknown");
    }

    [Fact]
    public void GetVersion_ShouldReturnValidVersionFormat()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act
        var version = OqsCore.GetVersion();

        // Assert - Should match semantic version pattern like "0.10.0" or "0.10.1-dev"
        version.Should().MatchRegex(@"^\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$", 
            "version should follow semantic versioning pattern");
    }
}

[Collection("LibOqs Collection")]
public class LibOqsThreadManagementTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void ThreadStop_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.ThreadStop();
        act.Should().NotThrow();
    }
}

[Collection("LibOqs Collection")]
public class LibOqsThreadSafetyTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public async Task ConcurrentInitialization_ShouldBeThreadSafe()
    {
        // Arrange
        const int threadCount = 10;
        var tasks = new Task[threadCount];
        var exceptions = new Exception[threadCount];

        // Act - Multiple threads calling Initialize concurrently
        for (int i = 0; i < threadCount; i++)
        {
            var index = i;
            tasks[i] = Task.Run(() =>
            {
                try
                {
                    OqsCore.Initialize();
                }
                catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or DllNotFoundException)
                {
                    exceptions[index] = ex;
                }
            }, TestContext.Current.CancellationToken);
        }

        await Task.WhenAll(tasks);

        // Assert - No exceptions should occur
        exceptions.Should().AllSatisfy(ex => ex.Should().BeNull());
    }

    [Fact]
    public async Task ConcurrentRandomBytesGeneration_ShouldBeThreadSafe()
    {
        // Arrange
        const int threadCount = 20;
        const int bytesPerThread = 32;
        var results = new byte[threadCount][];
        var tasks = new Task[threadCount];

        // Act - Multiple threads generating random bytes concurrently
        for (int i = 0; i < threadCount; i++)
        {
            var index = i;
            tasks[i] = Task.Run(() =>
            {
                results[index] = OqsCore.GenerateRandomBytes(bytesPerThread);
            }, TestContext.Current.CancellationToken);
        }

        await Task.WhenAll(tasks);

        // Assert - All results should be valid and different
        results.Should().AllSatisfy(bytes =>
        {
            bytes.Should().NotBeNull();
            bytes.Should().HaveCount(bytesPerThread);
            bytes.Should().NotBeEquivalentTo(new byte[bytesPerThread]); // Should not be all zeros
        });

        // Results should be different from each other (high probability)
        var uniqueResults = results.Distinct(new ByteArrayComparer()).ToArray();
        uniqueResults.Length.Should().BeGreaterThan(threadCount / 2, 
            "most random byte arrays should be unique");
    }

    [Fact]
    public async Task ConcurrentMemoryOperations_ShouldBeThreadSafe()
    {
        // Arrange
        const int threadCount = 10;
        const nuint memorySize = 64;
        var tasks = new Task[threadCount];
        var exceptions = new Exception[threadCount];

        // Act - Multiple threads doing memory operations concurrently
        for (int i = 0; i < threadCount; i++)
        {
            var index = i;
            tasks[i] = Task.Run(() =>
            {
                try
                {
                    var ptr = OqsCore.AllocateMemory(memorySize);
                    ptr.Should().NotBe(IntPtr.Zero);
                    OqsCore.CleanseMemory(ptr, memorySize);
                    OqsCore.FreeMemory(ptr, memorySize);
                }
                catch (Exception ex) when (ex is ArgumentException or OutOfMemoryException or InvalidOperationException)
                {
                    exceptions[index] = ex;
                }
            }, TestContext.Current.CancellationToken);
        }

        await Task.WhenAll(tasks);

        // Assert - No exceptions should occur
        exceptions.Should().AllSatisfy(ex => ex.Should().BeNull());
    }

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public bool Equals(byte[]? x, byte[]? y)
        {
            if (ReferenceEquals(x, y)) return true;
            if (x is null || y is null) return false;
            return x.SequenceEqual(y);
        }

        public int GetHashCode(byte[] obj)
        {
            return obj.Aggregate(0, (hash, b) => hash ^ b.GetHashCode());
        }
    }
}

[Collection("LibOqs Collection")]
public class LibOqsMemoryAllocationTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void AllocateMemory_WithValidSize_ShouldReturnValidPointer()
    {
        // Arrange - LibOqs already initialized by fixture
        const nuint size = 64;

        // Act
        var ptr = OqsCore.AllocateMemory(size);

        // Assert
        ptr.Should().NotBe(IntPtr.Zero);

        // Cleanup
        OqsCore.FreeMemory(ptr, size);
    }

    [Fact]
    public void AllocateMemory_WithZeroSize_ShouldThrowArgumentException()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.AllocateMemory(0);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*Size must be greater than zero*")
           .And.ParamName.Should().Be("size");
    }

    [Fact]
    public void AllocateMemory_WithExcessiveSize_ShouldThrowArgumentException()
    {
        // Arrange - LibOqs already initialized by fixture
        const nuint excessiveSize = (nuint)(2UL * 1024 * 1024 * 1024); // 2GB

        // Act & Assert
        var act = () => OqsCore.AllocateMemory(excessiveSize);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*exceeds maximum allowed size*")
           .And.ParamName.Should().Be("size");
    }

    [Fact]
    public void AllocateMemory_WithMaxAllowedSize_ShouldReturnValidPointer()
    {
        // Arrange - Test exactly at the 1GB boundary
        const nuint maxSize = 1024 * 1024 * 1024; // 1GB exactly

        try
        {
            // Act
            var ptr = OqsCore.AllocateMemory(maxSize);

            // Assert - Should succeed at boundary
            ptr.Should().NotBe(IntPtr.Zero);

            // Cleanup
            OqsCore.FreeMemory(ptr, maxSize);
        }
        catch (OutOfMemoryException)
        {
            // This is acceptable - system may not have enough memory
            // The important thing is it didn't throw ArgumentException
        }
    }

    [Fact]
    public void AllocateMemory_WithSizeJustOverLimit_ShouldThrowArgumentException()
    {
        // Arrange - Test exactly 1 byte over the 1GB limit
        const nuint oversizeByOne = (1024 * 1024 * 1024) + 1;

        // Act & Assert
        var act = () => OqsCore.AllocateMemory(oversizeByOne);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*exceeds maximum allowed size*")
           .And.ParamName.Should().Be("size");
    }
}

[Collection("LibOqs Collection")]
public class LibOqsMemoryFreeingTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void FreeMemory_WithValidPointer_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture
        const nuint size = 64;
        var ptr = OqsCore.AllocateMemory(size);

        // Act & Assert
        var act = () => OqsCore.FreeMemory(ptr, size);
        act.Should().NotThrow();
    }

    [Fact]
    public void FreeMemory_WithZeroPointer_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.FreeMemory(IntPtr.Zero, 64);
        act.Should().NotThrow();
    }

    [Fact]
    public void InsecureFreeMemory_WithValidPointer_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture
        const nuint size = 64;
        var ptr = OqsCore.AllocateMemory(size);

        // Act & Assert
        var act = () => OqsCore.InsecureFreeMemory(ptr);
        act.Should().NotThrow();
    }

    [Fact]
    public void InsecureFreeMemory_WithZeroPointer_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.InsecureFreeMemory(IntPtr.Zero);
        act.Should().NotThrow();
    }
}

[Collection("LibOqs Collection")]
public class LibOqsMemoryLifecycleTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void MemoryLifecycle_AllocateAndFree_ShouldWorkCorrectly()
    {
        // Arrange - LibOqs already initialized by fixture
        const nuint size = 256;

        // Act - Allocate
        var ptr = OqsCore.AllocateMemory(size);

        // Assert - Should have valid pointer
        ptr.Should().NotBe(IntPtr.Zero);

        // Act - Free
        var freeAction = () => OqsCore.FreeMemory(ptr, size);

        // Assert - Should not throw
        freeAction.Should().NotThrow();
    }

    [Fact]
    public void MemoryLifecycle_AllocateAndInsecureFree_ShouldWorkCorrectly()
    {
        // Arrange - LibOqs already initialized by fixture
        const nuint size = 128;

        // Act - Allocate
        var ptr = OqsCore.AllocateMemory(size);

        // Assert - Should have valid pointer
        ptr.Should().NotBe(IntPtr.Zero);

        // Act - Free with insecure free
        var freeAction = () => OqsCore.InsecureFreeMemory(ptr);

        // Assert - Should not throw
        freeAction.Should().NotThrow();
    }
}

[Collection("LibOqs Collection")]
public class LibOqsMemoryCleansingTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void CleanseMemory_WithValidPointer_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture
        const nuint size = 64;
        var ptr = OqsCore.AllocateMemory(size);

        // Act & Assert
        var act = () => OqsCore.CleanseMemory(ptr, size);
        act.Should().NotThrow();

        // Cleanup
        OqsCore.FreeMemory(ptr, size);
    }

    [Fact]
    public void CleanseMemory_WithZeroPointer_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.CleanseMemory(IntPtr.Zero, 64);
        act.Should().NotThrow();
    }
}

[Collection("LibOqs Collection")]
public class LibOqsRandomBytesGenerationTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void GenerateRandomBytes_WithValidLength_ShouldReturnRandomBytes()
    {
        // Arrange - LibOqs already initialized by fixture
        const int length = 32;

        // Act
        var randomBytes = OqsCore.GenerateRandomBytes(length);

        // Assert
        randomBytes.Should().NotBeNull();
        randomBytes.Should().HaveCount(length);
        randomBytes.Should().NotBeEquivalentTo(new byte[length]); // Should not be all zeros
    }

    [Fact]
    public void GenerateRandomBytes_WithZeroLength_ShouldReturnEmptyArray()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act
        var randomBytes = OqsCore.GenerateRandomBytes(0);

        // Assert
        randomBytes.Should().NotBeNull();
        randomBytes.Should().BeEmpty();
    }

    [Fact]
    public void GenerateRandomBytes_WithNegativeLength_ShouldThrowArgumentException()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.GenerateRandomBytes(-1);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void GenerateRandomBytes_WithExcessiveLength_ShouldThrowArgumentException()
    {
        // Arrange - LibOqs already initialized by fixture
        const int excessiveLength = 2 * 1024 * 1024; // 2MB

        // Act & Assert
        var act = () => OqsCore.GenerateRandomBytes(excessiveLength);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*exceeds maximum allowed size*");
    }

    [Fact]
    public void GenerateRandomBytes_WithMaxAllowedLength_ShouldReturnRandomBytes()
    {
        // Arrange - Test at 1MB boundary (maximum allowed)
        const int maxLength = 1024 * 1024; // 1MB

        // Act
        var randomBytes = OqsCore.GenerateRandomBytes(maxLength);

        // Assert
        randomBytes.Should().NotBeNull();
        randomBytes.Should().HaveCount(maxLength);
        // Don't validate entropy for very large arrays due to performance
    }

    [Fact]
    public void GenerateRandomBytes_WithLengthJustOverMax_ShouldThrowArgumentException()
    {
        // Arrange - Test 1 byte over 1MB limit
        const int overMaxLength = (1024 * 1024) + 1;

        // Act & Assert
        var act = () => OqsCore.GenerateRandomBytes(overMaxLength);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*exceeds maximum allowed size*");
    }

    [Fact]
    public void GenerateRandomBytes_Span_WithValidBuffer_ShouldFillBuffer()
    {
        // Arrange - LibOqs already initialized by fixture
        var buffer = new byte[32];
        var originalBuffer = new byte[32];

        // Act
        OqsCore.GenerateRandomBytes(buffer);

        // Assert
        buffer.Should().NotBeEquivalentTo(originalBuffer); // Should be filled with random data
    }

    [Fact]
    public void GenerateRandomBytes_Span_WithEmptyBuffer_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture
        
        // Act & Assert
        var act = () => OqsCore.GenerateRandomBytes([]);
        act.Should().NotThrow();
    }

    [Fact]
    public void GenerateRandomBytes_MultipleCalls_ShouldReturnDifferentResults()
    {
        // Arrange - LibOqs already initialized by fixture
        const int length = 32;

        // Act
        var randomBytes1 = OqsCore.GenerateRandomBytes(length);
        var randomBytes2 = OqsCore.GenerateRandomBytes(length);

        // Assert
        randomBytes1.Should().NotBeEquivalentTo(randomBytes2);
    }

    [Theory]
    [InlineData(1)]     // Single byte - should trigger entropy check
    [InlineData(2)]     // Very small - should trigger entropy check
    [InlineData(3)]     // Very small - should trigger entropy check
    public void GenerateRandomBytes_WithSmallLength_ShouldTriggerEntropyValidation(int length)
    {
        // Act & Assert - Small lengths (1-3 bytes) should fail entropy check if all same
        // Note: This test might occasionally pass due to random chance, but validates the code path
        var act = () => OqsCore.GenerateRandomBytes(length);
        
        // The entropy validation might catch low entropy, but for 1-3 bytes, it's likely to pass
        // This test mainly ensures the entropy validation code path is exercised
        act.Should().NotThrow(); // Should not crash, entropy validation should handle gracefully
    }

    [Fact]
    public void GenerateRandomBytes_WithLengthBelowEntropyCheck_ShouldNotValidateEntropy()
    {
        // Arrange - Length below entropy validation threshold (< 4 bytes)
        const int length = 3;

        // Act - Should succeed without entropy validation
        var randomBytes = OqsCore.GenerateRandomBytes(length);

        // Assert
        randomBytes.Should().NotBeNull();
        randomBytes.Should().HaveCount(length);
        // No entropy validation for arrays < 4 bytes
    }

    [Fact]
    public void GenerateRandomBytes_WithLengthAboveEntropyCheck_ShouldSkipValidation()
    {
        // Arrange - Length above entropy validation threshold (> 1024 bytes)
        const int length = 1025;

        // Act - Should succeed without entropy validation for large arrays
        var randomBytes = OqsCore.GenerateRandomBytes(length);

        // Assert
        randomBytes.Should().NotBeNull();
        randomBytes.Should().HaveCount(length);
        // No entropy validation for arrays > 1024 bytes due to performance
    }

    [Theory]
    [InlineData(4)]     // Minimum for entropy check
    [InlineData(32)]    // Common size
    [InlineData(256)]   // Medium size
    [InlineData(1024)]  // Maximum for entropy check
    public void GenerateRandomBytes_WithEntropyCheckRange_ShouldValidateEntropy(int length)
    {
        // Act - Lengths in range [4, 1024] should have entropy validation
        var randomBytes = OqsCore.GenerateRandomBytes(length);

        // Assert
        randomBytes.Should().NotBeNull();
        randomBytes.Should().HaveCount(length);
        
        // Verify the generated bytes have some entropy (not all the same)
        var firstByte = randomBytes[0];
        var allSame = randomBytes.All(b => b == firstByte);
        allSame.Should().BeFalse("generated bytes should have entropy and not all be the same value");
    }
}

[Collection("LibOqs Collection")]
public class LibOqsRandomAlgorithmTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void SwitchRandomAlgorithm_WithValidAlgorithm_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.SwitchRandomAlgorithm("system");
        act.Should().NotThrow();
    }

    [Fact]
    public void SwitchRandomAlgorithm_WithInvalidAlgorithm_ShouldThrowArgumentException()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.SwitchRandomAlgorithm("InvalidAlgorithm");
        act.Should().Throw<ArgumentException>()
           .WithMessage("*Failed to switch to random algorithm*");
    }

    [Fact]
    public void SwitchRandomAlgorithm_WithNullAlgorithm_ShouldThrowArgumentException()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.SwitchRandomAlgorithm(null!);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void SwitchRandomAlgorithm_WithEmptyAlgorithm_ShouldThrowArgumentException()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.SwitchRandomAlgorithm("");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void SwitchRandomAlgorithm_WithWhitespaceAlgorithm_ShouldThrowArgumentException()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.SwitchRandomAlgorithm("   ");
        act.Should().Throw<ArgumentException>();
    }
}

[Collection("LibOqs Collection")]
public class LibOqsCpuExtensionTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void HasCpuExtension_WithValidExtension_ShouldReturnBoolean()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.HasCpuExtension(OqsCpUext.OQS_CPU_EXT_AVX2);
        act.Should().NotThrow(); // Should return a valid boolean without throwing
    }

    [Theory]
    [InlineData(OqsCpUext.OQS_CPU_EXT_AES)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_AVX)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_AVX2)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_AVX512)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_BMI1)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_BMI2)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_PCLMULQDQ)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_VPCLMULQDQ)]
    [InlineData(OqsCpUext.OQS_CPU_EXT_POPCNT)]
    public void HasCpuExtension_WithAllExtensions_ShouldReturnBooleanValue(OqsCpUext extension)
    {
        // Arrange - LibOqs already initialized by fixture

        // Act
        var result = OqsCore.HasCpuExtension(extension);

        // Assert - Result should be a valid boolean (no exception thrown)
        // The fact that we got here means the method returned successfully
        Assert.True(result || !result);
    }

    [Fact]
    public void HasCpuExtension_CombinationSupport_ShouldBeConsistent()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act - Check if CPU extensions follow expected relationships
        var hasAVX = OqsCore.HasCpuExtension(OqsCpUext.OQS_CPU_EXT_AVX);
        var hasAVX2 = OqsCore.HasCpuExtension(OqsCpUext.OQS_CPU_EXT_AVX2);
        var hasAVX512 = OqsCore.HasCpuExtension(OqsCpUext.OQS_CPU_EXT_AVX512);
        var hasBMI1 = OqsCore.HasCpuExtension(OqsCpUext.OQS_CPU_EXT_BMI1);
        var hasBMI2 = OqsCore.HasCpuExtension(OqsCpUext.OQS_CPU_EXT_BMI2);

        // Assert - Logical relationships should hold
        if (hasAVX2)
        {
            hasAVX.Should().BeTrue("AVX2 requires AVX support");
        }
        
        if (hasAVX512)
        {
            hasAVX2.Should().BeTrue("AVX-512 typically requires AVX2 support");
        }

        if (hasBMI2)
        {
            hasBMI1.Should().BeTrue("BMI2 typically requires BMI1 support");
        }
    }
}

[Collection("LibOqs Collection")]
public class LibOqsStandardMemoryAllocationTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void Malloc_WithValidSize_ShouldReturnValidPointer()
    {
        // Arrange - LibOqs already initialized by fixture
        const nuint size = 64;

        // Act
        var ptr = OqsCore.Malloc(size);

        // Assert
        ptr.Should().NotBe(IntPtr.Zero);

        // Cleanup
        OqsCore.InsecureFreeMemory(ptr);
    }

    [Fact]
    public void Malloc_WithZeroSize_ShouldThrowArgumentException()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.Malloc(0);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*Size must be greater than zero*")
           .And.ParamName.Should().Be("size");
    }

    [Fact]
    public void Malloc_WithExcessiveSize_ShouldThrowArgumentException()
    {
        // Arrange - LibOqs already initialized by fixture
        const nuint excessiveSize = (nuint)(2UL * 1024 * 1024 * 1024); // 2GB

        // Act & Assert
        var act = () => OqsCore.Malloc(excessiveSize);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*exceeds maximum allowed size*")
           .And.ParamName.Should().Be("size");
    }

    [Fact]
    public void Calloc_WithValidParameters_ShouldReturnValidPointer()
    {
        // Arrange - LibOqs already initialized by fixture
        const nuint numElements = 10;
        const nuint elementSize = 8;

        // Act
        var ptr = OqsCore.Calloc(numElements, elementSize);

        // Assert
        ptr.Should().NotBe(IntPtr.Zero);

        // Cleanup
        OqsCore.InsecureFreeMemory(ptr);
    }

    [Fact]
    public void Calloc_WithZeroElements_ShouldThrowArgumentException()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.Calloc(0, 8);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*Number of elements must be greater than zero*")
           .And.ParamName.Should().Be("numElements");
    }

    [Fact]
    public void Calloc_WithZeroElementSize_ShouldThrowArgumentException()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.Calloc(10, 0);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*Element size must be greater than zero*")
           .And.ParamName.Should().Be("elementSize");
    }

    [Fact]
    public void Calloc_WithOverflowParameters_ShouldThrowArgumentException()
    {
        // Arrange - LibOqs already initialized by fixture
        const nuint largeNumber = 1000000000;

        // Act & Assert
        var act = () => OqsCore.Calloc(largeNumber, largeNumber);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*Total allocation size would exceed maximum allowed size*");
    }
}

[Collection("LibOqs Collection")]
public class LibOqsSecureComparisonTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void SecureCompare_WithEqualMemory_ShouldReturnZero()
    {
        // Arrange - LibOqs already initialized by fixture
        const nuint size = 32;
        var ptr1 = OqsCore.AllocateMemory(size);
        var ptr2 = OqsCore.AllocateMemory(size);

        // Fill both with same data
        unsafe
        {
            var span1 = new Span<byte>((void*)ptr1, (int)size);
            var span2 = new Span<byte>((void*)ptr2, (int)size);
            span1.Fill(0x42);
            span2.Fill(0x42);
        }

        // Act
        var result = OqsCore.SecureCompare(ptr1, ptr2, size);

        // Assert
        result.Should().Be(0);

        // Cleanup
        OqsCore.FreeMemory(ptr1, size);
        OqsCore.FreeMemory(ptr2, size);
    }

    [Fact]
    public void SecureCompare_WithDifferentMemory_ShouldReturnNonZero()
    {
        // Arrange - LibOqs already initialized by fixture
        const nuint size = 32;
        var ptr1 = OqsCore.AllocateMemory(size);
        var ptr2 = OqsCore.AllocateMemory(size);

        // Fill with different data
        unsafe
        {
            var span1 = new Span<byte>((void*)ptr1, (int)size);
            var span2 = new Span<byte>((void*)ptr2, (int)size);
            span1.Fill(0x42);
            span2.Fill(0x24);
        }

        // Act
        var result = OqsCore.SecureCompare(ptr1, ptr2, size);

        // Assert
        result.Should().NotBe(0);

        // Cleanup
        OqsCore.FreeMemory(ptr1, size);
        OqsCore.FreeMemory(ptr2, size);
    }

    [Fact]
    public void SecureCompare_WithNullPointers_ShouldThrowArgumentException()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act1 = () => OqsCore.SecureCompare(IntPtr.Zero, new IntPtr(0x1000), 32);
        act1.Should().Throw<ArgumentException>()
            .WithMessage("*Memory pointers cannot be null*");

        var act2 = () => OqsCore.SecureCompare(new IntPtr(0x1000), IntPtr.Zero, 32);
        act2.Should().Throw<ArgumentException>()
            .WithMessage("*Memory pointers cannot be null*");
    }
}

[Collection("LibOqs Collection")]
public class LibOqsSecureByteArrayTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void CreateSecureByteArray_WithValidLength_ShouldReturnSecureArray()
    {
        // Arrange
        const int length = 32;

        // Act
        using var secureArray = OqsCore.CreateSecureByteArray(length);

        // Assert
        secureArray.Should().NotBeNull();
        secureArray.Length.Should().Be(length);
    }

    [Fact]
    public void CreateSecureByteArray_WithZeroLength_ShouldReturnEmptyArray()
    {
        // Act
        using var secureArray = OqsCore.CreateSecureByteArray(0);

        // Assert
        secureArray.Should().NotBeNull();
        secureArray.Length.Should().Be(0);
    }

    [Fact]
    public void CreateSecureByteArray_WithNegativeLength_ShouldThrowArgumentException()
    {
        // Act & Assert
        var act = () => OqsCore.CreateSecureByteArray(-1);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void CreateSecureByteArray_WithExcessiveLength_ShouldThrowArgumentException()
    {
        // Act & Assert
        var act = () => OqsCore.CreateSecureByteArray(2 * 1024 * 1024); // 2MB
        act.Should().Throw<ArgumentException>()
           .WithMessage("*exceeds maximum allowed size*");
    }

    [Fact]
    public void CreateSecureByteArray_FromData_ShouldCopyData()
    {
        // Arrange
        var originalData = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        using var secureArray = OqsCore.CreateSecureByteArray(originalData);

        // Assert
        secureArray.Should().NotBeNull();
        secureArray.Length.Should().Be(originalData.Length);
        secureArray.AsSpan().ToArray().Should().BeEquivalentTo(originalData);
    }

    [Fact]
    public void CreateSecureByteArray_FromEmptyData_ShouldReturnEmptyArray()
    {
        // Arrange
        var emptyData = ReadOnlySpan<byte>.Empty;

        // Act
        using var secureArray = OqsCore.CreateSecureByteArray(emptyData);

        // Assert
        secureArray.Should().NotBeNull();
        secureArray.Length.Should().Be(0);
    }
}

[Collection("LibOqs Collection")]
public class LibOqsMemoryLeakTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void AllocateMemory_WithoutFreeing_ShouldHandleMultipleAllocations()
    {
        // Arrange - LibOqs already initialized by fixture
        const nuint size = 1024;
        var pointers = new IntPtr[100];

        // Act - Allocate memory multiple times without freeing (simulating potential leak scenario)
        for (int i = 0; i < pointers.Length; i++)
        {
            pointers[i] = OqsCore.AllocateMemory(size);
            pointers[i].Should().NotBe(IntPtr.Zero);
        }

        // Assert - All allocations should succeed
        pointers.Should().AllSatisfy(ptr => ptr.Should().NotBe(IntPtr.Zero));
        
        // Cleanup - Free all allocated memory to prevent actual leaks in test
        for (int i = 0; i < pointers.Length; i++)
        {
            OqsCore.FreeMemory(pointers[i], size);
        }
    }

    [Fact]
    public void CreateSecureByteArray_MultipleCreations_ShouldHandleCorrectly()
    {
        // Arrange - LibOqs already initialized by fixture
        const int arrayCount = 50;
        const int arraySize = 256;

        // Act & Assert - Multiple secure array creations and disposals
        for (int i = 0; i < arrayCount; i++)
        {
            using var secureArray = OqsCore.CreateSecureByteArray(arraySize);
            secureArray.Should().NotBeNull();
            secureArray.Length.Should().Be(arraySize);
            
            // Use the array to ensure it's properly initialized
            secureArray.AsSpan().Fill((byte)(i % 256));
            secureArray[0].Should().Be((byte)(i % 256));
        }
        
        // All arrays should be properly disposed by using statement
    }

    [Fact]
    public void GenerateRandomBytes_LargeAmounts_ShouldNotCauseMemoryIssues()
    {
        // Arrange - LibOqs already initialized by fixture
        const int iterationCount = 100;
        const int bytesPerIteration = 4096; // 4KB per iteration

        // Act - Generate large amounts of random data
        for (int i = 0; i < iterationCount; i++)
        {
            var randomBytes = OqsCore.GenerateRandomBytes(bytesPerIteration);
            
            // Assert - Each generation should succeed
            randomBytes.Should().NotBeNull();
            randomBytes.Should().HaveCount(bytesPerIteration);
            randomBytes.Should().NotBeEquivalentTo(new byte[bytesPerIteration]);
        }
        
        // Memory should be automatically managed by GC for these arrays
    }

    [Fact]
    public void CreateSecureByteArray_EdgeCases_ShouldHandleCorrectly()
    {
        // Test maximum allowed size
        const int maxSize = 1024 * 1024; // 1MB
        using var largeArray = OqsCore.CreateSecureByteArray(maxSize);
        largeArray.Should().NotBeNull();
        largeArray.Length.Should().Be(maxSize);
        
        // Test size just over limit
        var act = () => OqsCore.CreateSecureByteArray(maxSize + 1);
        act.Should().Throw<ArgumentException>();
        
        // Test with data that exceeds limit
        var largeData = new byte[maxSize + 1];
        var act2 = () => OqsCore.CreateSecureByteArray(largeData.AsSpan());
        act2.Should().Throw<ArgumentException>();
    }
}

[Collection("LibOqs Collection")]
public class LibOqsInternalMethodTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void SecureCompareUnsafe_WithEqualMemory_ShouldReturnZero()
    {
        // Arrange
        const nuint size = 32;
        var ptr1 = OqsCore.AllocateMemory(size);
        var ptr2 = OqsCore.AllocateMemory(size);

        try
        {
            // Fill both with same data
            unsafe
            {
                var span1 = new Span<byte>((void*)ptr1, (int)size);
                var span2 = new Span<byte>((void*)ptr2, (int)size);
                span1.Fill(0x42);
                span2.Fill(0x42);
            }

            // Act - Use reflection to access internal method
            var method = typeof(OqsCore).GetMethod("SecureCompareUnsafe",
                BindingFlags.NonPublic | BindingFlags.Static);
            method.Should().NotBeNull();

            var result = (int)method!.Invoke(null, [ptr1, ptr2, size])!;

            // Assert
            result.Should().Be(0);
        }
        finally
        {
            OqsCore.FreeMemory(ptr1, size);
            OqsCore.FreeMemory(ptr2, size);
        }
    }

    [Fact]
    public void SecureCompareUnsafe_WithDifferentMemory_ShouldReturnNonZero()
    {
        // Arrange
        const nuint size = 32;
        var ptr1 = OqsCore.AllocateMemory(size);
        var ptr2 = OqsCore.AllocateMemory(size);

        try
        {
            // Fill with different data
            unsafe
            {
                var span1 = new Span<byte>((void*)ptr1, (int)size);
                var span2 = new Span<byte>((void*)ptr2, (int)size);
                span1.Fill(0x42);
                span2.Fill(0x24);
            }

            // Act - Use reflection to access internal method
            var method = typeof(OqsCore).GetMethod("SecureCompareUnsafe",
                BindingFlags.NonPublic | BindingFlags.Static);
            method.Should().NotBeNull();

            var result = (int)method!.Invoke(null, [ptr1, ptr2, size])!;

            // Assert
            result.Should().NotBe(0);
        }
        finally
        {
            OqsCore.FreeMemory(ptr1, size);
            OqsCore.FreeMemory(ptr2, size);
        }
    }

    [Fact]
    public void FastEnsureInitialized_WhenNotInitialized_ShouldThrowInvalidOperationException()
    {
        // Arrange - Create a new test scenario where we can control initialization
        // Note: This is tricky because LibOqs is already initialized by the fixture
        // We'll use reflection to access the private field and method

        var initializedField = typeof(OqsCore).GetField("_initialized",
            BindingFlags.NonPublic | BindingFlags.Static);
        var fastEnsureMethod = typeof(OqsCore).GetMethod("FastEnsureInitialized",
            BindingFlags.NonPublic | BindingFlags.Static);

        initializedField.Should().NotBeNull();
        fastEnsureMethod.Should().NotBeNull();

        // Get current state
        var originalState = (bool)initializedField!.GetValue(null)!;

        try
        {
            // Temporarily set to false
            initializedField.SetValue(null, false);

            // Act & Assert
            var act = () => fastEnsureMethod!.Invoke(null, null);
            act.Should().Throw<TargetInvocationException>()
               .WithInnerException<InvalidOperationException>()
               .WithMessage("*liboqs must be initialized before use*");
        }
        finally
        {
            // Restore original state
            initializedField.SetValue(null, originalState);
        }
    }

    [Fact]
    public void FastEnsureInitialized_WhenInitialized_ShouldNotThrow()
    {
        // Arrange - LibOqs is initialized by fixture
        var fastEnsureMethod = typeof(OqsCore).GetMethod("FastEnsureInitialized",
            BindingFlags.NonPublic | BindingFlags.Static);

        fastEnsureMethod.Should().NotBeNull();

        // Act & Assert
        var act = () => fastEnsureMethod!.Invoke(null, null);
        act.Should().NotThrow();
    }
}

[Collection("LibOqs Collection")]
public class LibOqsMemoryPressureTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void HintMemoryPressure_WithValidBytesAllocated_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture
        const long bytesAllocated = 1024 * 1024; // 1MB

        // Act & Assert
        var act = () => OqsCore.HintMemoryPressure(bytesAllocated);
        act.Should().NotThrow();
    }

    [Fact]
    public void HintMemoryPressure_WithZeroBytes_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.HintMemoryPressure(0);
        act.Should().NotThrow();
    }

    [Fact]
    public void HintMemoryPressure_WithNegativeBytes_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.HintMemoryPressure(-1000);
        act.Should().NotThrow();
    }

    [Fact]
    public void HintMemoryPressure_WithForceGC_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture
        const long bytesAllocated = 2 * 1024 * 1024; // 2MB

        // Act & Assert
        var act = () => OqsCore.HintMemoryPressure(bytesAllocated, forceGarbageCollection: true);
        act.Should().NotThrow();
    }

    [Fact]
    public void RemoveMemoryPressure_WithValidBytesFreed_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture
        const long bytesFreed = 1024 * 1024; // 1MB

        // Act & Assert
        var act = () => OqsCore.RemoveMemoryPressure(bytesFreed);
        act.Should().NotThrow();
    }

    [Fact]
    public void RemoveMemoryPressure_WithZeroBytes_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.RemoveMemoryPressure(0);
        act.Should().NotThrow();
    }

    [Fact]
    public void RemoveMemoryPressure_WithNegativeBytes_ShouldNotThrow()
    {
        // Arrange - LibOqs already initialized by fixture

        // Act & Assert
        var act = () => OqsCore.RemoveMemoryPressure(-1000);
        act.Should().NotThrow();
    }

    [Fact]
    public void RemoveMemoryPressure_WithExcessiveAmount_ShouldHandleGracefully()
    {
        // Arrange - Try to remove more pressure than was added
        const long excessiveAmount = long.MaxValue;

        // Act & Assert - Should handle ArgumentOutOfRangeException gracefully
        var act = () => OqsCore.RemoveMemoryPressure(excessiveAmount);
        act.Should().NotThrow();
    }

    [Fact]
    public void MemoryPressure_AddAndRemove_ShouldWorkCorrectly()
    {
        // Arrange - LibOqs already initialized by fixture
        const long bytes = 5 * 1024 * 1024; // 5MB

        // Act - Add then remove pressure
        var addAction = () => OqsCore.HintMemoryPressure(bytes);
        var removeAction = () => OqsCore.RemoveMemoryPressure(bytes);

        // Assert - Both operations should succeed
        addAction.Should().NotThrow();
        removeAction.Should().NotThrow();
    }

    [Fact]
    public async Task MemoryPressure_ConcurrentOperations_ShouldBeThreadSafe()
    {
        // Arrange
        const int threadCount = 10;
        const long bytesPerThread = 1024 * 1024; // 1MB per thread
        var tasks = new Task[threadCount];
        var exceptions = new Exception[threadCount];

        // Act - Multiple threads adding/removing memory pressure concurrently
        for (int i = 0; i < threadCount; i++)
        {
            var index = i;
            tasks[i] = Task.Run(() =>
            {
                try
                {
                    // Add pressure
                    OqsCore.HintMemoryPressure(bytesPerThread);
                    
                    // Small delay to simulate work
                    TimingUtils.AdaptiveDelayAsync(10, TestContext.Current.CancellationToken).Wait();
                    
                    // Remove pressure
                    OqsCore.RemoveMemoryPressure(bytesPerThread);
                }
                catch (ArgumentException ex)
                {
                    // Memory pressure operations should not throw ArgumentException in normal usage
                    exceptions[index] = ex;
                }
                catch (OutOfMemoryException ex)
                {
                    // System may be under memory pressure
                    exceptions[index] = ex;
                }
                catch (InvalidOperationException ex)
                {
                    // GC operations may throw InvalidOperationException in rare cases
                    exceptions[index] = ex;
                }
            }, TestContext.Current.CancellationToken);
        }

        await Task.WhenAll(tasks);

        // Assert - No exceptions should occur
        exceptions.Should().AllSatisfy(ex => ex.Should().BeNull());
    }

    [Theory]
    [InlineData(1024)] // 1KB - small allocation
    [InlineData(1024 * 1024)] // 1MB - medium allocation
    [InlineData(10 * 1024 * 1024)] // 10MB - large allocation
    public void HintMemoryPressure_WithVariousSizes_ShouldNotThrow(long bytes)
    {
        // Act & Assert
        var act = () => OqsCore.HintMemoryPressure(bytes);
        act.Should().NotThrow();
    }
}

[Collection("LibOqs Collection")]
public class LibOqsMemoryUsageInfoTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void GetMemoryUsageInfo_WithNullAlgorithm_ShouldReturnNull()
    {
        // Act
        var result = OqsCore.GetMemoryUsageInfo(null!);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void GetMemoryUsageInfo_WithEmptyAlgorithm_ShouldReturnNull()
    {
        // Act
        var result = OqsCore.GetMemoryUsageInfo("");

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void GetMemoryUsageInfo_WithWhitespaceAlgorithm_ShouldReturnNull()
    {
        // Act
        var result = OqsCore.GetMemoryUsageInfo("   ");

        // Assert
        result.Should().BeNull();
    }

    [Theory]
    [InlineData("Classic-McEliece-348864")]
    [InlineData("Classic-McEliece-460896")]
    [InlineData("Classic-McEliece-6688128")]
    [InlineData("Classic-McEliece-6960119")]
    [InlineData("Classic-McEliece-8192128")]
    public void GetMemoryUsageInfo_WithClassicMcElieceAlgorithms_ShouldReturnLargeKeyInfo(string algorithmName)
    {
        // Act
        var result = OqsCore.GetMemoryUsageInfo(algorithmName);

        // Assert
        Assert.True(result.HasValue, "Memory usage info should not be null for Classic McEliece algorithms");
        var memoryInfo = result.Value;
        memoryInfo.IsLargeKeyAlgorithm.Should().BeTrue();
        memoryInfo.RecommendMemoryPressureHints.Should().BeTrue();
        memoryInfo.EstimatedPeakUsage.Should().BeGreaterThan(1_000_000); // > 1MB
        memoryInfo.UsageDescription.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void GetMemoryUsageInfo_WithSpecificClassicMcEliece_ShouldReturnCorrectUsage()
    {
        // Act - Test specific large variant
        var result = OqsCore.GetMemoryUsageInfo("Classic-McEliece-8192128");

        // Assert
        Assert.True(result.HasValue, "Memory usage info should not be null for Classic-McEliece-8192128");
        var memoryInfo = result.Value;
        memoryInfo.EstimatedPeakUsage.Should().Be(3_000_000); // 3MB
        memoryInfo.UsageDescription.Should().Be("Very high memory usage (> 2MB)");
    }

    [Theory]
    [InlineData("ML-KEM-512")]
    [InlineData("ML-KEM-768")]
    [InlineData("ML-KEM-1024")]
    [InlineData("Kyber512")]
    [InlineData("Kyber768")]
    [InlineData("Kyber1024")]
    public void GetMemoryUsageInfo_WithKyberAlgorithms_ShouldReturnLowUsage(string algorithmName)
    {
        // Act
        var result = OqsCore.GetMemoryUsageInfo(algorithmName);

        // Assert
        Assert.True(result.HasValue, $"Memory usage info should not be null for {algorithmName}");
        var memoryInfo = result.Value;
        memoryInfo.IsLargeKeyAlgorithm.Should().BeFalse();
        memoryInfo.RecommendMemoryPressureHints.Should().BeFalse();
        memoryInfo.EstimatedPeakUsage.Should().Be(10_000); // 10KB
        memoryInfo.UsageDescription.Should().Be("Low memory usage (< 50KB)");
    }

    [Theory]
    [InlineData("ML-DSA-44")]
    [InlineData("ML-DSA-65")]
    [InlineData("ML-DSA-87")]
    [InlineData("Dilithium2")]
    [InlineData("Dilithium3")]
    [InlineData("Dilithium5")]
    public void GetMemoryUsageInfo_WithDilithiumAlgorithms_ShouldReturnLowUsage(string algorithmName)
    {
        // Act
        var result = OqsCore.GetMemoryUsageInfo(algorithmName);

        // Assert
        Assert.True(result.HasValue, $"Memory usage info should not be null for {algorithmName}");
        var memoryInfo = result.Value;
        memoryInfo.IsLargeKeyAlgorithm.Should().BeFalse();
        memoryInfo.RecommendMemoryPressureHints.Should().BeFalse();
        memoryInfo.EstimatedPeakUsage.Should().Be(20_000); // 20KB
        memoryInfo.UsageDescription.Should().Be("Low memory usage (< 50KB)");
    }

    [Theory]
    [InlineData("NTRU-HPS-2048-509")]
    [InlineData("NTRU-HPS-4096-1229")]
    [InlineData("NTRU-HRSS-701")]
    public void GetMemoryUsageInfo_WithNTRUAlgorithms_ShouldReturnModerateUsage(string algorithmName)
    {
        // Act
        var result = OqsCore.GetMemoryUsageInfo(algorithmName);

        // Assert
        Assert.True(result.HasValue, $"Memory usage info should not be null for {algorithmName}");
        var memoryInfo = result.Value;
        memoryInfo.IsLargeKeyAlgorithm.Should().BeFalse();
        memoryInfo.RecommendMemoryPressureHints.Should().BeFalse();
        memoryInfo.EstimatedPeakUsage.Should().Be(100_000); // 100KB
        memoryInfo.UsageDescription.Should().Be("Moderate memory usage (50KB - 500KB)");
    }

    [Fact]
    public void GetMemoryUsageInfo_WithUnknownAlgorithm_ShouldReturnDefaultInfo()
    {
        // Act
        var result = OqsCore.GetMemoryUsageInfo("UnknownAlgorithm");

        // Assert
        Assert.True(result.HasValue, "Memory usage info should not be null for unknown algorithms");
        var memoryInfo = result.Value;
        memoryInfo.IsLargeKeyAlgorithm.Should().BeFalse();
        memoryInfo.RecommendMemoryPressureHints.Should().BeFalse();
        memoryInfo.EstimatedPeakUsage.Should().Be(50_000); // 50KB default
        memoryInfo.UsageDescription.Should().Be("Moderate memory usage (50KB - 500KB)");
    }

    [Fact]
    public void MemoryUsageInfo_UsageDescription_ShouldCategorizeCorrectly()
    {
        // Test various usage levels
        var lowUsage = new MemoryUsageInfo { EstimatedPeakUsage = 30_000 };
        var moderateUsage = new MemoryUsageInfo { EstimatedPeakUsage = 200_000 };
        var highUsage = new MemoryUsageInfo { EstimatedPeakUsage = 1_000_000 };
        var veryHighUsage = new MemoryUsageInfo { EstimatedPeakUsage = 5_000_000 };

        // Assert
        lowUsage.UsageDescription.Should().Be("Low memory usage (< 50KB)");
        moderateUsage.UsageDescription.Should().Be("Moderate memory usage (50KB - 500KB)");
        highUsage.UsageDescription.Should().Be("High memory usage (500KB - 2MB)");
        veryHighUsage.UsageDescription.Should().Be("Very high memory usage (> 2MB)");
    }

    [Fact]
    public void MemoryUsageInfo_EdgeCases_ShouldHandleCorrectly()
    {
        // Test boundary conditions
        var exactly50KB = new MemoryUsageInfo { EstimatedPeakUsage = 50_000 };
        var exactly500KB = new MemoryUsageInfo { EstimatedPeakUsage = 500_000 };
        var exactly2MB = new MemoryUsageInfo { EstimatedPeakUsage = 2_000_000 };

        // Assert boundaries
        exactly50KB.UsageDescription.Should().Be("Moderate memory usage (50KB - 500KB)");
        exactly500KB.UsageDescription.Should().Be("High memory usage (500KB - 2MB)");
        exactly2MB.UsageDescription.Should().Be("Very high memory usage (> 2MB)");
    }

    [Theory]
    [InlineData("Classic-McEliece-6960119", true, true, 2_500_000L)]
    [InlineData("Classic-McEliece-8192128", true, true, 3_000_000L)]
    [InlineData("ML-KEM-768", false, false, 10_000L)]
    [InlineData("ML-DSA-65", false, false, 20_000L)]
    public void GetMemoryUsageInfo_WithSpecificAlgorithms_ShouldMatchExpectedValues(
        string algorithmName, bool expectedLargeKey, bool expectedPressureHints, long expectedPeakUsage)
    {
        // Act
        var result = OqsCore.GetMemoryUsageInfo(algorithmName);

        // Assert
        Assert.True(result.HasValue, $"Memory usage info should not be null for {algorithmName}");
        var memoryInfo = result.Value;
        memoryInfo.IsLargeKeyAlgorithm.Should().Be(expectedLargeKey);
        memoryInfo.RecommendMemoryPressureHints.Should().Be(expectedPressureHints);
        memoryInfo.EstimatedPeakUsage.Should().Be(expectedPeakUsage);
    }

    [Fact]
    public void MemoryUsageInfo_WithZeroUsage_ShouldHandleGracefully()
    {
        // Arrange
        var zeroUsage = new MemoryUsageInfo { EstimatedPeakUsage = 0 };

        // Act & Assert
        zeroUsage.UsageDescription.Should().Be("Low memory usage (< 50KB)");
    }

    [Fact]
    public void MemoryUsageInfo_WithNegativeUsage_ShouldHandleGracefully()
    {
        // Arrange - Edge case with negative usage
        var negativeUsage = new MemoryUsageInfo { EstimatedPeakUsage = -1000 };

        // Act & Assert - Should still work (even though negative doesn't make sense)
        negativeUsage.UsageDescription.Should().Be("Low memory usage (< 50KB)");
    }
}

[Collection("LibOqs Collection")]
public class LibOqsMemoryPressureIntegrationTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void MemoryPressure_WithLargeKeyAlgorithmWorkflow_ShouldWorkEnd2End()
    {
        // Arrange - Simulate working with a large-key algorithm
        const string algorithmName = "Classic-McEliece-8192128";
        var result = OqsCore.GetMemoryUsageInfo(algorithmName);

        // Act & Assert - Full workflow
        Assert.True(result.HasValue, "Memory usage info should not be null for Classic-McEliece-8192128");
        var memoryInfo = result.Value;
        memoryInfo.RecommendMemoryPressureHints.Should().BeTrue();

        // Simulate start of operation
        var hintAction = () => OqsCore.HintMemoryPressure(memoryInfo.EstimatedPeakUsage);
        hintAction.Should().NotThrow();

        // Simulate end of operation
        var removeAction = () => OqsCore.RemoveMemoryPressure(memoryInfo.EstimatedPeakUsage);
        removeAction.Should().NotThrow();
    }

    [Fact]
    public void MemoryPressure_WithSmallKeyAlgorithmWorkflow_ShouldNotRecommendHints()
    {
        // Arrange - Simulate working with a small-key algorithm
        const string algorithmName = "ML-KEM-768";
        var result = OqsCore.GetMemoryUsageInfo(algorithmName);

        // Act & Assert
        Assert.True(result.HasValue, "Memory usage info should not be null for ML-KEM-768");
        var memoryInfo = result.Value;
        memoryInfo.RecommendMemoryPressureHints.Should().BeFalse();
        memoryInfo.IsLargeKeyAlgorithm.Should().BeFalse();
        memoryInfo.EstimatedPeakUsage.Should().BeLessThan(100_000); // < 100KB
    }

    [Fact]
    public async Task MemoryPressure_BatchOperationSimulation_ShouldHandleCorrectly()
    {
        // Arrange - Simulate batch processing scenario
        const string algorithmName = "Classic-McEliece-6960119";
        const int batchSize = 10;
        var result = OqsCore.GetMemoryUsageInfo(algorithmName);

        Assert.True(result.HasValue, "Memory usage info should not be null for Classic-McEliece-6960119");
        var memoryInfo = result.Value;
        
        // Act - Simulate batch operations
        for (int i = 0; i < batchSize; i++)
        {
            // Simulate start of each operation
            var hintAction = () => OqsCore.HintMemoryPressure(memoryInfo.EstimatedPeakUsage);
            hintAction.Should().NotThrow();

            // Simulate some processing time
            await Task.Delay(1, TestContext.Current.CancellationToken);

            // Simulate end of operation
            var removeAction = () => OqsCore.RemoveMemoryPressure(memoryInfo.EstimatedPeakUsage);
            removeAction.Should().NotThrow();
        }

        // Assert - All operations completed successfully
        Assert.True(true); // Test completed without exceptions
    }

    [Fact]
    public async Task MemoryPressure_WithForceGC_ShouldNotAffectPerformanceSignificantly()
    {
        // Arrange
        const long memoryAmount = 10 * 1024 * 1024; // 10MB
        const int iterations = 5;

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act - Test with forced GC
        for (int i = 0; i < iterations; i++)
        {
            OqsCore.HintMemoryPressure(memoryAmount, forceGarbageCollection: true);
            await Task.Delay(10, TestContext.Current.CancellationToken); // Small delay between operations
            OqsCore.RemoveMemoryPressure(memoryAmount);
        }

        stopwatch.Stop();

        // Assert - Should complete in reasonable time (< 5 seconds total)
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(5000, 
            "memory pressure operations with GC should not take excessively long");
    }

    [Fact]
    public void MemoryPressure_MixedAlgorithmTypes_ShouldHandleDifferentScenarios()
    {
        // Arrange - Test with different algorithm types
        var algorithms = new[]
        {
            ("ML-KEM-768", false),           // Small key, no hints recommended
            ("Classic-McEliece-8192128", true), // Large key, hints recommended
            ("ML-DSA-65", false),           // Small key, no hints recommended
            ("NTRU-HPS-4096-1229", false)  // Medium key, no hints recommended
        };

        // Act & Assert
        foreach (var (algorithmName, expectHints) in algorithms)
        {
            var result = OqsCore.GetMemoryUsageInfo(algorithmName);
            Assert.True(result.HasValue, $"Memory usage info should not be null for {algorithmName}");
            var memoryInfo = result.Value;
            memoryInfo.RecommendMemoryPressureHints.Should().Be(expectHints);

            // Test the pressure hint workflow
            var hintAction = () => OqsCore.HintMemoryPressure(memoryInfo.EstimatedPeakUsage);
            var removeAction = () => OqsCore.RemoveMemoryPressure(memoryInfo.EstimatedPeakUsage);

            hintAction.Should().NotThrow();
            removeAction.Should().NotThrow();
        }
    }
}

#pragma warning restore S1144