using OpenForge.Cryptography.LibOqs.Tests.Common;
using FluentAssertions;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.Core.Tests;

#pragma warning disable S1144, S1215, S3776
[Collection("LibOqs Collection")]
public class SecureMemoryTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    public sealed class SecureClearTests    {
        [Fact]
        public void SecureClear_WithNullArray_ShouldNotThrow()
        {
            // Act & Assert
            var act = () => SecureMemory.SecureClear(null);
            act.Should().NotThrow();
        }

        [Fact]
        public void SecureClear_WithEmptyArray_ShouldNotThrow()
        {
            // Arrange
            var emptyArray = Array.Empty<byte>();

            // Act & Assert
            var act = () => SecureMemory.SecureClear(emptyArray);
            act.Should().NotThrow();
        }

        [Fact]
        public void SecureClear_WithByteArray_ShouldClearContent()
        {
            // LibOqs already initialized by fixture

            // Arrange
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };

            // Act
            SecureMemory.SecureClear(data);

            // Assert - All bytes should be zero after clearing
            data.Should().OnlyContain(x => x == 0x00);
        }

        [Fact]
        public void SecureClear_WithSpan_ShouldClearContent()
        {
            // LibOqs already initialized by fixture

            // Arrange
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
            var span = data.AsSpan();

            // Act
            SecureMemory.SecureClear(span);

            // Assert - All bytes should be zero after clearing
            data.Should().OnlyContain(x => x == 0x00);
        }

        [Fact]
        public void SecureClear_WithEmptySpan_ShouldNotThrow()
        {
            // Act & Assert
            var act = () => SecureMemory.SecureClear([]);
            act.Should().NotThrow();
        }
    }

    public sealed class MemoryAllocationTests    {
        [Fact]
        public void SecureAlloc_WithZeroSize_ShouldReturnZero()
        {
            // Act
            var ptr = SecureMemory.SecureAlloc(0);

            // Assert
            ptr.Should().Be(IntPtr.Zero);
        }

        [Fact]
        public void SecureAlloc_WithValidSize_ShouldReturnValidPointer()
        {
            // LibOqs already initialized by fixture

            // Arrange
            const nuint size = 64;

            // Act
            var ptr = SecureMemory.SecureAlloc(size);

            // Assert
            ptr.Should().NotBe(IntPtr.Zero);

            // Cleanup
            SecureMemory.SecureFree(ptr, size);
        }

        // Note: Aligned memory allocation tests have been removed because OQS_MEM_aligned_alloc
        // is not exported by liboqs (compiled as local symbol)
    }

    public sealed class MemoryFreeTests    {
        [Fact]
        public void SecureFree_WithZeroPointer_ShouldNotThrow()
        {
            // Act & Assert
            var act = () => SecureMemory.SecureFree(IntPtr.Zero, 64);
            act.Should().NotThrow();
        }

        [Fact]
        public void SecureFree_WithZeroSize_ShouldNotThrow()
        {
            // Arrange
            var fakePtr = new IntPtr(0x1000); // Fake non-zero pointer

            // Act & Assert
            var act = () => SecureMemory.SecureFree(fakePtr, 0);
            act.Should().NotThrow();
        }

        // Note: Aligned memory free tests have been removed because OQS_MEM_aligned_free
        // and OQS_MEM_aligned_secure_free are not exported by liboqs

        [Fact]
        public void MemoryLifecycle_AllocAndFree_ShouldWorkCorrectly()
        {
            // LibOqs already initialized by fixture

            // Arrange
            const nuint size = 128;

            // Act - Allocate
            var ptr = SecureMemory.SecureAlloc(size);

            // Assert - Should have valid pointer
            ptr.Should().NotBe(IntPtr.Zero);

            // Act - Free
            var freeAction = () => SecureMemory.SecureFree(ptr, size);

            // Assert - Should not throw
            freeAction.Should().NotThrow();
        }

        // Note: Aligned memory lifecycle tests have been removed because OQS_MEM_aligned_*
        // functions are not exported by liboqs (compiled as local symbols)
    }

    public sealed class SecureArrayCreationTests    {
        [Fact]
        public void CreateSecureArray_WithValidSize_ShouldReturnArray()
        {
            // Arrange
            const int size = 32;

            // Act
            using var array = SecureMemory.CreateSecureArray(size);

            // Assert
            array.Should().NotBeNull();
            array.Length.Should().Be(size);
            array.Data.Should().NotBeNull();
            array.Data!.Length.Should().Be(size);
        }

        [Fact]
        public void CreateSecureArray_WithZeroSize_ShouldReturnEmptyArray()
        {
            // Act
            using var array = SecureMemory.CreateSecureArray(0);

            // Assert
            array.Should().NotBeNull();
            array.Length.Should().Be(0);
            array.Data.Should().NotBeNull();
        }
    }
}

[Collection("LibOqs Collection")]
public class SecureMemoryConcurrencyTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public async Task ConcurrentSecureAlloc_ShouldBeThreadSafe()
    {
        // Arrange
        const int threadCount = 10;
        const nuint memorySize = 256;
        var tasks = new Task<IntPtr>[threadCount];

        // Act - Multiple threads allocating memory concurrently
        for (int i = 0; i < threadCount; i++)
        {
            tasks[i] = Task.Run(() => SecureMemory.SecureAlloc(memorySize));
        }

        var pointers = await Task.WhenAll(tasks);

        // Assert - All allocations should succeed
        pointers.Should().AllSatisfy(ptr => ptr.Should().NotBe(IntPtr.Zero));

        // Cleanup
        foreach (var ptr in pointers)
        {
            SecureMemory.SecureFree(ptr, memorySize);
        }
    }

    [Fact]
    public async Task ConcurrentSecureClear_ShouldBeThreadSafe()
    {
        // Arrange
        const int threadCount = 10;
        var arrays = new byte[threadCount][];
        var tasks = new Task[threadCount];

        // Initialize arrays with data
        for (int i = 0; i < threadCount; i++)
        {
            arrays[i] = [0x01, 0x02, 0x03, 0x04, 0x05];
        }

        // Act - Multiple threads clearing memory concurrently
        for (int i = 0; i < threadCount; i++)
        {
            var index = i;
            tasks[i] = Task.Run(() => SecureMemory.SecureClear(arrays[index]), TestContext.Current.CancellationToken);
        }

        await Task.WhenAll(tasks);

        // Assert - All arrays should be cleared
        arrays.Should().AllSatisfy(arr => arr.Should().OnlyContain(x => x == 0x00));
    }

    [Fact]
    public async Task ConcurrentSecureArrayCreation_ShouldBeThreadSafe()
    {
        // Arrange
        const int threadCount = 15;
        const int arraySize = 128;
        var tasks = new Task<SecureByteArray>[threadCount];

        // Act - Multiple threads creating secure arrays concurrently
        for (int i = 0; i < threadCount; i++)
        {
            tasks[i] = Task.Run(() => SecureMemory.CreateSecureArray(arraySize));
        }

        var arrays = await Task.WhenAll(tasks);

        // Assert - All arrays should be valid
        arrays.Should().AllSatisfy(arr =>
        {
            arr.Should().NotBeNull();
            arr.Length.Should().Be(arraySize);
            arr.Data.Should().NotBeNull();
        });

        // Cleanup
        foreach (var array in arrays)
        {
            array.Dispose();
        }
    }
}

[Collection("LibOqs Collection")]
public class SecureMemoryStressTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void SecureAlloc_LargeAllocations_ShouldHandleCorrectly()
    {
        // Arrange - Test large but reasonable allocations
        const nuint largeSize = 1024 * 1024; // 1MB
        const int allocationCount = 10;
        var pointers = new IntPtr[allocationCount];

        try
        {
            // Act - Allocate multiple large blocks
            for (int i = 0; i < allocationCount; i++)
            {
                pointers[i] = SecureMemory.SecureAlloc(largeSize);
                
                // Assert - Each allocation should succeed
                pointers[i].Should().NotBe(IntPtr.Zero);
            }

            // Test memory is usable by writing to it
            unsafe
            {
                for (int i = 0; i < allocationCount; i++)
                {
                    if (pointers[i] != IntPtr.Zero)
                    {
                        var span = new Span<byte>((void*)pointers[i], (int)largeSize);
                        span.Fill((byte)(i % 256));
                        span[0].Should().Be((byte)(i % 256));
                        span[^1].Should().Be((byte)(i % 256));
                    }
                }
            }
        }
        finally
        {
            // Cleanup - Always free allocated memory
            for (int i = 0; i < allocationCount; i++)
            {
                if (pointers[i] != IntPtr.Zero)
                {
                    SecureMemory.SecureFree(pointers[i], largeSize);
                }
            }
        }
    }

    [Fact]
    public void CreateSecureArray_ManySmallArrays_ShouldHandleCorrectly()
    {
        // Arrange
        const int arrayCount = 1000;
        const int arraySize = 64;
        var arrays = new SecureByteArray[arrayCount];

        try
        {
            // Act - Create many small arrays
            for (int i = 0; i < arrayCount; i++)
            {
                arrays[i] = SecureMemory.CreateSecureArray(arraySize);
                
                // Assert - Each array should be valid
                arrays[i].Should().NotBeNull();
                arrays[i].Length.Should().Be(arraySize);
                
                // Use the array to ensure it's properly allocated
                arrays[i][0] = (byte)(i % 256);
                arrays[i][0].Should().Be((byte)(i % 256));
            }
        }
        finally
        {
            // Cleanup
            for (int i = 0; i < arrayCount; i++)
            {
                arrays[i]?.Dispose();
            }
        }
    }
}

[Collection("LibOqs Collection")]
public class SecureMemoryFailureTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void SecureAlloc_ExtremelyLargeSize_ShouldReturnZeroPointer()
    {
        // Arrange - Request an impossibly large amount of memory
        var extremeSize = nuint.MaxValue;

        // Act
        var ptr = SecureMemory.SecureAlloc(extremeSize);

        // Assert - Should return zero pointer (allocation failure)
        ptr.Should().Be(IntPtr.Zero);
    }

    [Theory]
    [InlineData(10737418240UL)] // 10GB
    [InlineData(0x7FFFFFFFFFFFFFFFUL)] // Large value near max
    public void SecureAlloc_VeryLargeSizes_ShouldHandleGracefully(nuint size)
    {
        // Act
        var ptr = SecureMemory.SecureAlloc(size);

        // Assert - Either succeeds or fails gracefully (returns zero)
        // We don't assert success because it depends on available system memory
        if (ptr != IntPtr.Zero)
        {
            // If allocation succeeded, we should be able to free it
            var freeAction = () => SecureMemory.SecureFree(ptr, size);
            freeAction.Should().NotThrow();
        }
        else
        {
            // Allocation failure is acceptable for very large sizes
            ptr.Should().Be(IntPtr.Zero);
        }
    }
}

[Collection("LibOqs Collection")]
public class SecureMemoryPinnedTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void SecureAlloc_MemoryPinning_ShouldRemainStable()
    {
        // Arrange
        const nuint size = 1024;
        var ptr = SecureMemory.SecureAlloc(size);
        
        try
        {
            ptr.Should().NotBe(IntPtr.Zero);
            
            // Act - Force garbage collection to test pinning
            var originalAddress = ptr;
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            
            // Assert - Memory address should remain the same (pinned)
            ptr.Should().Be(originalAddress, "secure memory should remain pinned during GC");
            
            // Memory should still be usable
            unsafe
            {
                var span = new Span<byte>((void*)ptr, (int)size);
                span.Fill(0x42);
                span[0].Should().Be(0x42);
                span[^1].Should().Be(0x42);
            }
        }
        finally
        {
            if (ptr != IntPtr.Zero)
            {
                SecureMemory.SecureFree(ptr, size);
            }
        }
    }

    [Fact]
    public void CreateSecureArray_PinnedMemoryValidation_ShouldRemainAccessible()
    {
        // Arrange
        using var array = SecureMemory.CreateSecureArray(256);
        
        // Act - Fill array with test data
        for (int i = 0; i < array.Length; i++)
        {
            array[i] = (byte)(i % 256);
        }
        
        // Force garbage collection
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        
        // Assert - Data should still be accessible and unchanged
        for (int i = 0; i < array.Length; i++)
        {
            array[i].Should().Be((byte)(i % 256), "secure array data should remain accessible after GC");
        }
        
        // Span should still work
        var span = array.AsSpan();
        span.Length.Should().Be(256);
        span[0].Should().Be(0);
        span[255].Should().Be(255);
    }
}

public sealed class SecureByteArrayTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void CreateSecureArray_WithNegativeSize_ShouldThrowArgumentOutOfRangeException()
    {
        // Act & Assert
        var act = () => SecureMemory.CreateSecureArray(-1);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void CreateSecureArray_WithValidSize_ShouldCreateArray()
    {
        // Arrange
        const int size = 16;

        // Act
        using var array = SecureMemory.CreateSecureArray(size);

        // Assert
        array.Length.Should().Be(size);
        array.Data.Should().NotBeNull();
        array.Data!.Length.Should().Be(size);
    }

    [Fact]
    public void CreateSecureArray_WithZeroSize_ShouldCreateEmptyArray()
    {
        // Act
        using var array = SecureMemory.CreateSecureArray(0);

        // Assert
        array.Length.Should().Be(0);
        array.Data.Should().NotBeNull();
    }

    [Fact]
    public void Indexer_WithValidIndex_ShouldGetAndSetValues()
    {
        // Arrange
        using var array = SecureMemory.CreateSecureArray(5);
        const byte testValue = 0x42;

        // Act
        array[2] = testValue;
        var retrievedValue = array[2];

        // Assert
        retrievedValue.Should().Be(testValue);
    }

    [Fact]
    public void Indexer_WithInvalidIndex_ShouldThrowArgumentOutOfRangeException()
    {
        // Arrange
        using var array = SecureMemory.CreateSecureArray(5);

        // Act & Assert - Test negative index
        var actNegative = () => array[-1];
        actNegative.Should().Throw<ArgumentOutOfRangeException>();

        // Act & Assert - Test index >= length
        var actTooLarge = () => array[5];
        actTooLarge.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Indexer_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        var array = SecureMemory.CreateSecureArray(5);
        array.Dispose();

        // Act & Assert
        var actGet = () => array[0];
        actGet.Should().Throw<ObjectDisposedException>();

        var actSet = () => array[0] = 0x42;
        actSet.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void ToArray_ShouldReturnCopy()
    {
        // Arrange
        using var array = SecureMemory.CreateSecureArray(3);
        array[0] = 0x01;
        array[1] = 0x02;
        array[2] = 0x03;

        // Act
        var copy = array.ToArray();

        // Assert
        copy.Should().NotBeNull();
        copy.Should().Equal(0x01, 0x02, 0x03);

        // Modifying the copy should not affect the original
        copy![0] = 0xFF;
        array[0].Should().Be(0x01);
    }

    [Fact]
    public void ToArray_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        var array = SecureMemory.CreateSecureArray(5);
        array.Dispose();

        // Act & Assert
        var act = () => array.ToArray();
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void CopyFrom_ShouldCopyData()
    {
        // Arrange
        using var array = SecureMemory.CreateSecureArray(5);
        var source = new byte[] { 0x10, 0x20, 0x30 };

        // Act
        array.CopyFrom(source, 0, 1, 3);

        // Assert
        array[0].Should().Be(0x00); // Not copied
        array[1].Should().Be(0x10);
        array[2].Should().Be(0x20);
        array[3].Should().Be(0x30);
        array[4].Should().Be(0x00); // Not copied
    }

    [Fact]
    public void CopyFrom_WithNullSource_ShouldThrowArgumentNullException()
    {
        // Arrange
        using var array = SecureMemory.CreateSecureArray(5);

        // Act & Assert
        var act = () => array.CopyFrom(null!, 0, 0, 3);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void CopyFrom_WithInvalidSourceIndex_ShouldThrowArgumentOutOfRangeException()
    {
        // Arrange
        using var array = SecureMemory.CreateSecureArray(5);
        var source = new byte[] { 0x10, 0x20, 0x30 };

        // Act & Assert
        var act = () => array.CopyFrom(source, -1, 0, 3);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void CopyFrom_WithInvalidDestinationIndex_ShouldThrowArgumentOutOfRangeException()
    {
        // Arrange
        using var array = SecureMemory.CreateSecureArray(5);
        var source = new byte[] { 0x10, 0x20, 0x30 };

        // Act & Assert
        var act = () => array.CopyFrom(source, 0, -1, 3);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void CopyFrom_WithInvalidLength_ShouldThrowArgumentException()
    {
        // Arrange
        using var array = SecureMemory.CreateSecureArray(5);
        var source = new byte[] { 0x10, 0x20, 0x30 };

        // Act & Assert - Length exceeds source bounds
        var act = () => array.CopyFrom(source, 0, 0, 10);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void CopyFrom_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        var array = SecureMemory.CreateSecureArray(5);
        array.Dispose();
        var source = new byte[] { 0x10, 0x20, 0x30 };

        // Act & Assert
        var act = () => array.CopyFrom(source, 0, 0, 3);
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void AsSpan_ShouldReturnValidSpan()
    {
        // Arrange
        using var array = SecureMemory.CreateSecureArray(3);
        array[0] = 0x01;
        array[1] = 0x02;
        array[2] = 0x03;

        // Act
        var span = array.AsSpan();

        // Assert
        span.Length.Should().Be(3);
        span[0].Should().Be(0x01);
        span[1].Should().Be(0x02);
        span[2].Should().Be(0x03);
    }

    [Fact]
    public void AsSpan_AfterDispose_ShouldReturnEmptySpan()
    {
        // Arrange
        var array = SecureMemory.CreateSecureArray(5);
        array.Dispose();

        // Act
        var span = array.AsSpan();

        // Assert
        span.IsEmpty.Should().BeTrue();
    }

    [Fact]
    public void Data_AfterDispose_ShouldReturnNull()
    {
        // Arrange
        var array = SecureMemory.CreateSecureArray(5);
        array.Data.Should().NotBeNull(); // Verify it starts non-null

        // Act
        array.Dispose();

        // Assert
        array.Data.Should().BeNull();
    }

    [Fact]
    public void Length_AfterDispose_ShouldReturnZero()
    {
        // Arrange
        var array = SecureMemory.CreateSecureArray(5);
        array.Length.Should().Be(5); // Verify it starts with correct length

        // Act
        array.Dispose();

        // Assert
        array.Length.Should().Be(0);
    }

    [Fact]
    public void Dispose_ShouldClearMemory()
    {
        // LibOqs already initialized by fixture

        // Arrange
        var array = SecureMemory.CreateSecureArray(5);
        array[0] = 0x01;
        array[1] = 0x02;
        array[2] = 0x03;
        array[3] = 0x04;
        array[4] = 0x05;

        // Get a reference to the underlying array before disposal
        var underlyingArray = array.Data!;

        // Act
        array.Dispose();

        // Assert - The underlying array should be cleared
        underlyingArray.Should().OnlyContain(x => x == 0x00);

        // Properties should indicate disposal
        array.Data.Should().BeNull();
        array.Length.Should().Be(0);
    }

    [Fact]
    public void Dispose_CalledMultipleTimes_ShouldNotThrow()
    {
        // Arrange
        using var array = SecureMemory.CreateSecureArray(5);

        // Act & Assert
        var act = () =>
        {
            array.Dispose();
            array.Dispose();
            array.Dispose();
        };

        act.Should().NotThrow();
    }

    [Fact]
    public async Task SecureByteArray_ConcurrentAccess_ShouldBeThreadSafe()
    {
        // Arrange
        using var array = SecureMemory.CreateSecureArray(100);
        const int threadCount = 10;
        var tasks = new Task[threadCount];
        var exceptions = new Exception[threadCount];

        // Act - Multiple threads accessing the array concurrently
        for (int i = 0; i < threadCount; i++)
        {
            var index = i;
            tasks[i] = Task.Run(() =>
            {
                try
                {
                    // Each thread works on its own section of the array
                    var startIndex = index * 10;
                    for (int j = 0; j < 10; j++)
                    {
                        array[startIndex + j] = (byte)(index + j);
                        var value = array[startIndex + j];
                        value.Should().Be((byte)(index + j));
                    }
                }
                catch (ArgumentOutOfRangeException ex)
                {
                    exceptions[index] = ex;
                }
                catch (ObjectDisposedException ex)
                {
                    exceptions[index] = ex;
                }
                catch (InvalidOperationException ex)
                {
                    exceptions[index] = ex;
                }
            }, TestContext.Current.CancellationToken);
        }

        await Task.WhenAll(tasks);

        // Assert - No exceptions should occur
        exceptions.Should().AllSatisfy(ex => ex.Should().BeNull());

        // Verify final state
        for (int i = 0; i < threadCount; i++)
        {
            var startIndex = i * 10;
            for (int j = 0; j < 10; j++)
            {
                array[startIndex + j].Should().Be((byte)(i + j));
            }
        }
    }
}

#pragma warning restore S1144, S1215, S3776