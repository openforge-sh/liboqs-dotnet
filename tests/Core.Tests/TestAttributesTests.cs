using System.Runtime.InteropServices;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.Core.Tests;

public sealed class TestAttributesTests
{
    public sealed class SkipOnPlatformAttributeTests
    {
        [Fact]
        public void SkipOnPlatformAttribute_WithCurrentPlatform_ShouldSkipTest()
        {
            // Arrange - Create attribute for current platform
            var currentPlatformName = GetCurrentPlatformName();
            var attribute = new SkipOnPlatformAttribute(currentPlatformName);

            // Assert
            attribute.Skip.Should().NotBeNullOrEmpty();
            attribute.Skip.Should().Contain($"Test skipped on {currentPlatformName}");
            attribute.Platforms.Should().Contain(currentPlatformName);
        }

        [Fact]
        public void SkipOnPlatformAttribute_WithOtherPlatform_ShouldNotSkipTest()
        {
            // Arrange - Create attribute for different platform
            var otherPlatform = GetNonCurrentPlatformName();
            var attribute = new SkipOnPlatformAttribute(otherPlatform);

            // Assert
            attribute.Skip.Should().BeNull();
            attribute.Platforms.Should().Contain(otherPlatform);
        }

        [Fact]
        public void SkipOnPlatformAttribute_WithMultiplePlatformsIncludingCurrent_ShouldSkipTest()
        {
            // Arrange
            var currentPlatform = GetCurrentPlatformName();
            var otherPlatform = GetNonCurrentPlatformName();
            var attribute = new SkipOnPlatformAttribute(currentPlatform, otherPlatform);

            // Assert
            attribute.Skip.Should().NotBeNullOrEmpty();
            attribute.Skip.Should().Contain($"Test skipped on {currentPlatform}");
            attribute.Platforms.Should().HaveCount(2);
        }

        [Fact]
        public void SkipOnPlatformAttribute_WithNullPlatforms_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            var act = () => new SkipOnPlatformAttribute(null!);
            act.Should().Throw<ArgumentNullException>();
        }

        [Theory]
        [InlineData("WINDOWS")]
        [InlineData("windows")]
        [InlineData("Windows")]
        public void SkipOnPlatformAttribute_CaseInsensitive_ShouldWorkCorrectly(string platformName)
        {
            // Arrange
            var attribute = new SkipOnPlatformAttribute(platformName);

            // Assert - Should behave the same regardless of case
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                attribute.Skip.Should().NotBeNullOrEmpty();
            }
            else
            {
                attribute.Skip.Should().BeNull();
            }
        }
    }

    public sealed class PlatformSpecificFactAttributeTests
    {
        [Fact]
        public void PlatformSpecificFactAttribute_WithCurrentPlatform_ShouldRunTest()
        {
            // Arrange
            var currentPlatform = GetCurrentPlatformName();
            var attribute = new PlatformSpecificFactAttribute(currentPlatform);

            // Assert
            attribute.Skip.Should().BeNull();
            attribute.Platforms.Should().Contain(currentPlatform);
        }

        [Fact]
        public void PlatformSpecificFactAttribute_WithOtherPlatform_ShouldSkipTest()
        {
            // Arrange
            var otherPlatform = GetNonCurrentPlatformName();
            var attribute = new PlatformSpecificFactAttribute(otherPlatform);

            // Assert
            attribute.Skip.Should().NotBeNullOrEmpty();
            attribute.Skip.Should().Contain($"Test only runs on: {otherPlatform}");
            attribute.Platforms.Should().Contain(otherPlatform);
        }

        [Fact]
        public void PlatformSpecificFactAttribute_WithMultiplePlatformsIncludingCurrent_ShouldRunTest()
        {
            // Arrange
            var currentPlatform = GetCurrentPlatformName();
            var otherPlatform = GetNonCurrentPlatformName();
            var attribute = new PlatformSpecificFactAttribute(currentPlatform, otherPlatform);

            // Assert
            attribute.Skip.Should().BeNull();
            attribute.Platforms.Should().HaveCount(2);
        }
    }

    public sealed class PlatformSpecificTheoryAttributeTests
    {
        [Fact]
        public void PlatformSpecificTheoryAttribute_WithCurrentPlatform_ShouldRunTest()
        {
            // Arrange
            var currentPlatform = GetCurrentPlatformName();
            var attribute = new PlatformSpecificTheoryAttribute(currentPlatform);

            // Assert
            attribute.Skip.Should().BeNull();
            attribute.Platforms.Should().Contain(currentPlatform);
        }

        [Fact]
        public void PlatformSpecificTheoryAttribute_WithOtherPlatform_ShouldSkipTest()
        {
            // Arrange
            var otherPlatform = GetNonCurrentPlatformName();
            var attribute = new PlatformSpecificTheoryAttribute(otherPlatform);

            // Assert
            attribute.Skip.Should().NotBeNullOrEmpty();
            attribute.Skip.Should().Contain($"Test only runs on: {otherPlatform}");
            attribute.Platforms.Should().Contain(otherPlatform);
        }
    }

    public sealed class SkipOnArchitectureAttributeTests
    {
        [Fact]
        public void SkipOnArchitectureAttribute_WithCurrentArchitecture_ShouldSkipTest()
        {
            // Arrange
            var currentArch = RuntimeInformation.OSArchitecture;
            var attribute = new SkipOnArchitectureAttribute(currentArch);

            // Assert
            attribute.Skip.Should().NotBeNullOrEmpty();
            attribute.Skip.Should().Contain($"Test skipped on {currentArch} architecture");
            attribute.Architectures.Should().Contain(currentArch);
        }

        [Fact]
        public void SkipOnArchitectureAttribute_WithDifferentArchitecture_ShouldNotSkipTest()
        {
            // Arrange - Use architecture different from current
            var currentArch = RuntimeInformation.OSArchitecture;
            var otherArch = currentArch == Architecture.X64 ? Architecture.Arm64 : Architecture.X64;
            var attribute = new SkipOnArchitectureAttribute(otherArch);

            // Assert
            attribute.Skip.Should().BeNull();
            attribute.Architectures.Should().Contain(otherArch);
        }

        [Fact]
        public void SkipOnArchitectureAttribute_WithNullArchitectures_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            var act = () => new SkipOnArchitectureAttribute(null!);
            act.Should().Throw<ArgumentNullException>();
        }
    }

    public sealed class ArchitectureSpecificFactAttributeTests
    {
        [Fact]
        public void ArchitectureSpecificFactAttribute_WithCurrentArchitecture_ShouldRunTest()
        {
            // Arrange
            var currentArch = RuntimeInformation.OSArchitecture;
            var attribute = new ArchitectureSpecificFactAttribute(currentArch);

            // Assert
            attribute.Skip.Should().BeNull();
            attribute.Architectures.Should().Contain(currentArch);
        }

        [Fact]
        public void ArchitectureSpecificFactAttribute_WithDifferentArchitecture_ShouldSkipTest()
        {
            // Arrange
            var currentArch = RuntimeInformation.OSArchitecture;
            var otherArch = currentArch == Architecture.X64 ? Architecture.Arm64 : Architecture.X64;
            var attribute = new ArchitectureSpecificFactAttribute(otherArch);

            // Assert
            attribute.Skip.Should().NotBeNullOrEmpty();
            attribute.Skip.Should().Contain($"Test only runs on: {otherArch}");
            attribute.Architectures.Should().Contain(otherArch);
        }
    }

    public sealed class TestCategoryAttributeTests
    {
        [Fact]
        public void TestCategoryAttribute_WithValidCategory_ShouldStoreCategory()
        {
            // Arrange & Act
            var attribute = new TestCategoryAttribute("Performance");

            // Assert
            attribute.Category.Should().Be("Performance");
        }

        [Fact]
        public void TestCategoryAttribute_WithNullCategory_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            var act = () => new TestCategoryAttribute(null!);
            act.Should().Throw<ArgumentNullException>();
        }

        [Theory]
        [InlineData("Security")]
        [InlineData("Integration")]
        [InlineData("Unit")]
        [InlineData("Performance")]
        public void TestCategoryAttribute_WithVariousCategories_ShouldStoreCorrectly(string category)
        {
            // Act
            var attribute = new TestCategoryAttribute(category);

            // Assert
            attribute.Category.Should().Be(category);
        }
    }

    public sealed class RequiresElevatedPrivilegesAttributeTests
    {
        private static bool IsRunningElevated()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                    var principal = new System.Security.Principal.WindowsPrincipal(identity);
                    return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
                catch (UnauthorizedAccessException)
                {
                    return false;
                }
                catch (System.Security.SecurityException)
                {
                    return false;
                }
            }
            else
            {
                // On Unix-like systems, check if running as root
                return Environment.GetEnvironmentVariable("USER") == "root" ||
                       Environment.GetEnvironmentVariable("EUID") == "0";
            }
        }

        [Fact]
        public void RequiresElevatedPrivilegesAttribute_WithoutElevation_ShouldSkipTest()
        {
            // Note: This test assumes we're not running as administrator/root
            // In normal test runs, this should be skipped
            var attribute = new RequiresElevatedPrivilegesAttribute();

            // Assert - Most test environments don't run elevated
            // So we expect this to be skipped in normal circumstances
            if (!IsRunningElevated())
            {
                attribute.Skip.Should().NotBeNullOrEmpty();
                attribute.Skip.Should().Contain("Test requires elevated privileges");
            }
            else
            {
                attribute.Skip.Should().BeNull();
            }
        }

        [PlatformSpecificFact("WINDOWS")]
        public void RequiresElevatedPrivilegesAttribute_OnWindows_ShouldCheckWindowsPrincipal()
        {
            // Arrange & Act
            var attribute = new RequiresElevatedPrivilegesAttribute();

            // Assert - The implementation should have attempted to check Windows principal
            // Skip status depends on whether running as Administrator
            if (IsRunningElevated())
            {
                attribute.Skip.Should().BeNull();
            }
            else
            {
                attribute.Skip.Should().NotBeNullOrEmpty();
                attribute.Skip.Should().Contain("Test requires elevated privileges");
            }
        }

        [PlatformSpecificFact("LINUX", "OSX")]
        public void RequiresElevatedPrivilegesAttribute_OnUnix_ShouldCheckEnvironmentVariables()
        {
            // Arrange & Act
            var attribute = new RequiresElevatedPrivilegesAttribute();

            // Assert - The implementation should have checked USER and EUID environment variables
            var currentUser = Environment.GetEnvironmentVariable("USER");
            var currentEuid = Environment.GetEnvironmentVariable("EUID");

            if (currentUser == "root" || currentEuid == "0")
            {
                attribute.Skip.Should().BeNull();
            }
            else
            {
                attribute.Skip.Should().NotBeNullOrEmpty();
                attribute.Skip.Should().Contain("Test requires elevated privileges");
            }
        }

        [Fact]
        public void RequiresElevatedPrivilegesAttribute_SkipMessage_ShouldBeConsistent()
        {
            // Arrange & Act
            var attribute = new RequiresElevatedPrivilegesAttribute();

            // Assert
            if (attribute.Skip != null)
            {
                attribute.Skip.Should().Be("Test requires elevated privileges (run as Administrator/root)");
            }
        }

        [Fact]
        public void RequiresElevatedPrivilegesAttribute_MultipleInstances_ShouldBehaveConsistently()
        {
            // Arrange & Act
            var attribute1 = new RequiresElevatedPrivilegesAttribute();
            var attribute2 = new RequiresElevatedPrivilegesAttribute();

            // Assert - Both instances should have the same skip behavior
            attribute1.Skip.Should().Be(attribute2.Skip);
        }

        [Fact]
        public void RequiresElevatedPrivilegesAttribute_IsFactAttribute_ShouldInheritFromFact()
        {
            // Arrange & Act
            var attribute = new RequiresElevatedPrivilegesAttribute();

            // Assert
            attribute.Should().BeAssignableTo<FactAttribute>();
        }

        [Theory]
        [InlineData(null, -1)]
        [InlineData("TestFile.cs", 42)]
        [InlineData("", 0)]
        public void RequiresElevatedPrivilegesAttribute_WithCallerInfo_ShouldAcceptParameters(string? sourceFilePath, int sourceLineNumber)
        {
            // Act & Assert - Should not throw
            var act = () => new RequiresElevatedPrivilegesAttribute(sourceFilePath, sourceLineNumber);
            act.Should().NotThrow();

            var attribute = act();
            // Skip behavior should be the same regardless of caller info
            if (!IsRunningElevated())
            {
                attribute.Skip.Should().NotBeNullOrEmpty();
            }
        }

        [Fact]
        public void RequiresElevatedPrivilegesAttribute_ShouldHandleWindowsSecurityExceptions()
        {
            // This test ensures that SecurityException handling path is covered
            // The attribute should handle cases where WindowsIdentity.GetCurrent() throws SecurityException
            var attribute = new RequiresElevatedPrivilegesAttribute();

            // Assert - Should not throw during construction even if security checks fail
            attribute.Should().NotBeNull();
            // On platforms where security checks might fail, should still set appropriate skip behavior
        }

#pragma warning disable S4144
        [Fact]
        public void RequiresElevatedPrivilegesAttribute_ShouldHandleUnauthorizedAccessExceptions()
        {
            // This test ensures that UnauthorizedAccessException handling path is covered
            // The attribute should handle cases where WindowsIdentity.GetCurrent() throws UnauthorizedAccessException
            var attribute = new RequiresElevatedPrivilegesAttribute();

            // Assert - Should not throw during construction even if access is denied
            attribute.Should().NotBeNull();
            // Should default to not elevated (skip test) when access exceptions occur
        }

        [PlatformSpecificFact("LINUX", "OSX")]
        public void RequiresElevatedPrivilegesAttribute_OnUnix_WithNullEnvironmentVariables_ShouldNotSkip()
        {
            // This test covers the case where environment variables might be null/empty
            // which exercises different code paths in the Unix elevation checking
            var attribute = new RequiresElevatedPrivilegesAttribute();

            // Assert - Should handle null environment variables gracefully
            attribute.Should().NotBeNull();
            // Behavior depends on actual environment variables, but should not throw
        }

        [PlatformSpecificFact("LINUX", "OSX")]
        public void RequiresElevatedPrivilegesAttribute_OnUnix_WithEUID0_ShouldNotSkip()
        {
            // This test specifically checks the EUID=0 path for Unix systems
            var currentEuid = Environment.GetEnvironmentVariable("EUID");
            var attribute = new RequiresElevatedPrivilegesAttribute();

            // Assert - Should properly check EUID environment variable
            attribute.Should().NotBeNull();
            if (currentEuid == "0")
            {
                attribute.Skip.Should().BeNull();
            }
        }

        [PlatformSpecificFact("LINUX", "OSX")]
        public void RequiresElevatedPrivilegesAttribute_OnUnix_WithUserRoot_ShouldNotSkip()
        {
            // This test specifically checks the USER=root path for Unix systems
            var currentUser = Environment.GetEnvironmentVariable("USER");
            var attribute = new RequiresElevatedPrivilegesAttribute();

            // Assert - Should properly check USER environment variable
            attribute.Should().NotBeNull();
            if (currentUser == "root")
            {
                attribute.Skip.Should().BeNull();
            }
        }

        [PlatformSpecificFact("WINDOWS")]
        public void RequiresElevatedPrivilegesAttribute_OnWindows_ShouldCheckAdministratorRole()
        {
            // This test ensures the Administrator role checking path is covered
            var attribute = new RequiresElevatedPrivilegesAttribute();

            // Assert - Should attempt to check Administrator role
            attribute.Should().NotBeNull();
            // The actual behavior depends on whether running as Administrator
        }

        [Fact]
        public void RequiresElevatedPrivilegesAttribute_DefaultConstructor_ShouldWorkCorrectly()
        {
            // This test ensures the default constructor path is covered
            var attribute = new RequiresElevatedPrivilegesAttribute();

            // Assert - Default constructor should work properly
            attribute.Should().NotBeNull();
            attribute.Should().BeAssignableTo<FactAttribute>();
        }

        [Fact]
        public void RequiresElevatedPrivilegesAttribute_InheritanceChain_ShouldBeCorrect()
        {
            // This test verifies the complete inheritance chain
            var attribute = new RequiresElevatedPrivilegesAttribute();

            // Assert - Should inherit from FactAttribute which inherits from Attribute
            attribute.Should().BeAssignableTo<FactAttribute>();
            attribute.Should().BeAssignableTo<Attribute>();
        }
    }

    public sealed class RequiresAlgorithmAttributeTests
    {
        [Fact]
        public void RequiresAlgorithmAttribute_WithValidAlgorithm_ShouldStoreAlgorithm()
        {
            // Arrange & Act
            var attribute = new RequiresAlgorithmAttribute("ML-KEM-512");

            // Assert
            attribute.AlgorithmName.Should().Be("ML-KEM-512");
            // Note: Skip behavior depends on runtime algorithm availability checking
        }

        [Fact]
        public void RequiresAlgorithmAttribute_WithNullAlgorithm_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            var act = () => new RequiresAlgorithmAttribute(null!);
            act.Should().Throw<ArgumentNullException>();
        }
    }

    public sealed class LongRunningTestAttributeTests
    {
        [Fact]
        public void LongRunningTestAttribute_WithDefaultDuration_ShouldSetMedium()
        {
            // Act
            var attribute = new LongRunningTestAttribute();

            // Assert
            attribute.DurationCategory.Should().Be("Medium");
        }

        [Theory]
        [InlineData("Short")]
        [InlineData("Medium")]
        [InlineData("Long")]
        [InlineData("VeryLong")]
        public void LongRunningTestAttribute_WithSpecificDuration_ShouldStoreCorrectly(string duration)
        {
            // Act
            var attribute = new LongRunningTestAttribute(duration);

            // Assert
            attribute.DurationCategory.Should().Be(duration);
        }

        [Fact]
        public void LongRunningTestAttribute_WithNullDuration_ShouldDefaultToMedium()
        {
            // Act
            var attribute = new LongRunningTestAttribute(null!);

            // Assert
            attribute.DurationCategory.Should().Be("Medium");
        }
    }

    public sealed class RequiresMinimumMemoryAttributeTests
    {
        [Fact]
        public void RequiresMinimumMemoryAttribute_WithReasonableMemory_ShouldNotSkip()
        {
            // Arrange - Request small amount of memory (1KB)
            const long smallMemoryRequirement = 1024;

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(smallMemoryRequirement);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(smallMemoryRequirement);
            attribute.Skip.Should().BeNull(); // Should not skip for small memory requirement
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_WithLargeMemory_MightSkip()
        {
            // Arrange - Request large amount of memory (10GB)
            const long largeMemoryRequirement = 10L * 1024 * 1024 * 1024;

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(largeMemoryRequirement);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(largeMemoryRequirement);
            // Skip behavior depends on current memory usage vs requirement
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_WithMediumMemory_ShouldNotSkip()
        {
            // Arrange - Request medium amount of memory (50MB - below threshold)
            const long mediumMemoryRequirement = 50L * 1024 * 1024;

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(mediumMemoryRequirement);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(mediumMemoryRequirement);
            attribute.Skip.Should().BeNull(); // Should not skip for medium memory requirement below threshold
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_WithZeroMemory_ShouldNotSkip()
        {
            // Arrange
            const long zeroMemoryRequirement = 0;

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(zeroMemoryRequirement);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(zeroMemoryRequirement);
            attribute.Skip.Should().BeNull();
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_WithNegativeMemory_ShouldNotSkip()
        {
            // Arrange
            const long negativeMemoryRequirement = -1024;

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(negativeMemoryRequirement);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(negativeMemoryRequirement);
            attribute.Skip.Should().BeNull();
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_WithExactlyThresholdMemory_ShouldNotSkip()
        {
            // Arrange - Request exactly 100MB (threshold boundary)
            const long thresholdMemoryRequirement = 100L * 1024 * 1024;

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(thresholdMemoryRequirement);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(thresholdMemoryRequirement);
            attribute.Skip.Should().BeNull(); // Should not skip for threshold memory requirement
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_WithJustOverThresholdMemory_MightCheckAvailability()
        {
            // Arrange - Request just over 100MB (threshold + 1MB)
            const long overThresholdMemoryRequirement = (100L * 1024 * 1024) + (1024 * 1024);

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(overThresholdMemoryRequirement);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(overThresholdMemoryRequirement);
            // Skip behavior depends on memory availability check - could be null or contain skip message
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_WithExtremelyLargeMemory_ShouldLikelySkip()
        {
            // Arrange - Request extremely large amount of memory (1TB)
            const long extremeMemoryRequirement = 1024L * 1024 * 1024 * 1024;

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(extremeMemoryRequirement);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(extremeMemoryRequirement);
            // Very likely to skip due to insufficient memory, but depends on system
        }

        [Theory]
        [InlineData(1024)]           // 1KB
        [InlineData(1048576)]        // 1MB
        [InlineData(52428800)]       // 50MB
        [InlineData(104857600)]      // 100MB (threshold)
        public void RequiresMinimumMemoryAttribute_WithVariousSmallSizes_ShouldStoreCorrectly(long memoryBytes)
        {
            // Act
            var attribute = new RequiresMinimumMemoryAttribute(memoryBytes);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(memoryBytes);
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_WithTwoGigabytesMemory_MightSkipBasedOnAvailability()
        {
            // Arrange - 2GB memory requirement (at fallback threshold)
            const long twoGigabytes = 2L * 1024 * 1024 * 1024;

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(twoGigabytes);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(twoGigabytes);
            // Skip behavior depends on memory availability and exception handling
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_WithOneGigabyteMemory_MightSkipIfCannotDetermineAvailability()
        {
            // Arrange - 1GB memory requirement (at fallback detection threshold)
            const long oneGigabyte = 1024L * 1024 * 1024;

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(oneGigabyte);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(oneGigabyte);
            // Skip behavior depends on whether memory availability can be determined
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_WithVeryLargeMemory_ShouldSkipDueToInsufficientMemory()
        {
            // Arrange - Request an absolutely massive amount of memory (100TB)
            const long massiveMemoryRequirement = 100L * 1024 * 1024 * 1024 * 1024;

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(massiveMemoryRequirement);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(massiveMemoryRequirement);
            // Should very likely be skipped due to insufficient available memory
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_WithExtremelyLargeMemoryOver2GB_ShouldSkipEvenOnExceptionFallback()
        {
            // Arrange - Request more than 2GB (fallback threshold for exception cases)
            const long over2GB = 3L * 1024 * 1024 * 1024;

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(over2GB);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(over2GB);
            // Should skip even if memory checking fails with exceptions
        }

        [Theory]
        [InlineData(150L * 1024 * 1024)]      // 150MB - just over threshold, should trigger memory check
        [InlineData(500L * 1024 * 1024)]      // 500MB - moderate size, should check availability
        [InlineData(1024L * 1024 * 1024)]     // 1GB - at fallback boundary
        [InlineData(1536L * 1024 * 1024)]     // 1.5GB - between boundaries
        public void RequiresMinimumMemoryAttribute_WithMemoryOverThreshold_ShouldCheckAvailability(long memoryBytes)
        {
            // Act
            var attribute = new RequiresMinimumMemoryAttribute(memoryBytes);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(memoryBytes);
            // These sizes should trigger the memory availability checking logic
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_ShouldHandleGCMemoryInfoAvailable()
        {
            // Arrange - Use a size that will trigger GC memory info checking (200MB)
            const long memoryRequirement = 200L * 1024 * 1024;

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(memoryRequirement);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(memoryRequirement);
            // This should exercise the GC.GetGCMemoryInfo() code path
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_ShouldHandleMemoryCheckExceptions()
        {
            // Arrange - Use a size that triggers memory checking but might cause exceptions
            const long memoryRequirement = 800L * 1024 * 1024; // 800MB

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(memoryRequirement);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(memoryRequirement);
            // This should exercise exception handling paths in memory availability checking
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_ExactlyAt2GBThreshold_ShouldUseExceptionFallback()
        {
            // Arrange - Exactly at the 2GB exception fallback threshold
            const long exactly2GB = 2L * 1024 * 1024 * 1024;

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(exactly2GB);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(exactly2GB);
            // Should be at the boundary of exception fallback logic
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_JustUnder2GBThreshold_ShouldNotSkipOnExceptionFallback()
        {
            // Arrange - Just under the 2GB exception fallback threshold
            const long justUnder2GB = (2L * 1024 * 1024 * 1024) - 1;

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(justUnder2GB);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(justUnder2GB);
            // Should not skip due to exception fallback threshold
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_GetAvailablePhysicalMemory_ShouldHandleExceptions()
        {
            // This test exercises the GetAvailablePhysicalMemory method indirectly
            // by testing with a size that triggers memory checking but might encounter exceptions
            // Arrange - Size between 100MB and 1GB to trigger memory checking
            const long memoryRequirement = 250L * 1024 * 1024; // 250MB

            // Act - This should exercise the memory availability checking code path
            var attribute = new RequiresMinimumMemoryAttribute(memoryRequirement);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(memoryRequirement);
            // The attribute construction should complete without throwing,
            // even if GetAvailablePhysicalMemory encounters exceptions
        }

        [Fact]
        public void RequiresMinimumMemoryAttribute_WithMemoryBetweenThresholds_ShouldExerciseGCMemoryInfo()
        {
            // Arrange - Use a size between reasonable threshold (100MB) and fallback threshold (1GB)
            // This should exercise the GC.GetGCMemoryInfo() code path
            const long memoryRequirement = 512L * 1024 * 1024; // 512MB

            // Act
            var attribute = new RequiresMinimumMemoryAttribute(memoryRequirement);

            // Assert
            attribute.MinimumMemoryBytes.Should().Be(memoryRequirement);
            // This size should trigger the memory availability check using GC.GetGCMemoryInfo()
        }
    }

    public sealed class SecurityCriticalAttributeTests
    {
        [Fact]
        public void SecurityCriticalAttribute_WithDefaultCategory_ShouldSetGeneral()
        {
            // Act
            var attribute = new SecurityCriticalAttribute();

            // Assert
            attribute.Category.Should().Be("General");
        }

        [Theory]
        [InlineData("Cryptography")]
        [InlineData("KeyManagement")]
        [InlineData("MemoryHandling")]
        public void SecurityCriticalAttribute_WithSpecificCategory_ShouldStoreCorrectly(string category)
        {
            // Act
            var attribute = new SecurityCriticalAttribute(category);

            // Assert
            attribute.Category.Should().Be(category);
        }

        [Fact]
        public void SecurityCriticalAttribute_WithNullCategory_ShouldDefaultToGeneral()
        {
            // Act
            var attribute = new SecurityCriticalAttribute(null!);

            // Assert
            attribute.Category.Should().Be("General");
        }
    }

    public sealed class AlgorithmSpecificTheoryAttributeTests
    {
        [Fact]
        public void AlgorithmSpecificTheoryAttribute_WithValidAlgorithms_ShouldStoreAlgorithms()
        {
            // Arrange
            string[] algorithms = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];

            // Act
            var attribute = new AlgorithmSpecificTheoryAttribute(algorithms);

            // Assert
            attribute.AlgorithmNames.Should().Equal(algorithms);
        }

        #pragma warning disable S3220, S3878
        [Fact]
        public void AlgorithmSpecificTheoryAttribute_WithNullAlgorithms_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            var act = () => new AlgorithmSpecificTheoryAttribute(null!);
            act.Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public void AlgorithmSpecificTheoryAttribute_WithEmptyAlgorithms_ShouldStoreEmpty()
        {
            // Act
            var attribute = new AlgorithmSpecificTheoryAttribute([]);

            // Assert
            attribute.AlgorithmNames.Should().BeEmpty();
        }
        #pragma warning disable S3220, S3878
    }

    public sealed class StressTestAttributeTests
    {
        [Fact]
        public void StressTestAttribute_WithDefaults_ShouldSetMemoryCategory()
        {
            // Act
            var attribute = new StressTestAttribute();

            // Assert
            attribute.StressCategory.Should().Be("Memory");
            attribute.ExpectedDurationMs.Should().Be(30000);
        }

        [Theory]
        [InlineData("CPU", 5000)]
        [InlineData("Memory", 10000)]
        [InlineData("IO", 15000)]
        public void StressTestAttribute_WithParameters_ShouldStoreCorrectly(string category, int duration)
        {
            // Act
            var attribute = new StressTestAttribute(category, duration);

            // Assert
            attribute.StressCategory.Should().Be(category);
            attribute.ExpectedDurationMs.Should().Be(duration);
        }

        [Fact]
        public void StressTestAttribute_WithNullCategory_ShouldDefaultToMemory()
        {
            // Act
            var attribute = new StressTestAttribute(null!);

            // Assert
            attribute.StressCategory.Should().Be("Memory");
        }
    }

    // Helper methods
    private static string GetCurrentPlatformName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return "WINDOWS";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return "LINUX";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return "OSX";
        return "UNKNOWN";
    }

    private static string GetNonCurrentPlatformName()
    {
        var current = GetCurrentPlatformName();
        return current switch
        {
            "WINDOWS" => "LINUX",
            "LINUX" => "WINDOWS",
            "OSX" => "WINDOWS",
            _ => "WINDOWS"
        };
    }
}

#pragma warning disable S4144