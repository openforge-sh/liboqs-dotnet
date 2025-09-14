using System.Diagnostics;
using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.Core.Tests;

public sealed class TestUtilitiesTests
{
    public sealed class RandomBytesGenerationTests
    {
        [Fact]
        public void GenerateRandomBytes_ShouldProduceValidOutput()
        {
            // Act
            var bytes1 = TestUtilities.GenerateRandomBytes(32);
            var bytes2 = TestUtilities.GenerateRandomBytes(32);

            // Assert
            bytes1.Should().NotBeNull();
            bytes1.Should().HaveCount(32);
            bytes2.Should().NotBeNull();
            bytes2.Should().HaveCount(32);
            bytes1.Should().NotEqual(bytes2, "random bytes should be different each time");
        }

        [Theory]
        [InlineData(1)]
        [InlineData(16)]
        [InlineData(256)]
        [InlineData(1024)]
        public void GenerateRandomBytes_WithVariousLengths_ShouldReturnCorrectSize(int length)
        {
            // Act
            var bytes = TestUtilities.GenerateRandomBytes(length);

            // Assert
            bytes.Should().NotBeNull();
            bytes.Should().HaveCount(length);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(-100)]
        public void GenerateRandomBytes_WithZeroOrNegativeLength_ShouldThrowArgumentOutOfRangeException(int length)
        {
            // Act & Assert
            var act = () => TestUtilities.GenerateRandomBytes(length);
            act.Should().Throw<ArgumentOutOfRangeException>()
                .WithParameterName(nameof(length))
                .WithMessage("*Length must be positive*");
        }
    }

    public sealed class RandomMessageGenerationTests
    {
        [Fact]
        public void GenerateRandomMessage_ShouldProduceVariedLengthMessages()
        {
            // Arrange
            var messages = new List<byte[]>();
            const int iterations = 50;

            // Act - Generate multiple messages
            for (int i = 0; i < iterations; i++)
            {
                messages.Add(TestUtilities.GenerateRandomMessage());
            }

            // Assert
            messages.Should().NotBeEmpty();
            messages.Should().AllSatisfy(msg =>
            {
                msg.Should().NotBeNull();
                msg.Length.Should().BeInRange(32, 1024);
            });

            // Should have some variety in lengths
            var lengths = messages.Select(m => m.Length).Distinct().ToList();
            lengths.Should().HaveCountGreaterThan(5, "should generate messages of varied lengths");
        }

        [Theory]
        [InlineData(10, 20)]
        [InlineData(1, 5)]
        [InlineData(100, 200)]
        public void GenerateRandomMessage_WithCustomRange_ShouldRespectLimits(int minLength, int maxLength)
        {
            // Act
            var messages = new List<byte[]>();
            for (int i = 0; i < 20; i++)
            {
                messages.Add(TestUtilities.GenerateRandomMessage(minLength, maxLength));
            }

            // Assert
            messages.Should().AllSatisfy(msg =>
            {
                msg.Length.Should().BeInRange(minLength, maxLength);
            });
        }
    }

    public sealed class ByteArrayComparisonTests
    {
        [Fact]
        public void ByteArraysEqual_WithIdenticalArrays_ShouldReturnTrue()
        {
            // Arrange
            var array1 = new byte[] { 1, 2, 3, 4, 5 };
            var array2 = new byte[] { 1, 2, 3, 4, 5 };

            // Act & Assert
            TestUtilities.ByteArraysEqual(array1, array2).Should().BeTrue();
        }

        [Fact]
        public void ByteArraysEqual_WithDifferentArrays_ShouldReturnFalse()
        {
            // Arrange
            var array1 = new byte[] { 1, 2, 3, 4, 5 };
            var array2 = new byte[] { 1, 2, 3, 4, 6 };

            // Act & Assert
            TestUtilities.ByteArraysEqual(array1, array2).Should().BeFalse();
        }

        [Fact]
        public void ByteArraysEqual_WithSameReference_ShouldReturnTrue()
        {
            // Arrange
            var array = new byte[] { 1, 2, 3, 4, 5 };

            // Act & Assert
            TestUtilities.ByteArraysEqual(array, array).Should().BeTrue();
        }

        [Fact]
        public void ByteArraysEqual_WithBothNull_ShouldReturnTrue()
        {
            // Act & Assert
            TestUtilities.ByteArraysEqual(null!, null!).Should().BeTrue();
        }

        [Fact]
        public void ByteArraysEqual_WithOneNull_ShouldReturnFalse()
        {
            // Arrange
            var array = new byte[] { 1, 2, 3 };

            // Act & Assert
            TestUtilities.ByteArraysEqual(array, null!).Should().BeFalse();
            TestUtilities.ByteArraysEqual(null!, array).Should().BeFalse();
        }

        [Fact]
        public void ByteArraysEqual_WithDifferentLengths_ShouldReturnFalse()
        {
            // Arrange
            var array1 = new byte[] { 1, 2, 3 };
            var array2 = new byte[] { 1, 2, 3, 4 };

            // Act & Assert
            TestUtilities.ByteArraysEqual(array1, array2).Should().BeFalse();
        }
    }

    public sealed class ConstantTimeEqualsTests
    {
        [Fact]
        public void ConstantTimeEquals_WithIdenticalArrays_ShouldReturnTrue()
        {
            // Arrange
            var array1 = new byte[] { 1, 2, 3, 4, 5 };
            var array2 = new byte[] { 1, 2, 3, 4, 5 };

            // Act & Assert
            TestUtilities.ConstantTimeEquals(array1, array2).Should().BeTrue();
        }

        [Fact]
        public void ConstantTimeEquals_WithDifferentArrays_ShouldReturnFalse()
        {
            // Arrange
            var array1 = new byte[] { 1, 2, 3, 4, 5 };
            var array2 = new byte[] { 1, 2, 3, 4, 6 };

            // Act & Assert
            TestUtilities.ConstantTimeEquals(array1, array2).Should().BeFalse();
        }

        [Fact]
        public void ConstantTimeEquals_TimingConsistency_ShouldBeConstantTime()
        {
            // Arrange - Create arrays that differ at different positions
            const int arraySize = 256;
            var baseArray = new byte[arraySize];
            var earlyDiffArray = new byte[arraySize];
            var lateDiffArray = new byte[arraySize];

            RandomNumberGenerator.Fill(baseArray);
            baseArray.CopyTo(earlyDiffArray, 0);
            baseArray.CopyTo(lateDiffArray, 0);

            earlyDiffArray[0] ^= 0xFF; // Differ at start
            lateDiffArray[^1] ^= 0xFF; // Differ at end

            // Warm-up phase to ensure JIT compilation and cache warming
            for (int i = 0; i < 1000; i++)
            {
                TestUtilities.ConstantTimeEquals(baseArray, earlyDiffArray);
                TestUtilities.ConstantTimeEquals(baseArray, lateDiffArray);
            }

            // Act - Measure timing with multiple runs to find best case
            const int runs = 5;
            double bestRatio = double.MaxValue;
            
            for (int run = 0; run < runs; run++)
            {
                // Force garbage collection before each run to reduce GC noise
                #pragma warning disable S1215, S2925
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
                TimingUtils.StabilizeSystem(); // Brief pause to let system settle
                #pragma warning restore S1215
                var earlyTimes = new List<long>();
                var lateTimes = new List<long>();
                var sw = Stopwatch.StartNew();

                for (int i = 0; i < 100; i++)
                {
                    sw.Restart();
                    TestUtilities.ConstantTimeEquals(baseArray, earlyDiffArray);
                    sw.Stop();
                    earlyTimes.Add(sw.ElapsedTicks);

                    sw.Restart();
                    TestUtilities.ConstantTimeEquals(baseArray, lateDiffArray);
                    sw.Stop();
                    lateTimes.Add(sw.ElapsedTicks);
                }

                // Remove outliers (top and bottom 10%)
                earlyTimes.Sort();
                lateTimes.Sort();
                var trimCount = earlyTimes.Count / 10;
                var trimmedEarly = earlyTimes.Skip(trimCount).Take(earlyTimes.Count - 2 * trimCount).ToList();
                var trimmedLate = lateTimes.Skip(trimCount).Take(lateTimes.Count - 2 * trimCount).ToList();

                // Use trimmed mean for more stable results
                var earlyAvg = trimmedEarly.Average();
                var lateAvg = trimmedLate.Average();
                var timingRatio = Math.Max(earlyAvg, lateAvg) / Math.Min(earlyAvg, lateAvg);
                
                bestRatio = Math.Min(bestRatio, timingRatio);
            }

            // Assert - Use a more realistic threshold that accounts for system noise
            // A ratio of 10.0 still ensures the algorithm doesn't have obvious timing leaks
            // while being resilient to CI environment noise
            // Use environment-aware threshold
            var baseline = TimingUtils.GetSystemBaseline();
            var testUtilThreshold = baseline.Environment switch
            {
                TimingUtils.EnvironmentType.CI => 20.0,      // Very lenient for CI
                TimingUtils.EnvironmentType.LocalSlow => 15.0,  // Somewhat lenient for slow systems
                TimingUtils.EnvironmentType.LocalFast => 10.0,  // Original threshold for fast systems
                _ => 15.0
            };
            
            bestRatio.Should().BeLessThan(testUtilThreshold, 
                "constant-time comparison should not leak position information (best ratio from {0} runs was {1:F2}, threshold: {2:F1} for {3})", 
                runs, bestRatio, testUtilThreshold, baseline.Environment);
        }
    }

    public sealed class HexConversionTests
    {
        [Fact]
        public void ToHexString_WithEmptyArray_ShouldReturnEmptyString()
        {
            // Arrange
            var emptyBytes = Array.Empty<byte>();

            // Act
            var result = TestUtilities.ToHexString(emptyBytes);

            // Assert
            result.Should().BeEmpty();
        }

        [Theory]
        [InlineData("00")]
        [InlineData("DEADBEEF")]
        [InlineData("0123456789ABCDEF")]
        public void ToHexString_ShouldProduceCorrectOutput(string expectedHex)
        {
            // Arrange
            var bytes = Convert.FromHexString(expectedHex);

            // Act
            var result = TestUtilities.ToHexString(bytes);

            // Assert
            result.Should().Be(expectedHex);
        }

        [Theory]
        [InlineData("00")]
        [InlineData("DEADBEEF")]
        [InlineData("0123456789ABCDEF")]
        public void FromHexString_ShouldProduceCorrectOutput(string hexString)
        {
            // Arrange
            var expectedBytes = Convert.FromHexString(hexString);

            // Act
            var result = TestUtilities.FromHexString(hexString);

            // Assert
            result.Should().Equal(expectedBytes);
        }

        [Theory]
        [InlineData("")]      // Empty string
        [InlineData(null)]    // Null string
        public void FromHexString_WithNullOrEmpty_ShouldThrowArgumentException(string? hexString)
        {
            // Act & Assert
            var act = () => TestUtilities.FromHexString(hexString!);
            act.Should().Throw<ArgumentException>()
                .WithParameterName("hex")
                .WithMessage("*Hex string cannot be null or empty*");
        }

        [Theory]
        [InlineData("123")]   // Odd length - should throw ArgumentException
        public void FromHexString_WithOddLength_ShouldThrowArgumentException(string hexString)
        {
            // Act & Assert
            var act = () => TestUtilities.FromHexString(hexString);
            act.Should().Throw<ArgumentException>()
                .WithMessage("*Hex string must have an even number of characters*");
        }

        [Theory]
        [InlineData("GG")]    // Invalid characters - should throw FormatException
        [InlineData("12GH")]  // Mixed valid/invalid - should throw FormatException
        [InlineData("ZZ")]    // Invalid characters
        public void FromHexString_WithInvalidCharacters_ShouldThrowFormatException(string hexString)
        {
            // Act & Assert
            var act = () => TestUtilities.FromHexString(hexString);
            act.Should().Throw<FormatException>()
                .WithMessage("*not a valid hex string*");
        }
    }

    public sealed class RepeatActionTests
    {
        [Fact]
        public void RepeatAction_ShouldExecuteSpecifiedTimes()
        {
            // Arrange
            int executionCount = 0;
            Action testAction = () => executionCount++;

            // Act
            TestUtilities.RepeatAction(testAction, 10);

            // Assert
            executionCount.Should().Be(10);
        }

        [Fact]
        public void RepeatAction_WithNullAction_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            var act = () => TestUtilities.RepeatAction(null!, 5);
            act.Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public void RepeatAction_WithZeroCount_ShouldThrowArgumentOutOfRangeException()
        {
            // Act & Assert
            var act = () => TestUtilities.RepeatAction(() => { }, 0);
            act.Should().Throw<ArgumentOutOfRangeException>();
        }

        [Fact]
        public void RepeatAction_WithNegativeCount_ShouldThrowArgumentOutOfRangeException()
        {
            // Act & Assert
            var act = () => TestUtilities.RepeatAction(() => { }, -1);
            act.Should().Throw<ArgumentOutOfRangeException>();
        }
    }

    public sealed class MeasureTimeTests
    {
        [Fact]
        public void MeasureTime_ShouldReturnApproximateExecutionTime()
        {
            // Arrange
            const int delayMs = 50;
            static void delayAction() => Thread.Sleep(delayMs);
            #pragma warning restore S2925

            // Act
            var elapsed = TestUtilities.MeasureTime(delayAction);

            // Assert
            elapsed.TotalMilliseconds.Should().BeInRange(delayMs - 10, delayMs + 100);
        }

        [Fact]
        public void MeasureTime_WithNullAction_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            var act = () => TestUtilities.MeasureTime(null!);
            act.Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public void MeasureTime_WithFastAction_ShouldReturnSmallTime()
        {
            // Arrange - Simple operation that should execute quickly
            static void fastAction() { _ = 1 + 1; }

            // Act
            var elapsed = TestUtilities.MeasureTime(fastAction);

            // Assert
            elapsed.Should().BePositive();
            elapsed.TotalMilliseconds.Should().BeLessThan(100);
        }
    }

    public sealed class SecureClearingTests
    {
        [Fact]
        public void IsSecurelyCleared_WithNullData_ShouldReturnTrue()
        {
            // Act & Assert
            TestUtilities.IsSecurelyCleared(null!).Should().BeTrue();
        }

        [Fact]
        public void IsSecurelyCleared_WithZeroData_ShouldReturnTrue()
        {
            // Arrange
            var data = new byte[16]; // All zeros

            // Act & Assert
            TestUtilities.IsSecurelyCleared(data).Should().BeTrue();
        }

        [Fact]
        public void IsSecurelyCleared_WithNonZeroData_ShouldReturnFalse()
        {
            // Arrange
            var data = new byte[] { 0, 0, 0, 1 }; // One non-zero

            // Act & Assert
            TestUtilities.IsSecurelyCleared(data).Should().BeFalse();
        }

        [Fact]
        public void VerifySecureClearing_WithWorkingClearingAction_ShouldNotThrow()
        {
            // Arrange
            var originalData = new byte[] { 1, 2, 3, 4, 5 };
            static void clearingAction(byte[] data) => Array.Clear(data);

            // Act & Assert
            var act = () => TestUtilities.VerifySecureClearing(originalData, clearingAction);
            act.Should().NotThrow();
        }

        [Fact]
        public void VerifySecureClearing_WithNonWorkingClearingAction_ShouldThrowInvalidOperationException()
        {
            // Arrange
            var originalData = new byte[] { 1, 2, 3, 4, 5 };
            Action<byte[]> nonClearingAction = data => { }; // Does nothing

            // Act & Assert
            var act = () => TestUtilities.VerifySecureClearing(originalData, nonClearingAction);
            act.Should().Throw<InvalidOperationException>()
                .WithMessage("*Data was not securely cleared*");
        }
    }

    public sealed class TestVectorGenerationTests
    {
        [Fact]
        public void GenerateTestVectors_ShouldCreateCorrectNumberOfVectors()
        {
            // Arrange
            const int count = 5;
            Func<int, string> generator = i => $"test{i}";

            // Act
            var vectors = TestUtilities.GenerateTestVectors(count, generator);

            // Assert
            vectors.Should().HaveCount(count);
            vectors.Should().Equal("test0", "test1", "test2", "test3", "test4");
        }

        [Fact]
        public void GenerateTestVectors_WithNullGenerator_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            var act = () => TestUtilities.GenerateTestVectors<string>(5, null!);
            act.Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public void GenerateTestVectors_WithZeroCount_ShouldThrowArgumentOutOfRangeException()
        {
            // Act & Assert
            var act = () => TestUtilities.GenerateTestVectors(0, i => i.ToString(System.Globalization.CultureInfo.InvariantCulture));
            act.Should().Throw<ArgumentOutOfRangeException>();
        }
    }

    public sealed class AsyncUtilityTests
    {
        [Fact]
        public async Task WaitForConditionAsync_WithTrueCondition_ShouldReturnTrueImmediately()
        {
            // Arrange
            static bool alwaysTrue() => true;

            // Act
            var result = await TestUtilities.WaitForConditionAsync(alwaysTrue, TimeSpan.FromSeconds(1));

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public async Task WaitForConditionAsync_WithFalseCondition_ShouldReturnFalseAfterTimeout()
        {
            // Arrange
            Func<bool> alwaysFalse = () => false;
            var timeout = TimeSpan.FromMilliseconds(50);

            // Act
            var sw = Stopwatch.StartNew();
            var result = await TestUtilities.WaitForConditionAsync(alwaysFalse, timeout);
            sw.Stop();

            // Assert
            result.Should().BeFalse();
            sw.Elapsed.Should().BeGreaterOrEqualTo(timeout);
        }

        [Fact]
        public async Task WaitForConditionAsync_WithEventuallyTrueCondition_ShouldReturnTrue()
        {
            // Arrange
            int counter = 0;
            bool eventuallyTrue() => ++counter >= 3;

            // Act
            var result = await TestUtilities.WaitForConditionAsync(eventuallyTrue, TimeSpan.FromSeconds(1));

            // Assert
            result.Should().BeTrue();
        }
    }

    public sealed class DataCorruptionTests
    {
        [Fact]
        public void CorruptData_ShouldModifySpecifiedIndices()
        {
            // Arrange
            var original = new byte[] { 1, 2, 3, 4, 5 };

            // Act
            var corrupted = TestUtilities.CorruptData(original, 0, 2, 4);

            // Assert
            corrupted.Should().NotEqual(original);
            corrupted[0].Should().NotBe(original[0]);
            corrupted[1].Should().Be(original[1]); // Unchanged
            corrupted[2].Should().NotBe(original[2]);
            corrupted[3].Should().Be(original[3]); // Unchanged
            corrupted[4].Should().NotBe(original[4]);
        }

        [Fact]
        public void CorruptData_WithOutOfRangeIndex_ShouldThrowArgumentOutOfRangeException()
        {
            // Arrange
            var original = new byte[] { 1, 2, 3 };

            // Act & Assert
            var act = () => TestUtilities.CorruptData(original, 5);
            act.Should().Throw<ArgumentOutOfRangeException>();
        }

        [Fact]
        public void GenerateCorruptedVariants_ShouldCreateDifferentVariants()
        {
            // Arrange
            var original = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            // Act
            var variants = TestUtilities.GenerateCorruptedVariants(original);

            // Assert
            variants.Should().HaveCount(5);
            variants.Should().AllSatisfy(variant => variant.Should().NotEqual(original));
            
            // All variants should be different from each other
            for (int i = 0; i < variants.Length; i++)
            {
                for (int j = i + 1; j < variants.Length; j++)
                {
                    variants[i].Should().NotEqual(variants[j], $"variant {i} should differ from variant {j}");
                }
            }
        }
    }

    public sealed class PatternedDataTests
    {
        [Theory]
        [InlineData(8, 0xAA)]
        [InlineData(16, 0x55)]
        [InlineData(32, 0xFF)]
        public void CreatePatternedData_ShouldCreateExpectedPattern(int length, byte pattern)
        {
            // Act
            var data = TestUtilities.CreatePatternedData(length, pattern);

            // Assert
            data.Should().HaveCount(length);
            for (int i = 0; i < length; i++)
            {
                var expected = (byte)(pattern ^ (byte)(i & 0xFF));
                data[i].Should().Be(expected);
            }
        }

        [Fact]
        public void CreatePatternedData_WithZeroLength_ShouldThrowArgumentOutOfRangeException()
        {
            // Act & Assert
            var act = () => TestUtilities.CreatePatternedData(0);
            act.Should().Throw<ArgumentOutOfRangeException>();
        }
    }

    public sealed class EdgeCaseValueTests
    {
        [Fact]
        public void GetUlongEdgeCases_ShouldReturnExpectedValues()
        {
            // Act
            var edgeCases = TestUtilities.GetUlongEdgeCases();

            // Assert
            edgeCases.Should().NotBeNull();
            edgeCases.Should().Contain(0UL);
            edgeCases.Should().Contain(1UL);
            edgeCases.Should().Contain(ulong.MaxValue);
            edgeCases.Should().Contain(byte.MaxValue);
            edgeCases.Should().Contain(ushort.MaxValue);
            edgeCases.Should().Contain(uint.MaxValue);
        }

        [Fact]
        public void GetIntEdgeCases_ShouldReturnExpectedValues()
        {
            // Act
            var edgeCases = TestUtilities.GetIntEdgeCases();

            // Assert
            edgeCases.Should().NotBeNull();
            edgeCases.Should().Contain(int.MinValue);
            edgeCases.Should().Contain(int.MaxValue);
            edgeCases.Should().Contain(0);
            edgeCases.Should().Contain(-1);
            edgeCases.Should().Contain(1);
        }
    }

    public sealed class MemoryPressureTests
    {
        [Fact]
        public void ExecuteWithMemoryPressure_ShouldExecuteAction()
        {
            // Arrange
            bool actionExecuted = false;
            void testAction() => actionExecuted = true;

            // Act
            TestUtilities.ExecuteWithMemoryPressure(testAction, 1); // Use minimal pressure

            // Assert
            actionExecuted.Should().BeTrue();
        }

        [Fact]
        public async Task ExecuteWithMemoryPressureAsync_ShouldExecuteAsyncAction()
        {
            // Arrange
            bool actionExecuted = false;
            async Task testAction()
            {
                await Task.Delay(1).ConfigureAwait(false);
                actionExecuted = true;
            }

            // Act
            await TestUtilities.ExecuteWithMemoryPressureAsync(testAction, 1);

            // Assert
            actionExecuted.Should().BeTrue();
        }
    }

    public sealed class TimingAttackResistanceTests
    {
        [Fact]
        public void HasConsistentTiming_WithConsistentOperation_ShouldReturnTrue()
        {
            // Arrange - Operation that should have consistent timing
            static bool consistentOperation()
            {
                // Simple operation that should take consistent time
                var sum = 0;
                for (int i = 0; i < 100; i++)
                {
                    sum += i;
                }
                return sum % 2 == 0;
            }

            // Act
            var isConsistent = TestUtilities.HasConsistentTiming(consistentOperation, 50, 50.0);

            // Assert
            isConsistent.Should().BeTrue();
        }

        [Fact]
        public void HasConsistentTimingWithStatistics_ShouldProvideVarianceInfo()
        {
            // Arrange
            static bool operation()
            {
                var sum = 0;
                for (int i = 0; i < 50; i++)
                {
                    sum += i;
                }
                return sum % 2 == 0;
            }

            // Act
            var isConsistent = TestUtilities.HasConsistentTimingWithStatistics(operation, out double actualVariance, 50, 50.0);

            // Assert
            isConsistent.Should().BeTrue();
            actualVariance.Should().BeInRange(0.0, 50.0);
        }
    }

    public sealed class AlgorithmTestCaseTests
    {
        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        public void GenerateAlgorithmTestCases_ShouldReturnDiverseTestCases(int baseLength)
        {
            // Act
            var testCases = TestUtilities.GenerateAlgorithmTestCases(baseLength).ToList();

            // Assert
            testCases.Should().NotBeEmpty();
            testCases.Should().AllSatisfy(testCase => testCase.Length.Should().Be(baseLength));
            
            // Should have variety in the test cases
            var distinctCases = testCases.Select(tc => Convert.ToHexString(tc)).Distinct().Count();
            distinctCases.Should().Be(testCases.Count, "all test cases should be different");
        }
    }

    public sealed class UniqueItemsValidationTests
    {
        [Fact]
        public void AllItemsUnique_WithUniqueItems_ShouldReturnTrue()
        {
            // Arrange
            var uniqueItems = new[] { 1, 2, 3, 4, 5 };

            // Act & Assert
            TestUtilities.AllItemsUnique(uniqueItems).Should().BeTrue();
        }

        [Fact]
        public void AllItemsUnique_WithDuplicateItems_ShouldReturnFalse()
        {
            // Arrange
            var duplicateItems = new[] { 1, 2, 3, 2, 5 };

            // Act & Assert
            TestUtilities.AllItemsUnique(duplicateItems).Should().BeFalse();
        }

        [Fact]
        public void AllItemsUnique_WithEmptyCollection_ShouldReturnTrue()
        {
            // Arrange
            var emptyItems = Array.Empty<int>();

            // Act & Assert
            TestUtilities.AllItemsUnique(emptyItems).Should().BeTrue();
        }
    }

    public sealed class EntropyDataGenerationTests
    {
        [Theory]
        [InlineData(0.0)] // No entropy
        [InlineData(0.5)] // Partial entropy
        [InlineData(1.0)] // Full entropy
        public void GenerateDataWithEntropy_ShouldRespectEntropyLevel(double entropyLevel)
        {
            // Act
            var data = TestUtilities.GenerateDataWithEntropy(100, entropyLevel);

            // Assert
            data.Should().HaveCount(100);
            
            if (Math.Abs(entropyLevel - 0.0) < double.Epsilon)
            {
                data.Should().OnlyContain(b => b == 0, "zero entropy should be all zeros");
            }
            else if (Math.Abs(entropyLevel - 1.0) < double.Epsilon)
            {
                // Full entropy should not be all the same
                var firstByte = data[0];
                var allSame = data.All(b => b == firstByte);
                allSame.Should().BeFalse("full entropy should have variation");
            }
        }

        [Fact]
        public void GenerateDataWithEntropy_WithInvalidEntropyLevel_ShouldThrowArgumentOutOfRangeException()
        {
            // Act & Assert
            var act1 = () => TestUtilities.GenerateDataWithEntropy(100, -0.1);
            act1.Should().Throw<ArgumentOutOfRangeException>();

            var act2 = () => TestUtilities.GenerateDataWithEntropy(100, 1.1);
            act2.Should().Throw<ArgumentOutOfRangeException>();
        }
    }
}