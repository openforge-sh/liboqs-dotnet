using System.Diagnostics;
using System.Runtime.InteropServices;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Core;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.KEM.Tests;

[Collection("LibOqs Collection")]
public sealed class PerformanceTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void KeyGeneration_Performance_ShouldBeReasonable()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var testAlgorithms = new[]
        {
            KemAlgorithms.ML_KEM_512,
            KemAlgorithms.ML_KEM_768,
            KemAlgorithms.ML_KEM_1024,
            KemAlgorithms.Kyber512,
            KemAlgorithms.Kyber768
        }.Where(alg => Kem.IsAlgorithmSupported(alg)).ToArray();

        testAlgorithms.Should().NotBeEmpty("At least one test algorithm should be supported");

        foreach (var algorithm in testAlgorithms)
        {
            using var kem = new Kem(algorithm);

            var averageMs = PerformanceTestUtilities.MeasureOperationPerformance(
                () => kem.GenerateKeyPair(),
                100);

            // Use adaptive timing validation instead of hardcoded thresholds
            TimingUtils.ValidatePerformance(
                new TimingResult 
                { 
                    MeanMs = averageMs, 
                    MedianMs = averageMs, 
                    Percentile95Ms = averageMs,
                    StandardDeviationMs = 0,
                    MinMs = averageMs,
                    MaxMs = averageMs,
                    SampleCount = 100,
                    OriginalSampleCount = 100,
                    UsePercentile = false,
                    Environment = TimingUtils.GetSystemBaseline().Environment,
                    PerformanceMultiplier = TimingUtils.GetSystemBaseline().PerformanceMultiplier
                },
                $"{algorithm} key generation", 50.0);
        }
    }

    [Fact]
    public void Encapsulation_Performance_ShouldBeReasonable()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var candidateAlgorithms = new[]
        {
            KemAlgorithms.ML_KEM_512,
            KemAlgorithms.Kyber512,
            KemAlgorithms.BIKE_L1
        };

        // Filter out BIKE algorithms on Windows and macOS as they are not supported
        var testAlgorithms = (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            ? candidateAlgorithms.Where(a => !a.Contains("BIKE", StringComparison.OrdinalIgnoreCase)).Where(Kem.IsAlgorithmSupported).ToArray()
            : candidateAlgorithms.Where(Kem.IsAlgorithmSupported).ToArray();

        testAlgorithms.Should().NotBeEmpty("At least one test algorithm should be supported");

        foreach (var algorithm in testAlgorithms)
        {
            using var kem = new Kem(algorithm);
            var (publicKey, _) = kem.GenerateKeyPair();

            var averageMs = PerformanceTestUtilities.MeasureOperationPerformance(
                () => kem.Encapsulate(publicKey),
                1000);

            // Use adaptive timing validation
            TimingUtils.ValidatePerformance(
                new TimingResult 
                { 
                    MeanMs = averageMs, 
                    MedianMs = averageMs, 
                    Percentile95Ms = averageMs,
                    StandardDeviationMs = 0,
                    MinMs = averageMs,
                    MaxMs = averageMs,
                    SampleCount = 1000,
                    OriginalSampleCount = 1000,
                    UsePercentile = false,
                    Environment = TimingUtils.GetSystemBaseline().Environment,
                    PerformanceMultiplier = TimingUtils.GetSystemBaseline().PerformanceMultiplier
                },
                $"{algorithm} encapsulation", 10.0);
        }
    }

    [Fact]
    public void Decapsulation_Performance_ShouldBeReasonable()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var testAlgorithms = new[]
        {
            KemAlgorithms.ML_KEM_512,
            KemAlgorithms.Kyber512,
            KemAlgorithms.HQC_128
        }.Where(Kem.IsAlgorithmSupported).ToArray();

        testAlgorithms.Should().NotBeEmpty("At least one test algorithm should be supported");

        foreach (var algorithm in testAlgorithms)
        {
            using var kem = new Kem(algorithm);
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            var (ciphertext, _) = kem.Encapsulate(publicKey);

            var averageMs = PerformanceTestUtilities.MeasureOperationPerformance(
                () => kem.Decapsulate(ciphertext, secretKey),
                1000);

            // Use adaptive timing validation
            TimingUtils.ValidatePerformance(
                new TimingResult 
                { 
                    MeanMs = averageMs, 
                    MedianMs = averageMs, 
                    Percentile95Ms = averageMs,
                    StandardDeviationMs = 0,
                    MinMs = averageMs,
                    MaxMs = averageMs,
                    SampleCount = 1000,
                    OriginalSampleCount = 1000,
                    UsePercentile = false,
                    Environment = TimingUtils.GetSystemBaseline().Environment,
                    PerformanceMultiplier = TimingUtils.GetSystemBaseline().PerformanceMultiplier
                },
                $"{algorithm} decapsulation", 10.0);
        }
    }

    [Fact]
    public void FullKemCycle_Performance_Comparison()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            // Compare performance across different algorithm families
            var algorithmFamilies = new Dictionary<string, string[]>
            {
                ["ML-KEM"] = [KemAlgorithms.ML_KEM_512, KemAlgorithms.ML_KEM_768, KemAlgorithms.ML_KEM_1024],
                ["Kyber"] = [KemAlgorithms.Kyber512, KemAlgorithms.Kyber768, KemAlgorithms.Kyber1024],
                ["HQC"] = [KemAlgorithms.HQC_128, KemAlgorithms.HQC_192, KemAlgorithms.HQC_256]
            };

        // Add BIKE algorithms only on Linux (disabled on Windows and macOS)
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            algorithmFamilies["BIKE"] = [KemAlgorithms.BIKE_L1, KemAlgorithms.BIKE_L3, KemAlgorithms.BIKE_L5];
        }

        var performanceResults = new List<(string algorithm, double keyGenMs, double encapMs, double decapMs)>();

        foreach (var (_, algorithms) in algorithmFamilies)
        {
            foreach (var algorithm in algorithms)
            {
                if (!Kem.IsAlgorithmSupported(algorithm))
                    continue;

                using var kem = new Kem(algorithm);

                // Warm-up
                var (warmupPub, warmupSec) = kem.GenerateKeyPair();
                var (warmupCt, _) = kem.Encapsulate(warmupPub);
                _ = kem.Decapsulate(warmupCt, warmupSec);

                const int iterations = 100;

                // Measure key generation
                var keyGenStopwatch = Stopwatch.StartNew();
                for (int i = 0; i < iterations; i++)
                {
                    _ = kem.GenerateKeyPair();
                }
                keyGenStopwatch.Stop();
                var keyGenMs = keyGenStopwatch.ElapsedMilliseconds / (double)iterations;

                // Measure encapsulation
                var (publicKey, secretKey) = kem.GenerateKeyPair();
                var encapStopwatch = Stopwatch.StartNew();
                for (int i = 0; i < iterations; i++)
                {
                    _ = kem.Encapsulate(publicKey);
                }
                encapStopwatch.Stop();
                var encapMs = encapStopwatch.ElapsedMilliseconds / (double)iterations;

                // Measure decapsulation
                var (ciphertext, _) = kem.Encapsulate(publicKey);
                var decapStopwatch = Stopwatch.StartNew();
                for (int i = 0; i < iterations; i++)
                {
                    _ = kem.Decapsulate(ciphertext, secretKey);
                }
                decapStopwatch.Stop();
                var decapMs = decapStopwatch.ElapsedMilliseconds / (double)iterations;

                performanceResults.Add((algorithm, keyGenMs, encapMs, decapMs));

                // Use environment-aware validation with algorithm-specific thresholds
                var isBike = algorithm.Contains("BIKE", StringComparison.Ordinal);
                var isHqc = algorithm.Contains("HQC", StringComparison.Ordinal);
                
                // BIKE and HQC algorithms are significantly slower than ML-KEM/Kyber
                // For regular algorithms, use the standard validation, but for BIKE/HQC treat as SPHINCS+ level
                PerformanceTestUtilities.ValidateAlgorithmPerformance(
                    algorithm, keyGenMs, encapMs, decapMs, isBike || isHqc);
            }
        }

            performanceResults.Should().NotBeEmpty("At least one algorithm should be tested");
        });
    }

    [Fact]
    public void MemoryAllocation_Performance()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            var algorithm = algorithms[0];
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {

        // Measure memory before operations
        #pragma warning disable S1215
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var memoryBefore = GC.GetTotalMemory(false);

        const int iterations = 100;

        using (var kem = new Kem(algorithm))
        {
            for (int i = 0; i < iterations; i++)
            {
                var (publicKey, secretKey) = kem.GenerateKeyPair();
                var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
                var recovered = kem.Decapsulate(ciphertext, secretKey);

                recovered.Should().BeEquivalentTo(sharedSecret);
            }
        }

        // Force garbage collection
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var memoryAfter = GC.GetTotalMemory(false);
        #pragma warning restore S1215

        var memoryUsed = memoryAfter - memoryBefore;
        var memoryPerOperation = memoryUsed / iterations;

                // Memory usage should be reasonable (less than 1MB per operation on average)
                memoryPerOperation.Should().BeLessThan(1024 * 1024,
                    "Average memory usage per KEM operation should be reasonable");
            });
        });
    }

    [Fact]
    public void Throughput_Test()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        // Test throughput for a fast algorithm
        var fastAlgorithms = new[] { KemAlgorithms.Kyber512, KemAlgorithms.ML_KEM_512 }
            .Where(Kem.IsAlgorithmSupported)
            .ToArray();

        fastAlgorithms.Should().NotBeEmpty("At least one fast algorithm should be supported");

        var algorithm = fastAlgorithms[0];
        using var kem = new Kem(algorithm);

        var (publicKey, secretKey) = kem.GenerateKeyPair();

        // Measure how many operations can be done in 1 second
        var stopwatch = Stopwatch.StartNew();
        var operationCount = 0;
        const int targetMilliseconds = 1000;

        while (stopwatch.ElapsedMilliseconds < targetMilliseconds)
        {
            var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
            var recovered = kem.Decapsulate(ciphertext, secretKey);
            recovered.Should().BeEquivalentTo(sharedSecret);
            operationCount++;
        }

        stopwatch.Stop();

        var throughput = operationCount * 1000.0 / stopwatch.ElapsedMilliseconds;

        // Use adaptive throughput threshold based on environment
        var expectedMinThroughput = PerformanceTestUtilities.Configuration.MinThroughputOpsPerSecond;
        throughput.Should().BeGreaterThan(expectedMinThroughput,
            $"{algorithm} should achieve reasonable throughput (expected: {expectedMinThroughput:F1} ops/sec)");
    }

    [Fact]
    public void ParallelPerformance_Test()
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            var algorithm = algorithms[0];

        // Sequential performance
        var sequentialStopwatch = Stopwatch.StartNew();
        const int totalOperations = 100;

        using (var kem = new Kem(algorithm))
        {
            for (int i = 0; i < totalOperations; i++)
            {
                var (publicKey, secretKey) = kem.GenerateKeyPair();
                var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
                var recovered = kem.Decapsulate(ciphertext, secretKey);
                recovered.Should().BeEquivalentTo(sharedSecret);
            }
        }

        sequentialStopwatch.Stop();
        var sequentialTime = sequentialStopwatch.ElapsedMilliseconds;

        // Parallel performance
        var parallelStopwatch = Stopwatch.StartNew();
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken = TestContext.Current.CancellationToken
        };

        Parallel.For(0, totalOperations, parallelOptions, i =>
        {
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {
                using var kem = new Kem(algorithm);
                var (publicKey, secretKey) = kem.GenerateKeyPair();
                var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
                var recovered = kem.Decapsulate(ciphertext, secretKey);
                recovered.Should().BeEquivalentTo(sharedSecret);
            });
        });

        parallelStopwatch.Stop();
        var parallelTime = parallelStopwatch.ElapsedMilliseconds;

        var speedup = (double)sequentialTime / parallelTime;

        // LibOQS operations are single-threaded, but running multiple independent operations
        // in parallel can still provide speedup by utilizing multiple CPU cores.
        // The speedup depends on the system's CPU architecture and current load.
        if (Environment.ProcessorCount > 1)
        {
            // Allow a wide range of performance outcomes:
            // - Parallel can be slower (0.3x) due to overhead and contention
            // - Parallel can be faster (up to ProcessorCount) when operations run on separate cores
            var maxRealisticSpeedup = Math.Min(Environment.ProcessorCount, 8.0); // Cap at 8x for sanity
            
            speedup.Should().BeGreaterThan(0.3,
                "Parallel execution should complete without severe degradation");
            speedup.Should().BeLessThanOrEqualTo(maxRealisticSpeedup,
                $"Speedup should not exceed processor count ({Environment.ProcessorCount} cores)");
            
            // Note: The actual speedup varies greatly depending on:
            // - CPU architecture (cache sizes, NUMA topology)
            // - System load and scheduling
            // - Algorithm complexity and memory access patterns
            }
        });
    }

    [Theory]
    [InlineData(10)]
    [InlineData(100)]
    [InlineData(1000)]
    public void ScalabilityTest_DifferentLoadLevels(int operationCount)
    {
        TestExecutionHelpers.ExecuteWithLargeStack(() =>
        {
            var algorithms = Kem.GetSupportedAlgorithms();
            algorithms.Should().NotBeEmpty();

            var algorithm = algorithms[0];
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {
                using var kem = new Kem(algorithm);

                var (publicKey, secretKey) = kem.GenerateKeyPair();

        var stopwatch = Stopwatch.StartNew();
        var successCount = 0;

        for (int i = 0; i < operationCount; i++)
        {
            var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
            var recovered = kem.Decapsulate(ciphertext, secretKey);

            if (recovered.SequenceEqual(sharedSecret))
            {
                successCount++;
            }
        }

        stopwatch.Stop();

        var averageMs = stopwatch.ElapsedMilliseconds / (double)operationCount;

        // All operations should succeed
        successCount.Should().Be(operationCount, "All operations should complete successfully");

                // Average time should remain relatively stable across load levels
                averageMs.Should().BeLessThan(50, "Average operation time should remain reasonable under load");
            });
        });
    }

    [Fact]
    public void NISTStandardizedAlgorithms_PerformanceComparison()
    {
        var nistAlgorithms = KemAlgorithms.NISTStandardized
            .Where(Kem.IsAlgorithmSupported)
            .ToArray();

        var results = new Dictionary<string, (double keyGen, double encap, double decap)>();

        foreach (var algorithm in nistAlgorithms)
        {
            using var kem = new Kem(algorithm);

            // Warm-up
            var (warmupPub, warmupSec) = kem.GenerateKeyPair();
            var (warmupCt, _) = kem.Encapsulate(warmupPub);
            _ = kem.Decapsulate(warmupCt, warmupSec);

            const int iterations = 50;

            // Key generation
            var keyGenStopwatch = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                _ = kem.GenerateKeyPair();
            }
            keyGenStopwatch.Stop();

            // Encapsulation
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            var encapStopwatch = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                _ = kem.Encapsulate(publicKey);
            }
            encapStopwatch.Stop();

            // Decapsulation
            var (ciphertext, _) = kem.Encapsulate(publicKey);
            var decapStopwatch = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                _ = kem.Decapsulate(ciphertext, secretKey);
            }
            decapStopwatch.Stop();

            var keyGenMs = keyGenStopwatch.ElapsedMilliseconds / (double)iterations;
            var encapMs = encapStopwatch.ElapsedMilliseconds / (double)iterations;
            var decapMs = decapStopwatch.ElapsedMilliseconds / (double)iterations;

            results[algorithm] = (keyGenMs, encapMs, decapMs);
        }

        foreach (var (algorithm, (keyGen, encap, decap)) in results)
        {
            // NIST standardized algorithms should have reasonable performance
            keyGen.Should().BeLessThan(100, $"{algorithm} key generation should be fast");
            encap.Should().BeLessThan(50, $"{algorithm} encapsulation should be fast");
            decap.Should().BeLessThan(50, $"{algorithm} decapsulation should be fast");
        }
    }

    [Fact]
    public void OptimizedParallelThroughput_Test()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms.FirstOrDefault(a => Kem.IsAlgorithmSupported(a) && 
            (a == KemAlgorithms.ML_KEM_512 || a == KemAlgorithms.Kyber512)) ?? algorithms[0];

        const int totalOperations = 1000;
        const int warmupOps = 100;

        // Warmup to ensure CPU caches are populated and JIT compilation is complete
        Parallel.For(0, warmupOps, new ParallelOptions 
        { 
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken = TestContext.Current.CancellationToken
        }, i =>
        {
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {
                using var kem = new Kem(algorithm);
                var (pk, sk) = kem.GenerateKeyPair();
                var (ct, _) = kem.Encapsulate(pk);
                _ = kem.Decapsulate(ct, sk);
            });
        });

        var sw = Stopwatch.StartNew();
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken = TestContext.Current.CancellationToken
        };

        Parallel.For(0, totalOperations, parallelOptions, i =>
        {
            TestExecutionHelpers.ConditionallyExecuteWithLargeStack(algorithm, () =>
            {
                using var kem = new Kem(algorithm);
                var (publicKey, secretKey) = kem.GenerateKeyPair();
                var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
                var recovered = kem.Decapsulate(ciphertext, secretKey);
                recovered.Should().BeEquivalentTo(sharedSecret);
            });
        });

        sw.Stop();

        var throughput = totalOperations * 1000.0 / sw.ElapsedMilliseconds;
        var expectedMinThroughput = Math.Max(100, Environment.ProcessorCount * 50); // At least 50 ops/sec per core

        throughput.Should().BeGreaterThan(expectedMinThroughput,
            $"Optimized parallel throughput should achieve at least {expectedMinThroughput} ops/sec " +
            $"(was {throughput:F1} ops/sec with {Environment.ProcessorCount} threads available)");
    }

#pragma warning restore S1144
}