using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Core;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.SIG.Tests;

[Collection("LibOqs Collection")]
public sealed class PerformanceTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void KeyGeneration_Performance_ShouldBeReasonable()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var testAlgorithms = new[]
        {
            SignatureAlgorithms.ML_DSA_44,
            SignatureAlgorithms.ML_DSA_65,
            SignatureAlgorithms.ML_DSA_87,
            SignatureAlgorithms.Dilithium2,
            SignatureAlgorithms.Dilithium3,
            SignatureAlgorithms.Falcon_512
        }.Where(Sig.IsAlgorithmSupported).ToArray();

        testAlgorithms.Should().NotBeEmpty("At least one test algorithm should be supported");

        foreach (var algorithm in testAlgorithms)
        {
            using var sig = new Sig(algorithm);

            var averageMs = PerformanceTestUtilities.MeasureOperationPerformance(
                () => sig.GenerateKeyPair(),
                50);

                TimingUtils.ValidatePerformance(
                new TimingResult
                {
                    MeanMs = averageMs,
                    MedianMs = averageMs,
                    Percentile95Ms = averageMs,
                    StandardDeviationMs = 0,
                    MinMs = averageMs,
                    MaxMs = averageMs,
                    SampleCount = 50,
                    OriginalSampleCount = 50,
                    UsePercentile = false,
                    Environment = TimingUtils.GetSystemBaseline().Environment,
                    PerformanceMultiplier = TimingUtils.GetSystemBaseline().PerformanceMultiplier
                },
                $"{algorithm} key generation", 100.0);
        }
    }

    [Fact]
    public void Signing_Performance_ShouldBeReasonable()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        // Test a subset of algorithms
        var candidateAlgorithms = new[]
        {
            SignatureAlgorithms.ML_DSA_44,
            SignatureAlgorithms.Dilithium2,
            SignatureAlgorithms.Falcon_512,
            SignatureAlgorithms.SPHINCS_PLUS_SHA2_128s_simple
        };

        // Temporarily exclude SPHINCS+ on Windows and macOS due to stack overflow issues
        var testAlgorithms = candidateAlgorithms
            .Where(a => {
                if ((RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) 
                    && a.Contains("SPHINCS", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
                return Sig.IsAlgorithmSupported(a);
            })
            .ToArray();

        testAlgorithms.Should().NotBeEmpty("At least one test algorithm should be supported");

        foreach (var algorithm in testAlgorithms)
        {
            using var sig = new Sig(algorithm);
            var (_, secretKey) = sig.GenerateKeyPair();

            var message = new byte[1024];
            RandomNumberGenerator.Fill(message);

            var averageMs = PerformanceTestUtilities.MeasureOperationPerformance(
                () => sig.Sign(message, secretKey),
                500);

            var isSphincsPlus = algorithm.Contains("SPHINCS", StringComparison.Ordinal);
            // SPHINCS+ algorithms are significantly slower, especially in CI environments
            var threshold = isSphincsPlus ? 500.0 : 100.0;

            TimingUtils.ValidatePerformance(
                new TimingResult
                {
                    MeanMs = averageMs,
                    MedianMs = averageMs,
                    Percentile95Ms = averageMs,
                    StandardDeviationMs = 0,
                    MinMs = averageMs,
                    MaxMs = averageMs,
                    SampleCount = 500,
                    OriginalSampleCount = 500,
                    UsePercentile = false,
                    Environment = TimingUtils.GetSystemBaseline().Environment,
                    PerformanceMultiplier = TimingUtils.GetSystemBaseline().PerformanceMultiplier
                },
                $"{algorithm} signing", threshold);
        }
    }

    [Fact]
    public void Verification_Performance_ShouldBeReasonable()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        // Test a subset of algorithms
        var testAlgorithms = new[]
        {
            SignatureAlgorithms.ML_DSA_44,
            SignatureAlgorithms.Dilithium2,
            SignatureAlgorithms.Falcon_512,
            SignatureAlgorithms.MAYO_1
        }.Where(Sig.IsAlgorithmSupported).ToArray();

        testAlgorithms.Should().NotBeEmpty("At least one test algorithm should be supported");

        foreach (var algorithm in testAlgorithms)
        {
            using var sig = new Sig(algorithm);
            var (publicKey, secretKey) = sig.GenerateKeyPair();

            var message = new byte[1024];
            RandomNumberGenerator.Fill(message);
            var signature = sig.Sign(message, secretKey);

            // Warm-up
            _ = sig.Verify(message, signature, publicKey);

            const int iterations = 1000;
            var stopwatch = Stopwatch.StartNew();

            for (int i = 0; i < iterations; i++)
            {
                _ = sig.Verify(message, signature, publicKey);
            }

            stopwatch.Stop();

            var averageMs = stopwatch.ElapsedMilliseconds / (double)iterations;

            // Use adaptive timing validation for verification
            TimingUtils.ValidatePerformance(
                new TimingResult
                {
                    MeanMs = averageMs,
                    MedianMs = averageMs,
                    Percentile95Ms = averageMs,
                    StandardDeviationMs = 0,
                    MinMs = averageMs,
                    MaxMs = averageMs,
                    SampleCount = iterations,
                    OriginalSampleCount = iterations,
                    UsePercentile = false,
                    Environment = TimingUtils.GetSystemBaseline().Environment,
                    PerformanceMultiplier = TimingUtils.GetSystemBaseline().PerformanceMultiplier
                },
                $"{algorithm} verification", 20.0);
        }
    }

    [Fact]
    public void FullSignatureCycle_Performance_Comparison()
    {
        // Compare performance across different algorithm families
        var algorithmFamilies = new Dictionary<string, string[]>
        {
            ["ML-DSA"] = [SignatureAlgorithms.ML_DSA_44, SignatureAlgorithms.ML_DSA_65, SignatureAlgorithms.ML_DSA_87],
            ["Dilithium"] = [SignatureAlgorithms.Dilithium2, SignatureAlgorithms.Dilithium3, SignatureAlgorithms.Dilithium5],
            ["Falcon"] = [SignatureAlgorithms.Falcon_512, SignatureAlgorithms.Falcon_1024],
            ["MAYO"] = [SignatureAlgorithms.MAYO_1, SignatureAlgorithms.MAYO_3, SignatureAlgorithms.MAYO_5]
        };

        // Temporarily exclude SPHINCS+ on Windows and macOS due to stack overflow issues
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            algorithmFamilies["SPHINCS+"] = [SignatureAlgorithms.SPHINCS_PLUS_SHA2_128s_simple, SignatureAlgorithms.SPHINCS_PLUS_SHA2_192s_simple];
        }

        var performanceResults = new List<(string algorithm, double keyGenMs, double signMs, double verifyMs)>();

        foreach (var (_, algorithms) in algorithmFamilies)
        {
            foreach (var algorithm in algorithms)
            {
                if (!Sig.IsAlgorithmSupported(algorithm))
                    continue;

                using var sig = new Sig(algorithm);

                // Warm-up
                var (warmupPub, warmupSec) = sig.GenerateKeyPair();
                var warmupMsg = new byte[256];
                RandomNumberGenerator.Fill(warmupMsg);
                var warmupSig = sig.Sign(warmupMsg, warmupSec);
                _ = sig.Verify(warmupMsg, warmupSig, warmupPub);

                const int iterations = 25;

                // Measure key generation
                var keyGenStopwatch = Stopwatch.StartNew();
                for (int i = 0; i < iterations; i++)
                {
                    _ = sig.GenerateKeyPair();
                }
                keyGenStopwatch.Stop();
                var keyGenMs = keyGenStopwatch.ElapsedMilliseconds / (double)iterations;

                // Measure signing
                var (publicKey, secretKey) = sig.GenerateKeyPair();
                var message = new byte[1024];
                RandomNumberGenerator.Fill(message);

                var signStopwatch = Stopwatch.StartNew();
                for (int i = 0; i < iterations; i++)
                {
                    _ = sig.Sign(message, secretKey);
                }
                signStopwatch.Stop();
                var signMs = signStopwatch.ElapsedMilliseconds / (double)iterations;

                // Measure verification
                var signature = sig.Sign(message, secretKey);
                var verifyStopwatch = Stopwatch.StartNew();
                for (int i = 0; i < iterations; i++)
                {
                    _ = sig.Verify(message, signature, publicKey);
                }
                verifyStopwatch.Stop();
                var verifyMs = verifyStopwatch.ElapsedMilliseconds / (double)iterations;

                performanceResults.Add((algorithm, keyGenMs, signMs, verifyMs));

                // Verify performance is reasonable (adjusted for algorithm characteristics and environment)
                var isSphincsPlus = algorithm.Contains("SPHINCS", StringComparison.Ordinal);
                PerformanceTestUtilities.ValidateAlgorithmPerformance(
                    algorithm, keyGenMs, signMs, verifyMs, isSphincsPlus);
            }
        }

        // Verify we tested at least one algorithm
        performanceResults.Should().NotBeEmpty("At least one algorithm should be tested");
    }

    [Fact]
    public void MemoryAllocation_Performance()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];

        // Measure memory before operations
#pragma warning disable S1215
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var memoryBefore = GC.GetTotalMemory(false);

        const int iterations = 100;

        using (var sig = new Sig(algorithm))
        {
            for (int i = 0; i < iterations; i++)
            {
                var (publicKey, secretKey) = sig.GenerateKeyPair();
                var message = new byte[512];
                RandomNumberGenerator.Fill(message);
                var signature = sig.Sign(message, secretKey);
                var isValid = sig.Verify(message, signature, publicKey);

                // Verify correctness
                isValid.Should().BeTrue();
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

        // Memory usage should be reasonable (less than 2MB per operation on average)
        memoryPerOperation.Should().BeLessThan(2 * 1024 * 1024,
            "Average memory usage per signature operation should be reasonable");
    }

    [Fact]
    public void Throughput_Test()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        // Test throughput for a fast algorithm
        var fastAlgorithms = new[] { SignatureAlgorithms.ML_DSA_44, SignatureAlgorithms.Dilithium2, SignatureAlgorithms.Falcon_512 }
            .Where(Sig.IsAlgorithmSupported)
            .ToArray();

        fastAlgorithms.Should().NotBeEmpty("At least one fast algorithm should be supported");

        var algorithm = fastAlgorithms[0];
        using var sig = new Sig(algorithm);

        var (publicKey, secretKey) = sig.GenerateKeyPair();
        var message = new byte[256];
        RandomNumberGenerator.Fill(message);

        // Measure how many operations can be done in 1 second
        var stopwatch = Stopwatch.StartNew();
        var operationCount = 0;
        const int targetMilliseconds = 1000;

        while (stopwatch.ElapsedMilliseconds < targetMilliseconds)
        {
            var signature = sig.Sign(message, secretKey);
            var isValid = sig.Verify(message, signature, publicKey);
            isValid.Should().BeTrue();
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
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];

        // Sequential performance
        var sequentialStopwatch = Stopwatch.StartNew();
        const int totalOperations = 50;

        using (var sig = new Sig(algorithm))
        {
            for (int i = 0; i < totalOperations; i++)
            {
                var (publicKey, secretKey) = sig.GenerateKeyPair();
                var message = new byte[256];
                RandomNumberGenerator.Fill(message);
                var signature = sig.Sign(message, secretKey);
                var isValid = sig.Verify(message, signature, publicKey);
                isValid.Should().BeTrue();
            }
        }

        sequentialStopwatch.Stop();
        var sequentialTime = sequentialStopwatch.Elapsed.TotalMilliseconds;

        // Parallel performance
        var parallelStopwatch = Stopwatch.StartNew();
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken = TestContext.Current.CancellationToken
        };

        Parallel.For(0, totalOperations, parallelOptions, i =>
        {
            using var sig = new Sig(algorithm);
            var (publicKey, secretKey) = sig.GenerateKeyPair();
            var message = new byte[256];
            RandomNumberGenerator.Fill(message);
            var signature = sig.Sign(message, secretKey);
            var isValid = sig.Verify(message, signature, publicKey);
            isValid.Should().BeTrue();
        });

        parallelStopwatch.Stop();
        var parallelTime = parallelStopwatch.Elapsed.TotalMilliseconds;

        // Parallel performance can vary greatly depending on algorithm and system
        // Just verify both approaches work and don't fail
        sequentialTime.Should().BeGreaterThan(0.001, "Sequential execution should complete and be measurable");
        parallelTime.Should().BeGreaterThan(0.001, "Parallel execution should complete and be measurable");

        // Note: Parallel may be slower due to overhead, especially for fast operations
        // We don't assert on speedup as it's highly environment-dependent
    }

    [Theory]
    [InlineData(10)]
    [InlineData(50)]
    [InlineData(100)]
    public void ScalabilityTest_DifferentLoadLevels(int operationCount)
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        var (publicKey, secretKey) = sig.GenerateKeyPair();
        var message = new byte[256];
        RandomNumberGenerator.Fill(message);

        var stopwatch = Stopwatch.StartNew();
        var successCount = 0;

        for (int i = 0; i < operationCount; i++)
        {
            var signature = sig.Sign(message, secretKey);
            var isValid = sig.Verify(message, signature, publicKey);

            if (isValid)
            {
                successCount++;
            }
        }

        stopwatch.Stop();

        var averageMs = stopwatch.ElapsedMilliseconds / (double)operationCount;

        // All operations should succeed
        successCount.Should().Be(operationCount, "All operations should complete successfully");

        // Average time should remain relatively stable across load levels
        averageMs.Should().BeLessThan(100, "Average operation time should remain reasonable under load");
    }

    [Fact]
    public void MessageSize_PerformanceImpact()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var messageSizes = new[] { 64, 256, 1024, 4096, 16384 };
        var signingTimes = new List<double>();
        var verificationTimes = new List<double>();

        foreach (var messageSize in messageSizes)
        {
            var message = new byte[messageSize];
            RandomNumberGenerator.Fill(message);

            // Measure signing time
            const int iterations = 100;
            var signStopwatch = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                _ = sig.Sign(message, secretKey);
            }
            signStopwatch.Stop();
            var avgSignTime = signStopwatch.ElapsedMilliseconds / (double)iterations;
            signingTimes.Add(avgSignTime);

            // Measure verification time
            var signature = sig.Sign(message, secretKey);
            var verifyStopwatch = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                _ = sig.Verify(message, signature, publicKey);
            }
            verifyStopwatch.Stop();
            var avgVerifyTime = verifyStopwatch.ElapsedMilliseconds / (double)iterations;
            verificationTimes.Add(avgVerifyTime);
        }

        // Performance should remain reasonable across different message sizes
        signingTimes.Should().AllSatisfy(time => time.Should().BeLessThan(100, "Signing time should be reasonable"));
        verificationTimes.Should().AllSatisfy(time => time.Should().BeLessThan(50, "Verification time should be reasonable"));

        // For most signature algorithms, performance scales linearly or better with message size
        // We just verify it doesn't degrade dramatically
        var maxSignTime = signingTimes.Max();
        var minSignTime = signingTimes.Min();
        // Use environment-aware threshold for performance scaling
        var baseline = TimingUtils.GetSystemBaseline();
        var scalingThreshold = baseline.Environment switch
        {
            TimingUtils.EnvironmentType.CI => 20.0,      // Very lenient for CI
            TimingUtils.EnvironmentType.LocalSlow => 15.0,  // Somewhat lenient for slow systems
            TimingUtils.EnvironmentType.LocalFast => 10.0,  // Original threshold for fast systems
            _ => 15.0
        };
        if (minSignTime > 0)
        {
            (maxSignTime / minSignTime).Should().BeLessThan(scalingThreshold,
                $"Signing performance should not degrade dramatically with message size (threshold: {scalingThreshold:F1} for {baseline.Environment})");
        }

        var maxVerifyTime = verificationTimes.Max();
        var minVerifyTime = verificationTimes.Min();
        if (minVerifyTime > 0)
        {
            (maxVerifyTime / minVerifyTime).Should().BeLessThan(scalingThreshold,
                $"Verification performance should not degrade dramatically with message size (threshold: {scalingThreshold:F1} for {baseline.Environment})");
        }
    }

    [Fact]
    public void NISTStandardizedAlgorithms_PerformanceComparison()
    {
        var nistAlgorithms = SignatureAlgorithms.NISTStandardized
            .Where(Sig.IsAlgorithmSupported)
            .ToArray();

        if (nistAlgorithms.Length == 0)
        {
            return; // No NIST standardized algorithms are supported in this build
        }

        var results = new Dictionary<string, (double keyGen, double sign, double verify)>();

        foreach (var algorithm in nistAlgorithms)
        {
            using var sig = new Sig(algorithm);

            // Warm-up
            var (warmupPub, warmupSec) = sig.GenerateKeyPair();
            var warmupMsg = new byte[256];
            RandomNumberGenerator.Fill(warmupMsg);
            var warmupSig = sig.Sign(warmupMsg, warmupSec);
            _ = sig.Verify(warmupMsg, warmupSig, warmupPub);

            const int iterations = 25;

            // Key generation
            var keyGenStopwatch = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                _ = sig.GenerateKeyPair();
            }
            keyGenStopwatch.Stop();

            // Signing
            var (publicKey, secretKey) = sig.GenerateKeyPair();
            var message = new byte[512];
            RandomNumberGenerator.Fill(message);

            var signStopwatch = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                _ = sig.Sign(message, secretKey);
            }
            signStopwatch.Stop();

            // Verification
            var signature = sig.Sign(message, secretKey);
            var verifyStopwatch = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                _ = sig.Verify(message, signature, publicKey);
            }
            verifyStopwatch.Stop();

            var keyGenMs = keyGenStopwatch.ElapsedMilliseconds / (double)iterations;
            var signMs = signStopwatch.ElapsedMilliseconds / (double)iterations;
            var verifyMs = verifyStopwatch.ElapsedMilliseconds / (double)iterations;

            results[algorithm] = (keyGenMs, signMs, verifyMs);
        }

        // Verify performance characteristics
        foreach (var (algorithm, (keyGen, sign, verify)) in results)
        {
            // NIST standardized algorithms should have reasonable performance
            keyGen.Should().BeLessThan(200, $"{algorithm} key generation should be reasonable");
            sign.Should().BeLessThan(100, $"{algorithm} signing should be reasonable");
            verify.Should().BeLessThan(50, $"{algorithm} verification should be reasonable");
        }
    }

    [Fact]
    public void LongRunning_PerformanceStability()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        var (publicKey, secretKey) = sig.GenerateKeyPair();
        var message = new byte[256];
        RandomNumberGenerator.Fill(message);

        const int operationCount = 1000;
        var timings = new List<double>();
        var successCount = 0;

        for (int i = 0; i < operationCount; i++)
        {
            var stopwatch = Stopwatch.StartNew();
            var signature = sig.Sign(message, secretKey);
            var isValid = sig.Verify(message, signature, publicKey);
            stopwatch.Stop();

            if (isValid)
            {
                successCount++;
                timings.Add(stopwatch.Elapsed.TotalMilliseconds);
            }
        }

        successCount.Should().Be(operationCount, "All operations should succeed");

        // Performance should remain stable over time
        var avgTiming = timings.Average();
        var maxTiming = timings.Max();
        var _ = timings.Min();

        // No single operation should be dramatically slower than the average
        // Use environment-aware multiplier
        var baseline = TimingUtils.GetSystemBaseline();
        var multiplier = baseline.Environment switch
        {
            TimingUtils.EnvironmentType.CI => 100.0,     // Very lenient for CI (high variance expected due to shared resources)
            TimingUtils.EnvironmentType.LocalSlow => 50.0,  // Somewhat lenient for slow systems
            TimingUtils.EnvironmentType.LocalFast => 25.0,  // Original threshold for fast systems
            _ => 50.0
        };

        maxTiming.Should().BeLessThan(avgTiming * multiplier,
            $"No operation should be dramatically slower than average (multiplier: {multiplier:F1} for {baseline.Environment})");

        // Performance should not degrade over time
        var firstHalfAvg = timings.Take(operationCount / 2).Average();
        var secondHalfAvg = timings.Skip(operationCount / 2).Average();

        // Second half should not be more than X% slower than first half (environment-aware)
        var degradationMultiplier = baseline.Environment switch
        {
            TimingUtils.EnvironmentType.CI => 2.2,       // Allow 120% degradation in CI
            TimingUtils.EnvironmentType.LocalSlow => 1.75,  // Allow 75% degradation for slow systems
            TimingUtils.EnvironmentType.LocalFast => 1.5,   // Original 50% degradation for fast systems
            _ => 1.75
        };

        secondHalfAvg.Should().BeLessThan(firstHalfAvg * degradationMultiplier,
            $"Performance should not degrade significantly over time (max degradation: {(degradationMultiplier - 1) * 100:F0}% for {baseline.Environment})");
    }

    [Fact]
    public void OptimizedParallelThroughput_Test()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms.FirstOrDefault(a => Sig.IsAlgorithmSupported(a) &&
            (a == SignatureAlgorithms.ML_DSA_44 || a == SignatureAlgorithms.Dilithium2 || a == SignatureAlgorithms.Falcon_512))
            ?? algorithms[0];

        const int totalOperations = 500; // Fewer operations for signatures (they're typically slower)
        const int warmupOps = 50;

        // Warmup to ensure CPU caches are populated and JIT compilation is complete
        Parallel.For(0, warmupOps, new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken = TestContext.Current.CancellationToken
        }, i =>
        {
            using var sig = new Sig(algorithm);
            var (pk, sk) = sig.GenerateKeyPair();
            var message = new byte[256];
            RandomNumberGenerator.Fill(message);
            var signature = sig.Sign(message, sk);
            _ = sig.Verify(message, signature, pk);
        });

        var sw = Stopwatch.StartNew();
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken = TestContext.Current.CancellationToken
        };

        Parallel.For(0, totalOperations, parallelOptions, i =>
        {
            using var sig = new Sig(algorithm);
            var (publicKey, secretKey) = sig.GenerateKeyPair();
            var message = new byte[256];
            RandomNumberGenerator.Fill(message);
            var signature = sig.Sign(message, secretKey);
            var isValid = sig.Verify(message, signature, publicKey);
            isValid.Should().BeTrue();
        });

        sw.Stop();

        var throughput = totalOperations * 1000.0 / sw.ElapsedMilliseconds;

        var expectedMinThroughput = algorithm.Contains("SPHINCS", StringComparison.Ordinal)
            ? Math.Max(10, Environment.ProcessorCount * 2)   // SPHINCS+ is very slow
            : Math.Max(50, Environment.ProcessorCount * 10); // Other algorithms

        throughput.Should().BeGreaterThan(expectedMinThroughput,
            $"Optimized parallel throughput should achieve at least {expectedMinThroughput} ops/sec " +
            $"for {algorithm} (was {throughput:F1} ops/sec with {Environment.ProcessorCount} threads available)");
    }

#pragma warning restore S1144
}