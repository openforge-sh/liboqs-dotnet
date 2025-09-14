using System.Diagnostics;
using FluentAssertions;

namespace OpenForge.Cryptography.LibOqs.Tests.Common;

public static class PerformanceTestUtilities
{
    public static class Configuration
    {
        public static double MaxKeyGenerationTimeMs => GetAdaptiveThreshold(200.0);

        public static double MaxEncapsulationTimeMs => GetAdaptiveThreshold(100.0);

        public static double MaxDecapsulationTimeMs => GetAdaptiveThreshold(50.0);

        // SPHINCS+ is significantly slower than other algorithms
        public static double MaxSphincsPlusTimeMs => GetAdaptiveThreshold(300.0);

        public static int MinIterations
        {
            get
            {
                var baseline = TimingUtils.GetSystemBaseline();
                return baseline.Environment == TimingUtils.EnvironmentType.CI ? 10 : 25;
            }
        }

        public static long MaxMemoryPerOperationBytes { get; set; } = 2 * 1024 * 1024; // 2MB

        public static double MinThroughputOpsPerSecond
        {
            get
            {
                var baseline = TimingUtils.GetSystemBaseline();
                var baseRate = 50.0;
                return baseRate / baseline.PerformanceMultiplier;
            }
        }

        private static double GetAdaptiveThreshold(double baseThreshold)
        {
            var baseline = TimingUtils.GetSystemBaseline();
            return baseThreshold * baseline.PerformanceMultiplier;
        }
    }

    public static double MeasureOperationPerformance(Action operation, int iterations, int warmupIterations = 10)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(iterations);
        ArgumentOutOfRangeException.ThrowIfNegative(warmupIterations);

        var config = TimingUtils.CreateCryptoTimingConfig();
        config.WarmupIterations = Math.Max(warmupIterations, config.WarmupIterations);
        config.MeasurementIterations = Math.Max(iterations, config.MeasurementIterations);

        var result = TimingUtils.MeasureOperationRobust(operation, config);
        
        return result.MedianMs;
    }

    public static TimingResult MeasureOperationDetailed(Action operation, TimingUtils.TimingTestConfig? config = null)
    {
        ArgumentNullException.ThrowIfNull(operation);
        config ??= TimingUtils.CreateCryptoTimingConfig();
        
        return TimingUtils.MeasureOperationRobust(operation, config);
    }

    public static double MeasureThroughput(Action operation, int durationMs = 1000, int warmupMs = 100)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(durationMs);
        ArgumentOutOfRangeException.ThrowIfNegative(warmupMs);

        var warmupStopwatch = Stopwatch.StartNew();
        while (warmupStopwatch.ElapsedMilliseconds < warmupMs)
        {
            operation();
        }

        var operationCount = 0;
        var measurementStopwatch = Stopwatch.StartNew();
        while (measurementStopwatch.ElapsedMilliseconds < durationMs)
        {
            operation();
            operationCount++;
        }

        return operationCount * 1000.0 / measurementStopwatch.ElapsedMilliseconds;
    }

    public static (TimeSpan duration, long memoryDeltaBytes) MeasureMemoryUsage(Action operation)
    {
        ArgumentNullException.ThrowIfNull(operation);

        #pragma warning disable S1215
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var initialMemory = GC.GetTotalMemory(false);
        #pragma warning restore S1215

        var stopwatch = Stopwatch.StartNew();
        operation();
        stopwatch.Stop();

        #pragma warning disable S1215
        var finalMemory = GC.GetTotalMemory(false);
        #pragma warning restore S1215

        return (stopwatch.Elapsed, finalMemory - initialMemory);
    }

    public static void ValidateAlgorithmPerformance(
        string algorithmName,
        double keyGenTimeMs,
        double encapTimeMs,
        double decapTimeMs,
        bool isSphincsPlus = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithmName);
        
        var baseline = TimingUtils.GetSystemBaseline();

        var maxKeyGenTime = isSphincsPlus ? Configuration.MaxSphincsPlusTimeMs : Configuration.MaxKeyGenerationTimeMs;
        var maxEncapTime = isSphincsPlus ? Configuration.MaxSphincsPlusTimeMs : Configuration.MaxEncapsulationTimeMs;
        var maxDecapTime = Configuration.MaxDecapsulationTimeMs;

        keyGenTimeMs.Should().BeLessThan(maxKeyGenTime,
            $"{algorithmName} key generation should be reasonable (was {keyGenTimeMs:F2}ms, max {maxKeyGenTime:F1}ms, env: {baseline.Environment})");

        encapTimeMs.Should().BeLessThan(maxEncapTime,
            $"{algorithmName} encapsulation/signing should be reasonable (was {encapTimeMs:F2}ms, max {maxEncapTime:F1}ms, env: {baseline.Environment})");

        decapTimeMs.Should().BeLessThan(maxDecapTime,
            $"{algorithmName} decapsulation/verification should be reasonable (was {decapTimeMs:F2}ms, max {maxDecapTime:F1}ms, env: {baseline.Environment})");
    }

    public static void ValidateAlgorithmPerformance(
        string algorithmName,
        TimingResult keyGenResult,
        TimingResult encapResult,
        TimingResult decapResult,
        bool isSphincsPlus = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithmName);
        ArgumentNullException.ThrowIfNull(keyGenResult);
        ArgumentNullException.ThrowIfNull(encapResult);
        ArgumentNullException.ThrowIfNull(decapResult);

        _ = isSphincsPlus ? Configuration.MaxSphincsPlusTimeMs : Configuration.MaxKeyGenerationTimeMs;
        _ = isSphincsPlus ? Configuration.MaxSphincsPlusTimeMs : Configuration.MaxEncapsulationTimeMs;
        _ = Configuration.MaxDecapsulationTimeMs;

        TimingUtils.ValidatePerformance(keyGenResult, $"{algorithmName} key generation", 
            isSphincsPlus ? 300.0 : 200.0);
        TimingUtils.ValidatePerformance(encapResult, $"{algorithmName} encapsulation/signing", 
            isSphincsPlus ? 300.0 : 100.0);
        TimingUtils.ValidatePerformance(decapResult, $"{algorithmName} decapsulation/verification", 50.0);
    }

    public static (int successCount, double averageTimeMs) RunScalabilityTest(
        Func<Action> operationFactory,
        int operationCount)
    {
        ArgumentNullException.ThrowIfNull(operationFactory);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(operationCount);

        var stopwatch = Stopwatch.StartNew();
        var successCount = 0;

        for (int i = 0; i < operationCount; i++)
        {
            try
            {
                var operation = operationFactory();
                operation();
                successCount++;
            }
            catch (Exception ex) when (ex is ArgumentException 
                or InvalidOperationException 
                or NotSupportedException 
                or OutOfMemoryException
                or AggregateException)
            {
                // Expected during performance testing
            }
        }

        stopwatch.Stop();
        var averageTimeMs = stopwatch.Elapsed.TotalMilliseconds / operationCount;

        return (successCount, averageTimeMs);
    }

    public static bool TestPerformanceStability(Action operation, int operationCount = 1000)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(operationCount);

        var timings = new List<double>();
        var successCount = 0;

        for (int i = 0; i < operationCount; i++)
        {
            try
            {
                var stopwatch = Stopwatch.StartNew();
                operation();
                stopwatch.Stop();

                timings.Add(stopwatch.Elapsed.TotalMilliseconds);
                successCount++;
            }
            catch (Exception ex) when (ex is ArgumentException 
                or InvalidOperationException 
                or NotSupportedException 
                or OutOfMemoryException
                or AggregateException)
            {
                // Expected during performance testing
            }
        }

        if (successCount != operationCount)
            return false;

        var avgTiming = timings.Average();
        var maxTiming = timings.Max();

        var maxAllowedRatio = 10.0;
        if (maxTiming > avgTiming * maxAllowedRatio)
            return false;

        var firstHalfAvg = timings.Take(operationCount / 2).Average();
        var secondHalfAvg = timings.Skip(operationCount / 2).Average();

        return secondHalfAvg <= firstHalfAvg * 1.5;
    }

    public static async Task<(double sequentialTimeMs, double parallelTimeMs)> TestParallelPerformance(
        Func<Action> operationFactory,
        int operationCount,
        int maxDegreeOfParallelism = -1)
    {
        ArgumentNullException.ThrowIfNull(operationFactory);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(operationCount);

        if (maxDegreeOfParallelism == -1)
            maxDegreeOfParallelism = Environment.ProcessorCount;

        var sequentialStopwatch = Stopwatch.StartNew();
        for (int i = 0; i < operationCount; i++)
        {
            var operation = operationFactory();
            operation();
        }
        sequentialStopwatch.Stop();
        var sequentialTime = sequentialStopwatch.ElapsedMilliseconds;

        var parallelStopwatch = Stopwatch.StartNew();
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = maxDegreeOfParallelism
        };

        await Task.Run(() =>
        {
            Parallel.For(0, operationCount, parallelOptions, i =>
            {
                var operation = operationFactory();
                operation();
            });
        }).ConfigureAwait(false);

        parallelStopwatch.Stop();
        var parallelTime = parallelStopwatch.ElapsedMilliseconds;

        return (sequentialTime, parallelTime);
    }
}