using System.Diagnostics;
using System.Security.Cryptography;
using FluentAssertions;

namespace OpenForge.Cryptography.LibOqs.Tests.Common;

#pragma warning disable S1215
public static class TimingUtils
{
    private static readonly object _lock = new();
    private static SystemPerformanceBaseline? _baseline;

    public sealed class SystemPerformanceBaseline
    {
        public DateTime MeasuredAt { get; init; }
        public double CpuIntensiveOperationMs { get; init; }
        public double MemoryAllocationMs { get; init; }
        public double CryptoOperationMs { get; init; }
        public double ThreadSwitchMs { get; init; }
        public EnvironmentType Environment { get; init; }

        public bool IsStale => DateTime.UtcNow - MeasuredAt > TimeSpan.FromMinutes(10);

        // CI environments get more lenient thresholds
        public double PerformanceMultiplier => Environment switch
        {
            EnvironmentType.CI => 3.0,
            EnvironmentType.LocalSlow => 2.0,
            EnvironmentType.LocalFast => 1.0,
            _ => 2.0
        };
    }

    public enum EnvironmentType
    {
        LocalFast,
        LocalSlow,
        CI
    }

    public sealed class TimingTestConfig
    {
        public int WarmupIterations { get; set; } = 5;
        public int MeasurementIterations { get; set; } = 10;
        public double OutlierThreshold { get; set; } = 2.0; // Standard deviations
        public int MaxRetryAttempts { get; set; } = 3;
        public TimeSpan MaxTestDuration { get; set; } = TimeSpan.FromMinutes(2);
        public bool UsePercentiles { get; set; } = true;
        public double PercentileThreshold { get; set; } = 95.0; // 95th percentile
    }

    public static SystemPerformanceBaseline GetSystemBaseline()
    {
        lock (_lock)
        {
            if (_baseline?.IsStale != false)
            {
                _baseline = MeasureSystemBaseline();
            }
            return _baseline;
        }
    }

    public static TimingResult MeasureOperationRobust(
        Action operation,
        TimingTestConfig? config = null)
    {
        ArgumentNullException.ThrowIfNull(operation);
        
        config ??= new TimingTestConfig();
        var baseline = GetSystemBaseline();

        // Warmup
        for (int i = 0; i < config.WarmupIterations; i++)
        {
            operation();
        }

        // Force garbage collection before measurement
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var measurements = new List<double>();
        var sw = new Stopwatch();
        var overallStart = Stopwatch.StartNew();

        for (int i = 0; i < config.MeasurementIterations; i++)
        {
            if (overallStart.Elapsed > config.MaxTestDuration)
                break;

            sw.Restart();
            operation();
            sw.Stop();

            measurements.Add(sw.Elapsed.TotalMilliseconds);
        }

        return AnalyzeMeasurements(measurements, baseline, config);
    }

    public static async Task<TimingResult> MeasureOperationRobustAsync(
        Func<Task> asyncOperation,
        TimingTestConfig? config = null)
    {
        ArgumentNullException.ThrowIfNull(asyncOperation);
        
        config ??= new TimingTestConfig();
        var baseline = GetSystemBaseline();

        // Warmup
        for (int i = 0; i < config.WarmupIterations; i++)
        {
            await asyncOperation().ConfigureAwait(false);
        }

        // Force garbage collection before measurement
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var measurements = new List<double>();
        var sw = new Stopwatch();
        var overallStart = Stopwatch.StartNew();

        for (int i = 0; i < config.MeasurementIterations; i++)
        {
            if (overallStart.Elapsed > config.MaxTestDuration)
                break;

            sw.Restart();
            await asyncOperation().ConfigureAwait(false);
            sw.Stop();

            measurements.Add(sw.Elapsed.TotalMilliseconds);
        }

        return AnalyzeMeasurements(measurements, baseline, config);
    }

    public static void ValidatePerformance(
        TimingResult result,
        string operationName,
        double expectedMaxMs,
        double? acceptableVariabilityPercent = 50.0)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentException.ThrowIfNullOrWhiteSpace(operationName);
        
        var baseline = GetSystemBaseline();
        var adjustedThreshold = expectedMaxMs * baseline.PerformanceMultiplier;
        var effectiveTime = result.UsePercentile ? result.Percentile95Ms : result.MedianMs;

        effectiveTime.Should().BeLessThan(adjustedThreshold,
            $"{operationName} should complete within {adjustedThreshold:F1}ms " +
            $"(was {effectiveTime:F1}ms, environment: {baseline.Environment})");

        if (acceptableVariabilityPercent.HasValue)
        {
            var variabilityPercent = result.StandardDeviationMs / result.MeanMs * 100;
            variabilityPercent.Should().BeLessThan(acceptableVariabilityPercent.Value,
                $"{operationName} should have consistent timing (variability was {variabilityPercent:F1}%)");
        }
    }

    public static void ExecuteTimingTestWithRetry(
        Action operation,
        Action<TimingResult> validation,
        TimingTestConfig? config = null)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(validation);
        
        config ??= new TimingTestConfig();
        Exception? lastException = null;

        for (int attempt = 0; attempt < config.MaxRetryAttempts; attempt++)
        {
            try
            {
                var result = MeasureOperationRobust(operation, config);
                validation(result);
                return; // Success
            }
            catch (Exception ex) when (attempt < config.MaxRetryAttempts - 1)
            {
                lastException = ex;

                // Wait before retry, increasing delay each attempt
                var delayMs = (attempt + 1) * 100;
                Thread.Sleep(delayMs);

                // Force garbage collection between attempts
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
            }
        }

        throw lastException ?? new InvalidOperationException("Timing test failed after all retry attempts");
    }

    public static TimingTestConfig CreateCryptoTimingConfig()
    {
        var baseline = GetSystemBaseline();
        return new TimingTestConfig
        {
            WarmupIterations = baseline.Environment == EnvironmentType.CI ? 3 : 5,
            MeasurementIterations = baseline.Environment == EnvironmentType.CI ? 5 : 10,
            MaxRetryAttempts = baseline.Environment == EnvironmentType.CI ? 5 : 3,
            MaxTestDuration = TimeSpan.FromMinutes(baseline.Environment == EnvironmentType.CI ? 5 : 2),
            OutlierThreshold = 2.5,
            UsePercentiles = true,
            PercentileThreshold = baseline.Environment == EnvironmentType.CI ? 90.0 : 95.0
        };
    }

    // Provides an adaptive delay that is environment-aware and non-blocking when possible.
    // Replaces hardcoded Task.Delay calls with intelligent coordination.
    public static async Task AdaptiveDelayAsync(int baseDelayMs, CancellationToken cancellationToken = default)
    {
        var baseline = GetSystemBaseline();

        // In fast environments, use minimal delays
        var adjustedDelay = baseline.Environment switch
        {
            EnvironmentType.LocalFast => Math.Max(1, baseDelayMs / 4),
            EnvironmentType.LocalSlow => Math.Max(1, baseDelayMs / 2),
            EnvironmentType.CI => Math.Max(5, baseDelayMs), // CI may need slightly longer delays
            _ => baseDelayMs
        };

        // For very small delays, use Task.Yield for better coordination
        if (adjustedDelay <= 5)
        {
            await Task.Yield();
            return;
        }

        await Task.Delay(adjustedDelay, cancellationToken).ConfigureAwait(false);
    }

    // Creates a task coordination barrier that allows multiple operations to synchronize
    // without hardcoded timing dependencies.
    public static Barrier CreateAdaptiveBarrier(int participantCount, TimeSpan? timeout = null)
    {
        var baseline = GetSystemBaseline();
        var _ = timeout ?? TimeSpan.FromMilliseconds(baseline.Environment switch
        {
            EnvironmentType.LocalFast => 1000,
            EnvironmentType.LocalSlow => 3000,
            EnvironmentType.CI => 10000,
            _ => 5000
        });

        return new Barrier(participantCount, _ =>
        {
            // Optional: Add minimal delay for coordination
            Thread.Yield();
        });
    }

    // Use this instead of arbitrary Thread.Sleep calls in tests.
    public static void StabilizeSystem()
    {
        var baseline = GetSystemBaseline();

        // Force garbage collection for consistent state
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        // Environment-specific stabilization
        var stabilizationMs = baseline.Environment switch
        {
            EnvironmentType.LocalFast => 5,
            EnvironmentType.LocalSlow => 10,
            EnvironmentType.CI => 25,
            _ => 10
        };

        Thread.Sleep(stabilizationMs);
    }

    private static SystemPerformanceBaseline MeasureSystemBaseline()
    {
        var sw = Stopwatch.StartNew();

        // CPU-intensive operation
        var cpuStart = Stopwatch.StartNew();
        var sum = 0L;
        for (int i = 0; i < 1_000_000; i++)
        {
            sum += i * i;
        }
        cpuStart.Stop();

        // Memory allocation
        var memStart = Stopwatch.StartNew();
        var arrays = new List<byte[]>();
        for (int i = 0; i < 1000; i++)
        {
            arrays.Add(new byte[1024]);
        }
        memStart.Stop();

        // Crypto operation
        var cryptoStart = Stopwatch.StartNew();
        var data = new byte[1024];
        RandomNumberGenerator.Fill(data);
        for (int i = 0; i < 100; i++)
        {
            _ = SHA256.HashData(data);
        }

        cryptoStart.Stop();

        // Thread switching
        var threadStart = Stopwatch.StartNew();
        var tasks = new List<Task>();
        for (int i = 0; i < 10; i++)
        {
            tasks.Add(Task.Run(() => Thread.Sleep(1)));
        }
        Task.WaitAll([.. tasks]);
        threadStart.Stop();

        sw.Stop();

        var environment = DetectEnvironment(sw.ElapsedMilliseconds);

        return new SystemPerformanceBaseline
        {
            MeasuredAt = DateTime.UtcNow,
            CpuIntensiveOperationMs = cpuStart.Elapsed.TotalMilliseconds,
            MemoryAllocationMs = memStart.Elapsed.TotalMilliseconds,
            CryptoOperationMs = cryptoStart.Elapsed.TotalMilliseconds,
            ThreadSwitchMs = threadStart.Elapsed.TotalMilliseconds,
            Environment = environment
        };
    }

    private static EnvironmentType DetectEnvironment(long baselineMeasurementMs)
    {
        // Check for common CI environment variables
        var ciVariables = new[] { "CI", "CONTINUOUS_INTEGRATION", "BUILD_NUMBER", "GITHUB_ACTIONS", "GITLAB_CI" };
        if (ciVariables.Any(var => !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(var))))
        {
            return EnvironmentType.CI;
        }

        // Use baseline measurement time as performance indicator
        return baselineMeasurementMs switch
        {
            < 50 => EnvironmentType.LocalFast,
            < 150 => EnvironmentType.LocalSlow,
            _ => EnvironmentType.CI // Very slow, assume CI
        };
    }

    private static TimingResult AnalyzeMeasurements(
        List<double> measurements,
        SystemPerformanceBaseline baseline,
        TimingTestConfig config)
    {
        if (measurements.Count == 0)
            throw new InvalidOperationException("No measurements collected");

        measurements.Sort();

        // Remove outliers if requested
        var filteredMeasurements = RemoveOutliers(measurements, config.OutlierThreshold);

        var mean = filteredMeasurements.Average();
        var median = GetPercentile(filteredMeasurements, 50);
        var p95 = GetPercentile(filteredMeasurements, config.PercentileThreshold);
        var stdDev = CalculateStandardDeviation(filteredMeasurements, mean);

        return new TimingResult
        {
            MeanMs = mean,
            MedianMs = median,
            Percentile95Ms = p95,
            StandardDeviationMs = stdDev,
            MinMs = filteredMeasurements.Min(),
            MaxMs = filteredMeasurements.Max(),
            SampleCount = filteredMeasurements.Count,
            OriginalSampleCount = measurements.Count,
            UsePercentile = config.UsePercentiles,
            Environment = baseline.Environment,
            PerformanceMultiplier = baseline.PerformanceMultiplier
        };
    }

    private static List<double> RemoveOutliers(List<double> values, double threshold)
    {
        if (values.Count < 3) return values;

        var mean = values.Average();
        var stdDev = CalculateStandardDeviation(values, mean);

        return [.. values.Where(x => Math.Abs(x - mean) <= threshold * stdDev)];
    }

    private static double GetPercentile(List<double> sortedValues, double percentile)
    {
        var index = percentile / 100.0 * (sortedValues.Count - 1);
        var lower = (int)Math.Floor(index);
        var upper = (int)Math.Ceiling(index);

        if (lower == upper)
            return sortedValues[lower];

        var weight = index - lower;
        return sortedValues[lower] * (1 - weight) + sortedValues[upper] * weight;
    }

    private static double CalculateStandardDeviation(List<double> values, double mean)
    {
        var sumSquaredDiffs = values.Sum(x => Math.Pow(x - mean, 2));
        return Math.Sqrt(sumSquaredDiffs / values.Count);
    }
}

public sealed class TimingResult
{
    public double MeanMs { get; init; }
    public double MedianMs { get; init; }
    public double Percentile95Ms { get; init; }
    public double StandardDeviationMs { get; init; }
    public double MinMs { get; init; }
    public double MaxMs { get; init; }
    public int SampleCount { get; init; }
    public int OriginalSampleCount { get; init; }
    public bool UsePercentile { get; init; }
    public TimingUtils.EnvironmentType Environment { get; init; }
    public double PerformanceMultiplier { get; init; }

    public override string ToString()
    {
        _ = UsePercentile ? Percentile95Ms : MedianMs;
        return $"Mean: {MeanMs:F1}ms, Median: {MedianMs:F1}ms, P95: {Percentile95Ms:F1}ms, " +
               $"StdDev: {StandardDeviationMs:F1}ms, Samples: {SampleCount}/{OriginalSampleCount}, " +
               $"Environment: {Environment} (x{PerformanceMultiplier:F1})";
    }
}

#pragma warning restore S1215