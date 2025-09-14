using System.Security.Cryptography;
using OpenForge.Cryptography.LibOqs.Core;

namespace OpenForge.Cryptography.LibOqs.Tests.Common;

internal static class TestUtilities
{
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();
    
    public static byte[] GenerateRandomBytes(int length)
    {
        if (length <= 0)
            throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive");
            
        var bytes = new byte[length];
        Rng.GetBytes(bytes);
        return bytes;
    }
    
    public static byte[] GenerateRandomMessage(int minLength = 32, int maxLength = 1024)
    {
        var length = RandomNumberGenerator.GetInt32(minLength, maxLength + 1);
        return GenerateRandomBytes(length);
    }
    
    public static bool ByteArraysEqual(byte[] a, byte[] b)
    {
        if (ReferenceEquals(a, b))
            return true;
            
        if (a == null || b == null)
            return false;
            
        if (a.Length != b.Length)
            return false;
            
        return a.SequenceEqual(b);
    }
    
    public static bool ConstantTimeEquals(byte[] a, byte[] b) => 
        SecurityUtilities.ConstantTimeEquals(a, b);
    
    public static string ToHexString(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        return SecurityUtilities.ToHexString(bytes.AsSpan()).ToUpperInvariant();
    }
    
    public static byte[] FromHexString(string hex)
    {
        if (string.IsNullOrEmpty(hex))
            throw new ArgumentException("Hex string cannot be null or empty", nameof(hex));
            
        if (hex.Length % 2 != 0)
            throw new ArgumentException("Hex string must have an even number of characters", nameof(hex));
            
        try
        {
            return SecurityUtilities.FromHexString(hex);
        }
        catch (ArgumentException ex) when (ex.Message.Contains("Invalid hex characters", StringComparison.Ordinal))
        {
            throw new FormatException($"String '{hex}' is not a valid hex string", ex);
        }
    }
    
    public static void RepeatAction(Action action, int count)
    {
        ArgumentNullException.ThrowIfNull(action);
            
        if (count <= 0)
            throw new ArgumentOutOfRangeException(nameof(count), "Count must be positive");
            
        for (var i = 0; i < count; i++)
        {
            action();
        }
    }
    
    public static TimeSpan MeasureTime(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);
            
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        action();
        stopwatch.Stop();
        return stopwatch.Elapsed;
    }
    
    public static bool IsSecurelyCleared(byte[] data)
    {
        if (data == null)
            return true;
            
        return data.All(b => b == 0);
    }
    
    public static void VerifySecureClearing(byte[] originalData, Action<byte[]> clearingAction)
    {
        ArgumentNullException.ThrowIfNull(originalData);
        ArgumentNullException.ThrowIfNull(clearingAction);
        
        var copy = (byte[])originalData.Clone();
        clearingAction(copy);
        
        if (!IsSecurelyCleared(copy))
            throw new InvalidOperationException("Data was not securely cleared");
    }
    
    public static T[] GenerateTestVectors<T>(int count, Func<int, T> generator)
    {
        ArgumentNullException.ThrowIfNull(generator);
        
        if (count <= 0)
            throw new ArgumentOutOfRangeException(nameof(count), "Count must be positive");
            
        var vectors = new T[count];
        for (var i = 0; i < count; i++)
        {
            vectors[i] = generator(i);
        }
        
        return vectors;
    }
    
    public static async Task<bool> WaitForConditionAsync(Func<bool> condition, TimeSpan timeout, TimeSpan? pollInterval = null)
    {
        ArgumentNullException.ThrowIfNull(condition);
        
        var interval = pollInterval ?? TimeSpan.FromMilliseconds(10);
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        
        while (stopwatch.Elapsed < timeout)
        {
            if (condition())
                return true;
                
            await Task.Delay(interval).ConfigureAwait(false);
        }
        
        return false;
    }
    
    public static byte[] CorruptData(byte[] original, params int[] byteIndices)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(byteIndices);
        
        var corrupted = (byte[])original.Clone();
        
        foreach (var index in byteIndices)
        {
            if (index < 0 || index >= corrupted.Length)
                throw new ArgumentOutOfRangeException(nameof(byteIndices), $"Index {index} is out of range");
                
            corrupted[index] ^= 0xFF; // Flip all bits
        }
        
        return corrupted;
    }
    
    public static byte[] CreatePatternedData(int length, byte pattern = 0xAA)
    {
        if (length <= 0)
            throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive");
            
        var data = new byte[length];
        for (var i = 0; i < length; i++)
        {
            data[i] = (byte)(pattern ^ (byte)(i & 0xFF));
        }
        
        return data;
    }
    
    public static void ExecuteWithMemoryPressure(Action action, int pressureMB = 100)
    {
        ArgumentNullException.ThrowIfNull(action);
        
        var pressure = new List<byte[]>();
        try
        {
            // Allocate memory to create pressure
            for (var i = 0; i < pressureMB; i++)
            {
                pressure.Add(new byte[1024 * 1024]); // 1MB chunks
            }
            
            // Force garbage collection to ensure memory pressure
            #pragma warning disable S1215
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            
            action();
        }
        finally
        {
            pressure.Clear();
            GC.Collect();
            #pragma warning restore S1215
        }
    }
    
    public static bool HasConsistentTiming(Func<bool> operation, int iterations = 1000, double tolerancePercent = 10.0)
    {
        ArgumentNullException.ThrowIfNull(operation);
        
        var trueTimes = new List<long>();
        var falseTimes = new List<long>();
        var stopwatch = new System.Diagnostics.Stopwatch();
        
        // Warm up
        for (var i = 0; i < 100; i++)
        {
            operation();
        }
        
        // Measure execution times
        for (var i = 0; i < iterations; i++)
        {
            stopwatch.Restart();
            var result = operation();
            stopwatch.Stop();
            
            if (result)
                trueTimes.Add(stopwatch.ElapsedTicks);
            else
                falseTimes.Add(stopwatch.ElapsedTicks);
        }
        
        if (trueTimes.Count == 0 || falseTimes.Count == 0)
            return true; // Can't compare if we don't have both true and false results
            
        var trueAvg = trueTimes.Average();
        var falseAvg = falseTimes.Average();
        var diff = Math.Abs(trueAvg - falseAvg);
        var avgTime = (trueAvg + falseAvg) / 2.0;
        
        var percentDifference = (diff / avgTime) * 100.0;
        return percentDifference <= tolerancePercent;
    }
    
    public static ulong[] GetUlongEdgeCases()
    {
        return
        [
            0UL,
            1UL,
            2UL,
            byte.MaxValue - 1,
            byte.MaxValue,
            byte.MaxValue + 1,
            ushort.MaxValue - 1,
            ushort.MaxValue,
            ushort.MaxValue + 1,
            uint.MaxValue - 1,
            uint.MaxValue,
            (ulong)uint.MaxValue + 1,
            ulong.MaxValue - 2,
            ulong.MaxValue - 1,
            ulong.MaxValue
        ];
    }
    
    public static int[] GetIntEdgeCases()
    {
        return
        [
            int.MinValue,
            int.MinValue + 1,
            -1000000,
            -1000,
            -100,
            -10,
            -1,
            0,
            1,
            10,
            100,
            1000,
            1000000,
            int.MaxValue - 1,
            int.MaxValue
        ];
    }

    public static async Task ExecuteWithMemoryPressureAsync(Func<Task> asyncAction, int pressureMB = 100)
    {
        ArgumentNullException.ThrowIfNull(asyncAction);
        
        var pressure = new List<byte[]>();
        try
        {
            // Allocate memory to create pressure
            for (var i = 0; i < pressureMB; i++)
            {
                pressure.Add(new byte[1024 * 1024]); // 1MB chunks
            }
            
            // Force garbage collection to ensure memory pressure
            #pragma warning disable S1215
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            
            await asyncAction().ConfigureAwait(false);
        }
        finally
        {
            pressure.Clear();
            GC.Collect();
            #pragma warning restore S1215
        }
    }

    public static byte[][] GenerateCorruptedVariants(byte[] original, int variantCount = 5)
    {
        ArgumentNullException.ThrowIfNull(original);
        
        var variants = new byte[variantCount][];
        
        // Pattern 1: Corrupt first byte
        variants[0] = CorruptData(original, 0);
        
        // Pattern 2: Corrupt last byte
        variants[1] = CorruptData(original, original.Length - 1);
        
        // Pattern 3: Corrupt middle byte
        variants[2] = CorruptData(original, original.Length / 2);
        
        // Pattern 4: Multiple byte corruption
        variants[3] = CorruptData(original, 0, original.Length / 4, original.Length / 2, original.Length - 1);
        
        // Pattern 5: All zeros (if we have at least 5 variants)
        if (variantCount >= 5)
        {
            variants[4] = new byte[original.Length];
        }
        
        return variants;
    }

    public static bool AllItemsUnique<T>(IEnumerable<T> items) where T : notnull
    {
        ArgumentNullException.ThrowIfNull(items);
        
        var seen = new HashSet<T>();
        foreach (var item in items)
        {
            if (!seen.Add(item))
                return false;
        }
        return true;
    }

    public static (TimeSpan duration, long memoryDeltaBytes) MeasureMemoryUsage(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);
        
        #pragma warning disable S1215
        var initialMemory = GC.GetTotalMemory(true);
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        
        action();
        
        stopwatch.Stop();
        var finalMemory = GC.GetTotalMemory(false);
        
        return (stopwatch.Elapsed, finalMemory - initialMemory);
    }

    public static async Task<(TimeSpan duration, long memoryDeltaBytes)> MeasureMemoryUsageAsync(Func<Task> asyncAction)
    {
        ArgumentNullException.ThrowIfNull(asyncAction);
        
        var initialMemory = GC.GetTotalMemory(true);
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        #pragma warning restore S1215
        
        await asyncAction().ConfigureAwait(false);
        
        stopwatch.Stop();
        var finalMemory = GC.GetTotalMemory(false);
        
        return (stopwatch.Elapsed, finalMemory - initialMemory);
    }

    public static byte[] GenerateDataWithEntropy(int length, double entropyLevel = 1.0)
    {
        if (length <= 0)
            throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive");
        
        if (entropyLevel < 0.0 || entropyLevel > 1.0)
            throw new ArgumentOutOfRangeException(nameof(entropyLevel), "Entropy level must be between 0.0 and 1.0");
        
        var data = new byte[length];
        
        if (Math.Abs(entropyLevel - 0.0) < double.Epsilon)
        {
            // All zeros (no entropy)
            return data;
        }
        
        if (Math.Abs(entropyLevel - 1.0) < double.Epsilon)
        {
            // Maximum entropy (random)
            Rng.GetBytes(data);
            return data;
        }
        
        // Partial entropy - mix random and pattern
        var randomBytes = (int)(length * entropyLevel);
        var randomData = new byte[randomBytes];
        Rng.GetBytes(randomData);
        
        Array.Copy(randomData, data, randomBytes);
        
        // Fill rest with pattern
        for (int i = randomBytes; i < length; i++)
        {
            data[i] = (byte)(i % 256);
        }
        
        return data;
    }

    public static bool HasConsistentTimingWithStatistics(Func<bool> operation, out double actualVariancePercent, 
        int iterations = 1000, double tolerancePercent = 10.0)
    {
        ArgumentNullException.ThrowIfNull(operation);
        
        var trueTimes = new List<long>();
        var falseTimes = new List<long>();
        var stopwatch = new System.Diagnostics.Stopwatch();
        
        // Warm up with more iterations
        for (var i = 0; i < 200; i++)
        {
            operation();
        }
        
        // Measure execution times
        for (var i = 0; i < iterations; i++)
        {
            stopwatch.Restart();
            var result = operation();
            stopwatch.Stop();
            
            if (result)
                trueTimes.Add(stopwatch.ElapsedTicks);
            else
                falseTimes.Add(stopwatch.ElapsedTicks);
        }
        
        if (trueTimes.Count == 0 || falseTimes.Count == 0)
        {
            actualVariancePercent = 0.0;
            return true; // Can't compare if we don't have both true and false results
        }
        
        var trueAvg = trueTimes.Average();
        var falseAvg = falseTimes.Average();
        
        // Calculate standard deviations
        var trueStdDev = Math.Sqrt(trueTimes.Select(t => Math.Pow(t - trueAvg, 2)).Average());
        var falseStdDev = Math.Sqrt(falseTimes.Select(t => Math.Pow(t - falseAvg, 2)).Average());
        
        var diff = Math.Abs(trueAvg - falseAvg);
        var avgTime = (trueAvg + falseAvg) / 2.0;
        
        actualVariancePercent = (diff / avgTime) * 100.0;
        
        // Also check if the difference is within statistical significance
        var combinedStdDev = Math.Sqrt((trueStdDev * trueStdDev + falseStdDev * falseStdDev) / 2.0);
        var statisticallySignificant = diff > (2.0 * combinedStdDev); // 2-sigma test
        
        return actualVariancePercent <= tolerancePercent && !statisticallySignificant;
    }

    public static IEnumerable<byte[]> GenerateAlgorithmTestCases(int baseLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(baseLength);
        
        // Test case 1: All zeros
        yield return new byte[baseLength];
        
        // Test case 2: All ones
        yield return CreatePatternedData(baseLength, 0xFF);
        
        // Test case 3: Alternating pattern
        yield return CreatePatternedData(baseLength, 0xAA);
        
        // Test case 4: Incremental pattern
        var incremental = new byte[baseLength];
        for (int i = 0; i < baseLength; i++)
            incremental[i] = (byte)(i % 256);
        yield return incremental;
        
        // Test case 5: High entropy random (but ensure it's different from previous patterns)
        byte[] randomCase;
        int attempts = 0;
        do
        {
            randomCase = GenerateRandomBytes(baseLength);
            attempts++;
        } while (attempts < 10 && (
            randomCase.All(b => b == 0) ||     // Not all zeros
            randomCase.All(b => b == 0xFF) ||  // Not all ones
            randomCase.All(b => b == 0xAA)));  // Not all alternating
        yield return randomCase;
        
        // Test case 6: Low entropy (mostly zeros with guaranteed non-zero bytes)
        var lowEntropy = new byte[baseLength];
        // Ensure at least a few non-zero bytes to distinguish from all-zeros
        if (baseLength >= 4)
        {
            lowEntropy[0] = 0x01;  // Guaranteed non-zero at start
            lowEntropy[baseLength / 2] = 0x02;  // Non-zero in middle
            lowEntropy[baseLength - 1] = 0x03;  // Non-zero at end
        }
        else if (baseLength > 0)
        {
            lowEntropy[0] = 0x01;  // At least one non-zero
        }
        yield return lowEntropy;
        
        // Test case 7: Boundary values (if length allows)
        if (baseLength >= 4)
        {
            var boundary = new byte[baseLength];
            boundary[0] = 0x00;
            boundary[1] = 0xFF;
            boundary[baseLength - 2] = 0xAA;
            boundary[baseLength - 1] = 0x55;
            yield return boundary;
        }
    }
}