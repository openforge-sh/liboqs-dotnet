using System.Collections.Concurrent;

namespace OpenForge.Cryptography.LibOqs.Tests.Common;

public static class TestIsolationUtilities
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> _testSemaphores = new();
    private static readonly SemaphoreSlim _globalPerformanceTestSemaphore = new(1, 1);
    
    public static async Task ExecuteIsolatedAsync(string testName, Func<Task> testAction, int maxConcurrency = 1)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(testName);
        ArgumentNullException.ThrowIfNull(testAction);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxConcurrency);
        
        var semaphore = _testSemaphores.GetOrAdd(testName, _ => new SemaphoreSlim(maxConcurrency, maxConcurrency));
        
        await semaphore.WaitAsync().ConfigureAwait(false);
        try
        {
            TimingUtils.StabilizeSystem();
            
            await testAction().ConfigureAwait(false);
        }
        finally
        {
            semaphore.Release();
        }
    }
    
    public static void ExecuteIsolated(string testName, Action testAction, int maxConcurrency = 1)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(testName);
        ArgumentNullException.ThrowIfNull(testAction);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxConcurrency);
        
        ExecuteIsolatedAsync(testName, () =>
        {
            testAction();
            return Task.CompletedTask;
        }, maxConcurrency).GetAwaiter().GetResult();
    }
    
    public static async Task ExecutePerformanceTestAsync(Func<Task> testAction)
    {
        ArgumentNullException.ThrowIfNull(testAction);
        
        await _globalPerformanceTestSemaphore.WaitAsync().ConfigureAwait(false);
        try
        {
            await PrepareForPerformanceTest().ConfigureAwait(false);
            
            await testAction().ConfigureAwait(false);
        }
        finally
        {
            _globalPerformanceTestSemaphore.Release();
        }
    }
    
    public static void ExecutePerformanceTest(Action testAction)
    {
        ArgumentNullException.ThrowIfNull(testAction);
        
        ExecutePerformanceTestAsync(() =>
        {
            testAction();
            return Task.CompletedTask;
        }).GetAwaiter().GetResult();
    }
    
    public static IDisposable CreateIsolatedScope(string testName, int maxConcurrency = 1)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(testName);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxConcurrency);
        
        return new IsolatedTestScope(testName, maxConcurrency);
    }
    
    public static IDisposable CreatePerformanceScope()
    {
        return new PerformanceTestScope();
    }
    
    public static void ResetSemaphores()
    {
        foreach (var kvp in _testSemaphores)
        {
            kvp.Value.Dispose();
        }
        _testSemaphores.Clear();
    }
    
    private static async Task PrepareForPerformanceTest()
    {
        for (int i = 0; i < 3; i++)
        {
            #pragma warning disable S1215
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            #pragma warning restore S1215
            
            await TimingUtils.AdaptiveDelayAsync(5).ConfigureAwait(false);
        }
        
        TimingUtils.StabilizeSystem();
        
        await TimingUtils.AdaptiveDelayAsync(10).ConfigureAwait(false);
    }
    
    private sealed class IsolatedTestScope : IDisposable
    {
        private readonly SemaphoreSlim _semaphore;
        private bool _disposed;
        
        public IsolatedTestScope(string testName, int maxConcurrency)
        {
            _semaphore = _testSemaphores.GetOrAdd(testName, _ => new SemaphoreSlim(maxConcurrency, maxConcurrency));
            _semaphore.Wait();
            
            TimingUtils.StabilizeSystem();
        }
        
        public void Dispose()
        {
            if (!_disposed)
            {
                _semaphore.Release();
                _semaphore.Dispose();
                _disposed = true;
            }
        }
    }
    
    private sealed class PerformanceTestScope : IDisposable
    {
        private bool _disposed;
        
        public PerformanceTestScope()
        {
            _globalPerformanceTestSemaphore.Wait();
            
            PrepareForPerformanceTest().GetAwaiter().GetResult();
        }
        
        public void Dispose()
        {
            if (!_disposed)
            {
                _globalPerformanceTestSemaphore.Release();
                _disposed = true;
            }
        }
    }
}

[AttributeUsage(AttributeTargets.Method)]
public sealed class IsolatedTestAttribute : Attribute
{
    public int MaxConcurrency { get; }
    
    public bool RequiresPerformanceIsolation { get; }
    
    public IsolatedTestAttribute(int maxConcurrency = 1, bool requiresPerformanceIsolation = false)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxConcurrency);
        MaxConcurrency = maxConcurrency;
        RequiresPerformanceIsolation = requiresPerformanceIsolation;
    }
}