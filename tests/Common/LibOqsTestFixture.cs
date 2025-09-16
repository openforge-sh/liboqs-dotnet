using OpenForge.Cryptography.LibOqs.Core;

namespace OpenForge.Cryptography.LibOqs.Tests.Common;

public sealed class LibOqsTestFixture : IDisposable
{
    private static readonly object _lock = new();
    private static bool _initialized;

    public LibOqsTestFixture()
    {
        lock (_lock)
        {
            if (!_initialized)
            {
                OqsCore.Initialize();
                _initialized = true;
            }
        }
    }

    public void Dispose()
    {
        // Do absolutely nothing
    }
}