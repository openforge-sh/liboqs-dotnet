using OpenForge.Cryptography.LibOqs.Core;

namespace OpenForge.Cryptography.LibOqs.Tests.Common;

public sealed class LibOqsTestFixture : IDisposable
{
    private static readonly object _lock = new();
    private static int _referenceCount;

    public LibOqsTestFixture()
    {
        lock (_lock)
        {
            if (_referenceCount == 0)
            {
                OqsCore.Initialize();
            }
            _referenceCount++;
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _referenceCount--;
            if (_referenceCount == 0)
            {
                OqsCore.Destroy();
            }
        }
    }
}