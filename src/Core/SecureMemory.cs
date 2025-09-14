namespace OpenForge.Cryptography.LibOqs.Core;

/// <summary>
/// Provides cryptographically secure memory operations using LibOQS native functions.
/// </summary>
public static class SecureMemory
{
    /// <summary>
    /// Securely clears a byte array using LibOQS's OQS_MEM_cleanse function.
    /// This ensures the memory is cryptographically wiped and cannot be optimized away by the compiler.
    /// </summary>
    /// <param name="data">The byte array to securely clear. Can be null.</param>
    public static unsafe void SecureClear(byte[]? data)
    {
        if (data == null || data.Length == 0)
            return;

        fixed (byte* ptr = data)
        {
            LibOqsNative.OQS_MEM_cleanse((IntPtr)ptr, (nuint)data.Length);
        }
    }

    /// <summary>
    /// Securely clears a span of bytes using LibOQS's OQS_MEM_cleanse function.
    /// This ensures the memory is cryptographically wiped and cannot be optimized away by the compiler.
    /// </summary>
    /// <param name="data">The span of bytes to securely clear.</param>
    public static unsafe void SecureClear(Span<byte> data)
    {
        if (data.IsEmpty)
            return;

        fixed (byte* ptr = data)
        {
            LibOqsNative.OQS_MEM_cleanse((IntPtr)ptr, (nuint)data.Length);
        }
    }

    /// <summary>
    /// Allocates secure memory using LibOQS's memory allocator.
    /// Memory allocated with this method should be freed with SecureFree.
    /// </summary>
    /// <param name="size">The size in bytes to allocate.</param>
    /// <returns>A pointer to the allocated memory, or IntPtr.Zero if allocation failed.</returns>
    public static IntPtr SecureAlloc(nuint size)
    {
        if (size == 0)
            return IntPtr.Zero;

        return LibOqsNative.OQS_MEM_malloc(size);
    }


    /// <summary>
    /// Securely frees memory allocated with SecureAlloc.
    /// The memory is cryptographically wiped before being freed.
    /// </summary>
    /// <param name="memPtr">Pointer to the memory to free.</param>
    /// <param name="size">Size of the memory block in bytes.</param>
    public static void SecureFree(IntPtr memPtr, nuint size)
    {
        if (memPtr == IntPtr.Zero || size == 0)
            return;

        LibOqsNative.OQS_MEM_secure_free(memPtr, size);
    }


    /// <summary>
    /// Creates a secure byte array that will be automatically cleared when disposed.
    /// </summary>
    /// <param name="size">The size of the array to create.</param>
    /// <returns>A SecureByteArray instance.</returns>
    public static SecureByteArray CreateSecureArray(int size)
    {
        return new SecureByteArray(size);
    }
}

/// <summary>
/// A byte array wrapper that provides automatic secure clearing when disposed.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Cryptographic data requires byte arrays for performance and interoperability")]
public sealed class SecureByteArray : IDisposable
{
    private byte[]? _data;
    private bool _disposed;

    /// <summary>
    /// Gets the underlying byte array. Returns null if disposed.
    /// </summary>
    public byte[]? Data => _disposed ? null : _data;

    /// <summary>
    /// Gets the length of the array. Returns 0 if disposed.
    /// </summary>
    public int Length => _disposed ? 0 : _data?.Length ?? 0;

    /// <summary>
    /// Gets or sets a byte at the specified index.
    /// </summary>
    /// <param name="index">The zero-based index.</param>
    /// <returns>The byte at the specified index.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the array has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the index is out of range.</exception>
    public byte this[int index]
    {
        get
        {
            ThrowIfDisposed();
            if (_data == null || index < 0 || index >= _data.Length)
                throw new ArgumentOutOfRangeException(nameof(index));
            return _data[index];
        }
        set
        {
            ThrowIfDisposed();
            if (_data == null || index < 0 || index >= _data.Length)
                throw new ArgumentOutOfRangeException(nameof(index));
            _data[index] = value;
        }
    }

    internal SecureByteArray(int size)
    {
        if (size < 0)
            throw new ArgumentOutOfRangeException(nameof(size), "Size must be non-negative");
        
        _data = size > 0 ? new byte[size] : [];
    }

    /// <summary>
    /// Creates a copy of the data as a regular byte array.
    /// Note: The returned array will not be securely cleared.
    /// </summary>
    /// <returns>A copy of the data, or null if disposed.</returns>
    public byte[]? ToArray()
    {
        ThrowIfDisposed();
        return _data?.Clone() as byte[];
    }

    /// <summary>
    /// Copies data from a source array into this secure array.
    /// </summary>
    /// <param name="source">The source array to copy from.</param>
    /// <param name="sourceIndex">The starting index in the source array.</param>
    /// <param name="destinationIndex">The starting index in this array.</param>
    /// <param name="length">The number of bytes to copy.</param>
    public void CopyFrom(byte[] source, int sourceIndex, int destinationIndex, int length)
    {
        ThrowIfDisposed();
        if (_data == null)
            throw new InvalidOperationException("Array is empty");
        
        Array.Copy(source, sourceIndex, _data, destinationIndex, length);
    }

    /// <summary>
    /// Gets a span representing the data.
    /// </summary>
    /// <returns>A span of the underlying data, or empty if disposed.</returns>
    public Span<byte> AsSpan()
    {
        return _disposed || _data == null ? [] : _data.AsSpan();
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    /// <summary>
    /// Securely clears the array and disposes of resources.
    /// </summary>
    public void Dispose()
    {
        if (_disposed || _data == null)
            return;

        SecureMemory.SecureClear(_data);
        _data = null;
        _disposed = true;
    }
}