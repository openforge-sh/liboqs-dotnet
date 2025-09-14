using System.Runtime.CompilerServices;

namespace OpenForge.Cryptography.LibOqs.Core;

/// <summary>
/// Provides shared validation utilities for cryptographic operations.
/// This class consolidates common validation logic used across KEM and signature implementations.
/// </summary>
public static class CryptographyValidation
{
    /// <summary>
    /// Validates that the algorithm name is not null, empty, or whitespace.
    /// </summary>
    /// <param name="algorithmName">The algorithm name to validate.</param>
    /// <exception cref="ArgumentException">Thrown if algorithmName is null, empty, or whitespace.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ValidateAlgorithmName(string? algorithmName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithmName);
    }

    /// <summary>
    /// Validates that the algorithm is supported and enabled.
    /// </summary>
    /// <param name="isSupported">Whether the algorithm is supported.</param>
    /// <param name="algorithmName">The name of the algorithm.</param>
    /// <exception cref="NotSupportedException">Thrown if the algorithm is not supported or enabled.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ValidateAlgorithmSupport(bool isSupported, string algorithmName)
    {
        if (!isSupported)
            throw new NotSupportedException($"Algorithm '{algorithmName}' is not enabled or supported");
    }

    /// <summary>
    /// Validates that a native handle is not null (IntPtr.Zero).
    /// </summary>
    /// <param name="handle">The native handle to validate.</param>
    /// <param name="algorithmName">The name of the algorithm for error messages.</param>
    /// <exception cref="InvalidOperationException">Thrown if the handle is null.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ValidateNativeHandle(IntPtr handle, string algorithmName)
    {
        if (handle == IntPtr.Zero)
            throw new InvalidOperationException($"Failed to create instance for algorithm '{algorithmName}'");
    }

    /// <summary>
    /// Validates that an operation result indicates success (typically 0 for liboqs).
    /// </summary>
    /// <param name="result">The result code from the operation.</param>
    /// <param name="operationName">The name of the operation for error messages.</param>
    /// <param name="algorithmName">The name of the algorithm for error messages.</param>
    /// <param name="additionalInfo">Additional information for error messages.</param>
    /// <exception cref="InvalidOperationException">Thrown if the operation failed.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ValidateOperationResult(int result, string operationName, string algorithmName, string? additionalInfo = null)
    {
        if (result != 0)
        {
            var message = $"Failed to {operationName} for algorithm '{algorithmName}'. Error code: {result}";
            if (!string.IsNullOrEmpty(additionalInfo))
                message += $". {additionalInfo}";
            throw new InvalidOperationException(message);
        }
    }

    /// <summary>
    /// Validates that an operation result indicates success (typically 0 for liboqs).
    /// </summary>
    /// <param name="result">The result code from the operation.</param>
    /// <param name="operationName">The name of the operation for error messages.</param>
    /// <param name="algorithmName">The name of the algorithm for error messages.</param>
    /// <param name="additionalInfo">Additional information for error messages.</param>
    /// <exception cref="InvalidOperationException">Thrown if the operation failed.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ValidateOperationResult(uint result, string operationName, string algorithmName, string? additionalInfo = null)
    {
        if (result != 0)
        {
            var message = $"Failed to {operationName} for algorithm '{algorithmName}'. Error code: {result}";
            if (!string.IsNullOrEmpty(additionalInfo))
                message += $". {additionalInfo}";
            throw new InvalidOperationException(message);
        }
    }

    /// <summary>
    /// Validates that an index is non-negative.
    /// </summary>
    /// <param name="index">The index to validate.</param>
    /// <param name="parameterName">The name of the parameter for exception messages.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the index is negative.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ValidateNonNegativeIndex(int index, string parameterName = "index")
    {
        if (index < 0)
            throw new ArgumentOutOfRangeException(parameterName, "Index must be non-negative");
    }

    /// <summary>
    /// Validates that a pointer is not null.
    /// </summary>
    /// <param name="memPtr">The pointer to validate.</param>
    /// <param name="operationName">The name of the operation for error messages.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the pointer is null.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ValidatePointer(IntPtr memPtr, string operationName)
    {
        if (memPtr == IntPtr.Zero)
            throw new ArgumentOutOfRangeException(operationName, "Invalid pointer returned from operation");
    }

    /// <summary>
    /// Validates that a context string is supported by the algorithm.
    /// </summary>
    /// <param name="supportsContext">Whether the algorithm supports context strings.</param>
    /// <param name="algorithmName">The name of the algorithm.</param>
    /// <exception cref="NotSupportedException">Thrown if the algorithm doesn't support context strings.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ValidateContextStringSupport(bool supportsContext, string algorithmName)
    {
        if (!supportsContext)
            throw new NotSupportedException($"Algorithm '{algorithmName}' does not support context strings");
    }
}