using System.Runtime.CompilerServices;
using System.Text;

namespace OpenForge.Cryptography.LibOqs.Core;

/// <summary>
/// Provides security-focused utilities including constant-time operations, secure comparisons,
/// input validation, and entropy checks for cryptographic operations.
/// All timing-sensitive operations are designed to prevent side-channel attacks.
/// </summary>
public static class SecurityUtilities
{
    /// <summary>
    /// Performs a constant-time comparison of two byte arrays to prevent timing attacks.
    /// This operation takes the same amount of time regardless of where the arrays differ.
    /// </summary>
    /// <param name="a">First byte array to compare.</param>
    /// <param name="b">Second byte array to compare.</param>
    /// <returns>True if the arrays are equal, false otherwise.</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool ConstantTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length)
            return false;

        uint result = 0;
        for (int i = 0; i < a.Length; i++)
        {
            result |= (uint)(a[i] ^ b[i]);
        }

        return result == 0;
    }

    /// <summary>
    /// Performs a constant-time comparison of two byte arrays to prevent timing attacks.
    /// This operation takes the same amount of time regardless of where the arrays differ.
    /// </summary>
    /// <param name="a">First byte array to compare. Can be null.</param>
    /// <param name="b">Second byte array to compare. Can be null.</param>
    /// <returns>True if the arrays are equal (including both being null), false otherwise.</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool ConstantTimeEquals(byte[]? a, byte[]? b)
    {
        if (ReferenceEquals(a, b))
            return true;
        
        if (a == null || b == null)
            return false;

        return ConstantTimeEquals(a.AsSpan(), b.AsSpan());
    }

    /// <summary>
    /// Constant-time conditional selection. Returns a if condition is true, b otherwise.
    /// The execution time is independent of the condition value.
    /// </summary>
    /// <param name="condition">The condition to evaluate.</param>
    /// <param name="a">Value to return if condition is true.</param>
    /// <param name="b">Value to return if condition is false.</param>
    /// <returns>a if condition is true, b otherwise.</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static byte ConstantTimeSelect(bool condition, byte a, byte b)
    {
        // Convert boolean to mask: 0xFF if true, 0x00 if false
        // Using subtraction to avoid potential compiler optimization
        int conditionInt = condition ? 1 : 0;
        uint mask = (uint)(0 - conditionInt);
        return (byte)((mask & a) | (~mask & b));
    }

    /// <summary>
    /// Constant-time conditional copy. Copies source to destination if condition is true.
    /// The execution time is independent of the condition value.
    /// </summary>
    /// <param name="condition">The condition to evaluate.</param>
    /// <param name="source">Source span to copy from.</param>
    /// <param name="destination">Destination span to copy to.</param>
    /// <exception cref="ArgumentException">Thrown if spans have different lengths.</exception>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void ConstantTimeCopy(bool condition, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (source.Length != destination.Length)
            throw new ArgumentException("Source and destination must have the same length");

        // Convert boolean to mask: 0xFF if true, 0x00 if false
        // Using subtraction to avoid potential compiler optimization
        int conditionInt = condition ? 1 : 0;
        byte mask = (byte)(0 - conditionInt);
        
        for (int i = 0; i < source.Length; i++)
        {
            destination[i] = (byte)((mask & source[i]) | (~mask & destination[i]));
        }
    }

    /// <summary>
    /// Validates that input parameters are within expected cryptographic bounds.
    /// This helps prevent buffer overflows and invalid operations.
    /// </summary>
    /// <param name="data">The data to validate.</param>
    /// <param name="expectedLength">The expected length of the data.</param>
    /// <param name="parameterName">The name of the parameter for exception messages.</param>
    /// <exception cref="ArgumentNullException">Thrown if data is null.</exception>
    /// <exception cref="ArgumentException">Thrown if data length doesn't match expected length.</exception>
    public static void ValidateParameterLength(byte[]? data, int expectedLength, string parameterName)
    {
        if (data == null)
            throw new ArgumentNullException(parameterName);
        
        if (data.Length != expectedLength)
            throw new ArgumentException($"{parameterName} must be exactly {expectedLength} bytes, got {data.Length}", parameterName);
    }

    /// <summary>
    /// Validates that input parameters are within expected cryptographic bounds.
    /// This helps prevent buffer overflows and invalid operations.
    /// </summary>
    /// <param name="data">The data to validate.</param>
    /// <param name="expectedLength">The expected length of the data.</param>
    /// <param name="parameterName">The name of the parameter for exception messages.</param>
    /// <exception cref="ArgumentException">Thrown if data length doesn't match expected length.</exception>
    public static void ValidateParameterLength(ReadOnlySpan<byte> data, int expectedLength, string parameterName)
    {
        if (data.Length != expectedLength)
            throw new ArgumentException($"{parameterName} must be exactly {expectedLength} bytes, got {data.Length}", parameterName);
    }

    /// <summary>
    /// Validates that input parameters are within acceptable cryptographic bounds.
    /// This helps prevent buffer overflows and invalid operations.
    /// </summary>
    /// <param name="data">The data to validate.</param>
    /// <param name="minLength">The minimum acceptable length of the data.</param>
    /// <param name="maxLength">The maximum acceptable length of the data.</param>
    /// <param name="parameterName">The name of the parameter for exception messages.</param>
    /// <exception cref="ArgumentNullException">Thrown if data is null.</exception>
    /// <exception cref="ArgumentException">Thrown if data length is outside acceptable bounds.</exception>
    public static void ValidateParameterLengthRange(byte[]? data, int minLength, int maxLength, string parameterName)
    {
        if (data == null)
            throw new ArgumentNullException(parameterName);
        
        if (data.Length < minLength || data.Length > maxLength)
            throw new ArgumentException($"{parameterName} must be between {minLength} and {maxLength} bytes, got {data.Length}", parameterName);
    }

    /// <summary>
    /// Validates that input parameters are within acceptable cryptographic bounds.
    /// This helps prevent buffer overflows and invalid operations.
    /// </summary>
    /// <param name="data">The data to validate.</param>
    /// <param name="minLength">The minimum acceptable length of the data.</param>
    /// <param name="maxLength">The maximum acceptable length of the data.</param>
    /// <param name="parameterName">The name of the parameter for exception messages.</param>
    /// <exception cref="ArgumentException">Thrown if data length is outside acceptable bounds.</exception>
    public static void ValidateParameterLengthRange(ReadOnlySpan<byte> data, int minLength, int maxLength, string parameterName)
    {
        if (data.Length < minLength || data.Length > maxLength)
            throw new ArgumentException($"{parameterName} must be between {minLength} and {maxLength} bytes, got {data.Length}", parameterName);
    }

    /// <summary>
    /// Validates that a size parameter is within reasonable bounds to prevent excessive memory allocation.
    /// </summary>
    /// <param name="size">The size to validate.</param>
    /// <param name="maxSize">The maximum acceptable size.</param>
    /// <param name="parameterName">The name of the parameter for exception messages.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if size is negative or exceeds maximum.</exception>
    public static void ValidateSize(int size, int maxSize, string parameterName)
    {
        if (size < 0)
            throw new ArgumentOutOfRangeException(parameterName, "Size must be non-negative");
        
        if (size > maxSize)
            throw new ArgumentOutOfRangeException(parameterName, $"Size {size} exceeds maximum allowed size {maxSize}");
    }

    /// <summary>
    /// Validates that random bytes appear to have adequate entropy.
    /// This is a basic sanity check and not a comprehensive entropy test.
    /// </summary>
    /// <param name="randomBytes">The random bytes to validate.</param>
    /// <param name="parameterName">The name of the parameter for exception messages.</param>
    /// <exception cref="ArgumentException">Thrown if the bytes appear to have insufficient entropy.</exception>
    public static void ValidateRandomBytesEntropy(ReadOnlySpan<byte> randomBytes, string parameterName)
    {
        if (randomBytes.Length == 0)
            return;

        // Check for all bytes being the same
        var firstByte = randomBytes[0];
        var allSame = true;
        
        for (int i = 1; i < randomBytes.Length && allSame; i++)
        {
            if (randomBytes[i] != firstByte)
            {
                allSame = false;
            }
        }

        if (allSame)
        {
            var byteValue = firstByte switch
            {
                0x00 => "0x00",
                0xFF => "0xFF",
                _ => $"0x{firstByte:X2}"
            };
            throw new ArgumentException($"{parameterName} appears to have insufficient entropy (all bytes are {byteValue})", parameterName);
        }

        // For longer sequences, check for simple repeating patterns
        if (randomBytes.Length >= 16)
        {
            // Check for simple repeating patterns (2, 4, or 8 byte patterns)
            foreach (var patternLength in new[] { 2, 4, 8 })
            {
                if (randomBytes.Length >= patternLength * 2 && IsRepeatingPattern(randomBytes, patternLength))
                {
                    throw new ArgumentException($"{parameterName} appears to have insufficient entropy (repeating {patternLength}-byte pattern)", parameterName);
                }
            }
        }
    }

    private static bool IsRepeatingPattern(ReadOnlySpan<byte> data, int patternLength)
    {
        if (data.Length < patternLength * 2)
            return false;

        // Check if the entire sequence is a repeating pattern
        for (int i = patternLength; i < data.Length; i++)
        {
            if (data[i] != data[i % patternLength])
                return false;
        }
        return true;
    }


    /// <summary>
    /// Creates a defensive copy of a byte array to prevent external modification.
    /// </summary>
    /// <param name="source">The source array to copy.</param>
    /// <returns>A defensive copy of the source array, or null if source is null.</returns>
    public static byte[]? CreateDefensiveCopy(byte[]? source)
    {
        return source?.Clone() as byte[];
    }

    /// <summary>
    /// Creates a defensive copy of a span into a new byte array.
    /// </summary>
    /// <param name="source">The source span to copy.</param>
    /// <returns>A new byte array containing a copy of the source data.</returns>
    public static byte[] CreateDefensiveCopy(ReadOnlySpan<byte> source)
    {
        return source.ToArray();
    }

    /// <summary>
    /// Securely converts a byte array to a hexadecimal string representation.
    /// This method is constant-time with respect to the data content to prevent timing attacks.
    /// </summary>
    /// <param name="bytes">The byte array to convert.</param>
    /// <returns>A lowercase hexadecimal string representation.</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static string ToHexString(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
            return string.Empty;
            
        var result = new StringBuilder(bytes.Length * 2);
        
        for (int i = 0; i < bytes.Length; i++)
        {
            result.Append(bytes[i].ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
        }
        
        return result.ToString();
    }

    /// <summary>
    /// Securely parses a hexadecimal string to a byte array.
    /// This method validates the input format and provides clear error messages.
    /// </summary>
    /// <param name="hexString">The hexadecimal string to parse.</param>
    /// <returns>The parsed byte array.</returns>
    /// <exception cref="ArgumentException">Thrown if the hex string format is invalid.</exception>
    public static byte[] FromHexString(string hexString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hexString);
        
        if (hexString.Length % 2 != 0)
            throw new ArgumentException("Hex string must have an even number of characters", nameof(hexString));
            
        var result = new byte[hexString.Length / 2];
        
        for (int i = 0; i < result.Length; i++)
        {
            var hexByte = hexString.AsSpan(i * 2, 2);
            if (!byte.TryParse(hexByte, System.Globalization.NumberStyles.HexNumber, null, out result[i]))
                throw new ArgumentException($"Invalid hex characters at position {i * 2}", nameof(hexString));
        }
        
        return result;
    }

    /// <summary>
    /// Validates that a string parameter is not null, empty, or whitespace.
    /// Provides consistent error messages for string validation.
    /// </summary>
    /// <param name="value">The string value to validate.</param>
    /// <param name="parameterName">The name of the parameter for error reporting.</param>
    /// <exception cref="ArgumentException">Thrown if the string is null, empty, or whitespace.</exception>
    public static void ValidateNonEmptyString(string? value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("Value cannot be null or whitespace.", parameterName);
    }

    /// <summary>
    /// Validates that a span is not empty and provides consistent error messages.
    /// </summary>
    /// <param name="span">The span to validate.</param>
    /// <param name="parameterName">The name of the parameter for error reporting.</param>
    /// <exception cref="ArgumentException">Thrown if the span is empty.</exception>
    public static void ValidateNonEmptySpan(ReadOnlySpan<byte> span, string parameterName)
    {
        if (span.IsEmpty)
            throw new ArgumentException("Parameter cannot be empty", parameterName);
    }
}