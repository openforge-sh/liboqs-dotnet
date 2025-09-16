using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.SIG.Tests;

[Collection("LibOqs Collection")]
public sealed class SecurityAndMessageTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;


    [Fact]
    public void Sign_WithEmptyMessage_ShouldProduceValidSignature()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var emptyMessage = Array.Empty<byte>();
        var signature = sig.Sign(emptyMessage, secretKey);

        signature.Should().NotBeNull();
        signature.Should().NotBeEmpty();

        var isValid = sig.Verify(emptyMessage, signature, publicKey);
        isValid.Should().BeTrue();
    }

    [Fact]
    public void Sign_WithVeryLargeMessage_ShouldWork()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var largeMessage = new byte[1024 * 1024];
        RandomNumberGenerator.Fill(largeMessage);

        var signature = sig.Sign(largeMessage, secretKey);
        var isValid = sig.Verify(largeMessage, signature, publicKey);

        isValid.Should().BeTrue("Should handle very large messages");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(33)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(129)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(257)]
    [InlineData(511)]
    [InlineData(512)]
    [InlineData(513)]
    [InlineData(1023)]
    [InlineData(1024)]
    [InlineData(1025)]
    public void Sign_WithVariousMessageSizes_ShouldWork(int messageSize)
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var message = new byte[messageSize];
        if (messageSize > 0)
        {
            RandomNumberGenerator.Fill(message);
        }

        var signature = sig.Sign(message, secretKey);
        var isValid = sig.Verify(message, signature, publicKey);

        isValid.Should().BeTrue($"Should work with message size {messageSize}");
    }

    [Fact]
    public void Sign_WithSpecialBytePatterns_ShouldWork()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var specialPatterns = new[]
        {
            new byte[256],                                              // All zeros
            [.. Enumerable.Repeat((byte)0xFF, 256)],              // All ones
            [.. Enumerable.Repeat((byte)0xAA, 256)],              // Alternating bits
            [.. Enumerable.Repeat((byte)0x55, 256)],              // Alternating bits (inverted)
            [.. Enumerable.Range(0, 256).Select(i => (byte)i)],   // Sequential bytes 0-255
            [.. Enumerable.Range(0, 256).Select(i => (byte)(255 - i))] // Sequential bytes 255-0
        };

        foreach (var pattern in specialPatterns)
        {
            var signature = sig.Sign(pattern, secretKey);
            var isValid = sig.Verify(pattern, signature, publicKey);

            isValid.Should().BeTrue("Should work with special byte patterns");
        }
    }

    [Fact]
    public void Sign_WithRepeatingBytePatterns_ShouldWork()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        // Test with messages that have repeating patterns
        for (byte b = 0; b < 16; b++) // Test with different byte values
        {
            var repeatingMessage = Enumerable.Repeat(b, 1000).ToArray();

            var signature = sig.Sign(repeatingMessage, secretKey);
            var isValid = sig.Verify(repeatingMessage, signature, publicKey);

            isValid.Should().BeTrue($"Should work with repeating byte pattern: 0x{b:X2}");
        }
    }

    [Fact]
    public void Message_WithUnicodeContent_ShouldWork()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var unicodeMessages = new[]
        {
            "Hello, World!",
            "こんにちは世界",                    // Japanese
            "Здравствуй, мир!",               // Russian
            "🌍🔒🔑💻⚡",                      // Emojis
            "مرحبا بالعالم",                   // Arabic
            "∑∏∆∇∂∫∮",                        // Mathematical symbols
            "αβγδεζηθικλμ",                   // Greek letters
            string.Join("", Enumerable.Range(0, 1000).Select(i => (char)('A' + (i % 26)))) // Long ASCII
        };

        foreach (var text in unicodeMessages)
        {
            var messageBytes = System.Text.Encoding.UTF8.GetBytes(text);

            var signature = sig.Sign(messageBytes, secretKey);
            var isValid = sig.Verify(messageBytes, signature, publicKey);

            isValid.Should().BeTrue($"Should work with Unicode content: {text.Substring(0, Math.Min(50, text.Length))}...");
        }
    }


    [Fact]
    public void Signature_ShouldNotRevealSecretKey()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (_, secretKey) = sig.GenerateKeyPair();

        var message = new byte[128];
        RandomNumberGenerator.Fill(message);

        var signature = sig.Sign(message, secretKey);

        // Signature should not contain the secret key
        // This is a basic check - in practice, this would be more sophisticated
        if (signature.Length >= secretKey.Length)
        {
            for (int i = 0; i <= signature.Length - secretKey.Length; i++)
            {
                var potentialMatch = signature.Skip(i).Take(secretKey.Length).ToArray();
                potentialMatch.Should().NotBeEquivalentTo(secretKey,
                    "Signature should not contain the secret key");
            }
        }
    }

    [Fact]
    public void Signature_ForDifferentMessages_ShouldBeDifferent()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (_, secretKey) = sig.GenerateKeyPair();

        const int messageCount = 10;
        var signatures = new List<byte[]>();

        for (int i = 0; i < messageCount; i++)
        {
            var message = new byte[128];
            RandomNumberGenerator.Fill(message);

            var signature = sig.Sign(message, secretKey);
            signatures.Add(signature);
        }

        // For probabilistic signature schemes, all signatures should be different
        // For deterministic schemes with different messages, signatures should still be different
        for (int i = 0; i < signatures.Count - 1; i++)
        {
            for (int j = i + 1; j < signatures.Count; j++)
            {
                signatures[i].Should().NotBeEquivalentTo(signatures[j],
                    $"Signature {i} should be different from signature {j}");
            }
        }
    }

    [Fact]
    public void PublicKey_ShouldNotRevealSecretKey()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        // Public key should not contain the secret key
        if (publicKey.Length >= secretKey.Length)
        {
            for (int i = 0; i <= publicKey.Length - secretKey.Length; i++)
            {
                var potentialMatch = publicKey.Skip(i).Take(secretKey.Length).ToArray();
                potentialMatch.Should().NotBeEquivalentTo(secretKey,
                    "Public key should not contain the secret key");
            }
        }

        // Also check the reverse (secret key should not contain public key)
        if (secretKey.Length >= publicKey.Length)
        {
            for (int i = 0; i <= secretKey.Length - publicKey.Length; i++)
            {
                var potentialMatch = secretKey.Skip(i).Take(publicKey.Length).ToArray();
                potentialMatch.Should().NotBeEquivalentTo(publicKey,
                    "Secret key should not contain the public key");
            }
        }
    }

    [Fact]
    public void Signature_WithMinimalBitFlip_ShouldFailVerification()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var message = new byte[256];
        RandomNumberGenerator.Fill(message);

        var originalSignature = sig.Sign(message, secretKey);

        // Test single bit flips throughout the signature
        for (int byteIndex = 0; byteIndex < originalSignature.Length; byteIndex++)
        {
            for (int bitIndex = 0; bitIndex < 8; bitIndex++)
            {
                var modifiedSignature = (byte[])originalSignature.Clone();
                modifiedSignature[byteIndex] ^= (byte)(1 << bitIndex);

                var isValid = sig.Verify(message, modifiedSignature, publicKey);
                isValid.Should().BeFalse(
                    $"Signature with single bit flip at byte {byteIndex}, bit {bitIndex} should not verify");
            }
        }
    }

    [Fact]
    public void Message_WithMinimalBitFlip_ShouldFailVerification()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var originalMessage = new byte[256];
        RandomNumberGenerator.Fill(originalMessage);

        var signature = sig.Sign(originalMessage, secretKey);

        // Test single bit flips throughout the message
        for (int byteIndex = 0; byteIndex < Math.Min(originalMessage.Length, 32); byteIndex++) // Test first 32 bytes for performance
        {
            for (int bitIndex = 0; bitIndex < 8; bitIndex++)
            {
                var modifiedMessage = (byte[])originalMessage.Clone();
                modifiedMessage[byteIndex] ^= (byte)(1 << bitIndex);

                var isValid = sig.Verify(modifiedMessage, signature, publicKey);
                isValid.Should().BeFalse(
                    $"Modified message with single bit flip at byte {byteIndex}, bit {bitIndex} should not verify");
            }
        }
    }

    [Fact]
    public void Signature_Entropy_ShouldBeHigh()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (_, secretKey) = sig.GenerateKeyPair();

        const int signatureCount = 20;
        var signatures = new List<byte[]>();

        // Generate multiple signatures (for probabilistic schemes, they should be different)
        var message = new byte[128];
        RandomNumberGenerator.Fill(message);

        for (int i = 0; i < signatureCount; i++)
        {
            var signature = sig.Sign(message, secretKey);
            signatures.Add(signature);
        }

        // Check entropy of signatures
        foreach (var signature in signatures)
        {
            // Simple entropy check: count unique bytes
            var uniqueBytes = signature.Distinct().Count();
            var totalBytes = signature.Length;

            // Signature should have reasonable byte diversity
            var diversity = (double)uniqueBytes / totalBytes;
            diversity.Should().BeGreaterThan(0.1,
                "Signature should have reasonable byte diversity");

            // Signature should not be all the same byte
            signature.Should().NotBeEquivalentTo(
                Enumerable.Repeat(signature[0], signature.Length).ToArray(),
                "Signature should not be all the same byte");
        }
    }

    [Fact]
    public void KeyGeneration_ShouldHaveUnpredictableOutput()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);

        const int keyPairCount = 20;
        var publicKeys = new List<byte[]>();
        var secretKeys = new List<byte[]>();

        for (int i = 0; i < keyPairCount; i++)
        {
            var (publicKey, secretKey) = sig.GenerateKeyPair();
            publicKeys.Add(publicKey);
            secretKeys.Add(secretKey);
        }

        // All keys should be unique
        publicKeys.Should().OnlyHaveUniqueItems();
        secretKeys.Should().OnlyHaveUniqueItems();

        // Keys should have reasonable entropy
        foreach (var key in publicKeys.Concat(secretKeys))
        {
            var uniqueBytes = key.Distinct().Count();
            var diversity = (double)uniqueBytes / key.Length;

            diversity.Should().BeGreaterThan(0.1,
                "Keys should have reasonable byte diversity");

            // Key should not be all zeros or all ones
            key.Should().NotBeEquivalentTo(new byte[key.Length]);
            key.Should().NotBeEquivalentTo(Enumerable.Repeat((byte)0xFF, key.Length).ToArray());
        }
    }

    [Fact]
    public void Signature_TemporalSecurity_ShouldNotLeakInformation()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        // Test that signing the same message multiple times doesn't reveal patterns
        var message = new byte[128];
        RandomNumberGenerator.Fill(message);

        const int iterations = 10;
        var signatures = new List<byte[]>();
        var timings = new List<TimeSpan>();

        for (int i = 0; i < iterations; i++)
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var signature = sig.Sign(message, secretKey);
            stopwatch.Stop();

            signatures.Add(signature);
            timings.Add(stopwatch.Elapsed);

            // Each signature should still verify correctly
            var isValid = sig.Verify(message, signature, publicKey);
            isValid.Should().BeTrue();
        }

        // For deterministic schemes, signatures might be identical
        // For probabilistic schemes, they should be different
        // We just ensure all are valid (already checked above)

        // Timing should not vary dramatically (side-channel resistance)
        if (timings.Count > 1)
        {
            var _ = timings.Average(t => t.TotalMilliseconds);
            var maxTiming = timings.Max(t => t.TotalMilliseconds);
            var minTiming = timings.Min(t => t.TotalMilliseconds);

            // Timing variation should not be excessive (less than 10x difference)
            if (minTiming > 0)
            {
                var timingRatio = maxTiming / minTiming;
                // Use environment-aware threshold for timing consistency
                var baseline = TimingUtils.GetSystemBaseline();
                var sigTimingThreshold = baseline.Environment switch
                {
                    TimingUtils.EnvironmentType.CI => 100.0,      // Very lenient for CI
                    TimingUtils.EnvironmentType.LocalSlow => 22.0,  // Somewhat lenient for slow systems
                    TimingUtils.EnvironmentType.LocalFast => 15.0,  // Original threshold for fast systems
                    _ => 22.0
                };
                
                timingRatio.Should().BeLessThan(sigTimingThreshold,
                    $"Signing timing should be relatively consistent to avoid timing attacks (threshold: {sigTimingThreshold:F1} for {baseline.Environment})");
            }
        }
    }

    [Fact]
    public void Signature_AgainstChosenMessageAttack_ShouldRemainSecure()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty();

        var algorithm = algorithms[0];
        using var sig = new Sig(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        // Simulate an attacker trying different message patterns
        var attackMessages = new[]
        {
            // Structured attacks
            new byte[64],                                               // All zeros
            [.. Enumerable.Repeat((byte)0xFF, 64)],               // All ones
            [.. Enumerable.Range(0, 64).Select(i => (byte)i)],    // Sequential

            // Try to find patterns in the secret key
            [.. publicKey.Take(Math.Min(publicKey.Length, 64))],   // Use public key as message

            // Boundary values
            [0x00],
            [0xFF],
            [0x80], // MSB set
            [0x01], // LSB set
        };

        var signatures = new List<byte[]>();

        foreach (var message in attackMessages)
        {
            var signature = sig.Sign(message, secretKey);
            signatures.Add(signature);

            // Should verify correctly
            var isValid = sig.Verify(message, signature, publicKey);
            isValid.Should().BeTrue();

            // Should not verify with wrong message
            var wrongMessage = new byte[message.Length];
            if (message.Length > 0)
            {
                RandomNumberGenerator.Fill(wrongMessage);
                var wrongVerify = sig.Verify(wrongMessage, signature, publicKey);
                wrongVerify.Should().BeFalse();
            }
        }

        // No signature should be identical to another (for different messages)
        for (int i = 0; i < signatures.Count - 1; i++)
        {
            for (int j = i + 1; j < signatures.Count; j++)
            {
                signatures[i].Should().NotBeEquivalentTo(signatures[j],
                    $"Signatures for different attack messages should be different");
            }
        }
    }

#pragma warning restore S1144
}