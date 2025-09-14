using System.Diagnostics;
using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Core;
using OpenForge.Cryptography.LibOqs.KEM;
using OpenForge.Cryptography.LibOqs.SIG;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.Tests;

[Collection("LibOqs Collection")]
public sealed class PerformanceTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void HybridCryptographyWorkflow_Performance_ShouldBeReasonable()
    {
        TestIsolationUtilities.ExecutePerformanceTest(() =>
        {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        using var kem = new Kem(kemAlgorithm);
        using var sig = new Sig(sigAlgorithm);

        var (kemPub, kemSec) = kem.GenerateKeyPair();
        var (sigPub, sigSec) = sig.GenerateKeyPair();

        var message = new byte[1024];
        RandomNumberGenerator.Fill(message);

        const int iterations = 50;
        var stopwatch = Stopwatch.StartNew();

        for (int i = 0; i < iterations; i++)
        {
            var signature = sig.Sign(message, sigSec);

            var (ciphertext, sharedSecret) = kem.Encapsulate(kemPub);

            var encryptedData = EncryptWithAes(message, sharedSecret);

            var recoveredSecret = kem.Decapsulate(ciphertext, kemSec);

            var isValid = sig.Verify(message, signature, sigPub);

            var decryptedData = DecryptWithAes(encryptedData, recoveredSecret);

            recoveredSecret.Should().BeEquivalentTo(sharedSecret);
            isValid.Should().BeTrue();
            decryptedData.Should().BeEquivalentTo(message);
        }

        stopwatch.Stop();
        var averageMs = stopwatch.ElapsedMilliseconds / (double)iterations;

        TimingUtils.ValidatePerformance(
            new TimingResult 
            { 
                MeanMs = averageMs, 
                MedianMs = averageMs, 
                Percentile95Ms = averageMs,
                StandardDeviationMs = 0,
                MinMs = averageMs,
                MaxMs = averageMs,
                SampleCount = iterations,
                OriginalSampleCount = iterations,
                UsePercentile = false,
                Environment = TimingUtils.GetSystemBaseline().Environment,
                PerformanceMultiplier = TimingUtils.GetSystemBaseline().PerformanceMultiplier
            },
            "Hybrid workflow", 200.0);
        });
    }

    [Fact]
    public void MultiRecipientEncryption_Performance_ShouldScaleReasonably()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        const int recipientCount = 10;
        var recipients = new List<(Kem kem, byte[] publicKey, byte[] secretKey)>();

        for (int i = 0; i < recipientCount; i++)
        {
            var kem = new Kem(kemAlgorithm);
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            recipients.Add((kem, publicKey, secretKey));
        }

        using var senderSig = new Sig(sigAlgorithm);
        using var senderKem = new Kem(kemAlgorithm);
        var (senderPub, senderSec) = senderSig.GenerateKeyPair();

        var message = new byte[2048];
        RandomNumberGenerator.Fill(message);

        try
        {
            var stopwatch = Stopwatch.StartNew();

            // Sign message once
            var signature = senderSig.Sign(message, senderSec);

            var encryptedForRecipients = new List<(byte[] ciphertext, byte[] encryptedData)>();
            foreach (var (_, publicKey, _) in recipients)
            {
                var (ciphertext, sharedSecret) = senderKem.Encapsulate(publicKey);
                var encryptedData = EncryptWithAes(message, sharedSecret);
                encryptedForRecipients.Add((ciphertext, encryptedData));
            }

            stopwatch.Stop();
            var encryptionTimeMs = stopwatch.ElapsedMilliseconds;

            stopwatch.Restart();
            for (int i = 0; i < recipientCount; i++)
            {
                var (kem, _, secretKey) = recipients[i];
                var (ciphertext, encryptedData) = encryptedForRecipients[i];

                var sharedSecret = kem.Decapsulate(ciphertext, secretKey);
                var decryptedMessage = DecryptWithAes(encryptedData, sharedSecret);
                var isValid = senderSig.Verify(decryptedMessage, signature, senderPub);

                decryptedMessage.Should().BeEquivalentTo(message);
                isValid.Should().BeTrue();
            }
            stopwatch.Stop();
            var decryptionTimeMs = stopwatch.ElapsedMilliseconds;

            var avgEncryptionPerRecipient = encryptionTimeMs / (double)recipientCount;
            var avgDecryptionPerRecipient = decryptionTimeMs / (double)recipientCount;

            var baseline = TimingUtils.GetSystemBaseline();
            var encryptThreshold = 100.0 * baseline.PerformanceMultiplier;
            var decryptThreshold = 75.0 * baseline.PerformanceMultiplier;
            
            avgEncryptionPerRecipient.Should().BeLessThan(encryptThreshold,
                $"Encryption per recipient should be reasonable (was {avgEncryptionPerRecipient:F1}ms, max {encryptThreshold:F1}ms, env: {baseline.Environment})");
            avgDecryptionPerRecipient.Should().BeLessThan(decryptThreshold,
                $"Decryption per recipient should be reasonable (was {avgDecryptionPerRecipient:F1}ms, max {decryptThreshold:F1}ms, env: {baseline.Environment})");
        }
        finally
        {
            foreach (var (kem, _, _) in recipients)
            {
                kem.Dispose();
            }
        }
    }

    [Fact]
    public void CertificateChain_Performance_ShouldHandleMultipleLevels()
    {
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        using var rootCaSig = new Sig(sigAlgorithm);
        using var intermediateCaSig = new Sig(sigAlgorithm);
        using var endEntitySig = new Sig(sigAlgorithm);

        var (rootCaPublic, rootCaSecret) = rootCaSig.GenerateKeyPair();
        var (intermediatePublic, intermediateSecret) = intermediateCaSig.GenerateKeyPair();
        var (endEntityPublic, endEntitySecret) = endEntitySig.GenerateKeyPair();

        const int iterations = 25;
        var stopwatch = Stopwatch.StartNew();

        for (int i = 0; i < iterations; i++)
        {
            var intermediateCert = CreateCertificateData("Intermediate CA", intermediatePublic);
            var intermediateCertSig = rootCaSig.Sign(intermediateCert, rootCaSecret);

            var endEntityCert = CreateCertificateData("End Entity", endEntityPublic);
            var endEntityCertSig = intermediateCaSig.Sign(endEntityCert, intermediateSecret);

            var message = $"Message {i}";
            var messageBytes = System.Text.Encoding.UTF8.GetBytes(message);
            var messageSignature = endEntitySig.Sign(messageBytes, endEntitySecret);

            var isEndEntityCertValid = intermediateCaSig.Verify(endEntityCert, endEntityCertSig, intermediatePublic);
            var isIntermediateCertValid = rootCaSig.Verify(intermediateCert, intermediateCertSig, rootCaPublic);
            var isMessageValid = endEntitySig.Verify(messageBytes, messageSignature, endEntityPublic);

            isEndEntityCertValid.Should().BeTrue();
            isIntermediateCertValid.Should().BeTrue();
            isMessageValid.Should().BeTrue();
        }

        stopwatch.Stop();
        var averageMs = stopwatch.ElapsedMilliseconds / (double)iterations;

        averageMs.Should().BeLessThan(150,
            $"Certificate chain operations should complete reasonably (was {averageMs:F2} ms)");
    }

    [Fact]
    public void ConcurrentHybridOperations_Performance_ShouldHandleParallelLoad()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        const int parallelTasks = 10;
        const int operationsPerTask = 20;
        var results = new List<TimeSpan>();

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken = TestContext.Current.CancellationToken
        };

        Parallel.For(0, parallelTasks, parallelOptions, taskId =>
        {
            var taskStopwatch = Stopwatch.StartNew();

            using var kem = new Kem(kemAlgorithm);
            using var sig = new Sig(sigAlgorithm);

            for (int i = 0; i < operationsPerTask; i++)
            {
                var (kemPub, kemSec) = kem.GenerateKeyPair();
                var (sigPub, sigSec) = sig.GenerateKeyPair();

                var message = new byte[512];
                RandomNumberGenerator.Fill(message);

                var signature = sig.Sign(message, sigSec);
                var (ciphertext, sharedSecret) = kem.Encapsulate(kemPub);
                var recoveredSecret = kem.Decapsulate(ciphertext, kemSec);
                var isValid = sig.Verify(message, signature, sigPub);

                recoveredSecret.Should().BeEquivalentTo(sharedSecret);
                isValid.Should().BeTrue();
            }

            taskStopwatch.Stop();
            lock (results)
            {
                results.Add(taskStopwatch.Elapsed);
            }
        });

        results.Should().HaveCount(parallelTasks);
        var maxTime = results.Max();
        var avgTime = results.Average(ts => ts.TotalMilliseconds);

        maxTime.TotalSeconds.Should().BeLessThan(30, "No task should take excessively long");
        avgTime.Should().BeLessThan(15000, "Average task time should be reasonable");
    }

    [Fact]
    public void LargeMessageSigning_Performance_ShouldScaleWithSize()
    {
        var sigAlgorithm = GetSupportedSignatureAlgorithm();
        using var sig = new Sig(sigAlgorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var messageSizes = new[] { 1024, 4096, 16384, 65536 }; // 1KB to 64KB
        var signingTimes = new List<double>();
        var verificationTimes = new List<double>();

        foreach (var messageSize in messageSizes)
        {
            var message = new byte[messageSize];
            RandomNumberGenerator.Fill(message);

            // Measure signing time
            const int iterations = 20;
            var signStopwatch = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                _ = sig.Sign(message, secretKey);
            }
            signStopwatch.Stop();
            var avgSignTime = signStopwatch.ElapsedMilliseconds / (double)iterations;
            signingTimes.Add(avgSignTime);

            // Measure verification time
            var signature = sig.Sign(message, secretKey);
            var verifyStopwatch = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                _ = sig.Verify(message, signature, publicKey);
            }
            verifyStopwatch.Stop();
            var avgVerifyTime = verifyStopwatch.ElapsedMilliseconds / (double)iterations;
            verificationTimes.Add(avgVerifyTime);
        }

        // Performance should remain reasonable across all sizes
        signingTimes.Should().AllSatisfy(time =>
            time.Should().BeLessThan(500, "Signing time should be reasonable"));
        verificationTimes.Should().AllSatisfy(time =>
            time.Should().BeLessThan(200, "Verification time should be reasonable"));
    }

    [Fact]
    public void KeyGeneration_Performance_CombinedOperations_ShouldBeEfficient()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        const int iterations = 30;
        var stopwatch = Stopwatch.StartNew();

        for (int i = 0; i < iterations; i++)
        {
            using var kem = new Kem(kemAlgorithm);
            using var sig = new Sig(sigAlgorithm);

            var (kemPub, kemSec) = kem.GenerateKeyPair();
            var (sigPub, sigSec) = sig.GenerateKeyPair();

            var testMessage = "Test message"u8.ToArray();
            var signature = sig.Sign(testMessage, sigSec);
            var (ciphertext, sharedSecret) = kem.Encapsulate(kemPub);

            var recoveredSecret = kem.Decapsulate(ciphertext, kemSec);
            var isValid = sig.Verify(testMessage, signature, sigPub);

            recoveredSecret.Should().BeEquivalentTo(sharedSecret);
            isValid.Should().BeTrue();
        }

        stopwatch.Stop();
        var averageMs = stopwatch.ElapsedMilliseconds / (double)iterations;

        averageMs.Should().BeLessThan(300,
            $"Combined key generation should be efficient (was {averageMs:F2} ms)");
    }

    [Fact]
    public void OptimizedParallelHybridThroughput_Test()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        const int totalOperations = 300; // Fewer operations for hybrid workflow (more complex)
        const int warmupOps = 30;

        Parallel.For(0, warmupOps, new ParallelOptions 
        { 
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken = TestContext.Current.CancellationToken
        }, i =>
        {
            using var kem = new Kem(kemAlgorithm);
            using var sig = new Sig(sigAlgorithm);
            
            var (kemPub, kemSec) = kem.GenerateKeyPair();
            var (sigPub, sigSec) = sig.GenerateKeyPair();
            
            var message = new byte[256];
            RandomNumberGenerator.Fill(message);
            
            var signature = sig.Sign(message, sigSec);
            var (ct, _) = kem.Encapsulate(kemPub);
            _ = kem.Decapsulate(ct, kemSec);
            _ = sig.Verify(message, signature, sigPub);
        });

        var sw = Stopwatch.StartNew();
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken = TestContext.Current.CancellationToken
        };

        Parallel.For(0, totalOperations, parallelOptions, i =>
        {
            using var kem = new Kem(kemAlgorithm);
            using var sig = new Sig(sigAlgorithm);

            var (kemPublicKey, kemSecretKey) = kem.GenerateKeyPair();
            var (sigPublicKey, sigSecretKey) = sig.GenerateKeyPair();

            var message = new byte[512];
            RandomNumberGenerator.Fill(message);

            var signature = sig.Sign(message, sigSecretKey);

            var (ciphertext, sharedSecret) = kem.Encapsulate(kemPublicKey);

            var encryptedData = EncryptWithAes(message, sharedSecret);
            var recoveredSecret = kem.Decapsulate(ciphertext, kemSecretKey);
            var decryptedData = DecryptWithAes(encryptedData, recoveredSecret);

            var isSignatureValid = sig.Verify(decryptedData, signature, sigPublicKey);

            recoveredSecret.Should().BeEquivalentTo(sharedSecret);
            decryptedData.Should().BeEquivalentTo(message);
            isSignatureValid.Should().BeTrue();
        });

        sw.Stop();

        var throughput = totalOperations * 1000.0 / sw.ElapsedMilliseconds;
        
        var expectedMinThroughput = Math.Max(25, Environment.ProcessorCount * 5);

        throughput.Should().BeGreaterThan(expectedMinThroughput,
            $"Optimized parallel hybrid throughput should achieve at least {expectedMinThroughput} ops/sec " +
            $"(was {throughput:F1} ops/sec with {Environment.ProcessorCount} threads available)");
    }

    private static string GetSupportedKemAlgorithm()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty("At least one KEM algorithm should be supported");

        var nistAlgorithms = algorithms.Where(alg => KemAlgorithms.NISTStandardized.Contains(alg)).ToArray();
        return nistAlgorithms.Length > 0 ? nistAlgorithms[0] : algorithms[0];
    }

    private static string GetSupportedSignatureAlgorithm()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty("At least one signature algorithm should be supported");

        var nistAlgorithms = algorithms.Where(alg => SignatureAlgorithms.NISTStandardized.Contains(alg)).ToArray();
        return nistAlgorithms.Length > 0 ? nistAlgorithms[0] : algorithms[0];
    }

    private static byte[] EncryptWithAes(byte[] message, byte[] sharedSecret)
    {
        using var aes = Aes.Create();
        var keyMaterial = SHA256.HashData(sharedSecret);
        aes.Key = keyMaterial;
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();
        using var ms = new MemoryStream();

        ms.Write(aes.IV);
        using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        cs.Write(message);
        cs.FlushFinalBlock();

        return ms.ToArray();
    }

    private static byte[] DecryptWithAes(byte[] encryptedData, byte[] sharedSecret)
    {
        using var aes = Aes.Create();
        var keyMaterial = SHA256.HashData(sharedSecret);
        aes.Key = keyMaterial;

        using var ms = new MemoryStream(encryptedData);

        var iv = new byte[16];
        ms.ReadExactly(iv, 0, 16);
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var output = new MemoryStream();
        cs.CopyTo(output);

        return output.ToArray();
    }

    private static byte[] CreateCertificateData(string identity, byte[] publicKey)
    {
        var identityBytes = System.Text.Encoding.UTF8.GetBytes(identity);
        var certData = new byte[identityBytes.Length + publicKey.Length + 8];

        var identityLen = BitConverter.GetBytes(identityBytes.Length);
        var keyLen = BitConverter.GetBytes(publicKey.Length);

        var offset = 0;
        identityLen.CopyTo(certData, offset); offset += 4;
        keyLen.CopyTo(certData, offset); offset += 4;
        identityBytes.CopyTo(certData, offset); offset += identityBytes.Length;
        publicKey.CopyTo(certData, offset);

        return certData;
    }

#pragma warning restore S1144
}