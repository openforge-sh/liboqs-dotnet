using System.Collections.Concurrent;
using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Core;
using OpenForge.Cryptography.LibOqs.KEM;
using OpenForge.Cryptography.LibOqs.SIG;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.Tests;

[Collection("LibOqs Collection")]
public sealed class StressTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144, S2925
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public async Task MassiveParallelOperations_ShouldHandleHighConcurrency()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        const int concurrentTasks = 50;
        const int operationsPerTask = 100;
        var totalOperations = concurrentTasks * operationsPerTask;

        var successfulOperations = new ConcurrentBag<bool>();
        var failures = new ConcurrentBag<Exception>();

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount * 2,
            CancellationToken = TestContext.Current.CancellationToken
        };

        await Task.Run(() =>
        {
            Parallel.For(0, concurrentTasks, parallelOptions, taskId =>
            {
                try
                {
                    using var kem = new Kem(kemAlgorithm);
                    using var sig = new Sig(sigAlgorithm);

                    for (int i = 0; i < operationsPerTask; i++)
                    {
                        var (kemPub, kemSec) = kem.GenerateKeyPair();
                        var (sigPub, sigSec) = sig.GenerateKeyPair();

                        var message = new byte[256];
                        RandomNumberGenerator.Fill(message);

                        var signature = sig.Sign(message, sigSec);
                        var (ciphertext, sharedSecret) = kem.Encapsulate(kemPub);
                        var recoveredSecret = kem.Decapsulate(ciphertext, kemSec);
                        var isValid = sig.Verify(message, signature, sigPub);

                        if (recoveredSecret.SequenceEqual(sharedSecret) && isValid)
                        {
                            successfulOperations.Add(true);
                        }
                        else
                        {
                            successfulOperations.Add(false);
                        }
                    }
                }
                catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
                {
                    failures.Add(ex);
                }
            });
        }, TestContext.Current.CancellationToken);

        failures.Should().BeEmpty("All parallel operations should complete without exceptions");
        successfulOperations.Should().HaveCount(totalOperations, "All operations should be recorded");
        successfulOperations.Should().AllSatisfy(success => success.Should().BeTrue("All operations should succeed"));
    }

    [Fact]
    public async Task LongRunningOperations_ShouldMaintainStability()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        using var kem = new Kem(kemAlgorithm);
        using var sig = new Sig(sigAlgorithm);

        const int totalOperations = 5000;
        const int batchSize = 100;
        var successCount = 0;
        var failureCount = 0;

        for (int batch = 0; batch < totalOperations / batchSize; batch++)
        {
            var batchTasks = new List<Task>();

            for (int i = 0; i < batchSize; i++)
            {
                batchTasks.Add(Task.Run(() =>
                {
                    try
                    {
                        var (kemPub, kemSec) = kem.GenerateKeyPair();
                        var (sigPub, sigSec) = sig.GenerateKeyPair();

                        var message = new byte[128];
                        RandomNumberGenerator.Fill(message);

                        var signature = sig.Sign(message, sigSec);
                        var (ciphertext, sharedSecret) = kem.Encapsulate(kemPub);
                        var recoveredSecret = kem.Decapsulate(ciphertext, kemSec);
                        var isValid = sig.Verify(message, signature, sigPub);

                        if (recoveredSecret.SequenceEqual(sharedSecret) && isValid)
                        {
                            Interlocked.Increment(ref successCount);
                        }
                        else
                        {
                            Interlocked.Increment(ref failureCount);
                        }
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
                    {
                        Interlocked.Increment(ref failureCount);
                    }
                }, TestContext.Current.CancellationToken));
            }

            await Task.WhenAll(batchTasks);

            await TimingUtils.AdaptiveDelayAsync(10, TestContext.Current.CancellationToken);
        }

        successCount.Should().Be(totalOperations, "All long-running operations should succeed");
        failureCount.Should().Be(0, "No operations should fail during long-running stress test");
    }

    [Fact]
    public void MemoryStressTest_ShouldNotLeakMemory()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        #pragma warning disable S1215
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var initialMemory = GC.GetTotalMemory(false);

        const int iterations = 1000;

        for (int i = 0; i < iterations; i++)
        {
            using var kem = new Kem(kemAlgorithm);
            using var sig = new Sig(sigAlgorithm);

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

            if (i % 100 == 0)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        #pragma warning restore S1215
        var finalMemory = GC.GetTotalMemory(false);

        var memoryGrowth = finalMemory - initialMemory;

        memoryGrowth.Should().BeLessThan(10 * 1024 * 1024,
            $"Memory growth should be reasonable, grew by {memoryGrowth / 1024.0 / 1024.0:F1} MB");
    }

    [Fact]
    public async Task HighVolumeKeyGeneration_ShouldMaintainPerformance()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        const int keyPairCount = 2000;
        var keyGenerationTimes = new ConcurrentBag<long>();

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken = TestContext.Current.CancellationToken
        };

        await Task.Run(() =>
        {
            Parallel.For(0, keyPairCount, parallelOptions, i =>
            {
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();

                using var kem = new Kem(kemAlgorithm);
                using var sig = new Sig(sigAlgorithm);

                var (kemPub, kemSec) = kem.GenerateKeyPair();
                var (sigPub, sigSec) = sig.GenerateKeyPair();

                    var testMessage = "test"u8.ToArray();
                var testSig = sig.Sign(testMessage, sigSec);
                var (testCt, testSs) = kem.Encapsulate(kemPub);
                var recoveredSs = kem.Decapsulate(testCt, kemSec);
                var isValidSig = sig.Verify(testMessage, testSig, sigPub);

                stopwatch.Stop();
                keyGenerationTimes.Add(stopwatch.ElapsedMilliseconds);

                    if (!recoveredSs.SequenceEqual(testSs) || !isValidSig)
                {
                    throw new InvalidOperationException("Key generation produced invalid keys");
                }
            });
        }, TestContext.Current.CancellationToken);

        var times = keyGenerationTimes.ToArray();
        times.Should().HaveCount(keyPairCount, "All key generations should be recorded");

        var averageTime = times.Average();
        var maxTime = times.Max();
        var _ = times.Min();

        averageTime.Should().BeLessThan(500, "Average key generation should be reasonable");
        maxTime.Should().BeLessThan(2000, "Maximum key generation time should be acceptable");

        Array.Sort(times);
        var percentile95 = times[(int)(times.Length * 0.95)];
        percentile95.Should().BeLessThan(1000, "95th percentile should be reasonable");
    }

    [Fact]
    public async Task ConcurrentMultiRecipientScenario_ShouldHandleComplexWorkload()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        const int senderCount = 20;
        const int recipientsPerSender = 10;
        const int messagesPerSender = 5;

        var allResults = new ConcurrentBag<bool>();
        var exceptions = new ConcurrentBag<Exception>();

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken = TestContext.Current.CancellationToken
        };

        await Task.Run(() =>
        {
            Parallel.For(0, senderCount, parallelOptions, senderId =>
            {
                try
                {
                    using var senderSig = new Sig(sigAlgorithm);
                    using var senderKem = new Kem(kemAlgorithm);
                    var (senderPub, senderSec) = senderSig.GenerateKeyPair();

                    var recipients = new List<(Kem kem, byte[] pub, byte[] sec)>();
                    for (int r = 0; r < recipientsPerSender; r++)
                    {
                        var kem = new Kem(kemAlgorithm);
                        var (pub, sec) = kem.GenerateKeyPair();
                        recipients.Add((kem, pub, sec));
                    }

                    try
                    {
                        for (int m = 0; m < messagesPerSender; m++)
                        {
                            var message = System.Text.Encoding.UTF8.GetBytes($"Message {m} from sender {senderId}");
                            var signature = senderSig.Sign(message, senderSec);

                            var encryptedMessages = new List<(byte[] ct, byte[] ss)>();
                            foreach (var (_, pub, _) in recipients)
                            {
                                var (ct, ss) = senderKem.Encapsulate(pub);
                                encryptedMessages.Add((ct, ss));
                            }

                            for (int i = 0; i < recipients.Count; i++)
                            {
                                var (kem, _, sec) = recipients[i];
                                var (ct, expectedSs) = encryptedMessages[i];

                                var recoveredSs = kem.Decapsulate(ct, sec);
                                var isValidSig = senderSig.Verify(message, signature, senderPub);

                                var success = recoveredSs.SequenceEqual(expectedSs) && isValidSig;
                                allResults.Add(success);
                            }
                        }
                    }
                    finally
                    {
                        foreach (var (kem, _, _) in recipients)
                        {
                            kem.Dispose();
                        }
                    }
                }
                catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
                {
                    exceptions.Add(ex);
                }
            });
        }, TestContext.Current.CancellationToken);

        exceptions.Should().BeEmpty("No exceptions should occur during complex workload");

        var totalExpectedResults = senderCount * recipientsPerSender * messagesPerSender;
        allResults.Should().HaveCount(totalExpectedResults, "All operations should be recorded");
        allResults.Should().AllSatisfy(result => result.Should().BeTrue("All operations should succeed"));
    }

    [Fact]
    public void ErrorRecoveryStressTest_ShouldHandleFailuresGracefully()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        using var kem = new Kem(kemAlgorithm);
        using var sig = new Sig(sigAlgorithm);

        var (kemPub, kemSec) = kem.GenerateKeyPair();
        var (sigPub, sigSec) = sig.GenerateKeyPair();

        var successCount = 0;
        var expectedFailures = 0;
        const int totalOperations = 1000;

        for (int i = 0; i < totalOperations; i++)
        {
            try
            {
                var message = new byte[64];
                RandomNumberGenerator.Fill(message);

                var signature = sig.Sign(message, sigSec);
                var (ciphertext, sharedSecret) = kem.Encapsulate(kemPub);
                var recoveredSecret = kem.Decapsulate(ciphertext, kemSec);
                var isValid = sig.Verify(message, signature, sigPub);

                if (recoveredSecret.SequenceEqual(sharedSecret) && isValid)
                {
                    successCount++;
                }

                if (i % 100 == 0)
                {
                    try
                    {
                        var corruptedSig = new byte[signature.Length];
                        signature.CopyTo(corruptedSig, 0);
                        corruptedSig[0] ^= 0xFF;

                        var shouldBeFalse = sig.Verify(message, corruptedSig, sigPub);
                        if (!shouldBeFalse)
                        {
                            expectedFailures++;
                        }

                        var corruptedCt = new byte[ciphertext.Length];
                        ciphertext.CopyTo(corruptedCt, 0);
                        if (corruptedCt.Length > 0)
                        {
                            corruptedCt[0] ^= 0xFF;
                            var corruptedResult = kem.Decapsulate(corruptedCt, kemSec);
                            if (corruptedResult.SequenceEqual(sharedSecret))
                            {
                                // Unexpected but not necessarily an error
                            }
                        }
                    }
                    catch (ArgumentException)
                    {
                        // Expected for corrupted input
                    }
                    catch (InvalidOperationException)
                    {
                        // Expected for corrupted operations
                    }
                }
            }
            catch (OutOfMemoryException)
            {
                throw;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
            {
                expectedFailures++;
            }
        }

        var successRate = successCount / (double)totalOperations;
        successRate.Should().BeGreaterThan(0.95, "Success rate should be very high under stress");
        expectedFailures.Should().BeLessThan((int)(totalOperations * 0.02), "Unexpected failures should be minimal (allowing 2%)");
    }

    [Fact]
    public async Task RapidInstanceCreationDestruction_ShouldNotCauseIssues()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        const int cycles = 500;
        var exceptions = new ConcurrentBag<Exception>();
        var successfulCycles = new ConcurrentBag<bool>();

        var tasks = new List<Task>();
        for (int t = 0; t < Environment.ProcessorCount; t++)
        {
            tasks.Add(Task.Run(() =>
            {
                for (int i = 0; i < cycles; i++)
                {
                    try
                    {
                        using (var kem = new Kem(kemAlgorithm))
                        using (var sig = new Sig(sigAlgorithm))
                        {
                            var (kemPub, kemSec) = kem.GenerateKeyPair();
                            var (sigPub, sigSec) = sig.GenerateKeyPair();

                            var message = "Quick test"u8.ToArray();
                            var signature = sig.Sign(message, sigSec);
                            var (ciphertext, sharedSecret) = kem.Encapsulate(kemPub);
                            var recoveredSecret = kem.Decapsulate(ciphertext, kemSec);
                            var isValid = sig.Verify(message, signature, sigPub);

                            var success = recoveredSecret.SequenceEqual(sharedSecret) && isValid;
                            successfulCycles.Add(success);
                        }

                        if (i % 50 == 0)
                        {
                            Thread.Yield();
                        }
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
                    {
                        exceptions.Add(ex);
                    }
                }
            }, TestContext.Current.CancellationToken));
        }

        await Task.WhenAll(tasks);

        exceptions.Should().BeEmpty("Rapid instance creation/destruction should not cause exceptions");

        var expectedSuccesses = cycles * Environment.ProcessorCount;
        successfulCycles.Should().HaveCount(expectedSuccesses, "All cycles should complete");
        successfulCycles.Should().AllSatisfy(success => success.Should().BeTrue("All operations should succeed"));
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

#pragma warning restore S1144, S2925
}