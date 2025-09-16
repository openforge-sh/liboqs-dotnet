using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Core;
using OpenForge.Cryptography.LibOqs.KEM;
using OpenForge.Cryptography.LibOqs.SIG;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.Tests;

[CollectionDefinition("LibOqs Collection")]
public sealed class EndToEndTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void SecureMessaging_EndToEndScenario_ShouldWorkCorrectly()
    {
        var aliceSignAlgorithm = GetSupportedSignatureAlgorithm();

        using var aliceSig = new Sig(aliceSignAlgorithm);

        var (alicePublicSignKey, aliceSecretSignKey) = aliceSig.GenerateKeyPair();

        var kemAlgorithm = GetSupportedKemAlgorithm();
        using var bobKem = new Kem(kemAlgorithm);
        var (bobKemPublicKey, bobKemSecretKey) = bobKem.GenerateKeyPair();

        var originalMessage = "Hello Bob! This is a secret message from Alice. ="u8.ToArray();

        var messageSignature = aliceSig.Sign(originalMessage, aliceSecretSignKey);

        using var aliceKem = new Kem(kemAlgorithm);
        var (ciphertext, sharedSecret) = aliceKem.Encapsulate(bobKemPublicKey);

        var encryptedData = EncryptWithSharedSecret(originalMessage, messageSignature, sharedSecret);

        var recoveredSharedSecret = bobKem.Decapsulate(ciphertext, bobKemSecretKey);

        var (decryptedMessage, decryptedSignature) = DecryptWithSharedSecret(encryptedData, recoveredSharedSecret);

        var isSignatureValid = aliceSig.Verify(decryptedMessage, decryptedSignature, alicePublicSignKey);

        recoveredSharedSecret.Should().BeEquivalentTo(sharedSecret, "Bob should recover the same shared secret");
        decryptedMessage.Should().BeEquivalentTo(originalMessage, "Bob should decrypt the original message");
        isSignatureValid.Should().BeTrue("Alice's signature should be valid");

        var decryptedText = Encoding.UTF8.GetString(decryptedMessage);
        decryptedText.Should().Be("Hello Bob! This is a secret message from Alice. =");
    }

    [Fact]
    public void HybridCryptography_MultipleRecipients_ShouldWork()
    {

        var signAlgorithm = GetSupportedSignatureAlgorithm();
        var kemAlgorithm = GetSupportedKemAlgorithm();

        using var aliceSig = new Sig(signAlgorithm);
        var (alicePublicSignKey, aliceSecretSignKey) = aliceSig.GenerateKeyPair();

        using var bobKem = new Kem(kemAlgorithm);
        using var charlieKem = new Kem(kemAlgorithm);
        using var daveKem = new Kem(kemAlgorithm);

        var (bobPublicKey, bobSecretKey) = bobKem.GenerateKeyPair();
        var (charliePublicKey, charlieSecretKey) = charlieKem.GenerateKeyPair();
        var (davePublicKey, daveSecretKey) = daveKem.GenerateKeyPair();

        var recipients = new[]
        {
            ("Bob", bobPublicKey, bobSecretKey, bobKem),
            ("Charlie", charliePublicKey, charlieSecretKey, charlieKem),
            ("Dave", davePublicKey, daveSecretKey, daveKem)
        };

        var message = "Important announcement for everyone!"u8.ToArray();
        var signature = aliceSig.Sign(message, aliceSecretSignKey);

        using var aliceKem = new Kem(kemAlgorithm);
        var encryptedMessages = new List<(string name, byte[] ciphertext, byte[] encryptedData)>();

        foreach (var (name, publicKey, _, _) in recipients)
        {
            var (ciphertext, sharedSecret) = aliceKem.Encapsulate(publicKey);
            var encryptedData = EncryptWithSharedSecret(message, signature, sharedSecret);
            encryptedMessages.Add((name, ciphertext, encryptedData));
        }

        for (int i = 0; i < recipients.Length; i++)
        {
            var (name, _, secretKey, kem) = recipients[i];
            var (_, ciphertext, encryptedData) = encryptedMessages[i];

            var sharedSecret = kem.Decapsulate(ciphertext, secretKey);
            var (decryptedMessage, decryptedSignature) = DecryptWithSharedSecret(encryptedData, sharedSecret);
            var isValid = aliceSig.Verify(decryptedMessage, decryptedSignature, alicePublicSignKey);

            decryptedMessage.Should().BeEquivalentTo(message, $"{name} should decrypt the original message");
            isValid.Should().BeTrue($"{name} should verify Alice's signature");
        }
    }

    [Fact]
    public void DigitalCertificate_ChainOfTrust_ShouldWork()
    {

        var signAlgorithm = GetSupportedSignatureAlgorithm();

        using var caSig = new Sig(signAlgorithm);
        var (caPublicKey, caSecretKey) = caSig.GenerateKeyPair();

        using var aliceSig = new Sig(signAlgorithm);
        using var bobSig = new Sig(signAlgorithm);

        var (alicePublicKey, aliceSecretKey) = aliceSig.GenerateKeyPair();
        var (bobPublicKey, _) = bobSig.GenerateKeyPair();

        var aliceCertData = CreateCertificateData("Alice Smith", alicePublicKey);
        var bobCertData = CreateCertificateData("Bob Jones", bobPublicKey);

        var aliceCertSignature = caSig.Sign(aliceCertData, caSecretKey);
        var _ = caSig.Sign(bobCertData, caSecretKey);

        var message = "Hello Bob, this is Alice"u8.ToArray();
        var messageSignature = aliceSig.Sign(message, aliceSecretKey);

        var isAliceCertValid = caSig.Verify(aliceCertData, aliceCertSignature, caPublicKey);
        isAliceCertValid.Should().BeTrue("Alice's certificate should be valid");

        var isMessageValid = aliceSig.Verify(message, messageSignature, alicePublicKey);
        isMessageValid.Should().BeTrue("Alice's message signature should be valid");

        var fakeCertData = CreateCertificateData("Alice Smith", bobPublicKey);
        var isFakeCertValid = caSig.Verify(fakeCertData, aliceCertSignature, caPublicKey);
        isFakeCertValid.Should().BeFalse("Fake certificate should not be valid");
    }

    [Fact]
    public void SecureFileTransfer_WithIntegrity_ShouldWork()
    {

        var signAlgorithm = GetSupportedSignatureAlgorithm();
        var kemAlgorithm = GetSupportedKemAlgorithm();

        using var aliceSig = new Sig(signAlgorithm);
        using var aliceKem = new Kem(kemAlgorithm);
        using var bobKem = new Kem(kemAlgorithm);

        var (alicePublicSignKey, aliceSecretSignKey) = aliceSig.GenerateKeyPair();
        var (bobKemPublicKey, bobKemSecretKey) = bobKem.GenerateKeyPair();

        var fileData = new byte[1024 * 1024];
        RandomNumberGenerator.Fill(fileData);

        var fileHash = SHA256.HashData(fileData);
        var hashSignature = aliceSig.Sign(fileHash, aliceSecretSignKey);

        var (ciphertext, sharedSecret) = aliceKem.Encapsulate(bobKemPublicKey);

        var encryptedFile = EncryptWithSharedSecret(fileData, hashSignature, sharedSecret);

        var recoveredSharedSecret = bobKem.Decapsulate(ciphertext, bobKemSecretKey);
        var (decryptedFile, decryptedSignature) = DecryptWithSharedSecret(encryptedFile, recoveredSharedSecret);

        var decryptedFileHash = SHA256.HashData(decryptedFile);
        var isIntegrityValid = aliceSig.Verify(decryptedFileHash, decryptedSignature, alicePublicSignKey);

        decryptedFile.Should().BeEquivalentTo(fileData, "File should be decrypted correctly");
        decryptedFileHash.Should().BeEquivalentTo(fileHash, "File hash should match");
        isIntegrityValid.Should().BeTrue("File integrity signature should be valid");
    }

    [Fact]
    public void QuantumSafeKeyExchange_DifferentAlgorithms_ShouldBeInteroperable()
    {

        var kemAlgorithms = GetMultipleSupportedKemAlgorithms(3);
        var signAlgorithms = GetMultipleSupportedSignatureAlgorithms(2);

        kemAlgorithms.Should().NotBeEmpty("At least one KEM algorithm should be supported");
        signAlgorithms.Should().NotBeEmpty("At least one signature algorithm should be supported");

        var message = "Quantum-safe interoperability test"u8.ToArray();
        var results = new List<(string kemAlg, string sigAlg, bool success)>();

        foreach (var kemAlg in kemAlgorithms)
        {
            foreach (var sigAlg in signAlgorithms)
            {
                try
                {
                    using var kem = new Kem(kemAlg);
                    using var sig = new Sig(sigAlg);

                    var (kemPub, kemSec) = kem.GenerateKeyPair();
                    var (sigPub, sigSec) = sig.GenerateKeyPair();

                    var (ciphertext, sharedSecret) = kem.Encapsulate(kemPub);
                    var recoveredSecret = kem.Decapsulate(ciphertext, kemSec);

                    var signature = sig.Sign(message, sigSec);
                    var isValid = sig.Verify(message, signature, sigPub);

                    var success = recoveredSecret.SequenceEqual(sharedSecret) && isValid;
                    results.Add((kemAlg, sigAlg, success));
                }
                catch (NotSupportedException)
                {
                    results.Add((kemAlg, sigAlg, false));
                }
                catch (ArgumentException)
                {
                    results.Add((kemAlg, sigAlg, false));
                }
                catch (InvalidOperationException)
                {
                    results.Add((kemAlg, sigAlg, false));
                }
                catch (OutOfMemoryException)
                {
                    results.Add((kemAlg, sigAlg, false));
                }
                catch (DllNotFoundException)
                {
                    results.Add((kemAlg, sigAlg, false));
                }
            }
        }

        results.Should().AllSatisfy(r => r.success.Should().BeTrue(
            $"Combination {r.kemAlg} + {r.sigAlg} should work"));
    }

    [Fact]
    public void RealWorldScenario_SecureEmailSystem_ShouldWork()
    {

        var signAlgorithm = GetSupportedSignatureAlgorithm();
        var kemAlgorithm = GetSupportedKemAlgorithm();

        var users = new Dictionary<string, (Sig sig, Kem kem, byte[] sigPub, byte[] sigSec, byte[] kemPub, byte[] kemSec)>();

        foreach (var username in new[] { "Alice", "Bob", "Charlie", "Dave" })
        {
            var sig = new Sig(signAlgorithm);
            var kem = new Kem(kemAlgorithm);
            var (sigPub, sigSec) = sig.GenerateKeyPair();
            var (kemPub, kemSec) = kem.GenerateKeyPair();
            users[username] = (sig, kem, sigPub, sigSec, kemPub, kemSec);
        }

        try
        {
            var originalMessage = "Meeting tomorrow at 2 PM in conference room A"u8.ToArray();
            var originalSignature = users["Alice"].sig.Sign(originalMessage, users["Alice"].sigSec);

            var encryptedForRecipients = new Dictionary<string, (byte[] ciphertext, byte[] encryptedData)>();

            foreach (var recipient in new[] { "Bob", "Charlie" })
            {
                var (ciphertext, sharedSecret) = users["Alice"].kem.Encapsulate(users[recipient].kemPub);
                var encryptedData = EncryptWithSharedSecret(originalMessage, originalSignature, sharedSecret);
                encryptedForRecipients[recipient] = (ciphertext, encryptedData);
            }

            foreach (var recipient in new[] { "Bob", "Charlie" })
            {
                var (ciphertext, encryptedData) = encryptedForRecipients[recipient];
                var sharedSecret = users[recipient].kem.Decapsulate(ciphertext, users[recipient].kemSec);
                var (decryptedMsg, decryptedSig) = DecryptWithSharedSecret(encryptedData, sharedSecret);
                var isValid = users["Alice"].sig.Verify(decryptedMsg, decryptedSig, users["Alice"].sigPub);

                decryptedMsg.Should().BeEquivalentTo(originalMessage);
                isValid.Should().BeTrue();
            }

            var replyMessage = "Sounds good, I'll be there!"u8.ToArray();
            var replySignature = users["Bob"].sig.Sign(replyMessage, users["Bob"].sigSec);
            var (replyCiphertext, replySharedSecret) = users["Bob"].kem.Encapsulate(users["Alice"].kemPub);
            var encryptedReply = EncryptWithSharedSecret(replyMessage, replySignature, replySharedSecret);

            var recoveredReplySecret = users["Alice"].kem.Decapsulate(replyCiphertext, users["Alice"].kemSec);
            var (decryptedReply, decryptedReplySig) = DecryptWithSharedSecret(encryptedReply, recoveredReplySecret);
            var isReplyValid = users["Bob"].sig.Verify(decryptedReply, decryptedReplySig, users["Bob"].sigPub);

            decryptedReply.Should().BeEquivalentTo(replyMessage);
            isReplyValid.Should().BeTrue();

            var forwardMessage = Encoding.UTF8.GetBytes("FWD: " + Encoding.UTF8.GetString(originalMessage));
            var forwardSignature = users["Charlie"].sig.Sign(forwardMessage, users["Charlie"].sigSec);
            var (fwdCiphertext, fwdSharedSecret) = users["Charlie"].kem.Encapsulate(users["Dave"].kemPub);
            var encryptedForward = EncryptWithSharedSecret(forwardMessage, forwardSignature, fwdSharedSecret);

            var recoveredFwdSecret = users["Dave"].kem.Decapsulate(fwdCiphertext, users["Dave"].kemSec);
            var (decryptedFwd, decryptedFwdSig) = DecryptWithSharedSecret(encryptedForward, recoveredFwdSecret);
            var isFwdValid = users["Charlie"].sig.Verify(decryptedFwd, decryptedFwdSig, users["Charlie"].sigPub);

            decryptedFwd.Should().BeEquivalentTo(forwardMessage);
            isFwdValid.Should().BeTrue();

            var decryptedFwdText = Encoding.UTF8.GetString(decryptedFwd);
            decryptedFwdText.Should().Contain("FWD:");
            decryptedFwdText.Should().Contain("Meeting tomorrow");

            var allPublicKeys = users.Values.Select(u => u.sigPub).Concat(users.Values.Select(u => u.kemPub)).ToArray();
            allPublicKeys.Should().OnlyHaveUniqueItems();
        }
        finally
        {
            foreach (var (sig, kem, _, _, _, _) in users.Values)
            {
                sig.Dispose();
                kem.Dispose();
            }
        }
    }

    [Fact]
    public void AdvancedScenario_HybridQuantumClassicalCryptography_ShouldWork()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var signAlgorithm = GetSupportedSignatureAlgorithm();

        using var kem = new Kem(kemAlgorithm);
        using var sig = new Sig(signAlgorithm);

        var (kemPub1, kemSec1) = kem.GenerateKeyPair();
        var (sigPub1, sigSec1) = sig.GenerateKeyPair();

        var (kemPub2, kemSec2) = kem.GenerateKeyPair();
        var (sigPub2, sigSec2) = sig.GenerateKeyPair();

        var session1Message = "First secure message"u8.ToArray();
        var (ciphertext1, sharedSecret1) = kem.Encapsulate(kemPub1);
        var signature1 = sig.Sign(session1Message, sigSec1);
        var recoveredSecret1 = kem.Decapsulate(ciphertext1, kemSec1);
        var isValid1 = sig.Verify(session1Message, signature1, sigPub1);

        sharedSecret1.Should().BeEquivalentTo(recoveredSecret1);
        isValid1.Should().BeTrue();

        var session2Message = "Second secure message after key rotation"u8.ToArray();
        var (ciphertext2, sharedSecret2) = kem.Encapsulate(kemPub2);
        var signature2 = sig.Sign(session2Message, sigSec2);
        var recoveredSecret2 = kem.Decapsulate(ciphertext2, kemSec2);
        var isValid2 = sig.Verify(session2Message, signature2, sigPub2);

        sharedSecret2.Should().BeEquivalentTo(recoveredSecret2);
        isValid2.Should().BeTrue();

        sharedSecret1.Should().NotBeEquivalentTo(sharedSecret2, "Session keys should be different after key rotation");

        var recoveredWithOldKey = kem.Decapsulate(ciphertext1, kemSec1);
        recoveredWithOldKey.Should().BeEquivalentTo(sharedSecret1, "Old keys should still work for decryption");
    }

    [Fact]
    public async Task StressTest_MultipleConcurrentOperations_ShouldMaintainIntegrity()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var signAlgorithm = GetSupportedSignatureAlgorithm();

        const int operationCount = 50;
        var results = new ConcurrentBag<(bool success, byte[] sharedSecret, byte[] signature)>();

        var tasks = new List<Task>();

        for (int i = 0; i < operationCount; i++)
        {
            var taskId = i;
            var task = Task.Run(() =>
            {
                try
                {
                    using var kem = new Kem(kemAlgorithm);
                    using var sig = new Sig(signAlgorithm);

                    var (kemPub, kemSec) = kem.GenerateKeyPair();
                    var (sigPub, sigSec) = sig.GenerateKeyPair();

                    var (ciphertext, sharedSecret) = kem.Encapsulate(kemPub);
                    var recoveredSecret = kem.Decapsulate(ciphertext, kemSec);

                    var message = Encoding.UTF8.GetBytes($"Test message {taskId}");
                    var signature = sig.Sign(message, sigSec);
                    var isValid = sig.Verify(message, signature, sigPub);

                    if (isValid && recoveredSecret.SequenceEqual(sharedSecret))
                    {
                        results.Add((true, sharedSecret, signature));
                    }
                    else
                    {
                        results.Add((false, Array.Empty<byte>(), Array.Empty<byte>()));
                    }
                }
                catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or CryptographicException or OutOfMemoryException)
                {
                    results.Add((false, Array.Empty<byte>(), Array.Empty<byte>()));
                }
            }, TestContext.Current.CancellationToken);

            tasks.Add(task);
        }

        await Task.WhenAll(tasks);

        results.Should().HaveCount(operationCount);
        results.Should().AllSatisfy(r => r.success.Should().BeTrue("All concurrent operations should succeed"));

        results.Should().AllSatisfy(r =>
        {
            r.sharedSecret.Should().NotBeEmpty("Shared secrets should not be empty");
            r.signature.Should().NotBeEmpty("Signatures should not be empty");
        });
    }

    private static string GetSupportedSignatureAlgorithm()
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty("At least one signature algorithm should be supported");

        var nistAlgorithms = algorithms.Where(alg => SignatureAlgorithms.NISTStandardized.Contains(alg)).ToArray();
        if (nistAlgorithms.Length > 0)
            return nistAlgorithms[0];

        return algorithms[0];
    }

    private static string GetSupportedKemAlgorithm()
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        algorithms.Should().NotBeEmpty("At least one KEM algorithm should be supported");

        var nistAlgorithms = algorithms.Where(alg => KemAlgorithms.NISTStandardized.Contains(alg)).ToArray();
        if (nistAlgorithms.Length > 0)
            return nistAlgorithms[0];

        return algorithms[0];
    }

    private static string[] GetMultipleSupportedKemAlgorithms(int maxCount)
    {
        var algorithms = Kem.GetSupportedAlgorithms();
        return [.. algorithms.Take(maxCount)];
    }

    private static string[] GetMultipleSupportedSignatureAlgorithms(int maxCount)
    {
        var algorithms = Sig.GetSupportedAlgorithms();
        return [.. algorithms.Take(maxCount)];
    }

    private static byte[] EncryptWithSharedSecret(byte[] message, byte[] signature, byte[] sharedSecret)
    {
        using var aes = Aes.Create();

        var keyMaterial = SHA256.HashData(sharedSecret);
        aes.Key = keyMaterial;
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();
        using var ms = new MemoryStream();

        ms.Write(aes.IV);

        using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);

        var messageLen = BitConverter.GetBytes(message.Length);
        var sigLen = BitConverter.GetBytes(signature.Length);

        cs.Write(messageLen);
        cs.Write(sigLen);
        cs.Write(message);
        cs.Write(signature);
        cs.FlushFinalBlock();

        return ms.ToArray();
    }

    private static (byte[] message, byte[] signature) DecryptWithSharedSecret(byte[] encryptedData, byte[] sharedSecret)
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

        var lengthBuffer = new byte[4];
        cs.ReadExactly(lengthBuffer, 0, 4);
        var messageLen = BitConverter.ToInt32(lengthBuffer, 0);

        cs.ReadExactly(lengthBuffer, 0, 4);
        var sigLen = BitConverter.ToInt32(lengthBuffer, 0);

        var message = new byte[messageLen];
        var signature = new byte[sigLen];

        cs.ReadExactly(message, 0, messageLen);
        cs.ReadExactly(signature, 0, sigLen);

        return (message, signature);
    }

    private static byte[] CreateCertificateData(string identity, byte[] publicKey)
    {
        var identityBytes = Encoding.UTF8.GetBytes(identity);
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

    [Fact]
    public void ComplexScenario_MultiLayeredSecurityWithAuditTrail_ShouldWork()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var signAlgorithm = GetSupportedSignatureAlgorithm();

        using var kem = new Kem(kemAlgorithm);
        using var sig = new Sig(signAlgorithm);

        var (senderSigPub, senderSigSec) = sig.GenerateKeyPair();
        kem.GenerateKeyPair();

        var recipients = new List<(string name, byte[] kemPub, byte[] kemSec)>();
        for (int i = 0; i < 3; i++)
        {
            var (recipientPub, recipientSec) = kem.GenerateKeyPair();
            recipients.Add(($"Recipient{i}", recipientPub, recipientSec));
        }

        var documentContent = "CONFIDENTIAL: Q4 Financial Projections"u8.ToArray();
        var documentMetadata = Encoding.UTF8.GetBytes($"Document ID: DOC-{DateTime.UtcNow:yyyyMMdd-HHmmss}");

        var documentSignature = sig.Sign(documentContent, senderSigSec);

        var documentEncryptionKeys = new List<(string recipient, byte[] ciphertext, byte[] sharedSecret)>();
        foreach (var (name, kemPub, _) in recipients)
        {
            var (ciphertext, sharedSecret) = kem.Encapsulate(kemPub);
            documentEncryptionKeys.Add((name, ciphertext, sharedSecret));
        }

        var auditTrailData = new List<byte>();
        auditTrailData.AddRange(documentMetadata);
        auditTrailData.AddRange(BitConverter.GetBytes(documentContent.Length));
        auditTrailData.AddRange(BitConverter.GetBytes(documentEncryptionKeys.Count));
        foreach (var (recipient, _, _) in documentEncryptionKeys)
        {
            auditTrailData.AddRange(Encoding.UTF8.GetBytes(recipient));
        }
        var auditTrailSignature = sig.Sign([.. auditTrailData], senderSigSec);

        var verificationResults = new List<(string recipient, bool documentValid, bool auditValid, byte[] decryptedContent)>();

        foreach (var (recipientName, ciphertext, _) in documentEncryptionKeys)
        {
            var (_, _, kemSec) = recipients.First(r => r.name == recipientName);

            kem.Decapsulate(ciphertext, kemSec);

            var decryptedContent = documentContent;

            var isDocumentValid = sig.Verify(documentContent, documentSignature, senderSigPub);

            var isAuditValid = sig.Verify(auditTrailData.ToArray(), auditTrailSignature, senderSigPub);

            verificationResults.Add((recipientName, isDocumentValid, isAuditValid, decryptedContent));
        }

        verificationResults.Should().HaveCount(3);
        verificationResults.Should().AllSatisfy(result =>
        {
            result.documentValid.Should().BeTrue($"Document should be valid for {result.recipient}");
            result.auditValid.Should().BeTrue($"Audit trail should be valid for {result.recipient}");
            result.decryptedContent.Should().BeEquivalentTo(documentContent, $"Content should match for {result.recipient}");
        });

        var sharedSecrets = documentEncryptionKeys.Select(k => k.sharedSecret).ToList();
        for (int i = 0; i < sharedSecrets.Count; i++)
        {
            for (int j = i + 1; j < sharedSecrets.Count; j++)
            {
                sharedSecrets[i].Should().NotBeEquivalentTo(sharedSecrets[j],
                    "Each KEM encapsulation should produce a unique shared secret for security");
            }
        }
    }
}