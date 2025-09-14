using System.Security.Cryptography;
using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Core;
using OpenForge.Cryptography.LibOqs.KEM;
using OpenForge.Cryptography.LibOqs.SIG;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.Tests;

[Collection("LibOqs Collection")]
public sealed class SecurityTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void HybridCryptography_KeyReuse_ShouldPreventCrossContamination()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        using var kem = new Kem(kemAlgorithm);
        using var sig = new Sig(sigAlgorithm);

        var (kemPub1, kemSec1) = kem.GenerateKeyPair();
        var (sigPub1, sigSec1) = sig.GenerateKeyPair();
        var (kemPub2, kemSec2) = kem.GenerateKeyPair();
        var (sigPub2, sigSec2) = sig.GenerateKeyPair();

        kemPub1.Should().NotBeEquivalentTo(kemPub2);
        kemSec1.Should().NotBeEquivalentTo(kemSec2);
        sigPub1.Should().NotBeEquivalentTo(sigPub2);
        sigSec1.Should().NotBeEquivalentTo(sigSec2);

        var message = "Test message for key isolation"u8.ToArray();

        var signature1 = sig.Sign(message, sigSec1);
        var (ciphertext1, sharedSecret1) = kem.Encapsulate(kemPub1);

        var signature2 = sig.Sign(message, sigSec2);
        var (ciphertext2, sharedSecret2) = kem.Encapsulate(kemPub2);

        sig.Verify(message, signature1, sigPub1).Should().BeTrue("Signature1 should verify with public key 1");
        sig.Verify(message, signature2, sigPub2).Should().BeTrue("Signature2 should verify with public key 2");

        sig.Verify(message, signature1, sigPub2).Should().BeFalse("Signature1 should not verify with wrong public key");
        sig.Verify(message, signature2, sigPub1).Should().BeFalse("Signature2 should not verify with wrong public key");

        var recovered1 = kem.Decapsulate(ciphertext1, kemSec1);
        var recovered2 = kem.Decapsulate(ciphertext2, kemSec2);

        recovered1.Should().BeEquivalentTo(sharedSecret1);
        recovered2.Should().BeEquivalentTo(sharedSecret2);

        var wrongRecovered1 = kem.Decapsulate(ciphertext1, kemSec2);
        var wrongRecovered2 = kem.Decapsulate(ciphertext2, kemSec1);

        wrongRecovered1.Should().NotBeEquivalentTo(sharedSecret1);
        wrongRecovered2.Should().NotBeEquivalentTo(sharedSecret2);
    }

    [Fact]
    public void SignatureValidation_TamperedData_ShouldFailVerification()
    {
        var sigAlgorithm = GetSupportedSignatureAlgorithm();
        using var sig = new Sig(sigAlgorithm);
        var (publicKey, secretKey) = sig.GenerateKeyPair();

        var originalMessage = "Important secure message"u8.ToArray();
        var signature = sig.Sign(originalMessage, secretKey);

        sig.Verify(originalMessage, signature, publicKey).Should().BeTrue("Original message should verify");

        var tamperingTests = new[]
        {
            ("Modified first byte", ModifyByte(originalMessage, 0)),
            ("Modified last byte", ModifyByte(originalMessage, originalMessage.Length - 1)),
            ("Modified middle byte", ModifyByte(originalMessage, originalMessage.Length / 2)),
            ("Single bit flip", FlipBit(originalMessage, 0, 0)),
            ("Added byte", [.. originalMessage, .. "B"u8.ToArray()]),
            ("Removed byte", originalMessage[..^1]),
            ("Empty message", []),
            ("Completely different", "Malicious message"u8.ToArray())
        };

        foreach (var (testName, tamperedMessage) in tamperingTests)
        {
            var isValid = sig.Verify(tamperedMessage, signature, publicKey);
            isValid.Should().BeFalse($"Tampered message ({testName}) should not verify");
        }

        var signatureTamperingTests = new[]
        {
            ("Modified signature first byte", ModifyByte(signature, 0)),
            ("Modified signature last byte", ModifyByte(signature, signature.Length - 1)),
            ("Zeroed signature", new byte[signature.Length]),
            ("Random signature", RandomBytes(signature.Length))
        };

        foreach (var (testName, tamperedSignature) in signatureTamperingTests)
        {
            var isValid = sig.Verify(originalMessage, tamperedSignature, publicKey);
            isValid.Should().BeFalse($"Message with tampered signature ({testName}) should not verify");
        }
    }

    [Fact]
    public void KemDecapsulation_TamperedCiphertext_ShouldProduceDifferentSecrets()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        using var kem = new Kem(kemAlgorithm);
        var (publicKey, secretKey) = kem.GenerateKeyPair();

        var (originalCiphertext, originalSecret) = kem.Encapsulate(publicKey);

        var recoveredOriginal = kem.Decapsulate(originalCiphertext, secretKey);
        recoveredOriginal.Should().BeEquivalentTo(originalSecret);

        var tamperingTests = new[]
        {
            ("First byte modified", ModifyByte(originalCiphertext, 0)),
            ("Last byte modified", ModifyByte(originalCiphertext, originalCiphertext.Length - 1)),
            ("Middle byte modified", ModifyByte(originalCiphertext, originalCiphertext.Length / 2)),
            ("Single bit flip", FlipBit(originalCiphertext, 0, 0)),
            ("Multiple bytes modified", ModifyMultipleBytes(originalCiphertext, [0, 1, 2]))
        };

        foreach (var (testName, tamperedCiphertext) in tamperingTests)
        {
            var tamperedSecret = kem.Decapsulate(tamperedCiphertext, secretKey);
            tamperedSecret.Should().NotBeEquivalentTo(originalSecret,
                $"Tampered ciphertext ({testName}) should produce different shared secret");
        }
    }

    [Fact]
    public void HybridCryptography_ReplayAttack_ShouldProduceDifferentResults()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        using var kem = new Kem(kemAlgorithm);
        using var sig = new Sig(sigAlgorithm);

        var (kemPub, kemSec) = kem.GenerateKeyPair();
        var (sigPub, sigSec) = sig.GenerateKeyPair();

        var message = "Sensitive transaction data"u8.ToArray();

        var results = new List<(byte[] signature, byte[] ciphertext, byte[] sharedSecret)>();

        for (int i = 0; i < 5; i++)
        {
            var signature = sig.Sign(message, sigSec);
            var (ciphertext, sharedSecret) = kem.Encapsulate(kemPub);
            results.Add((signature, ciphertext, sharedSecret));
        }

        for (int i = 0; i < results.Count - 1; i++)
        {
            for (int j = i + 1; j < results.Count; j++)
            {
                results[i].signature.Should().NotBeEquivalentTo(results[j].signature,
                    $"Signatures {i} and {j} should be different (randomized signing)");
                results[i].ciphertext.Should().NotBeEquivalentTo(results[j].ciphertext,
                    "Ciphertexts should be different (randomized encapsulation)");
                results[i].sharedSecret.Should().NotBeEquivalentTo(results[j].sharedSecret,
                    "Shared secrets should be different (fresh randomness)");
            }
        }

        foreach (var (signature, _, _) in results)
        {
            sig.Verify(message, signature, sigPub).Should().BeTrue("All signatures should verify");
        }

        foreach (var (_, ciphertext, expectedSecret) in results)
        {
            var recovered = kem.Decapsulate(ciphertext, kemSec);
            recovered.Should().BeEquivalentTo(expectedSecret);
        }
    }

    [Fact]
    public void CertificateValidation_ChainIntegrity_ShouldDetectTampering()
    {
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        using var rootCa = new Sig(sigAlgorithm);
        using var intermediate = new Sig(sigAlgorithm);
        using var endEntity = new Sig(sigAlgorithm);

        var (rootPub, rootSec) = rootCa.GenerateKeyPair();
        var (intermediatePub, intermediateSec) = intermediate.GenerateKeyPair();
        var (endPub, _) = endEntity.GenerateKeyPair();

        var intermediateCert = CreateCertificateData("Intermediate CA", intermediatePub);
        var intermediateCertSig = rootCa.Sign(intermediateCert, rootSec);

        var endEntityCert = CreateCertificateData("End Entity", endPub);
        var endEntityCertSig = intermediate.Sign(endEntityCert, intermediateSec);

        rootCa.Verify(intermediateCert, intermediateCertSig, rootPub).Should().BeTrue("Legitimate intermediate cert should verify");
        intermediate.Verify(endEntityCert, endEntityCertSig, intermediatePub).Should().BeTrue("Legitimate end entity cert should verify");

        var tamperedIntermediateCert = ModifyByte(intermediateCert, 10);
        rootCa.Verify(tamperedIntermediateCert, intermediateCertSig, rootPub).Should().BeFalse("Tampered intermediate cert should not verify");

        var tamperedEndEntityCert = ModifyByte(endEntityCert, 5);
        intermediate.Verify(tamperedEndEntityCert, endEntityCertSig, intermediatePub).Should().BeFalse("Tampered end entity cert should not verify");

        var tamperedIntermediateSig = ModifyByte(intermediateCertSig, 0);
        rootCa.Verify(intermediateCert, tamperedIntermediateSig, rootPub).Should().BeFalse("Cert with tampered signature should not verify");

        rootCa.Verify(endEntityCert, endEntityCertSig, rootPub).Should().BeFalse("End entity cert should not verify with root key");
        intermediate.Verify(intermediateCert, intermediateCertSig, intermediatePub).Should().BeFalse("Intermediate cert should not verify with intermediate key");
    }

    [Fact]
    public void RandomnessQuality_KeyGeneration_ShouldProduceUnpredictableKeys()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        using var kem = new Kem(kemAlgorithm);
        using var sig = new Sig(sigAlgorithm);

        const int keyCount = 20;
        var kemPublicKeys = new List<byte[]>();
        var sigPublicKeys = new List<byte[]>();

        for (int i = 0; i < keyCount; i++)
        {
            var (kemPub, _) = kem.GenerateKeyPair();
            var (sigPub, _) = sig.GenerateKeyPair();
            kemPublicKeys.Add(kemPub);
            sigPublicKeys.Add(sigPub);
        }

        for (int i = 0; i < keyCount - 1; i++)
        {
            for (int j = i + 1; j < keyCount; j++)
            {
                kemPublicKeys[i].Should().NotBeEquivalentTo(kemPublicKeys[j], $"KEM keys {i} and {j} should be different");
                sigPublicKeys[i].Should().NotBeEquivalentTo(sigPublicKeys[j], $"Signature keys {i} and {j} should be different");
            }
        }

        foreach (var kemKey in kemPublicKeys)
        {
            kemKey.Should().NotBeEquivalentTo(new byte[kemKey.Length], "KEM public key should not be all zeros");
        }

        foreach (var sigKey in sigPublicKeys)
        {
            sigKey.Should().NotBeEquivalentTo(new byte[sigKey.Length], "Signature public key should not be all zeros");
        }
    }

    [Fact]
    public void SecureMessageTransmission_EndToEndSecurity_ShouldPreventCommonAttacks()
    {
        var kemAlgorithm = GetSupportedKemAlgorithm();
        var sigAlgorithm = GetSupportedSignatureAlgorithm();

        using var aliceKem = new Kem(kemAlgorithm);
        using var aliceSig = new Sig(sigAlgorithm);
        using var bobKem = new Kem(kemAlgorithm);

        var (aliceSigPub, aliceSigSec) = aliceSig.GenerateKeyPair();
        var (bobKemPub, bobKemSec) = bobKem.GenerateKeyPair();

        var originalMessage = "Confidential business data requiring integrity and authentication"u8.ToArray();

        var signature = aliceSig.Sign(originalMessage, aliceSigSec);
        var (ciphertext, sharedSecret) = aliceKem.Encapsulate(bobKemPub);
        var encryptedMessage = EncryptWithAes(originalMessage, sharedSecret);

        var recoveredSecret = bobKem.Decapsulate(ciphertext, bobKemSec);
        var decryptedMessage = DecryptWithAes(encryptedMessage, recoveredSecret);
        var isValidSignature = aliceSig.Verify(decryptedMessage, signature, aliceSigPub);

        decryptedMessage.Should().BeEquivalentTo(originalMessage);
        isValidSignature.Should().BeTrue();


        var tamperedCiphertext = ModifyByte(ciphertext, ciphertext.Length / 2);
        var attackerSecret = bobKem.Decapsulate(tamperedCiphertext, bobKemSec);
        attackerSecret.Should().NotBeEquivalentTo(sharedSecret, "Tampered ciphertext should produce different secret");

        var tamperedEncrypted = ModifyByte(encryptedMessage, 20);
        try
        {
            var tamperedResult = DecryptWithAes(tamperedEncrypted, recoveredSecret);
            tamperedResult.Should().NotBeEquivalentTo(originalMessage, "Tampered encrypted message should produce corrupted data");
        }
        catch (CryptographicException)
        {
            // Expected when AES detects tampering
        }

        var fakeSignature = RandomBytes(signature.Length);
        var isFakeValid = aliceSig.Verify(originalMessage, fakeSignature, aliceSigPub);
        isFakeValid.Should().BeFalse("Fake signature should not verify");

        using var attackerSig = new Sig(sigAlgorithm);
        var (attackerPub, _) = attackerSig.GenerateKeyPair();
        var isWrongKeyValid = attackerSig.Verify(originalMessage, signature, attackerPub);
        isWrongKeyValid.Should().BeFalse("Signature should not verify with wrong public key");
    }

    [Fact]
    public void AlgorithmSecurityLevel_ShouldMeetMinimumRequirements()
    {
        var kemAlgorithms = Kem.GetSupportedAlgorithms();
        var sigAlgorithms = Sig.GetSupportedAlgorithms();

        kemAlgorithms.Should().NotBeEmpty("At least one KEM algorithm should be supported");
        sigAlgorithms.Should().NotBeEmpty("At least one signature algorithm should be supported");

        var nistKemAlgorithms = kemAlgorithms.Where(alg => KemAlgorithms.NISTStandardized.Contains(alg)).ToArray();
        var nistSigAlgorithms = sigAlgorithms.Where(alg => SignatureAlgorithms.NISTStandardized.Contains(alg)).ToArray();

        if (nistKemAlgorithms.Length > 0)
        {
            foreach (var algorithm in nistKemAlgorithms)
            {
                using var kem = new Kem(algorithm);

                kem.PublicKeyLength.Should().BeGreaterThan(0, $"{algorithm} should have non-zero public key length");
                kem.SecretKeyLength.Should().BeGreaterThan(0, $"{algorithm} should have non-zero secret key length");
                kem.CiphertextLength.Should().BeGreaterThan(0, $"{algorithm} should have non-zero ciphertext length");
                kem.SharedSecretLength.Should().BeGreaterThan(0, $"{algorithm} should have non-zero shared secret length");

                kem.ClaimedNistLevel.Should().BeGreaterOrEqualTo(1, $"{algorithm} should claim at least NIST level 1 security");
                kem.ClaimedNistLevel.Should().BeLessOrEqualTo(5, $"{algorithm} should not claim impossible security levels");
            }
        }

        if (nistSigAlgorithms.Length > 0)
        {
            foreach (var algorithm in nistSigAlgorithms)
            {
                using var sig = new Sig(algorithm);

                sig.PublicKeyLength.Should().BeGreaterThan(0, $"{algorithm} should have non-zero public key length");
                sig.SecretKeyLength.Should().BeGreaterThan(0, $"{algorithm} should have non-zero secret key length");
                sig.SignatureLength.Should().BeGreaterThan(0, $"{algorithm} should have non-zero signature length");

                sig.ClaimedNistLevel.Should().BeGreaterOrEqualTo(1, $"{algorithm} should claim at least NIST level 1 security");
                sig.ClaimedNistLevel.Should().BeLessOrEqualTo(5, $"{algorithm} should not claim impossible security levels");
            }
        }
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

    private static byte[] ModifyByte(byte[] original, int index)
    {
        var modified = new byte[original.Length];
        original.CopyTo(modified, 0);
        if (index < modified.Length)
        {
            modified[index] ^= 0xFF;
        }
        return modified;
    }

    private static byte[] FlipBit(byte[] original, int byteIndex, int bitIndex)
    {
        var modified = new byte[original.Length];
        original.CopyTo(modified, 0);
        if (byteIndex < modified.Length)
        {
            modified[byteIndex] ^= (byte)(1 << bitIndex);
        }
        return modified;
    }

    private static byte[] ModifyMultipleBytes(byte[] original, int[] indices)
    {
        var modified = new byte[original.Length];
        original.CopyTo(modified, 0);
        foreach (var index in indices)
        {
            if (index < modified.Length)
            {
                modified[index] ^= 0xFF;
            }
        }
        return modified;
    }

    private static byte[] RandomBytes(int length)
    {
        var bytes = new byte[length];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
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