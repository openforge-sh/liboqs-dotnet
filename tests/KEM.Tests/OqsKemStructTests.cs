using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.KEM.Tests;

[Collection("LibOqs Collection")]
public sealed class OqsKemStructTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void OqsKem_Equals_WithSameValues_ShouldReturnTrue()
    {
        var kem1 = CreateTestOqsKem();
        var kem2 = CreateTestOqsKem();

        kem1.Equals(kem2).Should().BeTrue();
        (kem1 == kem2).Should().BeTrue();
        (kem1 != kem2).Should().BeFalse();
    }

    [Fact]
    public void OqsKem_Equals_WithDifferentMethodName_ShouldReturnFalse()
    {
        var kem1 = CreateTestOqsKem();
        var kem2 = CreateTestOqsKem(methodName: new IntPtr(999));

        kem1.Equals(kem2).Should().BeFalse();
        (kem1 == kem2).Should().BeFalse();
        (kem1 != kem2).Should().BeTrue();
    }

    [Fact]
    public void OqsKem_Equals_WithDifferentAlgVersion_ShouldReturnFalse()
    {
        var kem1 = CreateTestOqsKem();
        var kem2 = CreateTestOqsKem(algVersion: new IntPtr(999));

        kem1.Equals(kem2).Should().BeFalse();
    }

    [Fact]
    public void OqsKem_Equals_WithDifferentClaimedNistLevel_ShouldReturnFalse()
    {
        var kem1 = CreateTestOqsKem();
        var kem2 = CreateTestOqsKem(claimedNistLevel: 5);

        kem1.Equals(kem2).Should().BeFalse();
    }

    [Fact]
    public void OqsKem_Equals_WithDifferentIndCca_ShouldReturnFalse()
    {
        var kem1 = CreateTestOqsKem();
        var kem2 = CreateTestOqsKem(indCca: 0);

        kem1.Equals(kem2).Should().BeFalse();
    }

    [Fact]
    public void OqsKem_Equals_WithDifferentLengths_ShouldReturnFalse()
    {
        var kem1 = CreateTestOqsKem();
        var kem2 = CreateTestOqsKem(lengthPublicKey: new UIntPtr(999));

        kem1.Equals(kem2).Should().BeFalse();

        var kem3 = CreateTestOqsKem(lengthSecretKey: new UIntPtr(999));
        kem1.Equals(kem3).Should().BeFalse();

        var kem4 = CreateTestOqsKem(lengthCiphertext: new UIntPtr(999));
        kem1.Equals(kem4).Should().BeFalse();

        var kem5 = CreateTestOqsKem(lengthSharedSecret: new UIntPtr(999));
        kem1.Equals(kem5).Should().BeFalse();
    }

    [Fact]
    public void OqsKem_Equals_WithDifferentFunctionPointers_ShouldReturnFalse()
    {
        var kem1 = CreateTestOqsKem();
        var kem2 = CreateTestOqsKem(keypair: new IntPtr(999));

        kem1.Equals(kem2).Should().BeFalse();

        var kem3 = CreateTestOqsKem(encaps: new IntPtr(999));
        kem1.Equals(kem3).Should().BeFalse();

        var kem4 = CreateTestOqsKem(decaps: new IntPtr(999));
        kem1.Equals(kem4).Should().BeFalse();
    }

    [Fact]
    public void OqsKem_Equals_WithObject_ShouldHandleCorrectly()
    {
        var kem1 = CreateTestOqsKem();
        var kem2 = CreateTestOqsKem();

        kem1.Equals((object)kem2).Should().BeTrue();
        kem1.Equals("not an OqsKem").Should().BeFalse();
        kem1.Equals(null).Should().BeFalse();
    }

    [Fact]
    public void OqsKem_GetHashCode_WithSameValues_ShouldReturnSameHash()
    {
        var kem1 = CreateTestOqsKem();
        var kem2 = CreateTestOqsKem();

        kem1.GetHashCode().Should().Be(kem2.GetHashCode());
    }

    [Fact]
    public void OqsKem_GetHashCode_WithDifferentValues_ShouldReturnDifferentHash()
    {
        var kem1 = CreateTestOqsKem();
        var kem2 = CreateTestOqsKem(claimedNistLevel: 5);

        kem1.GetHashCode().Should().NotBe(kem2.GetHashCode());
    }

    private static OqsKem CreateTestOqsKem(
        IntPtr? methodName = null,
        IntPtr? algVersion = null,
        byte claimedNistLevel = 3,
        byte indCca = 1,
        UIntPtr? lengthPublicKey = null,
        UIntPtr? lengthSecretKey = null,
        UIntPtr? lengthCiphertext = null,
        UIntPtr? lengthSharedSecret = null,
        UIntPtr? lengthKeypairSeed = null,
        UIntPtr? lengthEncapsSeed = null,
        IntPtr? keypairDerand = null,
        IntPtr? keypair = null,
        IntPtr? encapsDerand = null,
        IntPtr? encaps = null,
        IntPtr? decaps = null)
    {
        // Use reflection to create OqsKem with custom values
        var type = typeof(OqsKem);
        var instance = Activator.CreateInstance(type);

        var fields = type.GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public);
        
        foreach (var field in fields)
        {
            object? value = field.Name switch
            {
                "method_name" => methodName ?? new IntPtr(123),
                "alg_version" => algVersion ?? new IntPtr(456),
                "claimed_nist_level" => claimedNistLevel,
                "ind_cca" => indCca,
                "length_public_key" => lengthPublicKey ?? new UIntPtr(100),
                "length_secret_key" => lengthSecretKey ?? new UIntPtr(200),
                "length_ciphertext" => lengthCiphertext ?? new UIntPtr(300),
                "length_shared_secret" => lengthSharedSecret ?? new UIntPtr(32),
                "length_keypair_seed" => lengthKeypairSeed ?? new UIntPtr(48),
                "length_encaps_seed" => lengthEncapsSeed ?? new UIntPtr(48),
                "keypair_derand" => keypairDerand ?? new IntPtr(161718),
                "keypair" => keypair ?? new IntPtr(789),
                "encaps_derand" => encapsDerand ?? new IntPtr(192021),
                "encaps" => encaps ?? new IntPtr(101112),
                "decaps" => decaps ?? new IntPtr(131415),
                _ => null
            };

            if (value != null)
            {
                field.SetValue(instance, value);
            }
        }

        return (OqsKem)instance!;
    }

#pragma warning restore S1144
}