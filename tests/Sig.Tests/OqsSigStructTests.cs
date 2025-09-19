using FluentAssertions;
using OpenForge.Cryptography.LibOqs.SIG;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.SIG.Tests;

[Collection("LibOqs Collection")]
public sealed class OqsSigStructTests(LibOqsTestFixture fixture)
{
#pragma warning disable S1144
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void OqsSig_Equals_WithSameValues_ShouldReturnTrue()
    {
        var sig1 = CreateTestOqsSig();
        var sig2 = CreateTestOqsSig();

        sig1.Equals(sig2).Should().BeTrue();
        (sig1 == sig2).Should().BeTrue();
        (sig1 != sig2).Should().BeFalse();
    }

    [Fact]
    public void OqsSig_Equals_WithDifferentMethodName_ShouldReturnFalse()
    {
        var sig1 = CreateTestOqsSig();
        var sig2 = CreateTestOqsSig(methodName: new IntPtr(999));

        sig1.Equals(sig2).Should().BeFalse();
        (sig1 == sig2).Should().BeFalse();
        (sig1 != sig2).Should().BeTrue();
    }

    [Fact]
    public void OqsSig_Equals_WithDifferentAlgVersion_ShouldReturnFalse()
    {
        var sig1 = CreateTestOqsSig();
        var sig2 = CreateTestOqsSig(algVersion: new IntPtr(999));

        sig1.Equals(sig2).Should().BeFalse();
    }

    [Fact]
    public void OqsSig_Equals_WithDifferentClaimedNistLevel_ShouldReturnFalse()
    {
        var sig1 = CreateTestOqsSig();
        var sig2 = CreateTestOqsSig(claimedNistLevel: 5);

        sig1.Equals(sig2).Should().BeFalse();
    }

    [Fact]
    public void OqsSig_Equals_WithDifferentEufCma_ShouldReturnFalse()
    {
        var sig1 = CreateTestOqsSig();
        var sig2 = CreateTestOqsSig(eufCma: 0);

        sig1.Equals(sig2).Should().BeFalse();
    }

    [Fact]
    public void OqsSig_Equals_WithDifferentLengths_ShouldReturnFalse()
    {
        var sig1 = CreateTestOqsSig();
        var sig2 = CreateTestOqsSig(lengthPublicKey: new UIntPtr(999));

        sig1.Equals(sig2).Should().BeFalse();

        var sig3 = CreateTestOqsSig(lengthSecretKey: new UIntPtr(999));
        sig1.Equals(sig3).Should().BeFalse();

        var sig4 = CreateTestOqsSig(lengthSignature: new UIntPtr(999));
        sig1.Equals(sig4).Should().BeFalse();
    }

    [Fact]
    public void OqsSig_Equals_WithDifferentFunctionPointers_ShouldReturnFalse()
    {
        var sig1 = CreateTestOqsSig();
        var sig2 = CreateTestOqsSig(keypair: new IntPtr(999));

        sig1.Equals(sig2).Should().BeFalse();

        var sig3 = CreateTestOqsSig(sign: new IntPtr(999));
        sig1.Equals(sig3).Should().BeFalse();

        var sig4 = CreateTestOqsSig(verify: new IntPtr(999));
        sig1.Equals(sig4).Should().BeFalse();
    }

    [Fact]
    public void OqsSig_Equals_WithObject_ShouldHandleCorrectly()
    {
        var sig1 = CreateTestOqsSig();
        var sig2 = CreateTestOqsSig();

        sig1.Equals((object)sig2).Should().BeTrue();
        sig1.Equals("not an OqsSig").Should().BeFalse();
        sig1.Equals(null).Should().BeFalse();
    }

    [Fact]
    public void OqsSig_GetHashCode_WithSameValues_ShouldReturnSameHash()
    {
        var sig1 = CreateTestOqsSig();
        var sig2 = CreateTestOqsSig();

        sig1.GetHashCode().Should().Be(sig2.GetHashCode());
    }

    [Fact]
    public void OqsSig_GetHashCode_WithDifferentValues_ShouldReturnDifferentHash()
    {
        var sig1 = CreateTestOqsSig();
        var sig2 = CreateTestOqsSig(claimedNistLevel: 5);

        sig1.GetHashCode().Should().NotBe(sig2.GetHashCode());
    }

    private static OqsSig CreateTestOqsSig(
        IntPtr? methodName = null,
        IntPtr? algVersion = null,
        byte claimedNistLevel = 3,
        byte eufCma = 1,
        UIntPtr? lengthPublicKey = null,
        UIntPtr? lengthSecretKey = null,
        UIntPtr? lengthSignature = null,
        IntPtr? keypair = null,
        IntPtr? sign = null,
        IntPtr? verify = null)
    {
        // Use reflection to create OqsSig with custom values
        var type = typeof(OqsSig);
        var instance = Activator.CreateInstance(type);

        var fields = type.GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public);
        
        foreach (var field in fields)
        {
            object? value = field.Name switch
            {
                "method_name" => methodName ?? new IntPtr(123),
                "alg_version" => algVersion ?? new IntPtr(456),
                "claimed_nist_level" => claimedNistLevel,
                "euf_cma" => eufCma,
                "length_public_key" => lengthPublicKey ?? new UIntPtr(100),
                "length_secret_key" => lengthSecretKey ?? new UIntPtr(200),
                "length_signature" => lengthSignature ?? new UIntPtr(300),
                "keypair" => keypair ?? new IntPtr(789),
                "sign" => sign ?? new IntPtr(101112),
                "verify" => verify ?? new IntPtr(131415),
                _ => null
            };

            if (value != null)
            {
                field.SetValue(instance, value);
            }
        }

        return (OqsSig)instance!;
    }

#pragma warning restore S1144
}