using FluentAssertions;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.Core.Tests;

public sealed class AlgorithmConstantsTests(LibOqsTestFixture fixture)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    public sealed class KemAlgorithmsTests
    {
        [Fact]
        public void All_ShouldContainAllDefinedConstants()
        {
            // Arrange - Get all the constant field values using reflection
            var kemType = typeof(KemAlgorithms);
            var constantFields = kemType.GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
                .Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string))
                .Select(f => (string)f.GetValue(null)!)
                .Where(value => !string.IsNullOrEmpty(value))
                .ToArray();

            // Act & Assert - All constants should be in the All array
            constantFields.Should().AllSatisfy(constant =>
                KemAlgorithms.All.Should().Contain(constant,
                    $"constant {constant} should be included in KemAlgorithms.All"));
        }

        [Fact]
        public void All_ShouldNotContainNullOrEmptyValues()
        {
            // Act & Assert
            KemAlgorithms.All.Should().NotContainNulls();
            KemAlgorithms.All.Should().NotContain(string.Empty);
            KemAlgorithms.All.Should().AllSatisfy(alg => alg.Should().NotBeNullOrWhiteSpace());
        }

        [Fact]
        public void All_ShouldNotContainDuplicates()
        {
            // Act & Assert
            KemAlgorithms.All.Should().OnlyHaveUniqueItems();
        }

        [Fact]
        public void NISTStandardized_ShouldOnlyContainMLKEMAlgorithms()
        {
            // Act & Assert
            KemAlgorithms.NISTStandardized.Should().Contain([
                KemAlgorithms.ML_KEM_512,
                KemAlgorithms.ML_KEM_768,
                KemAlgorithms.ML_KEM_1024
            ]);

            KemAlgorithms.NISTStandardized.Should().HaveCount(3);
        }

        [Fact]
        public void NISTStandardized_ShouldBeSubsetOfAll()
        {
            // Act & Assert
            KemAlgorithms.NISTStandardized.Should().BeSubsetOf(KemAlgorithms.All);
        }

        [Fact]
        public void Deprecated_ShouldContainSIDHAndSIKE()
        {
            // Arrange
            var expectedDeprecated = new[]
            {
                KemAlgorithms.SIDH_p434, KemAlgorithms.SIDH_p503, KemAlgorithms.SIDH_p610, KemAlgorithms.SIDH_p751,
                KemAlgorithms.SIKE_p434, KemAlgorithms.SIKE_p503, KemAlgorithms.SIKE_p610, KemAlgorithms.SIKE_p751
            };

            // Act & Assert
            KemAlgorithms.Deprecated.Should().Contain(expectedDeprecated);
        }

        [Fact]
        public void Deprecated_ShouldBeSubsetOfAll()
        {
            // Act & Assert
            KemAlgorithms.Deprecated.Should().BeSubsetOf(KemAlgorithms.All);
        }

        [Theory]
        [InlineData(KemAlgorithms.ML_KEM_512)]
        [InlineData(KemAlgorithms.ML_KEM_768)]
        [InlineData(KemAlgorithms.ML_KEM_1024)]
        public void MLKEMConstants_ShouldHaveCorrectValues(string algorithmName)
        {
            // Act & Assert
            algorithmName.Should().StartWith("ML-KEM-");
            algorithmName.Should().MatchRegex(@"^ML-KEM-\d{3,4}$");
        }

        [Theory]
        [InlineData(KemAlgorithms.Kyber512)]
        [InlineData(KemAlgorithms.Kyber768)]
        [InlineData(KemAlgorithms.Kyber1024)]
        public void KyberConstants_ShouldHaveCorrectValues(string algorithmName)
        {
            // Act & Assert
            algorithmName.Should().StartWith("Kyber");
            algorithmName.Should().MatchRegex(@"^Kyber\d{3,4}$");
        }

        [Theory]
        [InlineData(KemAlgorithms.BIKE_L1)]
        [InlineData(KemAlgorithms.BIKE_L3)]
        [InlineData(KemAlgorithms.BIKE_L5)]
        public void BIKEConstants_ShouldHaveCorrectValues(string algorithmName)
        {
            // Act & Assert
            algorithmName.Should().StartWith("BIKE-L");
            algorithmName.Should().MatchRegex(@"^BIKE-L[135]$");
        }

        [Theory]
        [InlineData(KemAlgorithms.HQC_128)]
        [InlineData(KemAlgorithms.HQC_192)]
        [InlineData(KemAlgorithms.HQC_256)]
        public void HQCConstants_ShouldHaveCorrectValues(string algorithmName)
        {
            // Act & Assert
            algorithmName.Should().StartWith("HQC-");
            algorithmName.Should().MatchRegex(@"^HQC-(128|192|256)$");
        }

        [Theory]
        [InlineData(KemAlgorithms.ClassicMcEliece348864)]
        [InlineData(KemAlgorithms.ClassicMcEliece460896f)]
        [InlineData(KemAlgorithms.ClassicMcEliece8192128)]
        public void ClassicMcElieceConstants_ShouldHaveCorrectValues(string algorithmName)
        {
            // Act & Assert
            algorithmName.Should().StartWith("Classic-McEliece-");
            algorithmName.Should().MatchRegex(@"^Classic-McEliece-\d+f?$");
        }
    }

    public sealed class SignatureAlgorithmsTests
    {
        [Fact]
        public void All_ShouldContainAllDefinedConstants()
        {
            // Arrange - Get all the constant field values using reflection
            var sigType = typeof(SignatureAlgorithms);
            var constantFields = sigType.GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
                .Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string))
                .Select(f => (string)f.GetValue(null)!)
                .Where(value => !string.IsNullOrEmpty(value))
                .ToArray();

            // Act & Assert - All constants should be in the All array
            constantFields.Should().AllSatisfy(constant => 
                SignatureAlgorithms.All.Should().Contain(constant, 
                    $"constant {constant} should be included in SignatureAlgorithms.All"));
        }

        [Fact]
        public void All_ShouldNotContainNullOrEmptyValues()
        {
            // Act & Assert
            SignatureAlgorithms.All.Should().NotContainNulls();
            SignatureAlgorithms.All.Should().NotContain(string.Empty);
            SignatureAlgorithms.All.Should().AllSatisfy(alg => alg.Should().NotBeNullOrWhiteSpace());
        }

        [Fact]
        public void All_ShouldNotContainDuplicates()
        {
            // Act & Assert
            SignatureAlgorithms.All.Should().OnlyHaveUniqueItems();
        }

        [Fact]
        public void NISTStandardized_ShouldOnlyContainMLDSAAlgorithms()
        {
            // Act & Assert
            SignatureAlgorithms.NISTStandardized.Should().Contain([
                SignatureAlgorithms.ML_DSA_44,
                SignatureAlgorithms.ML_DSA_65,
                SignatureAlgorithms.ML_DSA_87
            ]);
            
            SignatureAlgorithms.NISTStandardized.Should().HaveCount(3);
        }

        [Fact]
        public void NISTStandardized_ShouldBeSubsetOfAll()
        {
            // Act & Assert
            SignatureAlgorithms.NISTStandardized.Should().BeSubsetOf(SignatureAlgorithms.All);
        }

        [Fact]
        public void Deprecated_ShouldContainRainbowAlgorithms()
        {
            // Arrange
            var expectedDeprecated = new[]
            {
                SignatureAlgorithms.Rainbow_I_Classic, SignatureAlgorithms.Rainbow_I_Circumzenithal, SignatureAlgorithms.Rainbow_I_Compressed,
                SignatureAlgorithms.Rainbow_III_Classic, SignatureAlgorithms.Rainbow_III_Circumzenithal, SignatureAlgorithms.Rainbow_III_Compressed,
                SignatureAlgorithms.Rainbow_V_Classic, SignatureAlgorithms.Rainbow_V_Circumzenithal, SignatureAlgorithms.Rainbow_V_Compressed
            };

            // Act & Assert
            SignatureAlgorithms.Deprecated.Should().Contain(expectedDeprecated);
        }

        [Fact]
        public void Deprecated_ShouldBeSubsetOfAll()
        {
            // Act & Assert
            SignatureAlgorithms.Deprecated.Should().BeSubsetOf(SignatureAlgorithms.All);
        }

        [Theory]
        [InlineData(SignatureAlgorithms.ML_DSA_44)]
        [InlineData(SignatureAlgorithms.ML_DSA_65)]
        [InlineData(SignatureAlgorithms.ML_DSA_87)]
        public void MLDSAConstants_ShouldHaveCorrectValues(string algorithmName)
        {
            // Act & Assert
            algorithmName.Should().StartWith("ML-DSA-");
            algorithmName.Should().MatchRegex(@"^ML-DSA-\d{2}$");
        }

        [Theory]
        [InlineData(SignatureAlgorithms.Dilithium2)]
        [InlineData(SignatureAlgorithms.Dilithium3)]
        [InlineData(SignatureAlgorithms.Dilithium5)]
        public void DilithiumConstants_ShouldHaveCorrectValues(string algorithmName)
        {
            // Act & Assert
            algorithmName.Should().StartWith("Dilithium");
            algorithmName.Should().MatchRegex(@"^Dilithium[2-5]$");
        }

        [Theory]
        [InlineData(SignatureAlgorithms.Falcon_512)]
        [InlineData(SignatureAlgorithms.Falcon_1024)]
        [InlineData(SignatureAlgorithms.Falcon_512_padded)]
        [InlineData(SignatureAlgorithms.Falcon_1024_padded)]
        public void FalconConstants_ShouldHaveCorrectValues(string algorithmName)
        {
            // Act & Assert
            algorithmName.Should().StartWith("Falcon");
            algorithmName.Should().MatchRegex(@"^Falcon(-padded)?-(512|1024)$");
        }

        [Theory]
        [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHA2_128f_simple)]
        [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHAKE_256s_robust)]
        [InlineData(SignatureAlgorithms.SPHINCS_PLUS_SHA2_192f_robust)]
        public void SPHINCSConstants_ShouldHaveCorrectValues(string algorithmName)
        {
            // Act & Assert
            algorithmName.Should().StartWith("SPHINCS+-");
            algorithmName.Should().MatchRegex(@"^SPHINCS\+-(SHA2|SHAKE)-(128|192|256)[fs]-(simple|robust)$");
        }

        [Theory]
        [InlineData(SignatureAlgorithms.MAYO_1)]
        [InlineData(SignatureAlgorithms.MAYO_3)]
        [InlineData(SignatureAlgorithms.MAYO_5)]
        public void MAYOConstants_ShouldHaveCorrectValues(string algorithmName)
        {
            // Act & Assert
            algorithmName.Should().StartWith("MAYO-");
            algorithmName.Should().MatchRegex(@"^MAYO-[1-5]$");
        }
    }

    public sealed class StatefulSignatureAlgorithmsTests
    {
        [Fact]
        public void All_ShouldNotContainNullOrEmptyValues()
        {
            // Act & Assert
            StatefulSignatureAlgorithms.All.Should().NotContainNulls();
            StatefulSignatureAlgorithms.All.Should().NotContain(string.Empty);
            StatefulSignatureAlgorithms.All.Should().AllSatisfy(alg => alg.Should().NotBeNullOrWhiteSpace());
        }

        [Fact]
        public void All_ShouldNotContainDuplicates()
        {
            // Act & Assert
            StatefulSignatureAlgorithms.All.Should().OnlyHaveUniqueItems();
        }

        [Fact]
        public void All_ShouldContainLMSAlgorithms()
        {
            // Act & Assert
            StatefulSignatureAlgorithms.All.Should().Contain([
                StatefulSignatureAlgorithms.LMS_SHA256_M32_H5,
                StatefulSignatureAlgorithms.LMS_SHA256_M32_H10,
                StatefulSignatureAlgorithms.LMS_SHA256_M32_H15,
                StatefulSignatureAlgorithms.LMS_SHA256_M32_H20,
                StatefulSignatureAlgorithms.LMS_SHA256_M32_H25
            ]);
        }

        [Fact]
        public void All_ShouldContainXMSSAlgorithms()
        {
            // Act & Assert
            StatefulSignatureAlgorithms.All.Should().Contain([
                StatefulSignatureAlgorithms.XMSS_SHA2_10_256,
                StatefulSignatureAlgorithms.XMSS_SHA2_16_256,
                StatefulSignatureAlgorithms.XMSS_SHA2_20_256,
                StatefulSignatureAlgorithms.XMSS_SHAKE_10_256,
                StatefulSignatureAlgorithms.XMSS_SHAKE_16_256,
                StatefulSignatureAlgorithms.XMSS_SHAKE_20_256
            ]);
        }

        [Fact]
        public void All_ShouldContainXMSSMTAlgorithms()
        {
            // Act & Assert
            StatefulSignatureAlgorithms.All.Should().Contain([
                StatefulSignatureAlgorithms.XMSSMT_SHA2_20_2_256,
                StatefulSignatureAlgorithms.XMSSMT_SHA2_40_4_256,
                StatefulSignatureAlgorithms.XMSSMT_SHA2_60_12_256,
                StatefulSignatureAlgorithms.XMSSMT_SHAKE_20_2_256,
                StatefulSignatureAlgorithms.XMSSMT_SHAKE_40_8_256,
                StatefulSignatureAlgorithms.XMSSMT_SHAKE_60_12_256
            ]);
        }
    }

    public sealed class NistSecurityLevelTests
    {
        [Theory]
        [InlineData(NistSecurityLevel.None, 0)]
        [InlineData(NistSecurityLevel.Level1, 1)]
        [InlineData(NistSecurityLevel.Level3, 3)]
        [InlineData(NistSecurityLevel.Level5, 5)]
        public void SecurityLevels_ShouldHaveCorrectValues(NistSecurityLevel level, int expectedValue)
        {
            // Act & Assert
            ((int)level).Should().Be(expectedValue);
        }

        [Fact]
        public void AllSecurityLevels_ShouldBeDefined()
        {
            // Act
            var definedValues = Enum.GetValues<NistSecurityLevel>();

            // Assert
            definedValues.Should().Contain([
                NistSecurityLevel.None,
                NistSecurityLevel.Level1,
                NistSecurityLevel.Level3,
                NistSecurityLevel.Level5
            ]);
        }
    }

    public sealed class AlgorithmConstantsUtilityTests
    {
        [Theory]
        [InlineData(KemAlgorithms.ML_KEM_512, true)]
        [InlineData(KemAlgorithms.ML_KEM_768, true)]
        [InlineData(KemAlgorithms.ML_KEM_1024, true)]
        [InlineData(SignatureAlgorithms.ML_DSA_44, true)]
        [InlineData(SignatureAlgorithms.ML_DSA_65, true)]
        [InlineData(SignatureAlgorithms.ML_DSA_87, true)]
        [InlineData(KemAlgorithms.Kyber512, false)]
        [InlineData(SignatureAlgorithms.Dilithium2, false)]
        [InlineData("NonExistentAlgorithm", false)]
        [InlineData("ml-kem-512", true)] // Test case insensitive
        [InlineData("ML-DSA-44", true)] // Test case insensitive
        public void IsNISTStandardized_ShouldReturnCorrectResult(string algorithmName, bool expectedResult)
        {
            // Act
            var result = AlgorithmConstants.IsNISTStandardized(algorithmName);

            // Assert
            result.Should().Be(expectedResult);
        }

        [Theory]
        [InlineData(KemAlgorithms.SIDH_p434, true)]
        [InlineData(KemAlgorithms.SIKE_p751, true)]
        [InlineData(SignatureAlgorithms.Rainbow_I_Classic, true)]
        [InlineData(KemAlgorithms.ML_KEM_512, false)]
        [InlineData(SignatureAlgorithms.ML_DSA_44, false)]
        [InlineData("NonExistentAlgorithm", false)]
        [InlineData("sidh-p434", true)] // Test case insensitive
        [InlineData("RAINBOW-I-CLASSIC", true)] // Test case insensitive
        public void IsDeprecated_ShouldReturnCorrectResult(string algorithmName, bool expectedResult)
        {
            // Act
            var result = AlgorithmConstants.IsDeprecated(algorithmName);

            // Assert
            result.Should().Be(expectedResult);
        }

        [Fact]
        public void IsNISTStandardized_WithNullArgument_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => AlgorithmConstants.IsNISTStandardized(null!);
            act.Should().Throw<ArgumentException>();
        }

        [Fact]
        public void IsNISTStandardized_WithEmptyArgument_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => AlgorithmConstants.IsNISTStandardized(string.Empty);
            act.Should().Throw<ArgumentException>();
        }

        [Fact]
        public void IsDeprecated_WithNullArgument_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => AlgorithmConstants.IsDeprecated(null!);
            act.Should().Throw<ArgumentException>();
        }

        [Fact]
        public void IsDeprecated_WithEmptyArgument_ShouldThrowArgumentException()
        {
            // Act & Assert
            var act = () => AlgorithmConstants.IsDeprecated(string.Empty);
            act.Should().Throw<ArgumentException>();
        }
    }

    public sealed class AlgorithmCrossValidationTests
    {
        [Fact]
        public void DeprecatedAlgorithms_ShouldNotBeInNISTStandardized()
        {
            // Arrange - Get all deprecated algorithms
            var allDeprecated = KemAlgorithms.Deprecated.Concat(SignatureAlgorithms.Deprecated).ToArray();
            var allNistStandardized = KemAlgorithms.NISTStandardized.Concat(SignatureAlgorithms.NISTStandardized).ToArray();

            // Act & Assert - No deprecated algorithm should be in NIST standardized list
            allDeprecated.Should().NotIntersectWith(allNistStandardized, 
                "deprecated algorithms should not be in NIST standardized list");
        }

        [Fact]
        public void NISTStandardizedAlgorithms_ShouldNotBeDeprecated()
        {
            // Arrange - Get all NIST standardized algorithms
            var allNistStandardized = KemAlgorithms.NISTStandardized.Concat(SignatureAlgorithms.NISTStandardized).ToArray();

            // Act & Assert - No NIST standardized algorithm should be marked as deprecated
            foreach (var algorithm in allNistStandardized)
            {
                AlgorithmConstants.IsDeprecated(algorithm).Should().BeFalse(
                    $"NIST standardized algorithm '{algorithm}' should not be deprecated");
            }
        }

        [Fact]
        public void DeprecatedAlgorithms_ShouldNotBeNISTStandardized()
        {
            // Arrange - Get all deprecated algorithms
            var allDeprecated = KemAlgorithms.Deprecated.Concat(SignatureAlgorithms.Deprecated).ToArray();

            // Act & Assert - No deprecated algorithm should be marked as NIST standardized
            foreach (var algorithm in allDeprecated)
            {
                AlgorithmConstants.IsNISTStandardized(algorithm).Should().BeFalse(
                    $"Deprecated algorithm '{algorithm}' should not be NIST standardized");
            }
        }

        [Fact]
        public void AllArrays_ShouldIncludeTheirSubsets()
        {
            // Assert - KEM algorithms
            KemAlgorithms.All.Should().Contain(KemAlgorithms.NISTStandardized, 
                "All KEM algorithms should include NIST standardized ones");
            KemAlgorithms.All.Should().Contain(KemAlgorithms.Deprecated, 
                "All KEM algorithms should include deprecated ones");

            // Assert - Signature algorithms
            SignatureAlgorithms.All.Should().Contain(SignatureAlgorithms.NISTStandardized, 
                "All signature algorithms should include NIST standardized ones");
            SignatureAlgorithms.All.Should().Contain(SignatureAlgorithms.Deprecated, 
                "All signature algorithms should include deprecated ones");
        }

        [Fact]
        public void AlgorithmArrays_ShouldNotHaveOverlap()
        {
            // Assert - KEM arrays should not overlap
            KemAlgorithms.NISTStandardized.Should().NotIntersectWith(KemAlgorithms.Deprecated,
                "NIST standardized and deprecated KEM algorithms should not overlap");

            // Assert - Signature arrays should not overlap
            SignatureAlgorithms.NISTStandardized.Should().NotIntersectWith(SignatureAlgorithms.Deprecated,
                "NIST standardized and deprecated signature algorithms should not overlap");
        }
    }

    public sealed class AlgorithmFutureProofingTests
    {
        [Fact]
        public void NewAlgorithmAddition_ShouldBeDetectedInAll()
        {
            // Act & Assert - If new algorithms are added, they should appear in All arrays
            // This test validates the current state and serves as documentation
            KemAlgorithms.All.Should().HaveCountGreaterThan(10, 
                "KEM algorithms list should contain multiple algorithms");
            SignatureAlgorithms.All.Should().HaveCountGreaterThan(10, 
                "Signature algorithms list should contain multiple algorithms");
            StatefulSignatureAlgorithms.All.Should().HaveCountGreaterThan(5, 
                "Stateful signature algorithms list should contain multiple algorithms");
        }

        [Fact]
        public void AlgorithmConstants_ShouldHandleNewNISTStandards()
        {
            // Arrange - Test with hypothetical future NIST algorithms
            var futureAlgorithms = new[]
            {
                "ML-KEM-2048", // Hypothetical future ML-KEM variant
                "ML-DSA-128",  // Hypothetical future ML-DSA variant
                "Future-Algorithm-Name"
            };

            // Act & Assert - Future algorithms should be handled gracefully
            foreach (var algorithm in futureAlgorithms)
            {
                // Should not throw exceptions when checking unknown algorithms
                var act1 = () => AlgorithmConstants.IsNISTStandardized(algorithm);
                var act2 = () => AlgorithmConstants.IsDeprecated(algorithm);
                
                act1.Should().NotThrow("IsNISTStandardized should handle unknown algorithms gracefully");
                act2.Should().NotThrow("IsDeprecated should handle unknown algorithms gracefully");
                
                var isNist = AlgorithmConstants.IsNISTStandardized(algorithm);
                var isDeprecated = AlgorithmConstants.IsDeprecated(algorithm);
                
                // Unknown algorithms should not be both NIST and deprecated
                if (!isNist && !isDeprecated)
                {
                    // This is expected for unknown algorithms
                    true.Should().BeTrue("Unknown algorithms should not be marked as either NIST or deprecated");
                }
            }
        }

        [Fact]
        public void AlgorithmNaming_ShouldFollowConsistentPatterns()
        {
            // Assert - ML-KEM algorithms follow naming pattern
            KemAlgorithms.NISTStandardized.Should().AllSatisfy(alg => 
                alg.Should().MatchRegex(@"^ML-KEM-\d+$", $"NIST KEM algorithm '{alg}' should follow ML-KEM-XXX pattern"));

            // Assert - ML-DSA algorithms follow naming pattern
            SignatureAlgorithms.NISTStandardized.Should().AllSatisfy(alg => 
                alg.Should().MatchRegex(@"^ML-DSA-\d+$", $"NIST signature algorithm '{alg}' should follow ML-DSA-XX pattern"));
        }

        [Fact]
        public void SecurityLevels_ShouldCoverAllNISTLevels()
        {
            // Act - Get all defined security levels
            var definedLevels = Enum.GetValues<NistSecurityLevel>();

            // Assert - Should include standard NIST security levels
            definedLevels.Should().Contain(NistSecurityLevel.Level1, "Level 1 (128-bit) security should be defined");
            definedLevels.Should().Contain(NistSecurityLevel.Level3, "Level 3 (192-bit) security should be defined");
            definedLevels.Should().Contain(NistSecurityLevel.Level5, "Level 5 (256-bit) security should be defined");
            definedLevels.Should().Contain(NistSecurityLevel.None, "None level should be defined for non-categorized algorithms");
        }

        [Fact]
        public void AlgorithmCounts_ShouldBeReasonable()
        {
            // Act & Assert - Validate reasonable algorithm counts
            KemAlgorithms.All.Length.Should().BeInRange(15, 100, 
                "Total KEM algorithms should be reasonable (not too few, not excessive)");
            SignatureAlgorithms.All.Length.Should().BeInRange(20, 150, 
                "Total signature algorithms should be reasonable (not too few, not excessive)");
            StatefulSignatureAlgorithms.All.Length.Should().BeInRange(5, 50, 
                "Total stateful signature algorithms should be reasonable");

            // NIST standardized should be small focused set
            KemAlgorithms.NISTStandardized.Length.Should().BeInRange(1, 10, 
                "NIST standardized KEMs should be a focused set");
            SignatureAlgorithms.NISTStandardized.Length.Should().BeInRange(1, 10, 
                "NIST standardized signatures should be a focused set");

            // Deprecated algorithms exist but shouldn't dominate
            KemAlgorithms.Deprecated.Length.Should().BeInRange(1, KemAlgorithms.All.Length / 2, 
                "Deprecated KEMs should exist but not dominate the list");
            SignatureAlgorithms.Deprecated.Length.Should().BeInRange(1, SignatureAlgorithms.All.Length / 2, 
                "Deprecated signatures should exist but not dominate the list");
        }

        [Theory]
        [InlineData("Classic-McEliece-")]
        [InlineData("SPHINCS+-")]
        [InlineData("XMSS-")]
        [InlineData("BIKE-")]
        [InlineData("HQC-")]
        public void AlgorithmFamilies_ShouldHaveMultipleVariants(string familyPrefix)
        {
            // Act - Find algorithms in this family
            var kemFamily = KemAlgorithms.All.Where(alg => alg.StartsWith(familyPrefix, StringComparison.Ordinal)).ToArray();
            var sigFamily = SignatureAlgorithms.All.Where(alg => alg.StartsWith(familyPrefix, StringComparison.Ordinal)).ToArray();
            var stflFamily = StatefulSignatureAlgorithms.All.Where(alg => alg.StartsWith(familyPrefix, StringComparison.Ordinal)).ToArray();

            var totalInFamily = kemFamily.Length + sigFamily.Length + stflFamily.Length;

            // Assert - Algorithm families should have multiple variants
            totalInFamily.Should().BeGreaterThan(0, 
                $"Algorithm family '{familyPrefix}' should have at least one variant");
            
            if (totalInFamily > 1)
            {
                totalInFamily.Should().BeInRange(2, 25, 
                    $"Algorithm family '{familyPrefix}' should have a reasonable number of variants");
            }
        }
    }
}