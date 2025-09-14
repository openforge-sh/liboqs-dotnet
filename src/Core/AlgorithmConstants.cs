namespace OpenForge.Cryptography.LibOqs.Core;
#pragma warning disable CA1707
#pragma warning disable CS1591

/// <summary>
/// Key Encapsulation Mechanism (KEM) algorithm identifiers.
/// </summary>
public static class KemAlgorithms
{
    public const string BIKE_L1 = "BIKE-L1";
    public const string BIKE_L3 = "BIKE-L3";
    public const string BIKE_L5 = "BIKE-L5";

    public const string ClassicMcEliece348864 = "Classic-McEliece-348864";
    public const string ClassicMcEliece348864f = "Classic-McEliece-348864f";
    public const string ClassicMcEliece460896 = "Classic-McEliece-460896";
    public const string ClassicMcEliece460896f = "Classic-McEliece-460896f";
    public const string ClassicMcEliece6688128 = "Classic-McEliece-6688128";
    public const string ClassicMcEliece6688128f = "Classic-McEliece-6688128f";
    public const string ClassicMcEliece6960119 = "Classic-McEliece-6960119";
    public const string ClassicMcEliece6960119f = "Classic-McEliece-6960119f";
    public const string ClassicMcEliece8192128 = "Classic-McEliece-8192128";
    public const string ClassicMcEliece8192128f = "Classic-McEliece-8192128f";
    public const string HQC_128 = "HQC-128";
    public const string HQC_192 = "HQC-192";
    public const string HQC_256 = "HQC-256";
    public const string Kyber512 = "Kyber512";
    public const string Kyber768 = "Kyber768";
    public const string Kyber1024 = "Kyber1024";
    public const string ML_KEM_512 = "ML-KEM-512";
    public const string ML_KEM_768 = "ML-KEM-768";
    public const string ML_KEM_1024 = "ML-KEM-1024";
    public const string NTRU_HPS_2048_509 = "NTRU-HPS-2048-509";
    public const string NTRU_HPS_2048_677 = "NTRU-HPS-2048-677";
    public const string NTRU_HPS_4096_821 = "NTRU-HPS-4096-821";
    public const string NTRU_HPS_4096_1229 = "NTRU-HPS-4096-1229";
    public const string NTRU_HRSS_701 = "NTRU-HRSS-701";
    public const string NTRU_HRSS_1373 = "NTRU-HRSS-1373";
    public const string NTRUPrime_sntrup761 = "sntrup761";
    public const string FrodoKEM_640_AES = "FrodoKEM-640-AES";
    public const string FrodoKEM_640_SHAKE = "FrodoKEM-640-SHAKE";
    public const string FrodoKEM_976_AES = "FrodoKEM-976-AES";
    public const string FrodoKEM_976_SHAKE = "FrodoKEM-976-SHAKE";
    public const string FrodoKEM_1344_AES = "FrodoKEM-1344-AES";
    public const string FrodoKEM_1344_SHAKE = "FrodoKEM-1344-SHAKE";  
    public const string Saber_LightSaber = "LightSaber-KEM";
    public const string Saber_Saber = "Saber-KEM";
    public const string Saber_FireSaber = "FireSaber-KEM";
    public const string SIDH_p434 = "SIDH-p434";
    public const string SIDH_p503 = "SIDH-p503";
    public const string SIDH_p610 = "SIDH-p610";
    public const string SIDH_p751 = "SIDH-p751";
    public const string SIKE_p434 = "SIKE-p434";
    public const string SIKE_p503 = "SIKE-p503";
    public const string SIKE_p610 = "SIKE-p610";
    public const string SIKE_p751 = "SIKE-p751";

    /// <summary>
    /// Gets all KEM algorithm identifiers.
    /// </summary>
    public static readonly string[] All = [
        BIKE_L1, BIKE_L3, BIKE_L5,
            ClassicMcEliece348864, ClassicMcEliece348864f, ClassicMcEliece460896, ClassicMcEliece460896f,
            ClassicMcEliece6688128, ClassicMcEliece6688128f, ClassicMcEliece6960119, ClassicMcEliece6960119f,
            ClassicMcEliece8192128, ClassicMcEliece8192128f,
            FrodoKEM_640_AES, FrodoKEM_640_SHAKE, FrodoKEM_976_AES, FrodoKEM_976_SHAKE,
            FrodoKEM_1344_AES, FrodoKEM_1344_SHAKE,
            HQC_128, HQC_192, HQC_256,
            Kyber512, Kyber768, Kyber1024,
            ML_KEM_512, ML_KEM_768, ML_KEM_1024,
            NTRU_HPS_2048_509, NTRU_HPS_2048_677, NTRU_HPS_4096_821, NTRU_HPS_4096_1229,
            NTRU_HRSS_701, NTRU_HRSS_1373,
            NTRUPrime_sntrup761,
            Saber_LightSaber, Saber_Saber, Saber_FireSaber,
            SIDH_p434, SIDH_p503, SIDH_p610, SIDH_p751,
            SIKE_p434, SIKE_p503, SIKE_p610, SIKE_p751
    ];

    /// <summary>
    /// Gets NIST standardized KEM algorithms (recommended for production use).
    /// </summary>
    public static readonly string[] NISTStandardized = [
        ML_KEM_512, ML_KEM_768, ML_KEM_1024
    ];

    /// <summary>
    /// Gets deprecated KEM algorithms (should not be used in production).
    /// </summary>
    public static readonly string[] Deprecated = [
        SIDH_p434, SIDH_p503, SIDH_p610, SIDH_p751,
            SIKE_p434, SIKE_p503, SIKE_p610, SIKE_p751
    ];
}

/// <summary>
/// Digital signature algorithm identifiers.
/// </summary>
public static class SignatureAlgorithms
{
    public const string Dilithium2 = "Dilithium2";
    public const string Dilithium3 = "Dilithium3";
    public const string Dilithium5 = "Dilithium5";
    public const string ML_DSA_44 = "ML-DSA-44";
    public const string ML_DSA_65 = "ML-DSA-65";
    public const string ML_DSA_87 = "ML-DSA-87";
    public const string Falcon_512 = "Falcon-512";
    public const string Falcon_1024 = "Falcon-1024";
    public const string SPHINCS_PLUS_SHA2_128f_simple = "SPHINCS+-SHA2-128f-simple";
    public const string SPHINCS_PLUS_SHA2_128f_robust = "SPHINCS+-SHA2-128f-robust";
    public const string SPHINCS_PLUS_SHA2_128s_simple = "SPHINCS+-SHA2-128s-simple";
    public const string SPHINCS_PLUS_SHA2_128s_robust = "SPHINCS+-SHA2-128s-robust";
    public const string SPHINCS_PLUS_SHA2_192f_simple = "SPHINCS+-SHA2-192f-simple";
    public const string SPHINCS_PLUS_SHA2_192f_robust = "SPHINCS+-SHA2-192f-robust";
    public const string SPHINCS_PLUS_SHA2_192s_simple = "SPHINCS+-SHA2-192s-simple";
    public const string SPHINCS_PLUS_SHA2_192s_robust = "SPHINCS+-SHA2-192s-robust";
    public const string SPHINCS_PLUS_SHA2_256f_simple = "SPHINCS+-SHA2-256f-simple";
    public const string SPHINCS_PLUS_SHA2_256f_robust = "SPHINCS+-SHA2-256f-robust";
    public const string SPHINCS_PLUS_SHA2_256s_simple = "SPHINCS+-SHA2-256s-simple";
    public const string SPHINCS_PLUS_SHA2_256s_robust = "SPHINCS+-SHA2-256s-robust";

    public const string SPHINCS_PLUS_SHAKE_128f_simple = "SPHINCS+-SHAKE-128f-simple";
    public const string SPHINCS_PLUS_SHAKE_128f_robust = "SPHINCS+-SHAKE-128f-robust";
    public const string SPHINCS_PLUS_SHAKE_128s_simple = "SPHINCS+-SHAKE-128s-simple";
    public const string SPHINCS_PLUS_SHAKE_128s_robust = "SPHINCS+-SHAKE-128s-robust";
    public const string SPHINCS_PLUS_SHAKE_192f_simple = "SPHINCS+-SHAKE-192f-simple";
    public const string SPHINCS_PLUS_SHAKE_192f_robust = "SPHINCS+-SHAKE-192f-robust";
    public const string SPHINCS_PLUS_SHAKE_192s_simple = "SPHINCS+-SHAKE-192s-simple";
    public const string SPHINCS_PLUS_SHAKE_192s_robust = "SPHINCS+-SHAKE-192s-robust";
    public const string SPHINCS_PLUS_SHAKE_256f_simple = "SPHINCS+-SHAKE-256f-simple";
    public const string SPHINCS_PLUS_SHAKE_256f_robust = "SPHINCS+-SHAKE-256f-robust";
    public const string SPHINCS_PLUS_SHAKE_256s_simple = "SPHINCS+-SHAKE-256s-simple";
    public const string SPHINCS_PLUS_SHAKE_256s_robust = "SPHINCS+-SHAKE-256s-robust";

    public const string CROSS_rsdp_128_balanced = "CROSS-rsdp-128-balanced";
    public const string CROSS_rsdp_128_fast = "CROSS-rsdp-128-fast";
    public const string CROSS_rsdp_128_small = "CROSS-rsdp-128-small";
    public const string CROSS_rsdp_192_balanced = "CROSS-rsdp-192-balanced";
    public const string CROSS_rsdp_192_fast = "CROSS-rsdp-192-fast";
    public const string CROSS_rsdp_192_small = "CROSS-rsdp-192-small";
    public const string CROSS_rsdp_256_balanced = "CROSS-rsdp-256-balanced";
    public const string CROSS_rsdp_256_fast = "CROSS-rsdp-256-fast";
    public const string CROSS_rsdp_256_small = "CROSS-rsdp-256-small";
    public const string CROSS_rsdpg_128_balanced = "CROSS-rsdpg-128-balanced";
    public const string CROSS_rsdpg_128_fast = "CROSS-rsdpg-128-fast";
    public const string CROSS_rsdpg_128_small = "CROSS-rsdpg-128-small";
    public const string CROSS_rsdpg_192_balanced = "CROSS-rsdpg-192-balanced";
    public const string CROSS_rsdpg_192_fast = "CROSS-rsdpg-192-fast";
    public const string CROSS_rsdpg_192_small = "CROSS-rsdpg-192-small";
    public const string CROSS_rsdpg_256_balanced = "CROSS-rsdpg-256-balanced";
    public const string CROSS_rsdpg_256_fast = "CROSS-rsdpg-256-fast";
    public const string CROSS_rsdpg_256_small = "CROSS-rsdpg-256-small";

    public const string Falcon_512_padded = "Falcon-padded-512";
    public const string Falcon_1024_padded = "Falcon-padded-1024";

    public const string MAYO_1 = "MAYO-1";
    public const string MAYO_2 = "MAYO-2";
    public const string MAYO_3 = "MAYO-3";
    public const string MAYO_5 = "MAYO-5";

    public const string SNOVA_24_5_4 = "SNOVA-24-5-4";
    public const string SNOVA_24_5_4_esk = "SNOVA-24-5-4-esk";
    public const string SNOVA_24_5_4_SHAKE = "SNOVA-24-5-4-SHAKE";
    public const string SNOVA_24_5_4_SHAKE_esk = "SNOVA-24-5-4-SHAKE-esk";
    public const string SNOVA_24_5_5 = "SNOVA-24-5-5";
    public const string SNOVA_25_8_3 = "SNOVA-25-8-3";
    public const string SNOVA_29_6_5 = "SNOVA-29-6-5";
    public const string SNOVA_37_17_2 = "SNOVA-37-17-2";
    public const string SNOVA_37_8_4 = "SNOVA-37-8-4";
    public const string SNOVA_49_11_3 = "SNOVA-49-11-3";
    public const string SNOVA_56_25_2 = "SNOVA-56-25-2";
    public const string SNOVA_60_10_4 = "SNOVA-60-10-4";

    public const string UOV_Ip = "OV-Ip";
    public const string UOV_Ip_pkc = "OV-Ip-pkc";
    public const string UOV_Ip_pkc_skc = "OV-Ip-pkc-skc";
    public const string UOV_Is = "OV-Is";
    public const string UOV_Is_pkc = "OV-Is-pkc";
    public const string UOV_Is_pkc_skc = "OV-Is-pkc-skc";
    public const string UOV_III = "OV-III";
    public const string UOV_III_pkc = "OV-III-pkc";
    public const string UOV_III_pkc_skc = "OV-III-pkc-skc";
    public const string UOV_V = "OV-V";
    public const string UOV_V_pkc = "OV-V-pkc";
    public const string UOV_V_pkc_skc = "OV-V-pkc-skc";

    public const string Rainbow_I_Classic = "Rainbow-I-Classic";
    public const string Rainbow_I_Circumzenithal = "Rainbow-I-Circumzenithal";
    public const string Rainbow_I_Compressed = "Rainbow-I-Compressed";
    public const string Rainbow_III_Classic = "Rainbow-III-Classic";
    public const string Rainbow_III_Circumzenithal = "Rainbow-III-Circumzenithal";
    public const string Rainbow_III_Compressed = "Rainbow-III-Compressed";
    public const string Rainbow_V_Classic = "Rainbow-V-Classic";
    public const string Rainbow_V_Circumzenithal = "Rainbow-V-Circumzenithal";
    public const string Rainbow_V_Compressed = "Rainbow-V-Compressed";

    /// <summary>
    /// Gets all signature algorithm identifiers.
    /// </summary>
    public static readonly string[] All = [
        Dilithium2, Dilithium3, Dilithium5,
            ML_DSA_44, ML_DSA_65, ML_DSA_87,
            Falcon_512, Falcon_1024, Falcon_512_padded, Falcon_1024_padded,
            CROSS_rsdp_128_balanced, CROSS_rsdp_128_fast, CROSS_rsdp_128_small,
            CROSS_rsdp_192_balanced, CROSS_rsdp_192_fast, CROSS_rsdp_192_small,
            CROSS_rsdp_256_balanced, CROSS_rsdp_256_fast, CROSS_rsdp_256_small,
            CROSS_rsdpg_128_balanced, CROSS_rsdpg_128_fast, CROSS_rsdpg_128_small,
            CROSS_rsdpg_192_balanced, CROSS_rsdpg_192_fast, CROSS_rsdpg_192_small,
            CROSS_rsdpg_256_balanced, CROSS_rsdpg_256_fast, CROSS_rsdpg_256_small,
            MAYO_1, MAYO_2, MAYO_3, MAYO_5,
            SNOVA_24_5_4, SNOVA_24_5_4_esk, SNOVA_24_5_4_SHAKE, SNOVA_24_5_4_SHAKE_esk,
            SNOVA_24_5_5, SNOVA_25_8_3, SNOVA_29_6_5, SNOVA_37_17_2, SNOVA_37_8_4,
            SNOVA_49_11_3, SNOVA_56_25_2, SNOVA_60_10_4,
            SPHINCS_PLUS_SHA2_128f_simple, SPHINCS_PLUS_SHA2_128f_robust,
            SPHINCS_PLUS_SHA2_128s_simple, SPHINCS_PLUS_SHA2_128s_robust,
            SPHINCS_PLUS_SHA2_192f_simple, SPHINCS_PLUS_SHA2_192f_robust,
            SPHINCS_PLUS_SHA2_192s_simple, SPHINCS_PLUS_SHA2_192s_robust,
            SPHINCS_PLUS_SHA2_256f_simple, SPHINCS_PLUS_SHA2_256f_robust,
            SPHINCS_PLUS_SHA2_256s_simple, SPHINCS_PLUS_SHA2_256s_robust,
            SPHINCS_PLUS_SHAKE_128f_simple, SPHINCS_PLUS_SHAKE_128f_robust,
            SPHINCS_PLUS_SHAKE_128s_simple, SPHINCS_PLUS_SHAKE_128s_robust,
            SPHINCS_PLUS_SHAKE_192f_simple, SPHINCS_PLUS_SHAKE_192f_robust,
            SPHINCS_PLUS_SHAKE_192s_simple, SPHINCS_PLUS_SHAKE_192s_robust,
            SPHINCS_PLUS_SHAKE_256f_simple, SPHINCS_PLUS_SHAKE_256f_robust,
            SPHINCS_PLUS_SHAKE_256s_simple, SPHINCS_PLUS_SHAKE_256s_robust,
            UOV_Ip, UOV_Ip_pkc, UOV_Ip_pkc_skc, UOV_Is, UOV_Is_pkc, UOV_Is_pkc_skc,
            UOV_III, UOV_III_pkc, UOV_III_pkc_skc, UOV_V, UOV_V_pkc, UOV_V_pkc_skc,
            Rainbow_I_Classic, Rainbow_I_Circumzenithal, Rainbow_I_Compressed,
            Rainbow_III_Classic, Rainbow_III_Circumzenithal, Rainbow_III_Compressed,
            Rainbow_V_Classic, Rainbow_V_Circumzenithal, Rainbow_V_Compressed
    ];

    /// <summary>
    /// Gets NIST standardized signature algorithms (recommended for production use).
    /// </summary>
    public static readonly string[] NISTStandardized = [
        ML_DSA_44, ML_DSA_65, ML_DSA_87
    ];

    /// <summary>
    /// Gets deprecated signature algorithms (should not be used in production).
    /// </summary>
    public static readonly string[] Deprecated = [
        Rainbow_I_Classic, Rainbow_I_Circumzenithal, Rainbow_I_Compressed,
            Rainbow_III_Classic, Rainbow_III_Circumzenithal, Rainbow_III_Compressed,
            Rainbow_V_Classic, Rainbow_V_Circumzenithal, Rainbow_V_Compressed
    ];
}

/// <summary>
/// Stateful signature algorithm identifiers.
/// These algorithms maintain state in the secret key and can only sign a limited number of times.
/// </summary>
public static class StatefulSignatureAlgorithms
{
    public const string LMS_SHA256_M32_H5 = "LMS_SHA256_M32_H5";
    public const string LMS_SHA256_M32_H10 = "LMS_SHA256_M32_H10";
    public const string LMS_SHA256_M32_H15 = "LMS_SHA256_M32_H15";
    public const string LMS_SHA256_M32_H20 = "LMS_SHA256_M32_H20";
    public const string LMS_SHA256_M32_H25 = "LMS_SHA256_M32_H25";

    public const string XMSS_SHA2_10_256 = "XMSS-SHA2_10_256";
    public const string XMSS_SHA2_16_256 = "XMSS-SHA2_16_256";
    public const string XMSS_SHA2_20_256 = "XMSS-SHA2_20_256";
    public const string XMSS_SHAKE_10_256 = "XMSS-SHAKE_10_256";
    public const string XMSS_SHAKE_16_256 = "XMSS-SHAKE_16_256";
    public const string XMSS_SHAKE_20_256 = "XMSS-SHAKE_20_256";

    public const string XMSSMT_SHA2_20_2_256 = "XMSSMT-SHA2_20/2_256";
    public const string XMSSMT_SHA2_20_4_256 = "XMSSMT-SHA2_20/4_256";
    public const string XMSSMT_SHA2_40_2_256 = "XMSSMT-SHA2_40/2_256";
    public const string XMSSMT_SHA2_40_4_256 = "XMSSMT-SHA2_40/4_256";
    public const string XMSSMT_SHA2_40_8_256 = "XMSSMT-SHA2_40/8_256";
    public const string XMSSMT_SHA2_60_3_256 = "XMSSMT-SHA2_60/3_256";
    public const string XMSSMT_SHA2_60_6_256 = "XMSSMT-SHA2_60/6_256";
    public const string XMSSMT_SHA2_60_12_256 = "XMSSMT-SHA2_60/12_256";

    public const string XMSSMT_SHAKE_20_2_256 = "XMSSMT-SHAKE_20/2_256";
    public const string XMSSMT_SHAKE_20_4_256 = "XMSSMT-SHAKE_20/4_256";
    public const string XMSSMT_SHAKE_40_2_256 = "XMSSMT-SHAKE_40/2_256";
    public const string XMSSMT_SHAKE_40_4_256 = "XMSSMT-SHAKE_40/4_256";
    public const string XMSSMT_SHAKE_40_8_256 = "XMSSMT-SHAKE_40/8_256";
    public const string XMSSMT_SHAKE_60_3_256 = "XMSSMT-SHAKE_60/3_256";
    public const string XMSSMT_SHAKE_60_6_256 = "XMSSMT-SHAKE_60/6_256";
    public const string XMSSMT_SHAKE_60_12_256 = "XMSSMT-SHAKE_60/12_256";

    /// <summary>
    /// Gets all stateful signature algorithm identifiers.
    /// </summary>
    public static readonly string[] All = [
        LMS_SHA256_M32_H5, LMS_SHA256_M32_H10, LMS_SHA256_M32_H15, LMS_SHA256_M32_H20, LMS_SHA256_M32_H25,
            XMSS_SHA2_10_256, XMSS_SHA2_16_256, XMSS_SHA2_20_256,
            XMSS_SHAKE_10_256, XMSS_SHAKE_16_256, XMSS_SHAKE_20_256,
            XMSSMT_SHA2_20_2_256, XMSSMT_SHA2_20_4_256, XMSSMT_SHA2_40_2_256, XMSSMT_SHA2_40_4_256,
            XMSSMT_SHA2_40_8_256, XMSSMT_SHA2_60_3_256, XMSSMT_SHA2_60_6_256, XMSSMT_SHA2_60_12_256,
            XMSSMT_SHAKE_20_2_256, XMSSMT_SHAKE_20_4_256, XMSSMT_SHAKE_40_2_256, XMSSMT_SHAKE_40_4_256,
            XMSSMT_SHAKE_40_8_256, XMSSMT_SHAKE_60_3_256, XMSSMT_SHAKE_60_6_256, XMSSMT_SHAKE_60_12_256
    ];
}

/// <summary>
/// Security levels as defined by NIST for post-quantum cryptography.
/// </summary>
public enum NistSecurityLevel
{
    /// <summary>
    /// No security level specified or unknown.
    /// </summary>
    None = 0,

    /// <summary>
    /// Security Level 1: Equivalent to AES-128 (128-bit security).
    /// </summary>
    Level1 = 1,

    /// <summary>
    /// Security Level 3: Equivalent to AES-192 (192-bit security).
    /// </summary>
    Level3 = 3,

    /// <summary>
    /// Security Level 5: Equivalent to AES-256 (256-bit security).
    /// </summary>
    Level5 = 5
}

/// <summary>
/// Provides constants for all liboqs algorithm identifiers.
/// This eliminates the need to use magic strings when working with cryptographic algorithms.
/// </summary>
public static class AlgorithmConstants
{
    /// <summary>
    /// Gets or sets whether deprecation warnings should be shown for deprecated algorithms.
    /// </summary>
    public static bool DeprecationWarningsEnabled { get; set; } = true;

    /// <summary>
    /// Determines if an algorithm is NIST standardized.
    /// </summary>
    /// <param name="algorithmName">The algorithm name to check.</param>
    /// <returns>True if the algorithm is NIST standardized, false otherwise.</returns>
    public static bool IsNISTStandardized(string algorithmName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithmName);

        return Array.Exists(KemAlgorithms.NISTStandardized, alg => alg.Equals(algorithmName, StringComparison.OrdinalIgnoreCase)) ||
               Array.Exists(SignatureAlgorithms.NISTStandardized, alg => alg.Equals(algorithmName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Determines if an algorithm is deprecated and should not be used.
    /// </summary>
    /// <param name="algorithmName">The algorithm name to check.</param>
    /// <returns>True if the algorithm is deprecated, false otherwise.</returns>
    public static bool IsDeprecated(string algorithmName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithmName);

        return Array.Exists(KemAlgorithms.Deprecated, alg => alg.Equals(algorithmName, StringComparison.OrdinalIgnoreCase)) ||
               Array.Exists(SignatureAlgorithms.Deprecated, alg => alg.Equals(algorithmName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Checks if an algorithm is deprecated and issues a warning if deprecation warnings are enabled.
    /// </summary>
    /// <param name="algorithmName">The algorithm name to check.</param>
    /// <param name="context">The context where the algorithm is being used.</param>
    public static void CheckForDeprecationWarning(string algorithmName, string context)
    {
        if (!DeprecationWarningsEnabled || string.IsNullOrWhiteSpace(algorithmName))
            return;

        if (IsDeprecated(algorithmName))
        {
            System.Diagnostics.Debug.WriteLine($"WARNING: Deprecated algorithm '{algorithmName}' is being used in {context}. " +
                                              "This algorithm has known security issues and should not be used in production.");
        }
    }
}

#pragma warning restore CA1707 // Identifiers should not contain underscores
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member