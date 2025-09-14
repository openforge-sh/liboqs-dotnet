namespace OpenForge.Cryptography.LibOqs.Samples.CommonScenarios;

/// <summary>
/// Main program for running common scenario examples.
/// </summary>
static class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("OpenForge.Cryptography.LibOqs");
        Console.WriteLine("Common Scenarios - Practical Post-Quantum Cryptography Usage");
        Console.WriteLine();

        if (args.Length > 0 && args[0] == "--help")
        {
            ShowHelp();
            return;
        }

        try
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Running all common scenario examples...\n");
                ScenarioExamples.RunAllScenarios();
            }
            else
            {
                switch (args[0].ToUpperInvariant())
                {
                    case "file":
                    case "encryption":
                        ScenarioExamples.FileEncryption();
                        break;
                    case "document":
                    case "signing":
                        ScenarioExamples.DocumentSigning();
                        break;
                    case "api":
                    case "authentication":
                        ScenarioExamples.ApiSecurity();
                        break;
                    case "database":
                    case "fields":
                        ScenarioExamples.DatabaseFieldEncryption();
                        break;
                    default:
                        Console.WriteLine($"Unknown scenario: {args[0]}");
                        Console.WriteLine("Use --help for available options.");
                        break;
                }
            }
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"Error running scenario: {ex.Message}");
            Console.WriteLine();
            Console.WriteLine("This might indicate:");
            Console.WriteLine("• Algorithm not supported on this platform");
            Console.WriteLine("• Invalid parameters in scenario setup");
        }
        catch (InvalidOperationException ex)
        {
            Console.WriteLine($"Error running scenario: {ex.Message}");
            Console.WriteLine();
            Console.WriteLine("This might indicate:");
            Console.WriteLine("• Missing native library dependencies");
            Console.WriteLine("• Unsupported platform or architecture");
        }

        Console.WriteLine();
        Console.WriteLine("Security Reminders:");
        Console.WriteLine("• These examples use simplified encryption for demonstration");
        Console.WriteLine("• Use proper AEAD ciphers (AES-GCM) in production");
        Console.WriteLine("• Implement secure key management and storage");
        Console.WriteLine("• Consider threat model and compliance requirements");
        Console.WriteLine();
        Console.WriteLine("Next Steps:");
        Console.WriteLine("• Review 'advanced' examples for complex migration scenarios");
        Console.WriteLine("• Check NIST guidance for post-quantum cryptography standards");
    }

    private static void ShowHelp()
    {
        Console.WriteLine("Available scenarios:");
        Console.WriteLine("  file             - File encryption using post-quantum KEM");
        Console.WriteLine("  document         - Document signing for authenticity");
        Console.WriteLine("  api              - API authentication and data protection");
        Console.WriteLine("  database         - Database field encryption");
        Console.WriteLine();
        Console.WriteLine("Run without arguments to execute all scenarios.");
    }
}