namespace OpenForge.Cryptography.LibOqs.Samples.Basics;

/// <summary>
/// Main program for running basic examples.
/// </summary>
static class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("OpenForge.Cryptography.LibOqs");
        Console.WriteLine("Basic Examples - Getting Started with Post-Quantum Cryptography");
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
                Console.WriteLine("Running all basic examples...\n");
                BasicExamples.RunAllExamples();
            }
            else
            {
                switch (args[0].ToUpperInvariant())
                {
                    case "kem":
                    case "keys":
                        BasicExamples.BasicKemUsage();
                        break;
                    case "signatures":
                    case "sig":
                        BasicExamples.BasicSignatureUsage();
                        break;
                    case "discovery":
                    case "algorithms":
                        BasicExamples.AlgorithmDiscovery();
                        break;
                    case "errors":
                    case "validation":
                        BasicExamples.ErrorHandling();
                        break;
                    case "performance":
                    case "memory":
                        BasicExamples.MemoryAndPerformance();
                        break;
                    default:
                        Console.WriteLine($"Unknown example: {args[0]}");
                        Console.WriteLine("Use --help for available options.");
                        break;
                }
            }
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"Error running examples: {ex.Message}");
            Console.WriteLine();
            Console.WriteLine("This might indicate:");
            Console.WriteLine("• Algorithm not supported on this platform");
            Console.WriteLine("• Invalid parameters passed to cryptographic functions");
        }
        catch (InvalidOperationException ex)
        {
            Console.WriteLine($"Error running examples: {ex.Message}");
            Console.WriteLine();
            Console.WriteLine("This might indicate:");
            Console.WriteLine("• Missing native library dependencies");
            Console.WriteLine("• Unsupported platform or architecture");
        }

        Console.WriteLine();
        Console.WriteLine("Next Steps:");
        Console.WriteLine("• Try the 'advanced' examples for more complex scenarios");
        Console.WriteLine("• Check the documentation at https://docs.openforge.io/");
        Console.WriteLine("• Visit https://openquantumsafe.org/ for more about post-quantum crypto");
    }

    private static void ShowHelp()
    {
        Console.WriteLine("Available examples:");
        Console.WriteLine("  kem, keys        - Basic KEM (key encapsulation) usage");
        Console.WriteLine("  signatures, sig  - Basic digital signature usage");
        Console.WriteLine("  discovery        - Algorithm discovery and comparison");
        Console.WriteLine("  errors           - Error handling and validation");
        Console.WriteLine("  performance      - Memory and performance considerations");
        Console.WriteLine();
        Console.WriteLine("Run without arguments to execute all examples.");
    }
}