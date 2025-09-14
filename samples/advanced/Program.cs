namespace OpenForge.Cryptography.LibOqs.Samples.Advanced;

/// <summary>
/// Main program for running advanced examples.
/// </summary>
static class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("OpenForge.Cryptography.LibOqs");
        Console.WriteLine("Advanced Examples - Complex Post-Quantum Cryptography Scenarios");
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
                Console.WriteLine("Running all advanced examples...\n");
                AdvancedExamples.RunAllExamples();
            }
            else
            {
                switch (args[0].ToUpperInvariant())
                {
                    case "algorithms":
                    case "selection":
                        AdvancedExamples.AlgorithmSelection();
                        break;
                    case "performance":
                    case "benchmarking":
                        AdvancedExamples.PerformanceBenchmarking();
                        break;
                    case "cross-platform":
                    case "deployment":
                        AdvancedExamples.CrossPlatformDeployment();
                        break;
                    case "interoperability":
                    case "interop":
                        AdvancedExamples.Interoperability();
                        break;
                    case "migration":
                    case "strategy":
                        AdvancedExamples.MigrationStrategies();
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
        Console.WriteLine("Security Reminders:");
        Console.WriteLine("• These examples demonstrate advanced concepts for experienced developers");
        Console.WriteLine("• Always validate algorithm compatibility with your use case");
        Console.WriteLine("• Consider migration timeline and regulatory requirements");
        Console.WriteLine("• Test thoroughly on target platforms before deployment");
        Console.WriteLine();
        Console.WriteLine("Next Steps:");
        Console.WriteLine("• Review NIST guidance for post-quantum cryptography standards");
        Console.WriteLine("• Plan your migration strategy based on organizational needs");
        Console.WriteLine("• Test interoperability with existing systems");
    }

    private static void ShowHelp()
    {
        Console.WriteLine("Available examples:");
        Console.WriteLine("  algorithms, selection    - Algorithm selection guidance and comparison");
        Console.WriteLine("  performance, benchmarking - Performance analysis and optimization");
        Console.WriteLine("  cross-platform, deployment - Cross-platform compatibility and deployment");
        Console.WriteLine("  interoperability, interop - Integration with other crypto libraries");
        Console.WriteLine("  migration, strategy      - Migration planning and hybrid approaches");
        Console.WriteLine();
        Console.WriteLine("Run without arguments to execute all examples.");
    }
}