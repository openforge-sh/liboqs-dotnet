namespace OpenForge.Cryptography.LibOqs.Samples.Testing;

/// <summary>
/// Main program for running testing and validation examples.
/// </summary>
static class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("OpenForge.Cryptography.LibOqs");
        Console.WriteLine("Testing and Validation Examples");
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
                Console.WriteLine("Running all validation tests...\n");
                ValidationExamples.RunAllValidation();
            }
            else
            {
                switch (args[0].ToUpperInvariant())
                {
                    case "consistency":
                    case "specs":
                        ValidationExamples.AlgorithmConsistency();
                        break;
                    case "functional":
                    case "correctness":
                        ValidationExamples.FunctionalCorrectness();
                        break;
                    case "edge":
                    case "errors":
                        ValidationExamples.EdgeCaseValidation();
                        break;
                    case "performance":
                    case "speed":
                        ValidationExamples.PerformanceValidation();
                        break;
                    default:
                        Console.WriteLine($"Unknown test: {args[0]}");
                        Console.WriteLine("Use --help for available options.");
                        break;
                }
            }
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"Error running tests: {ex.Message}");
            Console.WriteLine();
            Console.WriteLine("This might indicate:");
            Console.WriteLine("• Algorithm not supported on this platform");
            Console.WriteLine("• Invalid parameters in test setup");
        }
        catch (InvalidOperationException ex)
        {
            Console.WriteLine($"Error running tests: {ex.Message}");
            Console.WriteLine();
            Console.WriteLine("This might indicate:");
            Console.WriteLine("• Missing native library dependencies");
            Console.WriteLine("• Unsupported platform or architecture");
        }

        Console.WriteLine();
        Console.WriteLine("Testing Resources:");
        Console.WriteLine("• NIST test vectors: https://csrc.nist.gov/projects/pqc");
        Console.WriteLine("• liboqs test suite: https://github.com/open-quantum-safe/liboqs");
        Console.WriteLine("• Interoperability testing with other implementations");
    }

    private static void ShowHelp()
    {
        Console.WriteLine("Available tests:");
        Console.WriteLine("  consistency      - Algorithm spec consistency validation");
        Console.WriteLine("  functional       - Functional correctness tests");
        Console.WriteLine("  edge             - Edge case and error condition tests");
        Console.WriteLine("  performance      - Performance consistency validation");
        Console.WriteLine();
        Console.WriteLine("Run without arguments to execute all tests.");
    }
}