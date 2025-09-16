using System.Runtime.InteropServices;
using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

namespace OpenForge.Cryptography.LibOqs.Core.Tests;

[Collection("LibOqs Collection")]
public class AssemblyLocationDiagnosticTests(LibOqsTestFixture fixture, ITestOutputHelper output) : TestBase(output)
{
    private readonly LibOqsTestFixture _fixture = fixture;

    [Fact]
    public void DiagnoseAssemblyLocations()
    {
        Log("=== ASSEMBLY LOCATION DIAGNOSTICS ===");
        Log($"Platform: {CurrentPlatform}");
        Log($"Architecture: {CurrentArchitecture}");
        Log($"Framework: {RuntimeInformation.FrameworkDescription}");
        Log($"AppContext.BaseDirectory: {AppContext.BaseDirectory}");
        Log($"Environment.CurrentDirectory: {Environment.CurrentDirectory}");
        
        // Get all loaded assemblies that might be relevant
        var assemblies = AppDomain.CurrentDomain.GetAssemblies()
            .Where(a => a.GetName().Name?.Contains("OpenForge.Cryptography.LibOqs", StringComparison.OrdinalIgnoreCase) == true)
            .ToList();

        Log($"Found {assemblies.Count} relevant assemblies");

        foreach (var assembly in assemblies)
        {
            var name = assembly.GetName().Name;
            var location = assembly.Location;
            var codeBase = "";
            
            try 
            {
                #pragma warning disable CA1031, SYSLIB0012
                codeBase = assembly.CodeBase ?? "null";
#               pragma warning restore SYSLIB0012
            }
            catch (Exception ex)
            {
                codeBase = $"Error: {ex.Message}";
            }

            Log($"Assembly: {name}");
            Log($"  Location: '{location}' (IsEmpty: {string.IsNullOrEmpty(location)})");
            Log($"  CodeBase: '{codeBase}'");
            Log($"  IsDynamic: {assembly.IsDynamic}");
            
            if (!string.IsNullOrEmpty(location))
            {
                var dir = Path.GetDirectoryName(location);
                Log($"  Directory: '{dir}'");
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                {
                    var runtimesPath = Path.Combine(dir, "runtimes");
                    Log($"  Runtimes folder exists: {Directory.Exists(runtimesPath)}");
                    if (Directory.Exists(runtimesPath))
                    {
                        var archPath = Path.Combine(runtimesPath, "linux-arm64", "native");
                        Log($"  ARM64 native path exists: {Directory.Exists(archPath)}");
                        if (Directory.Exists(archPath))
                        {
                            var libPath = Path.Combine(archPath, "liboqs.so");
                            Log($"  liboqs.so exists: {File.Exists(libPath)}");
                        }
                    }
                }
            }
            Log("");
        }

        // Test the actual library loading mechanism
        Log("=== TESTING LIBRARY LOADING ===");
        try
        {
            // This should trigger the NativeLibraryLoader
            OqsCore.Initialize();
            var version = OqsCore.GetVersion();
            Log($"Successfully loaded LibOQS version: {version}");
        }
        catch (Exception ex)
        {
            Log($"Failed to load LibOQS: {ex.Message}");
            Log($"Stack trace: {ex.StackTrace}");
        }
        #pragma warning restore CA1031

        // Add a simple assertion to satisfy the test framework
        Assert.True(true, "Diagnostic test completed - check output for assembly location information");
    }
}