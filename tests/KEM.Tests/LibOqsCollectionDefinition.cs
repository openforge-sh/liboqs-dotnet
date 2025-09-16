using OpenForge.Cryptography.LibOqs.Tests.Common;
using Xunit;

[assembly: AssemblyFixture(typeof(LibOqsTestFixture))]
namespace OpenForge.Cryptography.LibOqs.KEM.Tests;

[CollectionDefinition("LibOqs Collection")]
public sealed class LibOqsCollectionDefinition : ICollectionFixture<LibOqsTestFixture>
{
}