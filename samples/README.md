# OpenForge.Cryptography.LibOqs Samples

This directory contains practical examples for using OpenForge.Cryptography.LibOqs in real-world applications. The samples focus on clear, straightforward implementations without over-engineering.

## Sample Categories

### Basics (`basics/`)
Start here! Essential examples covering fundamental library usage:
- **Basic KEM Usage** - Key encapsulation and shared secrets
- **Basic Signatures** - Digital signing and verification  
- **Algorithm Discovery** - Finding available algorithms
- **Error Handling** - Proper exception handling
- **Memory & Performance** - Efficient usage patterns

### Common Scenarios (`common-scenarios/`)
Practical examples for real-world applications:
- **File Encryption** - Secure AES-GCM encryption with ML-KEM key exchange
- **Document Signing** - Digital signatures for authenticity and tamper detection
- **API Security** - Authenticate REST API calls with timestamps
- **Database Fields** - Encrypt sensitive database columns with post-quantum security

### Advanced (`advanced/`)
Complex scenarios for experienced developers:
- **Algorithm Selection** - Choose the right algorithms for your needs
- **Benchmarking** - Performance measurement and analysis
- **Cross-Platform** - Deploy across different operating systems
- **Interoperability** - Work with other cryptographic libraries
- **Migration Strategies** - Transition from classical to post-quantum
- **Advanced Signatures** - Multi-document signing and batch verification

### Testing (`testing/`)
Validation and testing examples:
- **Algorithm Consistency** - Verify implementations match specifications
- **Functional Correctness** - Ensure cryptographic operations work properly
- **Edge Cases** - Handle error conditions and invalid inputs
- **Performance Validation** - Check for reasonable performance

## Quick Start

1. **New to post-quantum crypto?** Start with `basics/`
2. **Need practical examples?** Check `common-scenarios/`  
3. **Planning migration?** Review `advanced/`
4. **Want to validate?** Use `testing/`

## Running Examples

Each directory is a complete .NET console application:

```bash
cd samples/basics/
dotnet run                    # Run all examples

dotnet run kem               # Run specific example
dotnet run --help            # Show available options
```

## Design Philosophy

These samples prioritize:
- **Clarity over cleverness** - Easy to understand implementations
- **Practical usage** - Real problems developers face
- **Security best practices** - Proper key management and error handling  
- **Minimal dependencies** - Focus on the crypto library, not frameworks

## What's Different

Unlike typical crypto examples that focus on academic concepts, these samples show:
- How to choose algorithms for different use cases
- Real error handling and validation
- Performance considerations and trade-offs
- Integration with existing systems
- Migration planning and strategy

## Key Concepts Covered

### Key Encapsulation Mechanisms (KEM)
- ML-KEM-512, ML-KEM-768, ML-KEM-1024
- Encapsulation and decapsulation
- Hybrid encryption patterns
- Key size and performance trade-offs

### Digital Signatures  
- ML-DSA-44, ML-DSA-65, ML-DSA-87
- Message signing and verification
- Document authenticity
- API authentication patterns

### Security Considerations
- Algorithm selection criteria
- Key management best practices
- Error handling and validation
- Performance vs security trade-offs
- Secure memory management and key disposal
- AES-GCM authenticated encryption patterns

## Next Steps

- Check [NIST Post-Quantum Standards](https://csrc.nist.gov/projects/pqc)
- Explore [Migration Planning](advanced/README.md#5-migration-strategies-migration)
- Visit [Open Quantum Safe](https://openquantumsafe.org/) for more resources

## Recent Improvements

- **Enhanced Security**: Replaced XOR encryption with proper AES-GCM authenticated encryption
- **Better API Usage**: Updated to use only public API methods throughout all samples
- **Resource Management**: Added proper `using` statements for automatic disposal
- **Error Handling**: Improved exception handling with specific types and better messages
- **Documentation**: Enhanced comments and explanations for cryptographic concepts

## Implementation Notes

All samples use:
- **.NET 9+** for modern C# features
- **Clean exception handling** with specific exception types
- **Proper resource disposal** with using statements for secure cleanup
- **Authenticated encryption** with AES-GCM for hybrid crypto scenarios
- **Clear documentation** explaining security considerations and best practices
- **Performance awareness** noting algorithm trade-offs and optimization tips
- **Production patterns** demonstrating real-world usage scenarios

These examples demonstrate production-ready patterns while remaining educational and approachable.