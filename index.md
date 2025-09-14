# OpenForge.Cryptography.LibOqs Documentation

Welcome to the official documentation for **OpenForge.Cryptography.LibOqs**, a comprehensive .NET wrapper for quantum-safe cryptography.

## 🚀 Getting Started

This documentation provides complete API reference for all packages and classes in the OpenForge.Cryptography.LibOqs library.

For comprehensive information including:
- Installation instructions
- Usage examples
- Supported algorithms
- Security considerations
- Package structure

Please refer to the main [README](README.md) page.

## 📚 Documentation Sections

### 💻 [Examples & Samples](samples/README.md)
Comprehensive examples and tutorials covering all library features:
- **Basic Examples** - Fundamental concepts and getting started
- **Common Scenarios** - File encryption, document signing, API security, database encryption
- **Advanced Usage** - Algorithm selection, performance optimization, cross-platform deployment, migration strategies
- **Testing & Validation** - Algorithm consistency, functional correctness, edge cases

### 📖 [API Reference](api/index.md)
Complete API documentation with detailed information about:
- **Namespaces** - Organized by functionality (KEM, Sig, SigStfl, Core)
- **Classes** - Complete class documentation with examples
- **Methods** - All public methods with parameters and return types
- **Properties** - Property descriptions and usage
- **Constants** - Algorithm identifiers and configuration options

## 🎯 Quick Links

### Key Encapsulation (KEM)
- `OpenForge.Cryptography.LibOqs.KEM.Kem` - Main KEM class
- `KemAlgorithms` - Available KEM algorithms

### Digital Signatures
- `OpenForge.Cryptography.LibOqs.Sig.Signature` - Main signature class  
- `SignatureAlgorithms` - Available signature algorithms

### Stateful Signatures
- `OpenForge.Cryptography.LibOqs.SigStfl.StatefulSignature` - Stateful signature class
- `StatefulSignatureAlgorithms` - Available stateful algorithms

## 📦 NuGet Packages

| Package | Description | When to Use |
|---------|-------------|-------------|
| `OpenForge.Cryptography.LibOqs` | Complete library with all algorithms | General purpose quantum-safe cryptography |
| `OpenForge.Cryptography.LibOqs.KEM` | Key encapsulation only | Key exchange scenarios |
| `OpenForge.Cryptography.LibOqs.Sig` | Digital signatures only | Authentication scenarios |
| `OpenForge.Cryptography.LibOqs.SigStfl` | Stateful signatures | Special use cases requiring stateful signatures |

## 🔒 Security Note

For production use, we recommend NIST-standardized algorithms:
- **ML-KEM** (formerly Kyber) for key encapsulation
- **ML-DSA** (formerly Dilithium) for digital signatures

## 📄 License

Licensed under the MIT License. See the [project repository](https://github.com/openforge/liboqs-dotnet) for details.