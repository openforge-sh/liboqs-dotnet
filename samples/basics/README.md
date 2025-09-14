# Basic Examples

This directory contains fundamental examples for getting started with OpenForge.Cryptography.LibOqs. These examples demonstrate the core concepts and basic usage patterns.

## Examples Included

### Key Encapsulation Mechanisms (KEM)
- **Basic KEM Usage**: Generate keys, encapsulate, and decapsulate shared secrets
- **Algorithm Comparison**: Compare ML-KEM-512, ML-KEM-768, and ML-KEM-1024
- **Error Handling**: Proper exception handling and validation

### Digital Signatures  
- **Basic Signatures**: Sign and verify messages with ML-DSA algorithms
- **Algorithm Selection**: Choose the right algorithm for your use case
- **Performance Considerations**: Understanding the trade-offs

### Core Library Features
- **Algorithm Discovery**: Find available algorithms on your platform
- **Memory Management**: Efficient handling of cryptographic keys and data
- **Thread Safety**: Safe usage in multi-threaded applications

## Quick Start

Each example includes:
- Complete working code
- Clear explanations
- Performance considerations
- Best practices

Start with the basic examples and progress to more advanced usage patterns in the `advanced/` directory.

## Running Examples

```bash
cd basics/
dotnet run
```

Most examples include command-line options to run specific demonstrations.