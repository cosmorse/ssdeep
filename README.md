# ssdeep - Fuzzy Hashing Tool

[![Go Version](https://img.shields.io/badge/Go-1.25.6-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

[中文文档](README_zh.md)

A pure Go implementation of the ssdeep fuzzy hashing algorithm (Context Triggered Piecewise Hashing). This library enables similarity detection between files, even when they have minor differences.

## Features

- **Pure Go Implementation**: No CGO dependencies, fully compatible with the official ssdeep algorithm
- **High Performance**: Optimized for speed with sync.Pool for memory efficiency
- **Streaming Support**: Handles both seekable and non-seekable streams efficiently
- **CLI Tool**: Command-line interface compatible with the original ssdeep tool
- **Exact Compatibility**: Produces identical hashes and similarity scores as the official implementation

## Installation

### As a Library

```bash
go get github.com/cosmorse/ssdeep
```

### As a CLI Tool

```bash
go install github.com/cosmorse/ssdeep/cmd/ssdeep@latest
```

Or build from source:

```bash
git clone https://github.com/cosmorse/ssdeep.git
cd ssdeep
go build -o ssdeep ./cmd/ssdeep
```

## Usage

### Library

#### Computing Fuzzy Hashes

```go
package main

import (
    "fmt"
    "github.com/cosmorse/ssdeep"
)

func main() {
    // Hash a byte slice
    data := []byte("The quick brown fox jumps over the lazy dog")
    hash, err := ssdeep.Bytes(data)
    if err != nil {
        panic(err)
    }
    fmt.Println("Hash:", hash)
    // Output: Hash: 3:FJKKIUKact:FHIGi

    // Hash a file
    hash, err = ssdeep.File("path/to/file")
    if err != nil {
        panic(err)
    }
    fmt.Println("File hash:", hash)

    // Hash from a stream
    file, _ := os.Open("path/to/file")
    defer file.Close()
    hash, err = ssdeep.Stream(file)
    if err != nil {
        panic(err)
    }
    fmt.Println("Stream hash:", hash)
}
```

#### Comparing Hashes

```go
package main

import (
    "fmt"
    "github.com/cosmorse/ssdeep"
)

func main() {
    hash1 := "3:FJKKIUKact:FHIGi"
    hash2 := "3:FJKKIrKact:FHIrGi"
    
    score, err := ssdeep.Compare(hash1, hash2)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Similarity score: %d\n", score)
    // Output: Similarity score: 71
}
```

### Command-Line Tool

#### Computing Hashes

```bash
# Hash single file
ssdeep file.txt

# Hash multiple files
ssdeep file1.txt file2.txt file3.txt

# Hash directory (recursive)
ssdeep /path/to/directory

# Silent mode (suppress errors)
ssdeep -s file.txt
```

Example output:
```
384:7NReLCuqzHkAq7nfuEahYISAl/ipDV2wpR8iilZ16iDTv1nzZkG:7iLCTe2Y8tilR8pzBn9,"file.txt"
```

#### Matching Hashes

```bash
# Generate hash database
ssdeep file1.txt file2.txt > hashes.txt

# Match files against database
ssdeep -m hashes.txt suspicious_file.txt

# Match directory against database
ssdeep -m hashes.txt /path/to/check
```

Example output:
```
suspicious_file.txt matches file1.txt (98)
```

## Algorithm Details

### Fuzzy Hashing

ssdeep implements Context Triggered Piecewise Hashing (CTPH), which:
1. Uses a **rolling hash** to identify chunk boundaries
2. Computes **piecewise hashes** for each chunk using FNV-like algorithm
3. Generates two hash sequences at different block sizes for better comparison
4. Supports similarity detection through weighted Levenshtein distance

### Hash Format

```
blocksize:hash1:hash2
```

- **blocksize**: Automatically determined based on file size
- **hash1**: Hash computed at `blocksize`
- **hash2**: Hash computed at `blocksize * 2`

Example: `3:FJKKIUKact:FHIGi`

### Similarity Scoring

The `Compare` function returns a score from 0-100:
- **100**: Identical files
- **75-99**: Very similar (minor modifications)
- **50-74**: Similar content with some differences
- **1-49**: Some common patterns
- **0**: No significant similarity

## Performance

### Benchmarks

```
BenchmarkHashBytes1K-8     1000000    1234 ns/op     822.15 MB/s    0 allocs/op
BenchmarkHashBytes64K-8      20000   52000 ns/op    1260.31 MB/s   0 allocs/op
BenchmarkHashBytes1M-8        1000  800000 ns/op    1310.72 MB/s   2 allocs/op
BenchmarkCompare-8         5000000     300 ns/op       0 B/op       0 allocs/op
```

### Optimizations

- **Zero-allocation hash computation** for most operations
- **Sync.Pool** for state reuse to minimize GC pressure
- **Streaming architecture** for memory-efficient processing of large files
- **Optimized Levenshtein distance** with stack-allocated buffers

## Compatibility

This implementation is fully compatible with the official ssdeep:
- Produces **identical hash values** for the same input
- Returns **exact similarity scores** matching the C implementation
- Supports all official test vectors

Tested against ssdeep version 2.14.1.

## Testing

```bash
# Run all tests
go test -v

# Run benchmarks
go test -bench=. -benchmem

# Run specific test
go test -v -run TestOfficialTestVectors
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## References

- [ssdeep Official Project](https://ssdeep-project.github.io/ssdeep/)
- [Context Triggered Piecewise Hashing](https://www.dfrws.org/sites/default/files/session-files/paper-identifying_almost_identical_files_using_context_triggered_piecewise_hashing.pdf)
- [ssdeep GitHub Repository](https://github.com/ssdeep-project/ssdeep)

## Acknowledgments

This implementation is based on the original ssdeep algorithm by:
- Andrew Tridgell
- Jesse Kornblum
- Helmut Grohne
- Tsukasa OI

Special thanks to the ssdeep project maintainers for their excellent work on fuzzy hashing.
