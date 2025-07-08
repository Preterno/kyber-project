# ML-KEM Python Implementation

A Python implementation of the ML-KEM (Kyber-based Module-Lattice Key Encapsulation Mechanism) algorithm as standardized in **NIST FIPS 203**.

## Features

- **Complete ML-KEM Implementation**: All three variants (512, 768, 1024) following official NIST FIPS 203 specification
- **Secure Messaging CLI**: Real-time encrypted chat using ML-KEM for key exchange and AES-GCM for message encryption
- **Performance Tools**: Comprehensive benchmarking and correctness/CCA-resistance verification
- **Modular Design**: Clean separation of KEM operations, PKE primitives, and utility functions

## Quick Start

```bash
git clone https://github.com/Preterno/ml-kem.git
cd ml-kem
pip install -r requirements.txt
python test.py  # Verify installation
```

## Installation

### Requirements

- Python 3.8 or higher
- Dependencies listed in `requirements.txt`

### Setup

```bash
git clone https://github.com/Preterno/ml-kem.git
cd ml-kem
pip install -r requirements.txt
```

## Usage

### Basic Example

```python
from pke.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024
from kem.keygen import ml_kem_keygen
from kem.encapsulate import ml_kem_encaps
from kem.decapsulate import ml_kem_decaps

# Choose ML-KEM variant
params = ML_KEM_768

# Generate key pair
ek, dk = ml_kem_keygen(params)  # ek = encapsulation key, dk = decapsulation key

# Encapsulate (sender side)
K, ct = ml_kem_encaps(ek, params)  # K = shared secret, ct = ciphertext

# Decapsulate (receiver side)
K_prime = ml_kem_decaps(dk, ct, params)

assert K == K_prime  # Shared secrets should match
```

### Run Tests

To verify correctness and CCA security:

```bash
python test.py
```

### Run Benchmarks

To measure performance of ML-KEM operations:

```bash
python benchmark_mlkem.py
```

### Secure Messaging CLI

Launch the encrypted chat application:

1. **Start the server:**

```bash
python chat/server.py
```

2. **Connect with client:**

```bash
python chat/client.py
```

The client and server perform ML-KEM-768 key exchange and use AES-GCM for encrypted messaging.

## Project Structure

```
.
├── kem/                    # ML-KEM logic (keygen, encaps, decaps)
├── pke/                    # Kyber PKE primitives
├── utils/                  # Support utilities (hashing, polynomials, etc.)
├── chat/                   # CLI chat app using ML-KEM + AES
├── benchmark_mlkem.py
├── test.py
├── requirements.txt
```

## Performance Benchmarks

### Execution Time Comparison

| Variant     | KeyGen   | Encaps   | Decaps   | Full Cycle | Public Key Size |
| ----------- | -------- | -------- | -------- | ---------- | --------------- |
| ML-KEM-512  | 13.13 ms | 15.20 ms | 40.00 ms | 53.04 ms   | 800 bytes       |
| ML-KEM-768  | 19.57 ms | 22.85 ms | 59.28 ms | 78.63 ms   | 1,184 bytes     |
| ML-KEM-1024 | 28.00 ms | 32.68 ms | 84.03 ms | 115.77 ms  | 1,568 bytes     |

### Throughput Comparison

| Variant     | KeyGen       | Encaps       | Decaps       | Full Cycle   |
| ----------- | ------------ | ------------ | ------------ | ------------ |
| ML-KEM-512  | 76.2 ops/sec | 65.8 ops/sec | 25.0 ops/sec | 18.9 ops/sec |
| ML-KEM-768  | 51.1 ops/sec | 43.8 ops/sec | 16.9 ops/sec | 12.7 ops/sec |
| ML-KEM-1024 | 35.7 ops/sec | 30.6 ops/sec | 11.9 ops/sec | 8.6 ops/sec  |

> **Note:** Benchmarks may vary depending on hardware and system configuration. Run `python benchmark_mlkem.py` for your specific environment.

## Disclaimer

This project is for educational and research use only. It has not undergone security audits and is not intended for production or security-critical deployments.
