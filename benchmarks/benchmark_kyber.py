"""
ML-KEM (Kyber) Performance Benchmark

Simple, focused benchmarking of ML-KEM key operations:
- Key Generation
- Encapsulation  
- Decapsulation
- Timing analysis
"""

import time
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kyber_project.kem.keygen import ml_kem_keygen
from kyber_project.kem.encapsulate import ml_kem_encaps
from kyber_project.kem.decapsulate import ml_kem_decaps
from kyber_project.pke.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024

def benchmark_operation(operation_name, operation_func, iterations=50):
    """Benchmark a single operation."""
    print(f"\nBenchmarking {operation_name} ({iterations} iterations)...")
    
    # Warm up
    for _ in range(5):
        operation_func()
    
    # Actual timing
    times = []
    for i in range(iterations):
        start = time.perf_counter()
        result = operation_func()
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to ms
        
        if i % 10 == 0:
            print(f"  Progress: {i+1}/{iterations}")
    
    # Calculate statistics
    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    
    print(f"  Average: {avg_time:.2f} ms")
    print(f"  Min:     {min_time:.2f} ms") 
    print(f"  Max:     {max_time:.2f} ms")
    
    return {
        'avg_ms': avg_time,
        'min_ms': min_time,
        'max_ms': max_time,
        'ops_per_sec': 1000 / avg_time
    }

def benchmark_kyber_variant(params):
    """Benchmark all operations for a specific Kyber variant."""
    print(f"\n{'='*60}")
    print(f"BENCHMARKING {params.name}")
    print(f"Security Level: {params.security_category}")
    print(f"{'='*60}")
    
    # Pre-generate keys for encaps/decaps testing
    test_ek, test_dk = ml_kem_keygen(params)
    test_K, test_c = ml_kem_encaps(test_ek, params)
    
    results = {}
    
    # Benchmark Key Generation
    results['keygen'] = benchmark_operation(
        "Key Generation",
        lambda: ml_kem_keygen(params)
    )
    
    # Benchmark Encapsulation
    results['encaps'] = benchmark_operation(
        "Encapsulation", 
        lambda: ml_kem_encaps(test_ek, params)
    )
    
    # Benchmark Decapsulation
    results['decaps'] = benchmark_operation(
        "Decapsulation",
        lambda: ml_kem_decaps(test_dk, test_c, params)
    )
    
    # Benchmark Full KEM Cycle
    def full_cycle():
        ek, dk = ml_kem_keygen(params)
        K1, c = ml_kem_encaps(ek, params)
        K2 = ml_kem_decaps(dk, c, params)
        return K1 == K2
    
    results['full_cycle'] = benchmark_operation(
        "Full KEM Cycle",
        full_cycle
    )
    
    # Print summary
    print(f"\n{params.name} PERFORMANCE SUMMARY:")
    print("-" * 40)
    print(f"KeyGen:     {results['keygen']['avg_ms']:.2f} ms ({results['keygen']['ops_per_sec']:.1f} ops/sec)")
    print(f"Encaps:     {results['encaps']['avg_ms']:.2f} ms ({results['encaps']['ops_per_sec']:.1f} ops/sec)")
    print(f"Decaps:     {results['decaps']['avg_ms']:.2f} ms ({results['decaps']['ops_per_sec']:.1f} ops/sec)")
    print(f"Full Cycle: {results['full_cycle']['avg_ms']:.2f} ms ({results['full_cycle']['ops_per_sec']:.1f} ops/sec)")
    print(f"Total Memory: {sum(r['memory_mb'] for r in results.values() if 'memory_mb' in r):.2f} MB")
    
    # Key sizes
    ek, dk = ml_kem_keygen(params)
    K, c = ml_kem_encaps(ek, params)
    print(f"\nKEY SIZES:")
    print(f"Public Key:    {len(ek):,} bytes")
    print(f"Secret Key:    {len(dk):,} bytes") 
    print(f"Ciphertext:    {len(c):,} bytes")
    print(f"Shared Secret: {len(K):,} bytes")
    
    return results

def print_comparison_table(all_results):
    """Print comparison table across all variants."""
    print(f"\n{'='*80}")
    print("ML-KEM VARIANTS COMPARISON")
    print(f"{'='*80}")
    
    print(f"{'Variant':<12} {'KeyGen(ms)':<12} {'Encaps(ms)':<12} {'Decaps(ms)':<12}")
    print("-" * 60)
    
    for variant, results in all_results.items():
        keygen_time = results['keygen']['avg_ms']
        encaps_time = results['encaps']['avg_ms'] 
        decaps_time = results['decaps']['avg_ms']
        
        print(f"{variant:<12} {keygen_time:<12.2f} {encaps_time:<12.2f} {decaps_time:<12.2f}")

def main():
    """Run complete Kyber benchmark suite."""
    print("ML-KEM (KYBER) PERFORMANCE BENCHMARK")
    print("=" * 80)
    print(f"Python: {sys.version.split()[0]}")
    
    variants = [
        ('ML-KEM-512', ML_KEM_512),
        ('ML-KEM-768', ML_KEM_768), 
        ('ML-KEM-1024', ML_KEM_1024)
    ]
    
    all_results = {}
    
    for name, params in variants:
        try:
            all_results[name] = benchmark_kyber_variant(params)
        except Exception as e:
            print(f"Error benchmarking {name}: {e}")
            continue
    
    # Print final comparison
    if all_results:
        print_comparison_table(all_results)
    
    print(f"\nBenchmark completed!")

if __name__ == "__main__":
    main()