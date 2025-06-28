"""
KEM-focused Performance Benchmark

Simple benchmarking focused on KEM operations with emphasis on:
- Timing analysis across security levels
- Throughput measurement
- Key size analysis
"""

import time
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kem.keygen import ml_kem_keygen
from kem.encapsulate import ml_kem_encaps, ml_kem_encaps_deterministic
from kem.decapsulate import ml_kem_decaps
from pke.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024

def time_operation(operation_func, iterations=25):
    """Time an operation and return statistics."""
    # Warm up
    for _ in range(3):
        operation_func()
    
    # Time the operation
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        operation_func()
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to ms
    
    return {
        'avg_ms': sum(times) / len(times),
        'min_ms': min(times),
        'max_ms': max(times),
        'total_ms': sum(times)
    }

def benchmark_kem_operations(params, iterations=25):
    """Benchmark all KEM operations for a parameter set."""
    print(f"\nBenchmarking {params.name}:")
    print(f"  Security Level: {params.security_category}")
    print(f"  Iterations: {iterations}")
    
    results = {}
    
    # Key Generation
    print("  → Key Generation...")
    results['keygen'] = time_operation(
        lambda: ml_kem_keygen(params),
        iterations
    )
    
    # Pre-generate keys for other operations
    ek, dk = ml_kem_keygen(params)
    
    # Encapsulation
    print("  → Encapsulation...")
    results['encaps'] = time_operation(
        lambda: ml_kem_encaps(ek, params),
        iterations
    )
    
    # Decapsulation (using a fresh ciphertext each time)
    print("  → Decapsulation...")
    def decaps_op():
        _, c = ml_kem_encaps(ek, params)
        return ml_kem_decaps(dk, c, params)
    
    results['decaps'] = time_operation(decaps_op, iterations)
    
    # Full KEM cycle
    print("  → Full KEM Cycle...")
    def full_cycle():
        ek_temp, dk_temp = ml_kem_keygen(params)
        K1, c = ml_kem_encaps(ek_temp, params)
        K2 = ml_kem_decaps(dk_temp, c, params)
        assert K1 == K2
        return K1
    
    results['full_cycle'] = time_operation(full_cycle, iterations)
    
    # Key sizes
    K, c = ml_kem_encaps(ek, params)
    results['sizes'] = {
        'public_key_bytes': len(ek),
        'secret_key_bytes': len(dk),
        'ciphertext_bytes': len(c),
        'shared_secret_bytes': len(K)
    }
    
    # Throughput (operations per second)
    results['throughput'] = {
        'keygen_ops_per_sec': 1000 / results['keygen']['avg_ms'],
        'encaps_ops_per_sec': 1000 / results['encaps']['avg_ms'],
        'decaps_ops_per_sec': 1000 / results['decaps']['avg_ms'],
        'full_cycle_ops_per_sec': 1000 / results['full_cycle']['avg_ms']
    }
    
    return results

def print_performance_summary(variant_name, results):
    """Print performance summary for a variant."""
    print(f"\n{variant_name} PERFORMANCE:")
    print("-" * 40)
    
    # Timing
    print(f"KeyGen:     {results['keygen']['avg_ms']:.2f} ms")
    print(f"Encaps:     {results['encaps']['avg_ms']:.2f} ms") 
    print(f"Decaps:     {results['decaps']['avg_ms']:.2f} ms")
    print(f"Full Cycle: {results['full_cycle']['avg_ms']:.2f} ms")
    
    # Throughput
    print(f"\nTHROUGHPUT:")
    print(f"KeyGen:     {results['throughput']['keygen_ops_per_sec']:.1f} ops/sec")
    print(f"Encaps:     {results['throughput']['encaps_ops_per_sec']:.1f} ops/sec")
    print(f"Decaps:     {results['throughput']['decaps_ops_per_sec']:.1f} ops/sec")
    print(f"Full Cycle: {results['throughput']['full_cycle_ops_per_sec']:.1f} ops/sec")
    
    # Sizes
    sizes = results['sizes']
    print(f"\nKEY SIZES:")
    print(f"Public Key:    {sizes['public_key_bytes']:,} bytes")
    print(f"Secret Key:    {sizes['secret_key_bytes']:,} bytes")
    print(f"Ciphertext:    {sizes['ciphertext_bytes']:,} bytes")
    print(f"Shared Secret: {sizes['shared_secret_bytes']:,} bytes")

def test_correctness(params, test_rounds=10):
    """Quick correctness test."""
    print(f"\nTesting {params.name} correctness ({test_rounds} rounds)...")
    
    for i in range(test_rounds):
        # Test normal encapsulation
        ek, dk = ml_kem_keygen(params)
        K1, c = ml_kem_encaps(ek, params)
        K2 = ml_kem_decaps(dk, c, params)
        
        if K1 != K2:
            print(f"   FAILED at round {i+1}")
            return False
        
        # Test deterministic encapsulation
        message = b"Test message for deterministic!!"
        K3, c3 = ml_kem_encaps_deterministic(ek, message, params)
        K4, c4 = ml_kem_encaps_deterministic(ek, message, params)
        
        if K3 != K4 or c3 != c4:
            print(f"   Deterministic encaps FAILED at round {i+1}")
            return False
    
    print(f"   All {test_rounds} rounds passed")
    return True

def print_comparison_table(all_results):
    """Print comparison table across all variants."""
    print(f"\n{'='*80}")
    print("KEM PERFORMANCE COMPARISON")
    print(f"{'='*80}")
    
    # Header
    print(f"{'Variant':<12} {'KeyGen':<10} {'Encaps':<10} {'Decaps':<10} {'Cycle':<10} {'PK Size':<10}")
    print(f"{'':12} {'(ms)':<10} {'(ms)':<10} {'(ms)':<10} {'(ms)':<10} {'(bytes)':<10}")
    print("-" * 80)
    
    # Data
    for variant, results in all_results.items():
        keygen_time = results['keygen']['avg_ms']
        encaps_time = results['encaps']['avg_ms']
        decaps_time = results['decaps']['avg_ms'] 
        cycle_time = results['full_cycle']['avg_ms']
        pk_size = results['sizes']['public_key_bytes']
        
        print(f"{variant:<12} {keygen_time:<10.2f} {encaps_time:<10.2f} {decaps_time:<10.2f} {cycle_time:<10.2f} {pk_size:<10,}")
    
    print("\nTHROUGHPUT COMPARISON (ops/sec):")
    print("-" * 80)
    print(f"{'Variant':<12} {'KeyGen':<10} {'Encaps':<10} {'Decaps':<10} {'Cycle':<10}")
    print("-" * 60)
    
    for variant, results in all_results.items():
        throughput = results['throughput']
        print(f"{variant:<12} {throughput['keygen_ops_per_sec']:<10.1f} {throughput['encaps_ops_per_sec']:<10.1f} {throughput['decaps_ops_per_sec']:<10.1f} {throughput['full_cycle_ops_per_sec']:<10.1f}")

def main():
    """Run KEM-focused benchmarks."""
    print("ML-KEM FOCUSED PERFORMANCE BENCHMARK")
    print("=" * 60)
    
    variants = [
        ('ML-KEM-512', ML_KEM_512),
        ('ML-KEM-768', ML_KEM_768),
        ('ML-KEM-1024', ML_KEM_1024)
    ]
    
    all_results = {}
    
    # Test correctness first
    print("CORRECTNESS TESTING:")
    print("=" * 40)
    all_correct = True
    for name, params in variants:
        if not test_correctness(params):
            print(f"  {name} failed correctness test!")
            all_correct = False
    
    if not all_correct:
        print("\n Some variants failed correctness tests. Stopping.")
        return
    
    print("\n All variants passed correctness tests!")
    
    # Run performance benchmarks
    print("\n\nPERFORMANCE BENCHMARKING:")
    print("=" * 40)
    
    for name, params in variants:
        try:
            results = benchmark_kem_operations(params, iterations=25)
            all_results[name] = results
            print_performance_summary(name, results)
        except Exception as e:
            print(f"Error benchmarking {name}: {e}")
    
    # Print final comparison
    if all_results:
        print_comparison_table(all_results)
    
    print(f"\n KEM benchmarking completed!")

if __name__ == "__main__":
    main()