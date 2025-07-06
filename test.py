#!/usr/bin/env python3
"""
Simple Working Test for ML-KEM Implementation - Success Scenarios Only
This test shows detailed key logging (K and K_prime) for verification.
"""

import sys
import os
import time

# Add parent directory to Python path so 'kyber_project' can be imported
project_root = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(project_root)
sys.path.insert(0, parent_dir)

from pke.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024
from kem.keygen import ml_kem_keygen
from kem.encapsulate import ml_kem_encaps
from kem.decapsulate import ml_kem_decaps

def display_key(name, key, max_bytes=16):
    """Display key in hex format for verification"""
    if len(key) > max_bytes:
        return f"{name}: {key[:max_bytes].hex()}... (total {len(key)} bytes)"
    else:
        return f"{name}: {key.hex()} ({len(key)} bytes)"

def test_ml_kem_512():
    """Test ML-KEM-512 - fastest variant with detailed key logging"""
    print("Testing ML-KEM-512...")
    
    # Generate keys
    ek, dk = ml_kem_keygen(ML_KEM_512)
    print(f"  ✓ Key generation: ek={len(ek)} bytes, dk={len(dk)} bytes")
    
    # Encapsulate
    secret_k, ct = ml_kem_encaps(ek, ML_KEM_512)
    print(f"  ✓ Encapsulation: secret={len(secret_k)} bytes, ct={len(ct)} bytes")
    print(f"    {display_key('K (original)', secret_k)}")
    
    # Decapsulate
    recovered_k_prime = ml_kem_decaps(dk, ct, ML_KEM_512)
    print(f"  ✓ Decapsulation: recovered={len(recovered_k_prime)} bytes")
    print(f"    {display_key('K_prime (recovered)', recovered_k_prime)}")
    
    # Verify keys match
    if secret_k == recovered_k_prime:
        print("  ✓ SUCCESS: K == K_prime - ML-KEM-512 works correctly!")
        print(f"    Keys are identical: {secret_k[:8].hex()}... == {recovered_k_prime[:8].hex()}...")
        return True
    else:
        print("  ✗ FAILED: K != K_prime - Secrets don't match")
        print(f"    K:       {secret_k[:16].hex()}...")
        print(f"    K_prime: {recovered_k_prime[:16].hex()}...")
        return False

def test_ml_kem_768():
    """Test ML-KEM-768 - medium security with detailed key logging"""
    print("\nTesting ML-KEM-768...")
    
    try:
        # Generate keys
        ek, dk = ml_kem_keygen(ML_KEM_768)
        print(f"  ✓ Key generation: ek={len(ek)} bytes, dk={len(dk)} bytes")
        
        # Encapsulate
        secret_k, ct = ml_kem_encaps(ek, ML_KEM_768)
        print(f"  ✓ Encapsulation: secret={len(secret_k)} bytes, ct={len(ct)} bytes")
        print(f"    {display_key('K (original)', secret_k)}")
        
        # Decapsulate
        recovered_k_prime = ml_kem_decaps(dk, ct, ML_KEM_768)
        print(f"  ✓ Decapsulation: recovered={len(recovered_k_prime)} bytes")
        print(f"    {display_key('K_prime (recovered)', recovered_k_prime)}")
        
        # Verify keys match
        if secret_k == recovered_k_prime:
            print("  ✓ SUCCESS: K == K_prime - ML-KEM-768 works correctly!")
            print(f"    Keys are identical: {secret_k[:8].hex()}... == {recovered_k_prime[:8].hex()}...")
            return True
        else:
            print("  ✗ FAILED: K != K_prime - Secrets don't match")
            print(f"    K:       {secret_k[:16].hex()}...")
            print(f"    K_prime: {recovered_k_prime[:16].hex()}...")
            return False
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        return False

def test_ml_kem_1024():
    """Test ML-KEM-1024 - highest security with detailed key logging"""
    print("\nTesting ML-KEM-1024...")
    
    try:
        # Generate keys
        ek, dk = ml_kem_keygen(ML_KEM_1024)
        print(f"  ✓ Key generation: ek={len(ek)} bytes, dk={len(dk)} bytes")
        
        # Encapsulate
        secret_k, ct = ml_kem_encaps(ek, ML_KEM_1024)
        print(f"  ✓ Encapsulation: secret={len(secret_k)} bytes, ct={len(ct)} bytes")
        print(f"    {display_key('K (original)', secret_k)}")
        
        # Decapsulate
        recovered_k_prime = ml_kem_decaps(dk, ct, ML_KEM_1024)
        print(f"  ✓ Decapsulation: recovered={len(recovered_k_prime)} bytes")
        print(f"    {display_key('K_prime (recovered)', recovered_k_prime)}")
        
        # Verify keys match
        if secret_k == recovered_k_prime:
            print("  ✓ SUCCESS: K == K_prime - ML-KEM-1024 works correctly!")
            print(f"    Keys are identical: {secret_k[:8].hex()}... == {recovered_k_prime[:8].hex()}...")
            return True
        else:
            print("  ✗ FAILED: K != K_prime - Secrets don't match")
            print(f"    K:       {secret_k[:16].hex()}...")
            print(f"    K_prime: {recovered_k_prime[:16].hex()}...")
            return False
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        return False

def main():
    """Run success scenario tests only"""
    print("=" * 60)
    print("ML-KEM Success Test with Key Verification (K and K_prime)")
    print("=" * 60)
    
    start_time = time.time()
    
    # Run success scenario tests only
    print("\n🟢 SUCCESS SCENARIO TESTS:")
    results = []
    results.append(test_ml_kem_512())
    results.append(test_ml_kem_768()) 
    results.append(test_ml_kem_1024())
    
    # Summary
    total_time = time.time() - start_time
    passed = sum(results)
    total = len(results)
    
    print("\n" + "=" * 60)
    print("FINAL RESULTS:")
    print(f"  📊 Tests passed: {passed}/{total}")
    print(f"  ⏱️  Total time: {total_time:.2f} seconds")
    
    if passed == total:
        print("🎉 ALL SUCCESS TESTS PASSED!")
        print("   ✓ All K and K_prime values match correctly")
        print("   ✓ ML-KEM implementation working properly")
        return True
    else:
        print("❌ SOME TESTS FAILED!")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1) 