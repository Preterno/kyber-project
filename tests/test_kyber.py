"""
Simple ML-KEM (Kyber) Tests

Focused testing of ML-KEM correctness and basic functionality.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kyber_project.kem.keygen import ml_kem_keygen
from kyber_project.kem.encapsulate import ml_kem_encaps, ml_kem_encaps_deterministic
from kyber_project.kem.decapsulate import ml_kem_decaps
from kyber_project.pke.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024

def test_basic_correctness():
    """Test basic KEM correctness for all parameter sets."""
    print("Testing basic KEM correctness...")
    
    variants = [
        ('ML-KEM-512', ML_KEM_512),
        ('ML-KEM-768', ML_KEM_768),
        ('ML-KEM-1024', ML_KEM_1024)
    ]
    
    for name, params in variants:
        print(f"\n  Testing {name}...")
        
        for round_num in range(5):
            # Basic KEM cycle
            ek, dk = ml_kem_keygen(params)
            K1, c = ml_kem_encaps(ek, params)
            K2 = ml_kem_decaps(dk, c, params)
            
            if K1 != K2:
                print(f"     FAILED at round {round_num + 1}")
                return False
        
        print(f"     {name} passed all rounds")
    
    return True

def test_deterministic_encapsulation():
    """Test deterministic encapsulation."""
    print("\nTesting deterministic encapsulation...")
    
    params = ML_KEM_768
    ek, dk = ml_kem_keygen(params)
    message = b"Test message for deterministic!!"
    
    # Multiple deterministic encapsulations should be identical
    K1, c1 = ml_kem_encaps_deterministic(ek, message, params)
    K2, c2 = ml_kem_encaps_deterministic(ek, message, params)
    K3, c3 = ml_kem_encaps_deterministic(ek, message, params)
    
    if K1 != K2 or K1 != K3 or c1 != c2 or c1 != c3:
        print("   Deterministic encapsulation not consistent")
        return False
    
    # Should decrypt correctly
    K4 = ml_kem_decaps(dk, c1, params)
    if K1 != K4:
        print("   Deterministic encapsulation doesn't decrypt correctly")
        return False
    
    print("   Deterministic encapsulation works correctly")
    return True

def test_key_sizes():
    """Test that key sizes match specifications."""
    print("\nTesting key sizes...")
    
    expected_sizes = {
        'ML-KEM-512': {'pk': 800, 'sk': 1632, 'ct': 768},
        'ML-KEM-768': {'pk': 1184, 'sk': 2400, 'ct': 1088},
        'ML-KEM-1024': {'pk': 1568, 'sk': 3168, 'ct': 1408}
    }
    
    variants = [
        ('ML-KEM-512', ML_KEM_512),
        ('ML-KEM-768', ML_KEM_768),
        ('ML-KEM-1024', ML_KEM_1024)
    ]
    
    for name, params in variants:
        ek, dk = ml_kem_keygen(params)
        K, c = ml_kem_encaps(ek, params)
        
        expected = expected_sizes[name]
        
        if len(ek) != expected['pk']:
            print(f"   {name} public key size wrong: got {len(ek)}, expected {expected['pk']}")
            return False
            
        if len(dk) != expected['sk']:
            print(f"   {name} secret key size wrong: got {len(dk)}, expected {expected['sk']}")
            return False
            
        if len(c) != expected['ct']:
            print(f"   {name} ciphertext size wrong: got {len(c)}, expected {expected['ct']}")
            return False
            
        if len(K) != 32:
            print(f"   {name} shared secret size wrong: got {len(K)}, expected 32")
            return False
    
    print("   All key sizes correct")
    return True

def test_invalid_inputs():
    """Test handling of invalid inputs."""
    print("\nTesting invalid input handling...")
    
    params = ML_KEM_768
    ek, dk = ml_kem_keygen(params)
    
    # Test invalid public key size for encapsulation
    try:
        ml_kem_encaps(b"invalid_key", params)
        print("   Should have failed with invalid public key")
        return False
    except ValueError:
        pass  # Expected
    
    # Test invalid secret key size for decapsulation
    K, c = ml_kem_encaps(ek, params)
    try:
        ml_kem_decaps(b"invalid_key", c, params)
        print("   Should have failed with invalid secret key")
        return False
    except ValueError:
        pass  # Expected
    
    # Test invalid ciphertext size for decapsulation
    try:
        ml_kem_decaps(dk, b"invalid_ciphertext", params)
        print("   Should have failed with invalid ciphertext")
        return False
    except ValueError:
        pass  # Expected
    
    # Test invalid message size for deterministic encapsulation
    try:
        ml_kem_encaps_deterministic(ek, b"wrong_size", params)
        print("   Should have failed with wrong message size")
        return False
    except ValueError:
        pass  # Expected
    
    print("  ✓ Invalid input handling works correctly")
    return True

def test_implicit_rejection():
    """Test implicit rejection with corrupted ciphertext."""
    print("\nTesting implicit rejection...")
    
    params = ML_KEM_768
    ek, dk = ml_kem_keygen(params)
    K1, c = ml_kem_encaps(ek, params)
    
    # Corrupt the ciphertext
    c_corrupted = bytearray(c)
    c_corrupted[0] ^= 1  # Flip one bit
    c_corrupted = bytes(c_corrupted)
    
    # Should return a different key (implicit rejection)
    K2 = ml_kem_decaps(dk, c_corrupted, params)
    
    if K1 == K2:
        print("   Implicit rejection failed - same key returned")
        return False
    
    if len(K2) != 32:
        print("   Rejected key has wrong length")
        return False
    
    print("   Implicit rejection works correctly")
    return True

def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("ML-KEM (KYBER) FUNCTIONALITY TESTS")
    print("=" * 60)
    
    tests = [
        test_basic_correctness,
        test_deterministic_encapsulation,
        test_key_sizes,
        test_invalid_inputs,
        test_implicit_rejection
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print(f"   {test.__name__} FAILED")
        except Exception as e:
            print(f"   {test.__name__} ERROR: {e}")
    
    print(f"\n{'='*60}")
    print(f"TEST RESULTS: {passed}/{total} PASSED")
    print(f"{'='*60}")
    
    if passed == total:
        print(" ALL TESTS PASSED!")
        return True
    else:
        print(f" {total - passed} TESTS FAILED!")
        return False

def main():
    """Main test execution."""
    success = run_all_tests()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())