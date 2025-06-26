"""
Simple KEM Functionality Tests

Focused tests for ML-KEM Key Encapsulation Mechanism operations.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kem.keygen import ml_kem_keygen
from kem.encapsulate import ml_kem_encaps, ml_kem_encaps_deterministic
from kem.decapsulate import ml_kem_decaps
from pke.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024

def test_kem_interface():
    """Test that KEM operations return correct types and sizes."""
    print("Testing KEM interface compliance...")
    
    for name, params in [('ML-KEM-512', ML_KEM_512), ('ML-KEM-768', ML_KEM_768), ('ML-KEM-1024', ML_KEM_1024)]:
        print(f"  Testing {name}...")
        
        # KeyGen should return (public_key, secret_key)
        result = ml_kem_keygen(params)
        if not isinstance(result, tuple) or len(result) != 2:
            print(f"    xXx KeyGen doesn't return tuple of 2 elements")
            return False
        
        ek, dk = result
        if not isinstance(ek, bytes) or not isinstance(dk, bytes):
            print(f"    xXx KeyGen doesn't return bytes")
            return False
        
        # Encaps should return (shared_secret, ciphertext)
        result = ml_kem_encaps(ek, params)
        if not isinstance(result, tuple) or len(result) != 2:
            print(f"    xXx Encaps doesn't return tuple of 2 elements")
            return False
        
        K, c = result
        if not isinstance(K, bytes) or not isinstance(c, bytes):
            print(f"    xXx Encaps doesn't return bytes")
            return False
        
        # Decaps should return shared_secret
        result = ml_kem_decaps(dk, c, params)
        if not isinstance(result, bytes):
            print(f"    xXx Decaps doesn't return bytes")
            return False
    
    print("  yYy KEM interface compliance passed")
    return True

def test_kem_security_properties():
    """Test fundamental KEM security properties."""
    print("Testing KEM security properties...")
    
    params = ML_KEM_768
    
    # Test correctness
    ek, dk = ml_kem_keygen(params)
    K1, c = ml_kem_encaps(ek, params)
    K2 = ml_kem_decaps(dk, c, params)
    
    if K1 != K2:
        print("  xXx KEM correctness failed")
        return False
    
    # Test randomization - multiple encapsulations should be different
    encaps_results = []
    for _ in range(10):
        K, c = ml_kem_encaps(ek, params)
        encaps_results.append((K, c))
    
    # Check all are different
    unique_keys = set(result[0] for result in encaps_results)
    unique_ciphertexts = set(result[1] for result in encaps_results)
    
    if len(unique_keys) != len(encaps_results):
        print("  xXx Encapsulation not properly randomized (duplicate keys)")
        return False
    
    if len(unique_ciphertexts) != len(encaps_results):
        print("  xXx Encapsulation not properly randomized (duplicate ciphertexts)")
        return False
    
    print("  yYy KEM security properties passed")
    return True

def test_cross_parameter_isolation():
    """Test that different parameter sets don't interfere."""
    print("Testing cross-parameter isolation...")
    
    # Generate keys for all parameter sets
    keys = {}
    for name, params in [('ML-KEM-512', ML_KEM_512), ('ML-KEM-768', ML_KEM_768), ('ML-KEM-1024', ML_KEM_1024)]:
        ek, dk = ml_kem_keygen(params)
        keys[name] = (ek, dk, params)
    
    # Verify different sizes
    sizes = [(name, len(ek), len(dk)) for name, (ek, dk, _) in keys.items()]
    
    if len(set((ek_len, dk_len) for _, ek_len, dk_len in sizes)) != 3:
        print("  xXx Parameter sets have same key sizes")
        return False
    
    # Test wrong parameter usage fails
    ek_768, _, _ = keys['ML-KEM-768']
    
    try:
        # Should fail - wrong key size for ML-KEM-512
        ml_kem_encaps(ek_768, ML_KEM_512)
        print("  xXx Should have failed with wrong parameter set")
        return False
    except ValueError:
        pass  # Expected
    
    print("  yYy Cross-parameter isolation passed")
    return True

def test_key_reuse_safety():
    """Test that key reuse is safe."""
    print("Testing key reuse safety...")
    
    params = ML_KEM_768
    ek, dk = ml_kem_keygen(params)
    
    results = []
    for _ in range(20):
        K, c = ml_kem_encaps(ek, params)
        K_recovered = ml_kem_decaps(dk, c, params)
        
        if K != K_recovered:
            print("  xXx Key reuse caused correctness failure")
            return False
        
        results.append((K, c))
    
    # All results should be different
    unique_keys = set(result[0] for result in results)
    unique_ciphertexts = set(result[1] for result in results)
    
    if len(unique_keys) != len(results):
        print("  xXx Key reuse produced duplicate shared secrets")
        return False
    
    if len(unique_ciphertexts) != len(results):
        print("  xXx Key reuse produced duplicate ciphertexts")  
        return False
    
    print("  yYy Key reuse safety passed")
    return True

def test_implicit_rejection_consistency():
    """Test that implicit rejection is consistent."""
    print("Testing implicit rejection consistency...")
    
    params = ML_KEM_768
    ek, dk = ml_kem_keygen(params)
    
    # Create invalid ciphertext
    invalid_c = b"x" * params.ct_bytes
    
    # Multiple decapsulations should return same value
    results = []
    for _ in range(5):
        K = ml_kem_decaps(dk, invalid_c, params)
        results.append(K)
    
    if len(set(results)) != 1:
        print("  xXx Implicit rejection not consistent")
        return False
    
    if len(results[0]) != 32:
        print("  xXx Rejected key has wrong length")
        return False
    
    print("  yYy Implicit rejection consistency passed")
    return True

def test_deterministic_encaps_edge_cases():
    """Test edge cases for deterministic encapsulation."""
    print("Testing deterministic encapsulation edge cases...")
    
    params = ML_KEM_768
    ek, dk = ml_kem_keygen(params)
    
    # Test with all-zero message
    zero_msg = b'\x00' * 32
    K1, c1 = ml_kem_encaps_deterministic(ek, zero_msg, params)
    K2, c2 = ml_kem_encaps_deterministic(ek, zero_msg, params)
    
    if K1 != K2 or c1 != c2:
        print("  xXx Deterministic encaps inconsistent with zero message")
        return False
    
    # Test with all-one message
    one_msg = b'\xff' * 32
    K3, c3 = ml_kem_encaps_deterministic(ek, one_msg, params)
    K4, c4 = ml_kem_encaps_deterministic(ek, one_msg, params)
    
    if K3 != K4 or c3 != c4:
        print("  xXx Deterministic encaps inconsistent with one message")
        return False
    
    # Different messages should produce different results
    if K1 == K3 or c1 == c3:
        print("  xXx Different messages produced same results")
        return False
    
    # Both should decrypt correctly
    K5 = ml_kem_decaps(dk, c1, params)
    K6 = ml_kem_decaps(dk, c3, params)
    
    if K1 != K5 or K3 != K6:
        print("  xXx Deterministic encaps roundtrip failed")
        return False
    
    print("  yYy Deterministic encapsulation edge cases passed")
    return True

def run_compliance_tests():
    """Run KEM compliance tests."""
    print("Running KEM compliance tests...")
    
    expected_params = {
        'ML-KEM-512': {'k': 2, 'security_category': 1},
        'ML-KEM-768': {'k': 3, 'security_category': 3},
        'ML-KEM-1024': {'k': 4, 'security_category': 5}
    }
    
    for name, params in [('ML-KEM-512', ML_KEM_512), ('ML-KEM-768', ML_KEM_768), ('ML-KEM-1024', ML_KEM_1024)]:
        expected = expected_params[name]
        
        if params.k != expected['k']:
            print(f"  xXx {name} wrong k parameter: {params.k} vs {expected['k']}")
            return False
        
        if params.security_category != expected['security_category']:
            print(f"  xXx {name} wrong security category: {params.security_category} vs {expected['security_category']}")
            return False
        
        # Test actual key generation and sizes
        ek, dk = ml_kem_keygen(params)
        K, c = ml_kem_encaps(ek, params)
        
        if len(ek) != params.pk_bytes:
            print(f"  xXx {name} wrong public key size: {len(ek)} vs {params.pk_bytes}")
            return False
        
        if len(dk) != params.sk_bytes:
            print(f"  xXx {name} wrong secret key size: {len(dk)} vs {params.sk_bytes}")
            return False
        
        if len(c) != params.ct_bytes:
            print(f"  xXx {name} wrong ciphertext size: {len(c)} vs {params.ct_bytes}")
            return False
        
        if len(K) != 32:
            print(f"  xXx {name} wrong shared secret size: {len(K)} vs 32")
            return False
    
    print("  yYy KEM compliance tests passed")
    return True

def run_all_tests():
    """Run all KEM tests."""
    print("=" * 60)
    print("ML-KEM FOCUSED FUNCTIONALITY TESTS")
    print("=" * 60)
    
    tests = [
        test_kem_interface,
        test_kem_security_properties,
        test_cross_parameter_isolation,
        test_key_reuse_safety,
        test_implicit_rejection_consistency,
        test_deterministic_encaps_edge_cases,
        run_compliance_tests
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print(f"  ❌ {test.__name__} FAILED")
        except Exception as e:
            print(f"  ❌ {test.__name__} ERROR: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*60}")
    print(f"KEM TEST RESULTS: {passed}/{total} PASSED")
    print(f"{'='*60}")
    
    if passed == total:
        print(" ALL KEM TESTS PASSED!")
        return True
    else:
        print(f" {total - passed} KEM TESTS FAILED!")
        return False

def main():
    """Main test execution."""
    success = run_all_tests()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())