import sys
import os
import time

project_root = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(project_root)
sys.path.insert(0, parent_dir)

from pke.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024
from kem.keygen import ml_kem_keygen
from kem.encapsulate import ml_kem_encaps
from kem.decapsulate import ml_kem_decaps

def test_ml_kem_variant(params):
    print(f"\nTesting {params.name}")
    try:
        ek, dk = ml_kem_keygen(params)
        print(f"  KeyGen: ek={len(ek)} bytes, dk={len(dk)} bytes")

        K, ct = ml_kem_encaps(ek, params)
        print(f"  Encaps: K={len(K)} bytes, ct={len(ct)} bytes")
        print(f"    {display_key('K', K)}")

        K_prime = ml_kem_decaps(dk, ct, params)
        print(f"  Decaps: K'={len(K_prime)} bytes")
        print(f"    {display_key('K_prime', K_prime)}")

        if K == K_prime:
            print("  SUCCESS: K == K_prime")
        else:
            print("  FAILED: K != K_prime")
            return False

        tampered_ct = bytearray(ct)
        tampered_ct[0] ^= 0x01
        K_fake = ml_kem_decaps(dk, bytes(tampered_ct), params)
        if K_fake != K:
            print("  CCA-PROOF SUCCESS: Modified ciphertext yields different secret")
        else:
            print("  CCA-PROOF FAILURE: Tampered ciphertext gave same key")
            return False

        return True

    except Exception as e:
        print(f"  ERROR: {e}")
        return False

def display_key(name, key, max_bytes=16):
    if len(key) > max_bytes:
        return f"{name}: {key[:max_bytes].hex()}... (total {len(key)} bytes)"
    else:
        return f"{name}: {key.hex()} ({len(key)} bytes)"

def test_ml_kem_512():
    print("Testing ML-KEM-512...")
    ek, dk = ml_kem_keygen(ML_KEM_512)
    print(f"  ✓ Key generation: ek={len(ek)} bytes, dk={len(dk)} bytes")
    secret_k, ct = ml_kem_encaps(ek, ML_KEM_512)
    print(f"  ✓ Encapsulation: secret={len(secret_k)} bytes, ct={len(ct)} bytes")
    print(f"    {display_key('K (original)', secret_k)}")
    recovered_k_prime = ml_kem_decaps(dk, ct, ML_KEM_512)
    print(f"  ✓ Decapsulation: recovered={len(recovered_k_prime)} bytes")
    print(f"    {display_key('K_prime (recovered)', recovered_k_prime)}")
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
    print("\nTesting ML-KEM-768...")
    try:
        ek, dk = ml_kem_keygen(ML_KEM_768)
        print(f"  ✓ Key generation: ek={len(ek)} bytes, dk={len(dk)} bytes")
        secret_k, ct = ml_kem_encaps(ek, ML_KEM_768)
        print(f"  ✓ Encapsulation: secret={len(secret_k)} bytes, ct={len(ct)} bytes")
        print(f"    {display_key('K (original)', secret_k)}")
        recovered_k_prime = ml_kem_decaps(dk, ct, ML_KEM_768)
        print(f"  ✓ Decapsulation: recovered={len(recovered_k_prime)} bytes")
        print(f"    {display_key('K_prime (recovered)', recovered_k_prime)}")
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
    print("\nTesting ML-KEM-1024...")
    try:
        ek, dk = ml_kem_keygen(ML_KEM_1024)
        print(f"  ✓ Key generation: ek={len(ek)} bytes, dk={len(dk)} bytes")
        secret_k, ct = ml_kem_encaps(ek, ML_KEM_1024)
        print(f"  ✓ Encapsulation: secret={len(secret_k)} bytes, ct={len(ct)} bytes")
        print(f"    {display_key('K (original)', secret_k)}")
        recovered_k_prime = ml_kem_decaps(dk, ct, ML_KEM_1024)
        print(f"  ✓ Decapsulation: recovered={len(recovered_k_prime)} bytes")
        print(f"    {display_key('K_prime (recovered)', recovered_k_prime)}")
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
    print("=" * 60)
    print("ML-KEM Success Test with Key Verification (K and K_prime)")
    print("=" * 60)
    start_time = time.time()
    print("\n🟢 SUCCESS SCENARIO TESTS:")
    results = []
    results.append(test_ml_kem_512())
    results.append(test_ml_kem_768()) 
    results.append(test_ml_kem_1024())
    print("\n🔄 GENERIC VARIANT TESTS (from test.py):")
    variant_params = [ML_KEM_512, ML_KEM_768, ML_KEM_1024]
    variant_results = [test_ml_kem_variant(p) for p in variant_params]
    results.extend(variant_results)
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
