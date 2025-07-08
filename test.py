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

def display_key(name, key, max_bytes=16):
    if len(key) > max_bytes:
        return f"{name}: {key[:max_bytes].hex()}... ({len(key)} bytes)"
    else:
        return f"{name}: {key.hex()} ({len(key)} bytes)"

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

        # CCA test: modify ciphertext
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

def main():
    print("=" * 60)
    print("ML-KEM TEST SUITE")
    print("=" * 60)

    start_time = time.time()
    variants = [ML_KEM_512, ML_KEM_768, ML_KEM_1024]
    results = [test_ml_kem_variant(p) for p in variants]

    passed = sum(results)
    total_time = time.time() - start_time

    print("\n" + "=" * 60)
    print(f"Tests passed: {passed}/{len(variants)}")
    print(f"Total time: {total_time:.2f} seconds")

    return passed == len(variants)

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)