#!/usr/bin/env python3
"""Simple test script to verify the ML-KEM implementation works."""

import sys
import os

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_basic_functionality():
    """Test basic ML-KEM functionality."""
    try:
        from pke.params import ML_KEM_768
        from kem.keygen import ml_kem_keygen
        from kem.encapsulate import ml_kem_encaps
        from kem.decapsulate import ml_kem_decaps
        
        print("=== Basic ML-KEM Functionality Test ===")
        print(f"Testing {ML_KEM_768.name}")
        
        # Key generation
        print("1. Generating key pair...")
        ek, dk = ml_kem_keygen(ML_KEM_768)
        print(f"   Public key: {len(ek)} bytes")
        print(f"   Secret key: {len(dk)} bytes")
        
        # Encapsulation
        print("2. Encapsulating...")
        K1, c = ml_kem_encaps(ek, ML_KEM_768)
        print(f"   Shared secret: {len(K1)} bytes")
        print(f"   Ciphertext: {len(c)} bytes")
        
        # Decapsulation
        print("3. Decapsulating...")
        K2 = ml_kem_decaps(dk, c, ML_KEM_768)
        print(f"   Recovered secret: {len(K2)} bytes")
        
        # Verification
        if K1 == K2:
            print("4. SUCCESS: Shared secrets match!")
            return True
        else:
            print("4. FAILURE: Shared secrets don't match!")
            return False
            
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_basic_functionality()
    if success:
        print("\n Basic functionality test PASSED!")
    else:
        print("\n Basic functionality test FAILED!")
    sys.exit(0 if success else 1)
