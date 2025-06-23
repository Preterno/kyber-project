"""
ML-KEM Decapsulation algorithm as specified in NIST FIPS 203.

This module implements Algorithm 20: ML-KEM.Decaps(dk, c), which recovers
the shared secret from a ciphertext using the decapsulation key.
Includes implicit rejection for protection against chosen ciphertext attacks.
"""

from pke.params import MLKEMParams
from pke.decrypt import k_pke_decrypt
from pke.encrypt import k_pke_encrypt
from utils.hash_utils import H, J, G
from typing import Tuple

def ml_kem_decaps(dk: bytes, c: bytes, params: MLKEMParams) -> bytes:
    """ML-KEM Decapsulation (Algorithm 20).
    
    Recovers the shared secret from a ciphertext using the decapsulation key.
    Implements implicit rejection: if decryption fails or ciphertext is invalid,
    returns a pseudorandom value derived from the secret key and ciphertext.
    
    Args:
        dk: Decapsulation key (secret key) of length 768k + 96 bytes
        c: Ciphertext of length 32(d_u*k + d_v) bytes
        params: ML-KEM parameter set defining security level and parameters
        
    Returns:
        32-byte shared secret K
        
    Raises:
        ValueError: If inputs have incorrect lengths
    """
    if len(dk) != params.sk_bytes:
        raise ValueError(f"Decapsulation key must be {params.sk_bytes} bytes, got {len(dk)}")
    if len(c) != params.ct_bytes:
        raise ValueError(f"Ciphertext must be {params.ct_bytes} bytes, got {len(c)}")
    
    dk_pke, ek_pke, h_ek_pke, z = parse_decapsulation_key(dk, params)
    
    m_prime = k_pke_decrypt(dk_pke, c, params)
    
    g_input = m_prime + h_ek_pke
    g_output = G(g_input)  
    
    K_prime = g_output[:32]   
    r_prime = g_output[32:64] 
    
    
    c_prime = k_pke_encrypt(ek_pke, m_prime, r_prime, params)
    
    
    if constant_time_compare(c, c_prime):
        return K_prime
    else:
        rejection_input = z + c
        K_rejection = J(rejection_input)
        return K_rejection

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of two byte arrays.
    
    Compares two byte arrays in constant time to prevent timing attacks.
    This is crucial for the security of the implicit rejection mechanism.
    
    Args:
        a: First byte array
        b: Second byte array
        
    Returns:
        True if arrays are equal, False otherwise
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0 

def parse_decapsulation_key(dk: bytes, params: MLKEMParams) -> Tuple[bytes, bytes, bytes, bytes]:
    """Parse ML-KEM decapsulation key into its components.
    
    Extracts the four components of the decapsulation key:
    dk = (dk_PKE || ek_PKE || H(ek_PKE) || z)
    
    Args:
        dk: Complete decapsulation key  
        params: Parameter set for determining component sizes
        
    Returns:
        Tuple of (dk_pke, ek_pke, ek_pke_hash, z)
        
    Raises:
        ValueError: If decapsulation key has incorrect length
    """
    expected_length = params.sk_bytes
    if len(dk) != expected_length:
        raise ValueError(f"Decapsulation key must be {expected_length} bytes, got {len(dk)}")
    
    offset = 0
    
    dk_pke_len = 384 * params.k
    dk_pke = dk[offset:offset + dk_pke_len]
    offset += dk_pke_len
    
    ek_pke_len = params.pk_bytes
    ek_pke = dk[offset:offset + ek_pke_len]
    offset += ek_pke_len
    
    ek_pke_hash = dk[offset:offset + 32]
    offset += 32
    
    z = dk[offset:offset + 32]
    
    return dk_pke, ek_pke, ek_pke_hash, z
