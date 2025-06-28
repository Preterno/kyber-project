from pke.params import MLKEMParams
from pke.decrypt import k_pke_decrypt
from pke.encrypt import k_pke_encrypt
from utils.hash_utils import H, J, G
from typing import Tuple

def ml_kem_decaps(dk: bytes, c: bytes, params: MLKEMParams) -> bytes:

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
 
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0 

def parse_decapsulation_key(dk: bytes, params: MLKEMParams) -> Tuple[bytes, bytes, bytes, bytes]:
    
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
