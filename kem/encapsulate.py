from typing import Tuple
from pke.params import MLKEMParams
from pke.encrypt import k_pke_encrypt
from utils.hash_utils import H, J, G
from utils.random_utils import random_bytes

def ml_kem_encaps(ek: bytes, params: MLKEMParams) -> Tuple[bytes, bytes]:
    if len(ek) != params.pk_bytes:
        raise ValueError(f"Encapsulation key must be {params.pk_bytes} bytes, got {len(ek)}")
    m = random_bytes(32)
    ek_hash = H(ek)
    g_input = m + ek_hash
    g_output = G(g_input)
    K = g_output[:32]
    r = g_output[32:64]
    c = k_pke_encrypt(ek, m, r, params)
    return K, c

def ml_kem_encaps_deterministic(ek: bytes, m: bytes, params: MLKEMParams) -> Tuple[bytes, bytes]:
    if len(ek) != params.pk_bytes:
        raise ValueError(f"Encapsulation key must be {params.pk_bytes} bytes, got {len(ek)}")
    if len(m) != 32:
        raise ValueError(f"Message must be exactly 32 bytes, got {len(m)}")
    ek_hash = H(ek)
    g_input = m + ek_hash
    g_output = G(g_input)
    K = g_output[:32]
    r = g_output[32:64]
    c = k_pke_encrypt(ek, m, r, params)
    return K, c

