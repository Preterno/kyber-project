from typing import Tuple
from pke.params import MLKEMParams
from pke.keygen import k_pke_keygen
from utils.hash_utils import H
from utils.random_utils import random_bytes

def ml_kem_keygen(params: MLKEMParams) -> Tuple[bytes, bytes]:    
    d = random_bytes(32)
    ek_pke, dk_pke = k_pke_keygen(d, params)
    z = random_bytes(32)
    ek_pke_hash = H(ek_pke)
    
    ek = ek_pke
    dk = dk_pke + ek_pke + ek_pke_hash + z
    return ek, dk