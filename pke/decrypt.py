import numpy as np
from typing import List
from kyber_project.pke.params import MLKEMParams, N, Q
from kyber_project.utils.poly_utils import ntt, intt, dot_product_ntt
from kyber_project.utils.serialization import byte_decode_12, byte_decode_du, byte_decode_dv

def k_pke_decrypt(dk_pke: bytes, c: bytes, params: MLKEMParams) -> bytes:

    if len(dk_pke) != 384 * params.k:
        raise ValueError(f"Secret key must be {384 * params.k} bytes, got {len(dk_pke)}")
    if len(c) != params.ct_bytes:
        raise ValueError(f"Ciphertext must be {params.ct_bytes} bytes, got {len(c)}")
    
    
    s = parse_secret_key(dk_pke, params.k)
    
    u_compressed, v_compressed = parse_ciphertext(c, params)
    
    u = [decompress(poly, params.du) for poly in u_compressed]
    v = decompress(v_compressed, params.dv)
    
    s_hat = [ntt(poly) for poly in s]
    u_hat = [ntt(poly) for poly in u]
    
    su_ntt = dot_product_ntt(s_hat, u_hat)
    
    su = intt(su_ntt)
    
    w = [(v[i] - su[i]) % Q for i in range(N)]
    
    m = compress_to_message(w)
    
    return m

def parse_secret_key(dk_pke: bytes, k: int) -> list:

    s = []
    offset = 0
    
    for i in range(k):
        poly_bytes = dk_pke[offset:offset + 384]
        poly = byte_decode_12(poly_bytes)
        s.append(poly)
        offset += 384
    
    return s

def parse_ciphertext(c: bytes, params: MLKEMParams) -> tuple:

    offset = 0
    
    u_compressed = []
    u_poly_bytes = 32 * params.du  
    
    for i in range(params.k):
        poly_bytes = c[offset:offset + u_poly_bytes]
        poly = byte_decode_du(poly_bytes, params.du)
        u_compressed.append(poly)
        offset += u_poly_bytes
    
    v_poly_bytes = 32 * params.dv
    v_bytes = c[offset:offset + v_poly_bytes]
    v_compressed = byte_decode_dv(v_bytes, params.dv)
    
    return u_compressed, v_compressed

def decompress(poly_compressed: list, d: int) -> list:

    if d == 0:
        return [0] * len(poly_compressed)
    
    decompressed = []
    
    for coeff in poly_compressed:
        decompressed_coeff = round(Q * coeff / (1 << d)) % Q
        decompressed.append(decompressed_coeff)
    
    return decompressed

def compress_to_message(w: list) -> bytes:

    q_half = Q // 2
    q_quarter = Q // 4
    
    bits = []
    for coeff in w:
        coeff = coeff % Q
        
        if coeff > q_quarter and coeff < 3 * q_quarter:
            bits.append(1)
        else:
            bits.append(0)
    
    message = b""
    for i in range(32):
        byte_val = 0
        for j in range(8):
            bit_idx = i * 8 + j
            if bit_idx < len(bits) and bits[bit_idx]:
                byte_val |= (1 << j)
        message += bytes([byte_val])
    
    return message
