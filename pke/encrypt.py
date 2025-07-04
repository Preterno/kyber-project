import numpy as np
from typing import List
from kyber_project.pke.params import MLKEMParams, N, Q
from kyber_project.utils.poly_utils import sample_poly_cbd, ntt, intt, matrix_vector_multiply_ntt, dot_product_ntt
from kyber_project.utils.serialization import byte_decode_12, byte_encode_du, byte_encode_dv, bits_to_bytes

def k_pke_encrypt(ek_pke: bytes, m: bytes, r: bytes, params: MLKEMParams) -> bytes:
    if len(m) != 32:
        raise ValueError(f"Message m must be exactly 32 bytes, got {len(m)}")
    if len(r) != 32:
        raise ValueError(f"Randomness r must be exactly 32 bytes, got {len(r)}")
    if len(ek_pke) != params.pk_bytes:
        raise ValueError(f"Public key must be {params.pk_bytes} bytes, got {len(ek_pke)}")
    
    t_hat, rho = parse_public_key(ek_pke, params.k)
    A_hat = sample_matrix_A(rho, params.k)
    r1 = sample_error_vector_encrypt(r, params.k, params.eta2, 0)
    r2 = sample_error_vector_encrypt(r, 1, params.eta2, params.k)[0]
    r1_hat = [ntt(poly) for poly in r1]
    u_hat = matrix_transpose_vector_multiply_ntt(A_hat, r1_hat)
    e1 = sample_error_vector_encrypt(r, params.k, params.eta2, params.k)
    e1_hat = [ntt(poly) for poly in e1]
    for i in range(params.k):
        u_hat[i] = [(u_hat[i][j] + e1_hat[i][j]) % Q for j in range(N)]
    u = [intt(poly) for poly in u_hat]
    v_ntt = dot_product_ntt(t_hat, r1_hat)
    v = intt(v_ntt)
    v = [(v[i] + r2[i]) % Q for i in range(N)]
    m_poly = decompress_message(m)
    v = [(v[i] + m_poly[i]) % Q for i in range(N)]
    u_compressed = [compress(poly, params.du) for poly in u]
    v_compressed = compress(v, params.dv)
    c = serialize_ciphertext(u_compressed, v_compressed, params)
    return c

def parse_public_key(ek_pke: bytes, k: int) -> tuple:
    t_hat = []
    offset = 0
    for i in range(k):
        poly_bytes = ek_pke[offset:offset + 384]
        poly = byte_decode_12(poly_bytes)
        t_hat.append(poly)
        offset += 384
    rho = ek_pke[offset:offset + 32]
    return t_hat, rho

def sample_matrix_A(rho: bytes, k: int) -> list:
    from kyber_project.pke.keygen import sample_matrix_A as keygen_sample_matrix_A
    return keygen_sample_matrix_A(rho, k)

def sample_error_vector_encrypt(r: bytes, k: int, eta: int, offset: int) -> list:
    from kyber_project.pke.keygen import sample_error_vector
    return sample_error_vector(r, k, eta, offset)

def matrix_transpose_vector_multiply_ntt(A_hat: list, r1_hat: list) -> list:
    from kyber_project.utils.poly_utils import multiply_ntts, add_poly
    k = len(r1_hat)
    result = []
    for j in range(k):
        poly_result = [0] * N
        for i in range(k):
            product = multiply_ntts(A_hat[i][j], r1_hat[i])
            poly_result = add_poly(poly_result, product, Q)
        result.append(poly_result)
    return result

def decompress_message(m: bytes) -> list:
    m_bits = []
    for byte in m:
        for i in range(8):
            m_bits.append((byte >> i) & 1)
    q_half = Q // 2
    poly = []
    for i in range(N):
        poly.append(m_bits[i] * q_half)
    return poly

def compress(poly: list, d: int) -> list:
    if d == 0:
        return [0] * len(poly)
    compressed = []
    divisor = Q // (1 << d)
    for coeff in poly:
        compressed_coeff = round((1 << d) * coeff / Q) % (1 << d)
        compressed.append(compressed_coeff)
    return compressed

def serialize_ciphertext(u_compressed: list, v_compressed: list, params: MLKEMParams) -> bytes:
    c_bytes = b""
    for poly in u_compressed:
        c_bytes += byte_encode_du(poly, params.du)
    c_bytes += byte_encode_dv(v_compressed, params.dv)
    return c_bytes

