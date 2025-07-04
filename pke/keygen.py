import numpy as np
from typing import Tuple
from kyber_project.pke.params import MLKEMParams, N, Q
from kyber_project.utils.hash_utils import G
from kyber_project.utils.poly_utils import sample_uniform_poly, sample_poly_cbd, ntt, matrix_vector_multiply_ntt
from kyber_project.utils.serialization import byte_encode_12

def k_pke_keygen(d: bytes, params: MLKEMParams) -> Tuple[bytes, bytes]:

    if len(d) != 32:
        raise ValueError(f"Seed d must be exactly 32 bytes, got {len(d)}")
    
    expanded = G(d)
    rho = expanded[:32]
    sigma = expanded[32:64]
    A_hat = sample_matrix_A(rho, params.k)
    s = sample_secret_vector(sigma, params.k, params.eta1, 0)
    e = sample_error_vector(sigma, params.k, params.eta1, params.k)
    s_hat = [ntt(poly) for poly in s]
    e_hat = [ntt(poly) for poly in e]
    t_hat = matrix_vector_multiply_ntt(A_hat, s_hat)

    for i in range(params.k):
        t_hat[i] = [(t_hat[i][j] + e_hat[i][j]) % Q for j in range(N)]
    
    pk = serialize_public_key(t_hat, rho, params.k)
    sk = serialize_secret_key(s, params.k)
    return pk, sk

def sample_matrix_A(rho: bytes, k: int) -> list:
    A = []
    for i in range(k):
        row = []
        for j in range(k):
            poly = sample_uniform_poly(rho, i, j)
            row.append(poly)
        A.append(row)
    return A

def sample_secret_vector(sigma: bytes, k: int, eta: int, offset: int) -> list:
    s = []
    for i in range(k):
        poly = sample_poly_cbd(sigma, offset + i, eta)
        s.append(poly)
    return s

def sample_error_vector(sigma: bytes, k: int, eta: int, offset: int) -> list:
    e = []
    for i in range(k):
        poly = sample_poly_cbd(sigma, offset + i, eta)
        e.append(poly)
    return e

def serialize_public_key(t_hat: list, rho: bytes, k: int) -> bytes:
    pk_bytes = b""
    for poly in t_hat:
        pk_bytes += byte_encode_12(poly)
    pk_bytes += rho
    return pk_bytes

def serialize_secret_key(s: list, k: int) -> bytes:
    sk_bytes = b""
    for poly in s:
        sk_bytes += byte_encode_12(poly)
    return sk_bytes