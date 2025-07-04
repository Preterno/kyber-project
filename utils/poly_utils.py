import numpy as np
from typing import List, Tuple
from kyber_project.pke.params import N, Q, ZETA
from kyber_project.utils.hash_utils import XOF, PRF
from kyber_project.utils.serialization import bytes_to_bits

def bit_rev_7(x: int) -> int:
    result = 0
    for i in range(7):
        result = (result << 1) | (x & 1)
        x >>= 1
    return result

def mod_pow(base: int, exp: int, mod: int) -> int:
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

def _precompute_ntt_factors():
    factors = [0] * 128
    for i in range(128):
        bit_rev_i = bit_rev_7(i)
        factors[i] = mod_pow(ZETA, bit_rev_i, Q)
    return factors

def _precompute_base_case_factors():
    factors = [0] * 128
    for i in range(128):
        bit_rev_i = bit_rev_7(i)
        exp = (2 * bit_rev_i + 1) % (2 * N)
        factors[i] = mod_pow(ZETA, exp, Q)
    return factors

NTT_FACTORS = _precompute_ntt_factors()
BASE_CASE_FACTORS = _precompute_base_case_factors()

def ntt(f: List[int]) -> List[int]:
    if len(f) != N:
        raise ValueError(f"Input must have length {N}")
    f_hat = f[:]
    k = 1
    length = 128
    while length >= 2:
        start = 0
        while start < N:
            zeta = NTT_FACTORS[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * f_hat[j + length]) % Q
                f_hat[j + length] = (f_hat[j] - t) % Q
                f_hat[j] = (f_hat[j] + t) % Q
            start += 2 * length
        length //= 2
    return f_hat

def ntt_inverse(f_hat: List[int]) -> List[int]:
    if len(f_hat) != N:
        raise ValueError(f"Input must have length {N}")
    f = f_hat[:]
    k = 127
    length = 2
    while length <= 128:
        start = 0
        while start < N:
            zeta = NTT_FACTORS[k]
            k -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = (zeta * (f[j + length] - t)) % Q
            start += 2 * length
        length *= 2
    n_inv = 3303
    for i in range(N):
        f[i] = (f[i] * n_inv) % Q
    return f

def base_case_multiply(a0: int, a1: int, b0: int, b1: int, gamma: int) -> Tuple[int, int]:
    c0 = (a0 * b0 + a1 * b1 * gamma) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1

def multiply_ntts(f_hat: List[int], g_hat: List[int]) -> List[int]:
    if len(f_hat) != N or len(g_hat) != N:
        raise ValueError(f"Inputs must have length {N}")
    h_hat = [0] * N
    for i in range(128):
        gamma = BASE_CASE_FACTORS[i]
        c0, c1 = base_case_multiply(
            f_hat[2*i], f_hat[2*i + 1],
            g_hat[2*i], g_hat[2*i + 1],
            gamma
        )
        h_hat[2*i] = c0
        h_hat[2*i + 1] = c1
    return h_hat

def sample_ntt(B: bytes) -> List[int]:
    if len(B) != 34:
        raise ValueError("Input must be 34 bytes")
    rho = B[:32]
    i = B[32]
    j = B[33]
    xof = XOF(rho, i, j)
    a_hat = [0] * N
    idx = 0
    while idx < N:
        C = xof.squeeze(3)
        d1 = C[0] + 256 * (C[1] % 16)
        d2 = (C[1] // 16) + 16 * C[2]
        if d1 < Q:
            a_hat[idx] = d1
            idx += 1
        if d2 < Q and idx < N:
            a_hat[idx] = d2
            idx += 1
    return a_hat

def sample_poly_cbd(sigma: bytes, nonce: int, eta: int) -> List[int]:
    if eta not in {2, 3}:
        raise ValueError("eta must be 2 or 3")
    if len(sigma) != 32:
        raise ValueError("sigma must be 32 bytes")
    B = PRF(eta, sigma, bytes([nonce]))
    bits = bytes_to_bits(B)
    f = [0] * N
    for i in range(N):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        f[i] = (x - y) % Q
    return f

def sample_poly_cbd_raw(B: bytes, eta: int) -> List[int]:
    if eta not in {2, 3}:
        raise ValueError("eta must be 2 or 3")
    if len(B) != 64 * eta:
        raise ValueError(f"Input must be {64 * eta} bytes")
    bits = bytes_to_bits(B)
    f = [0] * N
    for i in range(N):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        f[i] = (x - y) % Q
    return f

def sample_poly(n: int = N, q: int = Q) -> List[int]:
    return [np.random.randint(0, q) for _ in range(n)]

def add_poly(a: List[int], b: List[int], q: int = Q) -> List[int]:
    if len(a) != len(b):
        raise ValueError("Polynomials must have same length")
    return [(x + y) % q for x, y in zip(a, b)]

def sub_poly(a: List[int], b: List[int], q: int = Q) -> List[int]:
    if len(a) != len(b):
        raise ValueError("Polynomials must have same length")
    return [(x - y) % q for x, y in zip(a, b)]

def mul_poly(a: List[int], b: List[int], q: int = Q) -> List[int]:
    if len(a) != N or len(b) != N:
        raise ValueError(f"Polynomials must have length {N}")
    a_hat = ntt(a)
    b_hat = ntt(b)
    c_hat = multiply_ntts(a_hat, b_hat)
    return ntt_inverse(c_hat)

def scalar_mul_poly(scalar: int, poly: List[int], q: int = Q) -> List[int]:
    return [(scalar * coeff) % q for coeff in poly]

def add_poly_vec(a: List[List[int]], b: List[List[int]], q: int = Q) -> List[List[int]]:
    if len(a) != len(b):
        raise ValueError("Vectors must have same length")
    return [add_poly(a[i], b[i], q) for i in range(len(a))]

def scalar_mul_poly_vec(scalar: int, vec: List[List[int]], q: int = Q) -> List[List[int]]:
    return [scalar_mul_poly(scalar, poly, q) for poly in vec]

def matrix_vector_mul_ntt(A_hat, s_hat):
    k = len(s_hat)
    result = []
    for i in range(k):
        component = [0] * N
        for j in range(k):
            product = multiply_ntts(A_hat[i][j], s_hat[j])
            component = add_poly(component, product, Q)
        result.append(component)
    return result

def vector_transpose_mul_ntt(s_hat: List[List[int]], u_hat: List[List[int]]) -> List[int]:
    k = len(s_hat)
    result = [0] * N
    for j in range(k):
        product = multiply_ntts(s_hat[j], u_hat[j])
        for i in range(N):
            result[i] = (result[i] + product[i]) % Q
    return result

def sample_uniform_poly(rho: bytes, i: int, j: int) -> List[int]:
    input_bytes = rho + bytes([i, j])
    return sample_ntt(input_bytes)

def matrix_vector_multiply_ntt(A_hat, s_hat):
    return matrix_vector_mul_ntt(A_hat, s_hat)

def dot_product_ntt(t_hat: List[List[int]], r1_hat: List[List[int]]) -> List[int]:
    k = len(t_hat)
    result = [0] * N
    for i in range(k):
        product = multiply_ntts(t_hat[i], r1_hat[i])
        for j in range(N):
            result[j] = (result[j] + product[j]) % Q
    return result

intt = ntt_inverse

