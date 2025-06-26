import numpy as np

def sample_poly(n=256, q=3329):
    return np.random.randint(low=0, high=q, size=n).tolist()

def add_poly(a, b, q=3329):
    return [(x + y) % q for x, y in zip(a, b)]

def sub_poly(a, b, q=3329):
    return [(x - y) % q for x, y in zip(a, b)]

def mul_poly(a, b, q=3329):
    # Naive convolution
    res = np.convolve(a, b)[:len(a)]
    return [int(x % q) for x in res]

# --- Dummy placeholders for missing Kyber polynomial operations ---
# These are NOT cryptographically correct and are only for structural testing.

N_PARAM_PLACEHOLDER = 256 # Should ideally come from params
Q_PARAM_PLACEHOLDER = 3329

def sample_uniform_poly(seed: bytes, i: int, j: int, n: int = N_PARAM_PLACEHOLDER, q: int = Q_PARAM_PLACEHOLDER) -> list[int]:
    """ Placeholder: Returns a zero polynomial. """
    # print(f"poly_utils.sample_uniform_poly called with seed len {len(seed)}, i={i}, j={j}")
    return [0] * n

def sample_poly_cbd(seed: bytes, nonce: int, eta: int, n: int = N_PARAM_PLACEHOLDER, q: int = Q_PARAM_PLACEHOLDER) -> list[int]:
    """ Placeholder: Returns a zero polynomial. """
    # print(f"poly_utils.sample_poly_cbd called with seed len {len(seed)}, nonce={nonce}, eta={eta}")
    return [0] * n

def ntt(poly: list[int], q: int = Q_PARAM_PLACEHOLDER) -> list[int]:
    """ Placeholder: Returns the same polynomial (identity NTT). """
    # print(f"poly_utils.ntt called with poly len {len(poly)}")
    return list(poly) # Ensure it's a copy

def intt(poly_ntt: list[int], q: int = Q_PARAM_PLACEHOLDER) -> list[int]:
    """ Placeholder: Returns the same polynomial (identity inverse NTT). """
    # print(f"poly_utils.intt called with poly_ntt len {len(poly_ntt)}")
    return list(poly_ntt)

def matrix_vector_multiply_ntt(matrix_poly_ntt: list[list[list[int]]], vector_poly_ntt: list[list[int]], q: int = Q_PARAM_PLACEHOLDER) -> list[list[int]]:
    """ Placeholder: Returns a vector of zero polynomials of correct dimension. """
    # print(f"poly_utils.matrix_vector_multiply_ntt called")
    if not matrix_poly_ntt:
        return []
    k = len(matrix_poly_ntt)
    if k > 0 and not matrix_poly_ntt[0]:
         # Or handle error appropriately if structure is unexpected
        return [[0]*N_PARAM_PLACEHOLDER for _ in range(k)]


    poly_len = len(matrix_poly_ntt[0][0]) if k > 0 and len(matrix_poly_ntt[0]) > 0 else N_PARAM_PLACEHOLDER

    # A_hat (k x k matrix of polys), s_hat (k-vector of polys)
    # Result is k-vector of polys
    # For placeholder, just return k zero polynomials of appropriate length
    result_vector = []
    for _ in range(k):
        result_vector.append([0] * poly_len)
    return result_vector

def dot_product_ntt(vec1_poly_ntt: list[list[int]], vec2_poly_ntt: list[list[int]], q: int = Q_PARAM_PLACEHOLDER) -> list[int]:
    """ Placeholder: Returns a zero polynomial. """
    # print(f"poly_utils.dot_product_ntt called")
    if not vec1_poly_ntt:
        return [0] * N_PARAM_PLACEHOLDER
    poly_len = len(vec1_poly_ntt[0]) if vec1_poly_ntt else N_PARAM_PLACEHOLDER
    return [0] * poly_len