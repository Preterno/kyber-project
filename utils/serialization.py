def poly_to_bytes(poly, q=3329, n=256):
    return b''.join([(x % q).to_bytes(2, 'little') for x in poly])

def bytes_to_poly(data, q=3329):
    return [int.from_bytes(data[i:i+2], 'little') % q for i in range(0, len(data), 2)]

def vec_to_bytes(vec):
    return b''.join([poly_to_bytes(p) for p in vec])

def bytes_to_vec(data, k=2, n=256):
    poly_len = n * 2
    return [bytes_to_poly(data[i:i+poly_len]) for i in range(0, k * poly_len, poly_len)]

# --- Dummy placeholders for missing Kyber-specific serialization functions ---
# These are NOT cryptographically correct and are only for structural testing.

N_PARAM_PLACEHOLDER = 256 # Should ideally come from params

def byte_encode_12(poly: list[int], n: int = N_PARAM_PLACEHOLDER) -> bytes:
    """ Placeholder: Returns a fixed number of zero bytes (12 bits/coeff * 256 coeffs / 8 bits/byte = 384 bytes). """
    # print(f"serialization.byte_encode_12 called with poly len {len(poly)}")
    return bytes([0] * (n * 12 // 8)) # 384 bytes for n=256

def byte_decode_12(poly_bytes: bytes, n: int = N_PARAM_PLACEHOLDER) -> list[int]:
    """ Placeholder: Returns a zero polynomial. """
    # print(f"serialization.byte_decode_12 called with bytes len {len(poly_bytes)}")
    # Expected poly_bytes length is n * 12 // 8 (384 for n=256)
    return [0] * n

def byte_decode_du(poly_bytes: bytes, du: int, n: int = N_PARAM_PLACEHOLDER) -> list[int]:
    """ Placeholder: Returns a zero polynomial. du determines compressed bit size. """
    # print(f"serialization.byte_decode_du called with bytes len {len(poly_bytes)}, du={du}")
    # Expected poly_bytes length is n * du // 8
    return [0] * n

def byte_decode_dv(poly_bytes: bytes, dv: int, n: int = N_PARAM_PLACEHOLDER) -> list[int]:
    """ Placeholder: Returns a zero polynomial. dv determines compressed bit size. """
    # print(f"serialization.byte_decode_dv called with bytes len {len(poly_bytes)}, dv={dv}")
    # Expected poly_bytes length is n * dv // 8
    return [0] * n