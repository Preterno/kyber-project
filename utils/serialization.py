from typing import List
from pke.params import N, Q

def bits_to_bytes(bits: List[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("Bit array length must be a multiple of 8")
    ell = len(bits) // 8
    B = bytearray(ell)
    for i in range(8 * ell):
        B[i // 8] += bits[i] * (2 ** (i % 8))
    return bytes(B)

def bytes_to_bits(data: bytes) -> List[int]:
    ell = len(data)
    bits = [0] * (8 * ell)
    C = list(data)
    for i in range(ell):
        for j in range(8):
            bits[8 * i + j] = C[i] % 2
            C[i] = C[i] // 2
    return bits

def byte_encode(F: List[int], d: int) -> bytes:
    if not (1 <= d <= 12):
        raise ValueError("d must be in range [1, 12]")
    if len(F) != N:
        raise ValueError(f"F must have length {N}")
    if d < 12:
        m = 2 ** d
        if any(x < 0 or x >= m for x in F):
            raise ValueError(f"All elements of F must be in range [0, {m-1}]")
    else:
        m = Q
        if any(x < 0 or x >= m for x in F):
            raise ValueError(f"All elements of F must be in range [0, {m-1}]")
    bits = []
    for i in range(N):
        a = F[i]
        for j in range(d):
            bits.append(a % 2)
            a = (a - bits[-1]) // 2
    return bits_to_bytes(bits)

def byte_decode(B: bytes, d: int) -> List[int]:
    if not (1 <= d <= 12):
        raise ValueError("d must be in range [1, 12]")
    if len(B) != 32 * d:
        raise ValueError(f"B must have length {32 * d}")
    m = 2 ** d if d < 12 else Q
    bits = bytes_to_bits(B)
    F = []
    for i in range(N):
        value = sum(bits[i * d + j] * (2 ** j) for j in range(d))
        F.append(value % m)
    return F

def compress(x: int, d: int) -> int:
    if d >= 12:
        raise ValueError("d must be less than 12")
    return ((x * (2 ** d) + Q // 2) // Q) % (2 ** d)

def decompress(y: int, d: int) -> int:
    if d >= 12:
        raise ValueError("d must be less than 12")
    return (y * Q + (2 ** (d - 1))) // (2 ** d)

def poly_to_bytes(poly: List[int], q: int = Q, n: int = N) -> bytes:
    return byte_encode(poly, 12)

def bytes_to_poly(data: bytes, q: int = Q) -> List[int]:
    return byte_decode(data, 12)

def vec_to_bytes(vec: List[List[int]]) -> bytes:
    return b''.join(byte_encode(poly, 12) for poly in vec)

def bytes_to_vec(data: bytes, k: int, n: int = N) -> List[List[int]]:
    poly_len = n * 12 // 8
    result = []
    for i in range(k):
        start = i * poly_len
        end = start + poly_len
        poly_bytes = data[start:end]
        poly = byte_decode(poly_bytes, 12)
        result.append(poly)
    return result

def byte_encode_12(f: List[int]) -> bytes:
    return byte_encode(f, 12)

def byte_decode_12(data: bytes) -> List[int]:
    return byte_decode(data, 12)

def byte_encode_du(f: List[int], du: int) -> bytes:
    return byte_encode(f, du)

def byte_decode_du(data: bytes, du: int) -> List[int]:
    return byte_decode(data, du)

def byte_encode_dv(f: List[int], dv: int) -> bytes:
    return byte_encode(f, dv)

def byte_decode_dv(data: bytes, dv: int) -> List[int]:
    return byte_decode(data, dv)

