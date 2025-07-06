import hashlib

def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()

def shake128(data: bytes, outlen: int) -> bytes:
    return hashlib.shake_128(data).digest(outlen)

def shake256(data: bytes, outlen: int) -> bytes:
    return hashlib.shake_256(data).digest(outlen)

def H(s: bytes) -> bytes:
    return sha3_256(s)

def J(s: bytes) -> bytes:
    return shake256(s, 32)

def G(c: bytes) -> bytes:
    return sha3_512(c)

def PRF(eta: int, s: bytes, b: bytes) -> bytes:
    if eta not in {2, 3}:
        raise ValueError("eta must be 2 or 3")
    if len(s) != 32:
        raise ValueError("s must be 32 bytes")
    if len(b) != 1:
        raise ValueError("b must be 1 byte")
    return shake256(s + b, 64 * eta)

class XOF:
    def __init__(self, rho: bytes, i: int, j: int):
        if len(rho) != 32:
            raise ValueError("rho must be 32 bytes")
        if not (0 <= i <= 255):
            raise ValueError("i must be in range [0, 255]")
        if not (0 <= j <= 255):
            raise ValueError("j must be in range [0, 255]")
        self._input = rho + bytes([i, j])
        self._output_so_far = 0

    def squeeze(self, length: int) -> bytes:
        # Create a fresh SHAKE instance each time to avoid state corruption
        shake = hashlib.shake_128()
        shake.update(self._input)
        # Skip the bytes we've already output, then get the next 'length' bytes
        total_output = shake.digest(self._output_so_far + length)
        result = total_output[self._output_so_far:self._output_so_far + length]
        self._output_so_far += length
        return result