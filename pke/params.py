from dataclasses import dataclass
from typing import Dict

# Global constants
N = 256
Q = 3329
ZETA = 17

@dataclass(frozen=True)
class MLKEMParams:   
    name: str
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int
    security_category: int
    
    @property
    def pk_bytes(self) -> int:
        """Size of public key (encapsulation key) in bytes."""
        return 384 * self.k + 32
    
    @property
    def pke_sk_bytes(self) -> int:
        """Size of PKE secret key (dk_PKE) in bytes."""
        # Each of the k polynomials in s is 384 bytes (256 coeffs * 12 bits/coeff / 8 bits/byte)
        return (256 * 12 // 8) * self.k

    @property
    def sk_bytes(self) -> int:
        """Size of secret key (decapsulation key) in bytes."""
        # dk = dk_PKE || ek_PKE || H(ek_PKE) || z
        # dk_PKE = pke_sk_bytes
        # ek_PKE = pk_bytes
        # H(ek_PKE) = 32 bytes
        # z = 32 bytes
        return self.pke_sk_bytes + self.pk_bytes + 32 + 32
    
    @property
    def ct_bytes(self) -> int:  
        """Size of ciphertext in bytes."""
        return 32 * (self.du * self.k + self.dv)
    
    @property
    def ss_bytes(self) -> int:
        """Size of shared secret in bytes."""
        return 32

ML_KEM_512 = MLKEMParams(
    name="ML-KEM-512",
    k=2,
    eta1=3,
    eta2=2,
    du=10,
    dv=4,
    security_category=1
)

ML_KEM_768 = MLKEMParams(
    name="ML-KEM-768", 
    k=3,
    eta1=2,
    eta2=2,
    du=10,
    dv=4,
    security_category=3
)

ML_KEM_1024 = MLKEMParams(
    name="ML-KEM-1024",
    k=4,
    eta1=2,
    eta2=2,
    du=11,
    dv=5,
    security_category=5
)

PARAMETER_SETS: Dict[str, MLKEMParams] = {
    "ML-KEM-512": ML_KEM_512,
    "ML-KEM-768": ML_KEM_768,
    "ML-KEM-1024": ML_KEM_1024
}

def get_params(name: str) -> MLKEMParams:
    if name not in PARAMETER_SETS:
        valid_names = list(PARAMETER_SETS.keys())
        raise ValueError(f"Unknown parameter set '{name}'. Valid options: {valid_names}")
    
    return PARAMETER_SETS[name]

# Default parameter set
DEFAULT_PARAMS = ML_KEM_768