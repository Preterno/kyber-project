import sys
import os

# Add the parent directory (../PQC) to sys.path
PARENT_PATH = os.path.abspath("..")
if PARENT_PATH not in sys.path:
    sys.path.insert(0, PARENT_PATH)

# Now import from kyber_project.*
from kyber_project.kem.keygen import ml_kem_keygen
from kyber_project.kem.encapsulate import ml_kem_encaps
from kyber_project.kem.decapsulate import ml_kem_decaps
from kyber_project.pke.params import ML_KEM_768
