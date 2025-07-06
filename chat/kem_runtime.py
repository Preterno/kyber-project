import sys
import os

# Add the parent directory so 'kyber_project' can be imported
project_root = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(project_root))
sys.path.insert(0, parent_dir)

# Now import using relative imports  
from kem.keygen import ml_kem_keygen
from kem.encapsulate import ml_kem_encaps
from kem.decapsulate import ml_kem_decaps
from pke.params import ML_KEM_768
