import timeit
from pke.keygen import k_pke_keygen
from pke.encrypt import k_pke_encrypt
from pke.decrypt import k_pke_decrypt
from pke.params import PARAMETER_SETS, MLKEMParams
from utils.random_utils import random_bytes

def benchmark_pke_keygen(params: MLKEMParams, num_executions=10):
    d_seed = random_bytes(32)
    stmt = "k_pke_keygen(d_seed, params)"
    setup_code = "from pke.keygen import k_pke_keygen"
    current_globals = {
        "k_pke_keygen": k_pke_keygen,
        "d_seed": d_seed,
        "params": params
    }
    total_time = timeit.timeit(stmt, setup=setup_code, globals=current_globals, number=num_executions)
    return total_time / num_executions

def benchmark_pke_encrypt(params: MLKEMParams, num_executions=100):
    d_seed = random_bytes(32)
    public_key, _ = k_pke_keygen(d_seed, params)
    message = random_bytes(32)
    pke_randomness = random_bytes(32)

    stmt = "k_pke_encrypt(public_key, message, pke_randomness, params)"
    setup_code = "from pke.encrypt import k_pke_encrypt"
    current_globals = {
        "k_pke_encrypt": k_pke_encrypt,
        "public_key": public_key,
        "message": message,
        "pke_randomness": pke_randomness,
        "params": params
    }
    total_time = timeit.timeit(stmt, setup=setup_code, globals=current_globals, number=num_executions)
    return total_time / num_executions

def benchmark_pke_decrypt(params: MLKEMParams, num_executions=100):
    d_seed = random_bytes(32)
    public_key, secret_key = k_pke_keygen(d_seed, params)
    message = random_bytes(32)
    pke_randomness = random_bytes(32)
    ciphertext = k_pke_encrypt(public_key, message, pke_randomness, params)

    stmt = "k_pke_decrypt(secret_key, ciphertext, params)"
    setup_code = "from pke.decrypt import k_pke_decrypt"
    current_globals = {
        "k_pke_decrypt": k_pke_decrypt,
        "secret_key": secret_key,
        "ciphertext": ciphertext,
        "params": params
    }
    total_time = timeit.timeit(stmt, setup=setup_code, globals=current_globals, number=num_executions)
    return total_time / num_executions

if __name__ == '__main__':
    print("Running PKE Benchmarks...")
    # Select which parameter sets to benchmark
    # For quick test, just one. For full, use all.
    # benchmark_param_names = ["ML-KEM-512"]
    benchmark_param_names = PARAMETER_SETS.keys()


    for params_name in benchmark_param_names:
        params = PARAMETER_SETS[params_name]
        print(f"\nBenchmarking for {params.name}:")

        keygen_time = benchmark_pke_keygen(params)
        print(f"  PKE Keygen: {keygen_time:.6f} seconds per call")

        encrypt_time = benchmark_pke_encrypt(params)
        print(f"  PKE Encrypt (dummy): {encrypt_time:.6f} seconds per call")

        decrypt_time = benchmark_pke_decrypt(params)
        print(f"  PKE Decrypt (with dummy ciphertext): {decrypt_time:.6f} seconds per call")

    print("\nNote: Encrypt performance is based on a dummy implementation.")
