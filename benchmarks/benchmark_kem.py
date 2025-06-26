import timeit
from kem.keygen import ml_kem_keygen
from kem.encapsulate import ml_kem_encaps
from kem.decapsulate import ml_kem_decaps
from pke.params import PARAMETER_SETS, MLKEMParams

def benchmark_kem_keygen(params: MLKEMParams, num_executions=10):
    stmt = "ml_kem_keygen(params)"
    setup_code = "from kem.keygen import ml_kem_keygen"
    current_globals = {
        "ml_kem_keygen": ml_kem_keygen,
        "params": params
    }
    total_time = timeit.timeit(stmt, setup=setup_code, globals=current_globals, number=num_executions)
    return total_time / num_executions

def benchmark_kem_encapsulate(params: MLKEMParams, num_executions=100):
    public_key, _ = ml_kem_keygen(params)

    stmt = "ml_kem_encaps(public_key, params)"
    setup_code = "from kem.encapsulate import ml_kem_encaps"
    current_globals = {
        "ml_kem_encaps": ml_kem_encaps,
        "public_key": public_key,
        "params": params
    }
    total_time = timeit.timeit(stmt, setup=setup_code, globals=current_globals, number=num_executions)
    return total_time / num_executions

def benchmark_kem_decapsulate(params: MLKEMParams, num_executions=100):
    public_key, secret_key = ml_kem_keygen(params)
    # Encapsulation is dummy, but provides a structurally correct ciphertext
    ciphertext, _ = ml_kem_encaps(public_key, params)

    stmt = "ml_kem_decaps(secret_key, ciphertext, params)"
    setup_code = "from kem.decapsulate import ml_kem_decaps"
    current_globals = {
        "ml_kem_decaps": ml_kem_decaps,
        "secret_key": secret_key,
        "ciphertext": ciphertext,
        "params": params
    }
    total_time = timeit.timeit(stmt, setup=setup_code, globals=current_globals, number=num_executions)
    return total_time / num_executions

if __name__ == '__main__':
    print("Running KEM Benchmarks...")
    # Select which parameter sets to benchmark
    # benchmark_param_names = ["ML-KEM-512"]
    benchmark_param_names = PARAMETER_SETS.keys()

    for params_name in benchmark_param_names:
        params = PARAMETER_SETS[params_name]
        print(f"\nBenchmarking for {params.name}:")

        keygen_time = benchmark_kem_keygen(params)
        print(f"  KEM Keygen: {keygen_time:.6f} seconds per call")

        encaps_time = benchmark_kem_encapsulate(params)
        print(f"  KEM Encapsulate (dummy): {encaps_time:.6f} seconds per call")

        decaps_time = benchmark_kem_decapsulate(params)
        print(f"  KEM Decapsulate (with dummy ciphertext): {decaps_time:.6f} seconds per call")

    print("\nNote: Encapsulate and Decapsulate performance is based on dummy implementations for some underlying operations.")
