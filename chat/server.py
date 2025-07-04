import socket
import threading
import time
import os
from kyber_project.chat.kem_runtime import (
    ml_kem_keygen,
    ml_kem_encaps,   
    ml_kem_decaps,
    ML_KEM_768
)

from kyber_project.chat.aes_utils import aes_encrypt, aes_decrypt

HOST = '127.0.0.1'
PORT = 65432

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed before expected bytes were received.")
        data += chunk
    return data

def receive_messages(conn, K):
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break

            nonce = data[:12]
            ciphertext = data[12:-16]
            tag = data[-16:]

            plaintext = aes_decrypt(K[:16], ciphertext, nonce, tag).decode()

            if plaintext.lower() == 'exit':
                print("\n[Client ended the chat]")
                os._exit(0)

            import sys
            sys.stdout.write("\r" + " " * 80 + "\r")
            print(f"[Client] {plaintext}")
            print("You: ", end="", flush=True)

        except Exception as e:
            print(f"\n[!] Receive error: {e}")
            break

def send_messages(conn, K):
    while True:
        try:
            msg = input("You: ").strip()
            if msg.lower() == 'exit':
                print("[You ended the chat]")
                nonce = os.urandom(12)
                ciphertext, tag = aes_encrypt(K[:16], b'exit', nonce)
                conn.sendall(nonce + ciphertext + tag)
                os._exit(0)

            nonce = os.urandom(12)
            ciphertext, tag = aes_encrypt(K[:16], msg.encode(), nonce)
            conn.sendall(nonce + ciphertext + tag)

        except Exception as e:
            print(f"[!] Send error: {e}")
            break

def handle_client(conn):
    start_time = time.perf_counter()
    ek, dk = ml_kem_keygen(ML_KEM_768)
    conn.sendall(ek)

    c = recv_exact(conn, ML_KEM_768.ct_bytes)
    K = ml_kem_decaps(dk, c, ML_KEM_768)
    end_time = time.perf_counter()

    print(f"[+] Key exchange complete. Time taken: {(end_time - start_time)*1000:.2f} ms")
    print(f"[+] Derived shared key (hex): {K.hex()}")
    print("[Type 'exit' to end chat]\n")

    threading.Thread(target=receive_messages, args=(conn, K), daemon=True).start()
    send_messages(conn, K)

def start_server():
    print(f"[+] Server listening on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"[+] Connection from {addr}")
            handle_client(conn)

if __name__ == '__main__':
    start_server()
