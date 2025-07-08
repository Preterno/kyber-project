import socket
import os
import threading
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pke.params import ML_KEM_768
from kem.encapsulate import ml_kem_encaps
from Crypto.Cipher import AES

def aes_encrypt(key: bytes, plaintext: bytes, nonce: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag

def aes_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

HOST = '127.0.0.1'
PORT = 65432

def receive_messages(sock, K):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break

            nonce = data[:12]
            ciphertext = data[12:-16]
            tag = data[-16:]

            plaintext = aes_decrypt(K[:16], ciphertext, nonce, tag).decode()

            if plaintext.lower() == 'exit':
                print("\n[Server ended the chat]")
                os._exit(0)

            import sys
            sys.stdout.write("\r" + " " * 80 + "\r")
            print(f"[Server] {plaintext}")
            print("You: ", end="", flush=True)

        except Exception as e:
            print(f"\n[!] Receive error: {e}")
            break

def send_messages(sock, K):
    while True:
        try:
            msg = input("You: ").strip()
            if msg.lower() == 'exit':
                print("[You ended the chat]")
                nonce = os.urandom(12)
                ciphertext, tag = aes_encrypt(K[:16], b'exit', nonce)
                sock.sendall(nonce + ciphertext + tag)
                os._exit(0)

            nonce = os.urandom(12)
            ciphertext, tag = aes_encrypt(K[:16], msg.encode(), nonce)
            sock.sendall(nonce + ciphertext + tag)

        except Exception as e:
            print(f"[!] Send error: {e}")
            break

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        ek = s.recv(ML_KEM_768.pk_bytes)

        start_time = time.perf_counter()
        K, c = ml_kem_encaps(ek, ML_KEM_768)
        s.sendall(c)
        end_time = time.perf_counter()

        print(f"[+] Key exchange complete. Time taken: {(end_time - start_time)*1000:.2f} ms")
        print(f"[+] Derived shared key (hex): {K.hex()}")
        print("[Type 'exit' to end chat]\n")

        threading.Thread(target=receive_messages, args=(s, K), daemon=True).start()
        send_messages(s, K)

if __name__ == '__main__':
    main()
