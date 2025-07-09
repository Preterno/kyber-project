from scapy.all import sniff, TCP, Raw, get_if_list
import re

TARGET_PORT = 65432  

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        tcp = packet.getlayer(TCP)
        payload = packet[Raw].load

        try:
            
            printable = payload.decode('ascii')
            looks_plain = bool(re.match(r'^[\x20-\x7E\r\n\t]+$', printable))

            print("\n[+] Packet Captured:")
            print(f"    From port: {tcp.sport} -> To port: {tcp.dport}")
            print(f"    Encrypted? {'NO (plaintext)' if looks_plain else 'YES 🔐'}")
            print(f"    Payload (first 64 bytes): {repr(payload[:64])}...")

        except UnicodeDecodeError:
            print("\n[+] Packet Captured:")
            print(f"    From port: {tcp.sport} -> To port: {tcp.dport}")
            print("    Encrypted? YES  (non-decodable binary)")
            print(f"    Payload (raw, first 64 bytes): {repr(payload[:64])}...")

if __name__ == '__main__':
    print(f"[Sniffing TCP packets on port {TARGET_PORT} via loopback interface...]")
    sniff(
        filter=f"tcp port {TARGET_PORT}",
        iface="\\Device\\NPF_Loopback", 
        prn=packet_callback,
        store=False
    )
