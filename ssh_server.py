import socket
import struct
import subprocess
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
import base64

HOST = "127.0.0.1"
PORT = 5001

# fake credentials
USERNAME = "user"
PASSWORD = "pass123"

# --- helper: send/recv length-prefixed bytes ---
def send_bytes(conn, b: bytes):
    conn.sendall(struct.pack(">I", len(b)))
    conn.sendall(b)

def recv_bytes(conn) -> bytes:
    raw_len = b""
    while len(raw_len) < 4:
        chunk = conn.recv(4 - len(raw_len))
        if not chunk:
            raise ConnectionError("Connection closed while reading length")
        raw_len += chunk
    length = struct.unpack(">I", raw_len)[0]
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while reading data")
        data += chunk
    return data

# --- derive fernet key from X25519 exchange ---
def derive_fernet_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ssh-sim-demo",
    )
    key = hkdf.derive(shared_secret)  # 32 raw bytes
    return base64.urlsafe_b64encode(key)  # fernet expects base64-encoded 32-byte key

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"Server listening on {HOST}:{PORT} ...")
        conn, addr = s.accept()
        print("Connection from", addr)
        with conn:
            # --- X25519 key exchange ---
            server_priv = x25519.X25519PrivateKey.generate()
            server_pub = server_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            # send server pub key
            send_bytes(conn, server_pub)
            # receive client pub key
            client_pub_bytes = recv_bytes(conn)
            client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
            shared = server_priv.exchange(client_pub)
            fernet_key = derive_fernet_key(shared)
            f = Fernet(fernet_key)
            print("Key exchange complete. Channel is encrypted now.")

            # --- authentication (encrypted) ---
            send_bytes(conn, f.encrypt(b"Username: "))
            user_enc = recv_bytes(conn)
            username = f.decrypt(user_enc).decode().strip()

            send_bytes(conn, f.encrypt(b"Password: "))
            pass_enc = recv_bytes(conn)
            password = f.decrypt(pass_enc).decode().strip()

            if username != USERNAME or password != PASSWORD:
                send_bytes(conn, f.encrypt(b"Authentication failed. Closing connection.\n"))
                print("Authentication failed for", addr)
                return
            else:
                send_bytes(conn, f.encrypt(b"Authentication successful! You can now run commands.\n"))
                print("Client authenticated:", username)

            # --- command loop (encrypted) ---
            while True:
                
                try:
                    enc_cmd = recv_bytes(conn)
                except ConnectionError:
                    print("Client disconnected.")
                    break
                try:
                    cmd = f.decrypt(enc_cmd).decode()
                except Exception:
                    send_bytes(conn, f.encrypt(b"Decryption failed on server.\n"))
                    break
                
                print(cmd)
                if cmd.strip().lower() == "exit":
                    send_bytes(conn, f.encrypt(b"Goodbye!\n"))
                    break

                # execute
                try:
                    output = subprocess.check_output(["powershell", "-Command", cmd], stderr=subprocess.STDOUT)

                except subprocess.CalledProcessError as e:
                    output = e.output
                if not output:
                    output = b"\n"
                # send encrypted output
                send_bytes(conn, f.encrypt(output))

if __name__ == "__main__":
    start_server()
