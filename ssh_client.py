import socket
import struct
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
import base64

HOST = "127.0.0.1"
PORT = 5001

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

def derive_fernet_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ssh-sim-demo",
    )
    key = hkdf.derive(shared_secret)
    return base64.urlsafe_b64encode(key)

def start_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        # --- X25519 key exchange ---
        client_priv = x25519.X25519PrivateKey.generate()
        client_pub = client_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        # receive server pub
        server_pub_bytes = recv_bytes(s)
        send_bytes(s, client_pub)
        server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
        shared = client_priv.exchange(server_pub)
        fernet_key = derive_fernet_key(shared)
        f = Fernet(fernet_key)
        print("Key exchange done. Channel encrypted.")

        # --- authentication ---
        prompt_enc = recv_bytes(s)
        prompt = f.decrypt(prompt_enc).decode()
        username = input(prompt)
        send_bytes(s, f.encrypt(username.encode()))

        prompt_enc = recv_bytes(s)
        prompt = f.decrypt(prompt_enc).decode()
        password = input(prompt)
        send_bytes(s, f.encrypt(password.encode()))

        resp_enc = recv_bytes(s)
        resp = f.decrypt(resp_enc).decode()
        print(resp, end="")
        if "failed" in resp.lower():
            return

        # --- command loop ---
        while True:
            cmd = input("ssh> ")
            send_bytes(s, f.encrypt(cmd.encode()))
            if cmd.strip().lower() == "exit":
                resp_enc = recv_bytes(s)
                print(f.decrypt(resp_enc).decode(), end="")
                break
            out_enc = recv_bytes(s)
            out = f.decrypt(out_enc)
            print(out.decode(errors="ignore"), end="")

if __name__ == "__main__":
    start_client()
