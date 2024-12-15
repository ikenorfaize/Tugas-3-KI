import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import socket

# Membuat pasangan kunci RSA untuk PKA (jika belum tersedia)
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(public_key)

# Fungsi untuk memuat kunci RSA dari file
def load_rsa_keys():
    try:
        with open("private_key.pem", "rb") as priv_file:
            private_key = RSA.import_key(priv_file.read())
        with open("public_key.pem", "rb") as pub_file:
            public_key = RSA.import_key(pub_file.read())
        return private_key, public_key
    except FileNotFoundError:
        print("Kunci RSA tidak ditemukan, membuat kunci baru...")
        generate_rsa_keys()
        return load_rsa_keys()

# Fungsi untuk menandatangani data
def sign_data(data, private_key):
    hash_obj = SHA256.new(data.encode())
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    return signature

# Fungsi untuk memverifikasi tanda tangan
def validate_signature(data, signature, public_key):
    hash_obj = SHA256.new(data.encode())
    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

# Fungsi server untuk mengirim kunci publik
def pka_server_program():
    host = '127.0.0.1'  # Alamat server PKA
    port = 6000         # Port untuk PKA

    # Muat kunci RSA
    private_key, public_key = load_rsa_keys()

    # Buat server socket
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(5)

    print("PKA berjalan. Menunggu permintaan klien...")

    while True:
        try:
            # Terima koneksi dari klien
            conn, address = server_socket.accept()
            print(f"Koneksi diterima dari: {address}")

            # Kirimkan kunci publik ke klien
            conn.send(public_key.export_key())
            print(f"Kunci publik dikirim ke: {address}")

            # Tutup koneksi dengan klien
            conn.close()
        except KeyboardInterrupt:
            print("\nPKA dihentikan secara manual.")
            break
        except Exception as e:
            print(f"Error: {e}")

    # Tutup server socket
    server_socket.close()

# Fungsi utama
if __name__ == "__main__":
    pka_server_program()
