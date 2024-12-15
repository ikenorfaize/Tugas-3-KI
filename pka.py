import socket
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from threading import Thread

# Konfigurasi logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def handle_client(conn, address, public_key):
    """Fungsi untuk menangani koneksi klien."""
    try:
        logging.info(f"Koneksi diterima dari: {address}")

        # Kirimkan kunci publik ke klien
        conn.send(public_key)
        logging.info(f"Kunci publik dikirim ke: {address}")

        # Terima data terenkripsi dari klien
        encrypted_key = conn.recv(1024)
        logging.info(f"Data terenkripsi diterima dari {address}: {encrypted_key}")

        # Muat kunci privat server untuk dekripsi
        try:
            with open("private_key.pem", "rb") as f:
                private_key = RSA.import_key(f.read())

            # Dekripsi data menggunakan kunci privat
            cipher = PKCS1_OAEP.new(private_key)
            decrypted_data = cipher.decrypt(encrypted_key)
            logging.info(f"Data berhasil didekripsi: {decrypted_data.decode('utf-8')}")
        except FileNotFoundError:
            logging.error("File private_key.pem tidak ditemukan.")
        except ValueError as ve:
            logging.error(f"Dekripsi gagal. Pastikan kunci cocok dan data tidak korup: {ve}")
        except Exception as e:
            logging.error(f"Error saat dekripsi: {e}")
    except Exception as e:
        logging.error(f"Error saat menangani klien {address}: {e}")
    finally:
        conn.close()


def pka_server_program(host='127.0.0.1', port=6000):
    """Program server PKA."""
    # Muat kunci publik server RSA dari file
    try:
        with open("public_key.pem", "rb") as f:
            public_key = f.read()
    except FileNotFoundError:
        logging.error("File public_key.pem tidak ditemukan.")
        return
    except Exception as e:
        logging.error(f"Error saat membaca kunci publik: {e}")
        return

    # Buat server socket
    try:
        server_socket = socket.socket()
        server_socket.bind((host, port))
        server_socket.listen(5)
        logging.info(f"PKA berjalan di {host}:{port}. Menunggu permintaan klien...")

        while True:
            try:
                # Terima koneksi dari klien
                conn, address = server_socket.accept()
                # Tangani klien di thread terpisah
                Thread(target=handle_client, args=(conn, address, public_key)).start()
            except KeyboardInterrupt:
                logging.info("\nPKA dihentikan secara manual.")
                break
            except Exception as e:
                logging.error(f"Error di server: {e}")

    except Exception as e:
        logging.error(f"Error saat menginisialisasi server: {e}")
    finally:
        server_socket.close()
        logging.info("Server socket ditutup.")

if __name__ == "__main__":
    pka_server_program()
