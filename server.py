import socket
import nacl.utils
import nacl.secret
from nacl.bindings import sodium_increment
from nacl.signing import VerifyKey
from datetime import datetime

def roundUp(string: str)-> None:
	data = bytes(string, "utf-8")
	data += b" " * (128-len(data))
	return data

def write_log(user: str):
	logfile = open("./log", "a")
	logfile.write("User conected:" + user + " at " + str(datetime.now()))

HOST = "127.0.0.1"
PORT = 3312
CHUNK_SIZE = 1024
SIGN_SIZE = 64
VERIFY_KEY_BYTES_SIZE = 32


key = nacl.utils.randombytes_deterministic(
		nacl.secret.SecretBox.KEY_SIZE,
		b"\xAB\xCD\xEF\xAB\xCD\xEF\xAB\xCD\xEF\xAB\xCD\xEF\xAB\xCD\xEF\xFF"
		b"\xAB\xCD\xEF\xAB\xCD\xEF\xAB\xCD\xEF\xAB\xCD\xEF\xAB\xCD\xEF\xFF",
)

box = nacl.secret.SecretBox(key)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.bind((HOST, PORT))
		s.listen()
		conn, addr = s.accept()
		with conn:
				received_user = conn.recv(128).decode("utf-8").strip()
				received_password = conn.recv(128).decode("utf-8").strip()

				credentials = open("./credentials.txt", "r")
				credential = credentials.readline()
				user, password = credential.split(':')
				print(user, password)
				if(user == received_user and password == received_password):
					conn.sendall(roundUp("auth_good"))
					write_log(received_user)
					# receive verified_key_bytes
					verified_key_bytes = conn.recv(VERIFY_KEY_BYTES_SIZE)
					# Create a VerifyKey object from a hex serialized public key
					verify_key = VerifyKey(verified_key_bytes)

					# receive nonce to decrypt
					nonce = conn.recv(nacl.secret.SecretBox.NONCE_SIZE)

					file_data = b""
					while True:
							# receive encrypted data
							# size of this is chunk + mac size
							data = conn.recv(CHUNK_SIZE + box.MACBYTES + SIGN_SIZE)
							if len(data) == 0:
									break
							elif len(data) % 16 != 0:
									data += bytes(" " * (16 - (len(data) % 16)), "utf-8")

							# decrypt using nonce
							decrypted_data = box.decrypt(data, nonce)
							verified_message = verify_key.verify(decrypted_data)
							file_data += verified_message
							# update nonce so that is same as in client
							nonce = sodium_increment(nonce)
					with open("./recibido.txt", "wb") as file:
							file.write(file_data)
				else:
					conn.sendall(roundUp("auth_bad"))
					conn.shutdown(SHUT_RDWR)
					conn.close()