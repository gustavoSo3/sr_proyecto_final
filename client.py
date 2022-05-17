import socket
import nacl.secret
import nacl.utils
from nacl.bindings import sodium_increment
from nacl.signing import SigningKey


def roundUp(string: str)-> None:
	data = bytes(string, "utf-8")
	data += b" " * (128-len(data))
	return data


HOST = "127.0.0.1"
PORT = 3312
VERIFY_KEY_BYTES_SIZE = 32
CHUNK_SIZE = 1024

key = nacl.utils.randombytes_deterministic(
		nacl.secret.SecretBox.KEY_SIZE,
		b"\xAB\xCD\xEF\xAB\xCD\xEF\xAB\xCD\xEF\xAB\xCD\xEF\xAB\xCD\xEF\xFF"
		b"\xAB\xCD\xEF\xAB\xCD\xEF\xAB\xCD\xEF\xAB\xCD\xEF\xAB\xCD\xEF\xFF",
)

# Generate a new random signing key
signing_key = SigningKey.generate()
# Obtain the verify key for a given signing key
verify_key = signing_key.verify_key

# Serialize the verify key to send it to a third party
verify_key_bytes = verify_key.encode()

box = nacl.secret.SecretBox(key)
nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((HOST, PORT))

		user = input("Enter Username: ")
		s.sendall(roundUp(user))
		password = input("Enter Password: ")
		s.sendall(roundUp(password))

		auth_response = s.recv(128).decode("utf-8").strip()
		if(auth_response == "auth_good"):
			# Send verify key bytes
			s.sendall(verify_key_bytes)

			# Send nonce once at the beginning
			s.sendall(nonce)
			with open("./mensaje.txt", "rb") as file:
					while True:
							# read file in chunks instead of lines to be consistent with size of
							# encryption and decription
							chunk = file.read(CHUNK_SIZE)
							if len(chunk) == 0:
									break
							elif len(chunk) % 16 != 0:
									chunk += bytes(" " * (16 - (len(chunk) % 16)), "utf-8")

							# sign data
							signed_data = signing_key.sign(chunk)
							# encrypt signed data
							encrypted_data = box.encrypt(signed_data, nonce).ciphertext
							# send encrypted signed data
							s.sendall(encrypted_data)
							# increment nonce to get a new one
							nonce = sodium_increment(nonce)
		else:
			print("Error trying to authenticate")
