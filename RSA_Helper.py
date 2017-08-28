from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class RSA_Helper():
	""" This is a RSA key creator, encrypter and decrypter class.
	"""
	def __init__(self):
		self.private_key=0 # private rsa key
		self.public_key=0 # public rsa key

	def create_new_rsa(self,private_file="private.pem",public_file="public.pem"):
		""" Create new rsa keys and save them in a file
			* Return rsa keys : return private, public
		"""
		self.private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048, # 2048
		backend=default_backend())

		# serialize key to write file
		pem = self.private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption()
		)

		# write private key with byte formatting
		with open(private_file,"wb") as f:
			for i in pem.splitlines():
				f.write(i)
				f.write(b"\n")

		# serialize public_key to write file
		self.public_key = self.private_key.public_key()
		pem = self.public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		# write public key to file
		with open(public_file,"wb") as f:
			for i in pem.splitlines():
				f.write(i)
				f.write(b"\n")
		# return keys
		return self.private_key,self.public_key

	def load_private_key_from_file(self,filepath="private.pem"):
		""" Load private key from filepath
			Return private_key object or none
		"""
		try:
			with open(filepath, "rb") as key_file:
				self.private_key = serialization.load_pem_private_key(
				key_file.read(),
				password=None,
				backend=default_backend()
			)
		except:
			self.private_key=None
		return self.private_key

	def load_public_key_from_file(self,filepath="public.pem"):
		""" Load public key from filepath
			Return public_key object or none
		"""
		try:
			with open(filepath, "rb") as key_file:
				self.public_key = serialization.load_pem_public_key(
				key_file.read(),
				backend=default_backend()
			)
		except:
			self.public_key=None
		return self.public_key

	def encrypt_msg(self,message):
		""" Encrypt given message via public key
			! DO NOT FORGET LOADING OR CREATING A key
			Return encrypted binary message, on error return None
		"""
		try:
			ciphertext = self.public_key.encrypt(
				message,
				padding.OAEP(
					mgf=padding.MGF1(algorithm=hashes.SHA1()),
					algorithm=hashes.SHA1(),
					label=None
				)
			)
		except:
			return None
		return ciphertext

	def decrypt_msg(self,message):
		""" Decrypt given message via private key
			! DO NOT FORGET LOADING OR CREATING A key
			Return plain text message, on error return None
		"""
		try:
			plaintext = self.private_key.decrypt(
				message,
				padding.OAEP(
					mgf=padding.MGF1(algorithm=hashes.SHA1()),
					algorithm=hashes.SHA1(),
					label=None
				)
			)
		except:
			return None
		return plaintext.decode("UTF-8")

def test():
	rsa_helper = RSA_Helper()

	#rsa_helper.create_new_rsa()
	rsa_helper.load_public_key_from_file()
	rsa_helper.load_private_key_from_file()

	msg = "hmenn".encode() # encode bytes
	print("Message:",msg)
	enc_msg = rsa_helper.encrypt_msg(msg)
	print("Encrypted Message:",enc_msg)
	dec_msg = rsa_helper.decrypt_msg(enc_msg)
	print("Decrypted Message:",dec_msg)


#key = create_new_rsa()

#test()
