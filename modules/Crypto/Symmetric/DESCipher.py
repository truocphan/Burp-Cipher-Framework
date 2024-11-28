import javax.crypto.Cipher as Cipher
import javax.crypto.spec.SecretKeySpec as SecretKeySpec
import javax.crypto.spec.IvParameterSpec as IvParameterSpec

import base64

class DESCipher:
	"""
	- algorithm: raw // "DES/ECB/NoPadding", "DES/CBC/PKCS5Padding"
	- provider: raw
	"""
	def __init__(self, algorithm, provider=None):
		self.algorithm = algorithm
		self.provider = provider


	"""
	- PlainText: base64 encode
	- SECRET_KEY: base64 encode
	- IV: base64 encode
	- Return value: base64 encode
	"""
	def encrypt(self, PlainText, SECRET_KEY, IV):
		PlainText = base64.b64decode(PlainText)
		SECRET_KEY = base64.b64decode(SECRET_KEY)
		IV = base64.b64decode(IV)

		if self.provider != None:
			instance = Cipher.getInstance(self.algorithm, self.provider)
		else:
			instance = Cipher.getInstance(self.algorithm)

		secretKeySpec = SecretKeySpec(SECRET_KEY, "DES")

		instance.init(1, secretKeySpec, IvParameterSpec(IV))

		CipherText = instance.doFinal(PlainText)

		return base64.b64encode(CipherText)


	"""
	- CipherText: base64 encode
	- SECRET_KEY: base64 encode
	- IV: base64 encode
	- Return value: base64 encode
	"""
	def decrypt(self, CipherText, SECRET_KEY, IV):
		CipherText = base64.b64decode(CipherText)
		SECRET_KEY = base64.b64decode(SECRET_KEY)
		IV = base64.b64decode(IV)

		if self.provider != None:
			instance = Cipher.getInstance(self.algorithm, self.provider)
		else:
			instance = Cipher.getInstance(self.algorithm)

		secretKeySpec = SecretKeySpec(SECRET_KEY, "DES")

		instance.init(2, secretKeySpec, IvParameterSpec(IV))

		PlainText = instance.doFinal(CipherText)

		return  base64.b64encode(PlainText)