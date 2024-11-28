import javax.crypto.Cipher as Cipher
import java.security.KeyFactory as KeyFactory
import java.security.spec.X509EncodedKeySpec as X509EncodedKeySpec
import java.security.spec.PKCS8EncodedKeySpec as PKCS8EncodedKeySpec
import java.security.Signature as Signature

import base64

class RSACipher:
	"""
	- algorithm: raw // "RSA/ECB/PKCS1Padding", "RSA/ECB/OAEPPadding"
	# SHA256withRSA
	- provider: raw
	"""
	def __init__(self, algorithm, provider=None):
		self.algorithm = algorithm
		self.provider = provider


	def RSAPublicKey(self, PublicKey):
		return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(base64.b64decode(PublicKey.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", ""))))


	def RSAPrivateKey(self, PrivateKey):
		return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(base64.b64decode(PrivateKey.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replace("\n", ""))))


	"""
	- PlainText: base64 encode
	- Return value: base64 encode
	"""
	def encrypt(self, PlainText, PublicKey=None, PrivateKey=None):
		if self.provider != None:
			instance = Cipher.getInstance(self.algorithm, self.provider)
		else:
			instance = Cipher.getInstance(self.algorithm)

		if PublicKey != None:
			encryptKey = self.RSAPublicKey(PublicKey)
		elif PrivateKey != None:
			encryptKey = self.RSAPrivateKey(PrivateKey)
		else:
			return None

		instance.init(1, encryptKey)
		CipherText = instance.doFinal(base64.b64decode(PlainText))
		return base64.b64encode(CipherText)


	"""
	- CipherText: base64 encode
	- Return value: base64 encode
	"""
	def decrypt(self, CipherText, PrivateKey=None, PublicKey=None):
		if self.provider != None:
			instance = Cipher.getInstance(self.algorithm, self.provider)
		else:
			instance = Cipher.getInstance(self.algorithm)

		if PrivateKey != None:
			decryptKey = self.RSAPrivateKey(PrivateKey)
		elif PublicKey != None:
			decryptKey = self.RSAPublicKey(PublicKey)
		else:
			return None

		instance.init(2, decryptKey)
		PlainText = instance.doFinal(base64.b64decode(CipherText))
		return  base64.b64encode(PlainText)


	"""
	- message: base64 encode
	- signData: base64 encode
	- Return value: boolean
	"""
	def verify(self, message, signData, PublicKey):
		if self.provider != None:
			sign = Signature.getInstance(self.algorithm, self.provider)
		else:
			sign = Signature.getInstance(self.algorithm)

		sign.initVerify(self.RSAPublicKey(PublicKey))
		sign.update(base64.b64decode(message))
		return sign.verify(base64.b64decode(signData))


	"""
	- message: base64 encode
	- Return value: base64 encode
	"""
	def signature(self, message, PrivateKey):
		if self.provider != None:
			sign = Signature.getInstance(self.algorithm, self.provider)
		else:
			sign = Signature.getInstance(self.algorithm)

		sign.initSign(self.RSAPrivateKey(PrivateKey))
		sign.update(base64.b64decode(message))
		return base64.b64encode(sign.sign())