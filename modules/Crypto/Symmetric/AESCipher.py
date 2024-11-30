import javax.crypto.Cipher as Cipher
import javax.crypto.spec.SecretKeySpec as SecretKeySpec
import javax.crypto.spec.IvParameterSpec as IvParameterSpec
import javax.crypto.spec.GCMParameterSpec as GCMParameterSpec

class AESCipher:
	"""
	- algorithm: str
	- provider: str
	"""
	def __init__(self, algorithm, provider=None):
		self.algorithm = algorithm
		self.provider = provider
		self.mode = algorithm.split("/")[1]


	"""
	- PlainText: str
	- SECRET_KEY: str // length of SECRET_KEY: 16, 24, 32
	- IV: str // length of IV: 16 for CBC, CFB, OFB, GCM
	- GCM_Tag: int // 128
	- Return value: str
	"""
	def encrypt(self, PlainText, SECRET_KEY, IV=None, GCM_Tag=128):
		if self.provider != None:
			instance = Cipher.getInstance(self.algorithm, self.provider)
		else:
			instance = Cipher.getInstance(self.algorithm)

		if self.mode == "ECB":
			instance.init(1, SecretKeySpec(SECRET_KEY, "AES"))
		elif self.mode == "GCM":
			instance.init(1, SecretKeySpec(SECRET_KEY, "AES"), GCMParameterSpec(GCM_Tag, IV))
		else:
			instance.init(1, SecretKeySpec(SECRET_KEY, "AES"), IvParameterSpec(IV))

		CipherText = instance.doFinal(PlainText)
		return CipherText.tostring()


	"""
	- CipherText: str
	- SECRET_KEY: str // length of SECRET_KEY: 16, 24, 32
	- IV: str // length of IV: 16 for CBC, CFB, OFB, GCM
	- GCM_Tag: int // 128
	- Return value: str
	"""
	def decrypt(self, CipherText, SECRET_KEY, IV=None, GCM_Tag=128):
		if self.provider != None:
			instance = Cipher.getInstance(self.algorithm, self.provider)
		else:
			instance = Cipher.getInstance(self.algorithm)

		if self.mode == "ECB":
			instance.init(2, SecretKeySpec(SECRET_KEY, "AES"))
		elif self.mode == "GCM":
			instance.init(2, SecretKeySpec(SECRET_KEY, "AES"), GCMParameterSpec(GCM_Tag, IV))
		else:
			instance.init(2, SecretKeySpec(SECRET_KEY, "AES"), IvParameterSpec(IV))

		PlainText = instance.doFinal(CipherText)
		return  PlainText.tostring()