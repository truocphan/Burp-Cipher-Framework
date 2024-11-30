import javax.crypto.Mac as Mac
import javax.crypto.spec.SecretKeySpec as SecretKeySpec

class HMAC_SHA256:
	"""
	- provider: str
	"""
	def __init__(self, provider=None):
		self.algorithm = "HmacSHA256"
		self.provider = provider


	"""
	- message: str
	- SECRET_KEY: str
	- Return value: str
	"""
	def digest(self, message, SECRET_KEY):
		if self.provider != None:
			mac = Mac.getInstance(self.algorithm, self.provider)
		else:
			mac = Mac.getInstance(self.algorithm)

		secretKeySpec = SecretKeySpec(SECRET_KEY, self.algorithm)
		mac.init(secretKeySpec)
		hmac = mac.doFinal(message)

		return hmac.tostring()


	"""
	- message: str
	- SECRET_KEY: str
	- Return value: hex str
	"""
	def hexdigest(self, message, SECRET_KEY):
		return "".join(["%02x"%ord(c) for c in self.digest(message, SECRET_KEY)])