import javax.crypto.Mac as Mac
import javax.crypto.spec.SecretKeySpec as SecretKeySpec

import base64

class HMAC_SHA256:
	"""
	- provider: raw
	"""
	def __init__(self, provider=None):
		self.algorithm = "HmacSHA256"
		self.provider = provider


	"""
	- message: base64 encode
	- SECRET_KEY: base64 encode
	- Return value: base64 encode
	"""
	def digest(self, message, SECRET_KEY):
		message = base64.b64decode(message)
		SECRET_KEY = base64.b64decode(SECRET_KEY)

		if self.provider != None:
			mac = Mac.getInstance(self.algorithm, self.provider)
		else:
			mac = Mac.getInstance(self.algorithm)

		secretKeySpec = SecretKeySpec(SECRET_KEY, self.algorithm)
		mac.init(secretKeySpec)
		hmac = mac.doFinal(message)

		return base64.b64encode(hmac)


	"""
	- message: base64 encode
	- SECRET_KEY: base64 encode
	- Return value: hex string
	"""
	def hexdigest(self, message, SECRET_KEY):
		return "".join(["%02x"%ord(c) for c in base64.b64decode(self.digest(message, SECRET_KEY))])