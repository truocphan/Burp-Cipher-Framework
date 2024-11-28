import java.security.MessageDigest as MessageDigest
import base64

class MD2:
	"""
	- provider: raw
	"""
	def __init__(self, provider=None):
		self.algorithm = "MD2"
		self.provider = provider


	"""
	- message: base64 encode
	- Return value: base64 encode
	"""
	def digest(self, message):
		message = base64.b64decode(message)

		if self.provider != None:
			return base64.b64encode(MessageDigest.getInstance(self.algorithm, self.provider).digest(message))
		else:
			return base64.b64encode(MessageDigest.getInstance(self.algorithm).digest(message))


	"""
	- message: base64 encode
	- Return value: hex string
	"""
	def hexdigest(self, message):
		return "".join(["%02x"%ord(c) for c in base64.b64decode(self.digest(message))])