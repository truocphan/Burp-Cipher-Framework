import java.security.MessageDigest as MessageDigest

class SHA384:
	"""
	- provider: str
	"""
	def __init__(self, provider=None):
		self.algorithm = "SHA-384"
		self.provider = provider


	"""
	- message: str
	- Return value: str
	"""
	def digest(self, message):
		if self.provider != None:
			return MessageDigest.getInstance(self.algorithm, self.provider).digest(message).tostring()
		else:
			return MessageDigest.getInstance(self.algorithm).digest(message).tostring()


	"""
	- message: str
	- Return value: hex str
	"""
	def hexdigest(self, message):
		return "".join(["%02x"%ord(c) for c in self.digest(message)])