import java.util.zip.CRC32 as crc32

import base64

class CRC32:
	def __init__(self):
		pass

	"""
	- message: base64 encode
	- Return value: hex string
	"""
	def checksum(self, message):
		message = base64.b64decode(message)

		crc = crc32()
		crc.update(message)
		return "{:x}".format(crc.getValue())