import java.util.zip.CRC32 as crc32

class CRC32:
	def __init__(self):
		pass

	"""
	- message: str
	- Return value: hex str
	"""
	def checksum(self, message):
		crc = crc32()
		crc.update(message)
		return "{:x}".format(crc.getValue())