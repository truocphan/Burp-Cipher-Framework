import time
import uuid as _uuid
import base64
import random
import string
import urllib

def timestamp(length):
	if length <= 0:
		return 0
	elif length < 10:
		return int(time.time() / 10**(10-length))
	elif length == 10:
		return int(time.time())
	else:
		return int(time.time() * 10**(length-10))

def uuid(version):
	if version == 1:
		return str(_uuid.uuid1())
	elif version == 4:
		return str(_uuid.uuid4())

def RandomNumber(min, max):
	return random.randint(min, max)

def RandomString(length, charsets=None):
	if type(charsets) not in [str, unicode]:
		charsets = string.ascii_letters+string.digits+string.punctuation

	return "".join(random.choice(charsets) for i in range(length))

def Str2Hex(message):
	return "".join(["%02x"%ord(c) for c in message])

def Hex2Str(message):
	return "".join([chr(int(message[i:i+2], 16)) for i in range(0, len(message), 2)])

def base64Encode(message):
	return base64.b64encode(message.encode()).decode()

def base64Decode(message):
	return base64.b64decode(message.encode()).decode()

def base64UrlEncode(message):
	return base64.urlsafe_b64encode(message.encode()).rstrip(b"=").decode()

def base64UrlDecode(message):
	padding = b"=" * (4-(len(message)%4))
	return base64.urlsafe_b64decode(message.encode()+padding).decode()

def UrlEncode(message):
	return urllib.quote(message)

def UrlDecode(message):
	return urllib.unquote(message)