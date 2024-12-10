![Burp Cipher Framework](./static/BCF.jpg)

<p align="center">
	<a href="#"><img src="https://img.shields.io/github/downloads/truocphan/Burp-Cipher-Framework/total" height=30></a>
	<a href="#"><img src="https://img.shields.io/github/stars/truocphan/Burp-Cipher-Framework" height=30></a>
	<a href="#"><img src="https://img.shields.io/github/forks/truocphan/Burp-Cipher-Framework" height=30></a>
	<a href="https://github.com/truocphan/Burp-Cipher-Framework/issues?q=is%3Aopen+is%3Aissue"><img src="https://img.shields.io/github/issues/truocphan/Burp-Cipher-Framework" height=30></a>
	<a href="https://github.com/truocphan/Burp-Cipher-Framework/issues?q=is%3Aissue+is%3Aclosed"><img src="https://img.shields.io/github/issues-closed/truocphan/Burp-Cipher-Framework" height=30></a>
</p>

__Burp Cipher Framework (BCF)__

---

# Built-in Variables and Functions
#### `RequestParser` -> [TP_HTTP_REQUEST_PARSER](https://github.com/truocphan/TP-HTTP-Request-Response-Parser)
```
RequestParser.request_method
RequestParser.request_path
RequestParser.request_pathParams.dumps(indent=4)
RequestParser.request_queryParams.dumps(indent=4)
RequestParser.request_fragment
RequestParser.request_httpVersion
RequestParser.request_headers.dumps(indent=4)
RequestParser.request_body.dumps(indent=4)
```

#### `ResponseParser` -> [TP_HTTP_RESPONSE_PARSER](https://github.com/truocphan/TP-HTTP-Request-Response-Parser)
```
ResponseParser.response_httpVersion
ResponseParser.response_statusCode
ResponseParser.response_statusText
ResponseParser.response_headers.dumps(indent=4)
ResponseParser.response_body.dumps(indent=4)
```

#### `serverPublicKeys` -> list
The list of _Public Keys_ used by the server is declared in the __BCFconf.json__ configuration file
```
serverPublicKeys[0]
# OUTPUT: '...'
```

#### `serverPrivateKeys` -> list
The list of _Private Keys_ used by the server is declared in the __BCFconf.json__ configuration file
```
serverPrivateKeys[0]
# OUTPUT: '...'
```

#### `serverSecretKeys` -> list
The list of _Secret Keys_ used by the server is declared in the __BCFconf.json__ configuration file
```
serverSecretKeys[0]
# OUTPUT: '...'
```

#### `serverIVs` -> list
The list of _IVs_ used by the server is declared in the __BCFconf.json__ configuration file
```
serverIVs[0]
# OUTPUT: '...'
```

#### `serverSalts` -> list
The list of _Salts_ used by the server is declared in the __BCFconf.json__ configuration file
```
serverSalts[0]
# OUTPUT: '...'
```

#### `serverPasswords` -> list
The list of _Passwords_ used by the server is declared in the __BCFconf.json__ configuration file
```
serverPasswords[0]
# OUTPUT: '...'
```

#### `clientPublicKeys` -> list
The list of _Public Keys_ used by the client is declared in the __BCFconf.json__ configuration file
```
clientPublicKeys[0]
# OUTPUT: '...'
```

#### `clientPrivateKeys` -> list
The list of _Private Keys_ used by the client is declared in the __BCFconf.json__ configuration file
```
clientPrivateKeys[0]
# OUTPUT: '...'
```

#### `clientSecretKeys` -> list
The list of _Secret Keys_ used by the client is declared in the __BCFconf.json__ configuration file
```
clientSecretKeys[0]
# OUTPUT: '...'
```

#### `clientIVs` -> list
The list of _IVs_ used by the client is declared in the __BCFconf.json__ configuration file
```
clientIVs[0]
# OUTPUT: '...'
```

#### `clientSalts` -> list
The list of _Salts_ used by the client is declared in the __BCFconf.json__ configuration file
```
clientSalts[0]
# OUTPUT: '...'
```

#### `clientPasswords` -> list
The list of _Passwords_ used by the client is declared in the __BCFconf.json__ configuration file
```
clientPasswords[0]
# OUTPUT: '...'
```

### Utils module
#### `timestamp(length :int)` -> int
```
Utils.timestamp(10)
# OUTPUT: 1732726800
```

#### `uuid(version :int)` -> str
```
Utils.uuid(4)
# OUTPUT: 'e0db37ce-3296-4253-a3ca-be43bc80073b'
```

#### `RandomNumber(min :int, max :int)` -> int
```
Utils.RandomNumber(0, 1000)
# OUTPUT: 465
```

#### `RandomString(length :int, charsets :str=None)` -> str
```
Utils.RandomString(10)
# OUTPUT: 'Wz<:1<.YSC'
```

#### `Str2Hex(message :str)` -> str
```
Utils.Str2Hex('TPCyberSec')
# OUTPUT: '54504379626572536563'
```

#### `Hex2Str(message :str)` -> str
```
Utils.Hex2Str('54504379626572536563')
# OUTPUT: 'TPCyberSec'
```

#### `base64Encode(message :str)` -> str
```
Utils.base64Encode('TPCyberSec')
# OUTPUT: 'VFBDeWJlclNlYw=='
```

#### `base64Decode(message :str)` -> str
```
Utils.base64Decode('VFBDeWJlclNlYw==')
# OUTPUT: 'TPCyberSec'
```

#### `base64UrlEncode(message :str)` -> str
```
Utils.base64UrlEncode('TPCyberSec')
# OUTPUT: 'VFBDeWJlclNlYw'
```

#### `base64UrlDecode(message :str)` -> str
```
Utils.base64UrlDecode('VFBDeWJlclNlYw')
# OUTPUT: 'TPCyberSec'
```

#### `UrlEncode(message :str)` -> str
```
Utils.UrlEncode('TP Cyber Security')
# OUTPUT: 'TP%20Cyber%20Security'
```

#### `UrlDecode(message :str)` -> str
```
Utils.UrlDecode('TP%20Cyber%20Security')
# OUTPUT: 'TP Cyber Security'
```

### Crypto.Symmetric modules
#### `AESCipher(algorithm :str, provider :str=None).encrypt(PlainText :str, SECRET_KEY :str, IV :str=None, GCM_Tag :int=128)` -> str
```
AESCipher('AES/ECB/NoPadding').encrypt('TPCyberSec      ', 'TPCSTPCSTPCSTPCS')
# OUTPUT: '\x04M\\H\x07\x06\x14\xfe\xc0\xddN\x8aX\x18\r\xf8'

AESCipher('AES/ECB/PKCS5Padding').encrypt('TPCyberSec', 'TPCSTPCSTPCSTPCS')
# OUTPUT: 'oD\x19)K\xb2\xe7\x10\xe4\x86uc\xc3\xa7\x08\x9e'

AESCipher('AES/CBC/NoPadding').encrypt('TPCyberSec      ', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: '\xab\r\x16\x98L\x9a~\xe3\x8d~n\xb6\xb7\xb3cV'

AESCipher('AES/CBC/PKCS5Padding').encrypt('TPCyberSec', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: 'X\xe1\x08d\xd1\xba\x1f\xeb\x00M\xfb\xeb\x8e`\x16q'

AESCipher('AES/CFB/NoPadding').encrypt('TPCyberSec', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: 't\xe6C\xa7\xffJ\xa8Y\x91\xb4'

AESCipher('AES/CFB/PKCS5Padding').encrypt('TPCyberSec', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: 't\xe6C\xa7\xffJ\xa8Y\x91\xb4\x17\xea\xba(\xf5\xbd'

AESCipher('AES/OFB/NoPadding').encrypt('TPCyberSec', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: 't\xe6C\xa7\xffJ\xa8Y\x91\xb4'

AESCipher('AES/OFB/PKCS5Padding').encrypt('TPCyberSec', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: 't\xe6C\xa7\xffJ\xa8Y\x91\xb4\x17\xea\xba(\xf5\xbd'

AESCipher('AES/GCM/NoPadding').encrypt('TPCyberSec', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: "{R6'\xba\x93\x98\xa5\x05\xb3!%\xc3\xb6>\x8d\t\x1b\x01\xbb\xb2\x86\xfe \x8ab"

AESCipher('AES/CTR/NoPadding').encrypt('TPCyberSec', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: 't\xe6C\xa7\xffJ\xa8Y\x91\xb4'
```

#### `AESCipher(algorithm :str, provider :str=None).decrypt(CipherText :str, SECRET_KEY :str, IV :str=None, GCM_Tag :int=128)` -> str
```
AESCipher('AES/ECB/NoPadding').decrypt('\x04M\\H\x07\x06\x14\xfe\xc0\xddN\x8aX\x18\r\xf8', 'TPCSTPCSTPCSTPCS')
# OUTPUT: 'TPCyberSec      '

AESCipher('AES/ECB/NoPadding').decrypt('oD\x19)K\xb2\xe7\x10\xe4\x86uc\xc3\xa7\x08\x9e', 'TPCSTPCSTPCSTPCS')
# OUTPUT: 'TPCyberSec\x06\x06\x06\x06\x06\x06'

AESCipher('AES/CBC/NoPadding').decrypt('\xab\r\x16\x98L\x9a~\xe3\x8d~n\xb6\xb7\xb3cV', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: 'TPCyberSec      '

AESCipher('AES/CBC/PKCS5Padding').decrypt('X\xe1\x08d\xd1\xba\x1f\xeb\x00M\xfb\xeb\x8e`\x16q', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: 'TPCyberSec'

AESCipher('AES/CFB/NoPadding').decrypt('t\xe6C\xa7\xffJ\xa8Y\x91\xb4', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: 'TPCyberSec'

AESCipher('AES/CFB/PKCS5Padding').decrypt('t\xe6C\xa7\xffJ\xa8Y\x91\xb4\x17\xea\xba(\xf5\xbd', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: 'TPCyberSec'

AESCipher('AES/OFB/NoPadding').decrypt('t\xe6C\xa7\xffJ\xa8Y\x91\xb4', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: 'TPCyberSec'

AESCipher('AES/OFB/PKCS5Padding').decrypt('t\xe6C\xa7\xffJ\xa8Y\x91\xb4\x17\xea\xba(\xf5\xbd', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: 'TPCyberSec'

AESCipher('AES/GCM/NoPadding').decrypt("{R6'\xba\x93\x98\xa5\x05\xb3!%\xc3\xb6>\x8d\t\x1b\x01\xbb\xb2\x86\xfe \x8ab", 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: 'TPCyberSec'

AESCipher('AES/CTR/NoPadding').decrypt('t\xe6C\xa7\xffJ\xa8Y\x91\xb4', 'TPCSTPCSTPCSTPCS', '0123456789012345')
# OUTPUT: 'TPCyberSec'
```

#### `DESCipher(algorithm :str, provider :str=None).encrypt(PlainText :str, SECRET_KEY :str, IV :str=None)` -> str
```
DESCipher('DES/ECB/NoPadding').encrypt('TPCyberSec      ', 'TPCSTPCS', '01234567')
# OUTPUT: 'D{UZ\x18Ck\xcc\x80\x10*p\x7f\t\x7f9'
```

#### `DESCipher(algorithm :str, provider :str=None).decrypt(CipherText :str, SECRET_KEY :str, IV :str=None)` -> str
```
DESCipher('DES/ECB/NoPadding').decrypt('D{UZ\x18Ck\xcc\x80\x10*p\x7f\t\x7f9', 'TPCSTPCS', '01234567')
# OUTPUT: 'TPCyberSec      '
```

### Crypto.Asymmetric modules
#### `RSACipher(algorithm :str, provider :str=None).encrypt(PlainText :str, PublicKey :str=None, PrivateKey :str=None)` -> str
```
PublicKey = '-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuTwspB6ubxVDBIb7IL7sSinHDmZLk/7RYzOWzVmLZo7dzBKiOmAbvFMMGRXFZ/37eThQ7VP31qe6MCH7PhtuP+KKOFpfgQc3O9umo78Qut4NGuCYNiuRrRx2jv1KESS+zIxllelx/JmEbtrME3boMZJ7W/y/SL8dfhYuGZYuqrGOe2ZRwekWkxAUJlAlHT/keDU8qU3oGDgVIn6Ck5MW0o8yBoMsm7o1LfvAGdt5jdxATXy1pzIi3Tr/bLVVkOPmaYrmRQ1McQLSekGA0+hn/MSMTIKRBA4JtSLaQ7YPZQPqwlvYm56958Lr8FPcQ7dz3KXWRY5wG+KSf+3vWnRZ3QIDAQAB-----END PUBLIC KEY-----'
PrivateKey = '-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5PCykHq5vFUMEhvsgvuxKKccOZkuT/tFjM5bNWYtmjt3MEqI6YBu8UwwZFcVn/ft5OFDtU/fWp7owIfs+G24/4oo4Wl+BBzc726ajvxC63g0a4Jg2K5GtHHaO/UoRJL7MjGWV6XH8mYRu2swTdugxkntb/L9Ivx1+Fi4Zli6qsY57ZlHB6RaTEBQmUCUdP+R4NTypTegYOBUifoKTkxbSjzIGgyybujUt+8AZ23mN3EBNfLWnMiLdOv9stVWQ4+ZpiuZFDUxxAtJ6QYDT6Gf8xIxMgpEEDgm1ItpDtg9lA+rCW9ibnr3nwuvwU9xDt3PcpdZFjnAb4pJ/7e9adFndAgMBAAECggEAAQJP5/D22EoQXGTz10DS/rBtkimCfeLkdxrf1myHct6SXLs5QQInBIabSUOyGJfsl8NzxWcwsW2meP6mZLc3iYeNYzMy0/wbE+tlY/z1dV8iSSQyEBF6sKu4BZ1hmuhNVcXqA8AKy+p2Kzhr5is+po56t4yP6jCIU5iBVchYprtggIeLUDAKIGterKEYxJt/N8pdJ0oGhx4cNxcRBDylqdm0HJphyP19BtBOsFtdT9cN6khNpsWGl7UirvlI8eoJxfkXzSgRLn0XoZhl1gDKAD9XCWnII9nzZyINUY1ICG2fISMMGGCNs9YmaY0wzMkhNvty8fPoWH+XrvNyomxIQQKBgQDiMQqPsRYZEw51CsGyyJFALHUfCxsLv6lXeFgCzBY74rksF4CrrNR1rcrvbMe06P54el+dtGevnpb+C1x/iFUkncGW6hNZii/dpKlxUvFTnYYWAITOiOJltDliFlXt7jCZEkGO9WcYRmTibve3pgjxB79MxEo4bJQCRSHTd6ZaLQKBgQDRpWUxaA5IdwuX7/pxG9ekFvxkJCpjDj14rkA832SLs1Zoq/d4D6/0WTp+c6wHL7fzU1DFbgCwB560ktlAvI77J6tapl1hps6RYh9H3bz+Hb6d6eFlhdyUKuTX1XXw6RcK3pYtYOltavl3bwAal/7TEKjrdS59qwx2BlsbQvQ8cQKBgQCHjjRyIQLJTC5h3mxvJNxHxVz7mcA/rkFidnDoXD8G7L1ku0EVoaJCVEFGc77LoMbAlTYwYSmyiiybW1u34pCEPTcDpoyqILLG9iPGEpsmLUVqci0lScvEf9nT+ubMjO77DYHUlyWN2sIjIbW7jfnV2XrAGvMQFaIuKhg3j4FWkQKBgQCYfp2QBae2EFnviBD864q9AjdOxHvMl9QhD2cMoFZrw+SLuOMGgyqzK6B/0LYGeDBvH2B2a+C2KqTHprW/ACllCWL8Sl1MpeBGIkCsrt9FXO+FwFVC2s8rO9RAJzZmKbaoImbM1VyWSaTyulwx+/PRJaIpu5A4uw4SX+cvelFcEQKBgHz2GicI/2cgYlRaeeR8tDSrfVNkhkF1qQZpC3GlTLMjmzZQzLXkjxvYRjNfSJaTZ9CMlaD1PFnqu7Uk9KhUwkClGnSsvFBO2MrRh6P32XS5eDVoP7jZ1pk5/dvuB1RSJqLT63FRaBi8XPSPeT/9po9lCfipK2tlNnggFMPZf3qQ-----END PRIVATE KEY-----'

RSACipher('RSA/ECB/PKCS1Padding').encrypt('TPCyberSec', PublicKey=PublicKey)
# OUTPUT: '\xb4\xb1\xbe\xaaS\xec\xba\xaa.\x18lUt\xb3`\x0b\xc7\x8b>\xe6\x0fVE\x82\t\xa6\xd7o8\xc5\xfauUv\xb1\x8d\xfa6C!\xf3\x93Rv\x9db\t\xdf\x1a\xb1%E!|\x00\xef\x08\x0c\xc2\xb1W:\x0c\x97k\xd28\xddZ\xe8\x18h\x7f\xed\x98h?;\xb3\x0e\xd6\x83\x11\xa7\t\xf0d\x7f]\xd5\xd3&\x98\x9b\x8f+\xbc\x9b{"6\xdd\xcc\xec\xfc1\xceR\xb3\xfa\xcaW\x03\x8f\x0f\x98\xe9\xeb\xad\x1b\x16a\x1b\\\x84\xd0\xe7! 8L\xba\xb08T\xb7\x87\xbd\xb4G\xad\t\xa6\xb6J\xfd\xef6Z\xbc4+[\xe3\xb7\xef_\xe4\xc25A*\x16a\x92\x10\xe9i2B !\xae_}\x1f\x05\x80W\xefS\x85\xe6]\x1f \x962J3\x1f\xdc\x91\xa7\xd5A{\x11\xa9\xef!\xd8=\x8e\xf29\x93\xed\xa7-\x93o\xff\x1bB\xb0\xd8\'u\x13\x1e=\x98\x14\x99\xcb\xcf\xf2\x18y+4\x00/L\xcc\xf9\xf6\\\x02\xe5\x87\xc1\xee\xd8\xd8\xcb\xb8`|z\x0c\x05\xa5Hx'

RSACipher('RSA/ECB/PKCS1Padding').encrypt('TPCyberSec', PrivateKey=PrivateKey)
# OUTPUT: '@|Y"\x8eaF{\x0c\x9ehY%\xa9X\x10d{\x01\xae\xc8\x1d;I\xfc>\x19\xb1\x16\x88V\x06\'S\x01\xc3\x18S/\\\xa0\x0f\xbd\xaf\xfe\xf7\x1a\xaa\x927J2\xb2\xc7L\x1f\xc2\xf2@\xb1\xa0\x11?\xf6#\xfb\x17\xb1@~\x07{\x85\xc9\xee\xe2b\xf7}\xb7Ub\x07/S#\x8f\'\x01qI$\x91\x97\x9bp\x8a\xa1\xaf\xfc\xc5\xe7\xb3\xd8\xec\x1b\xed*\x9b\xe5\xb8\x07\x14gf\xef\x1a\xe0\x9b\x9ft\x81\x19\xff\xc4&\xb7\xa3A\xd27\xbd\x95>>\xfe\xda\x80u\xb8\xb0\xb9\x84\xfe\xd0\xc2\x06N\x8e\x0c\xb0k\x13\x91\xb9\x8c\xcb\xde{\x0b\xbd\x85A\xado\xd8\xd4\x18i+\x05I\x07\xa0\xa6\x04]\x14>\x15I\xf24h\xd2kB\xcd\xbck\xf8\xf8lZ\xed\xc3=\x95\xb4\x8a\x96\xf9\xb5\xad>&\xff\xc2\x88\xf6\x156\x96\x80~\xf6\x1e\x9a\x13\x9f\x1c\x0fn\xdc.\xa2rJ\x88\xb5\xf31(\x82\xa2\xbc\x14\xa5\xed\x13\x03\xe8\xd9\xda\xc0\x15\x1e\x90\xe4~\xd6\xee\xfb\xc2\x1a\x8c'

RSACipher('RSA/ECB/NoPadding').encrypt('TPCyberSec', PublicKey=PublicKey)
RSACipher('RSA/ECB/OAEPPadding').encrypt('TPCyberSec', PublicKey=PublicKey, OAEPHashAlg="SHA-256", MGFHashAlg="SHA-256")
```

#### `RSACipher(algorithm :str, provider :str=None).decrypt(CipherText :str, PrivateKey :str=None, PublicKey :str=None)` -> str
```
PublicKey = '-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuTwspB6ubxVDBIb7IL7sSinHDmZLk/7RYzOWzVmLZo7dzBKiOmAbvFMMGRXFZ/37eThQ7VP31qe6MCH7PhtuP+KKOFpfgQc3O9umo78Qut4NGuCYNiuRrRx2jv1KESS+zIxllelx/JmEbtrME3boMZJ7W/y/SL8dfhYuGZYuqrGOe2ZRwekWkxAUJlAlHT/keDU8qU3oGDgVIn6Ck5MW0o8yBoMsm7o1LfvAGdt5jdxATXy1pzIi3Tr/bLVVkOPmaYrmRQ1McQLSekGA0+hn/MSMTIKRBA4JtSLaQ7YPZQPqwlvYm56958Lr8FPcQ7dz3KXWRY5wG+KSf+3vWnRZ3QIDAQAB-----END PUBLIC KEY-----'
PrivateKey = '-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5PCykHq5vFUMEhvsgvuxKKccOZkuT/tFjM5bNWYtmjt3MEqI6YBu8UwwZFcVn/ft5OFDtU/fWp7owIfs+G24/4oo4Wl+BBzc726ajvxC63g0a4Jg2K5GtHHaO/UoRJL7MjGWV6XH8mYRu2swTdugxkntb/L9Ivx1+Fi4Zli6qsY57ZlHB6RaTEBQmUCUdP+R4NTypTegYOBUifoKTkxbSjzIGgyybujUt+8AZ23mN3EBNfLWnMiLdOv9stVWQ4+ZpiuZFDUxxAtJ6QYDT6Gf8xIxMgpEEDgm1ItpDtg9lA+rCW9ibnr3nwuvwU9xDt3PcpdZFjnAb4pJ/7e9adFndAgMBAAECggEAAQJP5/D22EoQXGTz10DS/rBtkimCfeLkdxrf1myHct6SXLs5QQInBIabSUOyGJfsl8NzxWcwsW2meP6mZLc3iYeNYzMy0/wbE+tlY/z1dV8iSSQyEBF6sKu4BZ1hmuhNVcXqA8AKy+p2Kzhr5is+po56t4yP6jCIU5iBVchYprtggIeLUDAKIGterKEYxJt/N8pdJ0oGhx4cNxcRBDylqdm0HJphyP19BtBOsFtdT9cN6khNpsWGl7UirvlI8eoJxfkXzSgRLn0XoZhl1gDKAD9XCWnII9nzZyINUY1ICG2fISMMGGCNs9YmaY0wzMkhNvty8fPoWH+XrvNyomxIQQKBgQDiMQqPsRYZEw51CsGyyJFALHUfCxsLv6lXeFgCzBY74rksF4CrrNR1rcrvbMe06P54el+dtGevnpb+C1x/iFUkncGW6hNZii/dpKlxUvFTnYYWAITOiOJltDliFlXt7jCZEkGO9WcYRmTibve3pgjxB79MxEo4bJQCRSHTd6ZaLQKBgQDRpWUxaA5IdwuX7/pxG9ekFvxkJCpjDj14rkA832SLs1Zoq/d4D6/0WTp+c6wHL7fzU1DFbgCwB560ktlAvI77J6tapl1hps6RYh9H3bz+Hb6d6eFlhdyUKuTX1XXw6RcK3pYtYOltavl3bwAal/7TEKjrdS59qwx2BlsbQvQ8cQKBgQCHjjRyIQLJTC5h3mxvJNxHxVz7mcA/rkFidnDoXD8G7L1ku0EVoaJCVEFGc77LoMbAlTYwYSmyiiybW1u34pCEPTcDpoyqILLG9iPGEpsmLUVqci0lScvEf9nT+ubMjO77DYHUlyWN2sIjIbW7jfnV2XrAGvMQFaIuKhg3j4FWkQKBgQCYfp2QBae2EFnviBD864q9AjdOxHvMl9QhD2cMoFZrw+SLuOMGgyqzK6B/0LYGeDBvH2B2a+C2KqTHprW/ACllCWL8Sl1MpeBGIkCsrt9FXO+FwFVC2s8rO9RAJzZmKbaoImbM1VyWSaTyulwx+/PRJaIpu5A4uw4SX+cvelFcEQKBgHz2GicI/2cgYlRaeeR8tDSrfVNkhkF1qQZpC3GlTLMjmzZQzLXkjxvYRjNfSJaTZ9CMlaD1PFnqu7Uk9KhUwkClGnSsvFBO2MrRh6P32XS5eDVoP7jZ1pk5/dvuB1RSJqLT63FRaBi8XPSPeT/9po9lCfipK2tlNnggFMPZf3qQ-----END PRIVATE KEY-----'

RSACipher('RSA/ECB/PKCS1Padding').decrypt('\xb4\xb1\xbe\xaaS\xec\xba\xaa.\x18lUt\xb3`\x0b\xc7\x8b>\xe6\x0fVE\x82\t\xa6\xd7o8\xc5\xfauUv\xb1\x8d\xfa6C!\xf3\x93Rv\x9db\t\xdf\x1a\xb1%E!|\x00\xef\x08\x0c\xc2\xb1W:\x0c\x97k\xd28\xddZ\xe8\x18h\x7f\xed\x98h?;\xb3\x0e\xd6\x83\x11\xa7\t\xf0d\x7f]\xd5\xd3&\x98\x9b\x8f+\xbc\x9b{"6\xdd\xcc\xec\xfc1\xceR\xb3\xfa\xcaW\x03\x8f\x0f\x98\xe9\xeb\xad\x1b\x16a\x1b\\\x84\xd0\xe7! 8L\xba\xb08T\xb7\x87\xbd\xb4G\xad\t\xa6\xb6J\xfd\xef6Z\xbc4+[\xe3\xb7\xef_\xe4\xc25A*\x16a\x92\x10\xe9i2B !\xae_}\x1f\x05\x80W\xefS\x85\xe6]\x1f \x962J3\x1f\xdc\x91\xa7\xd5A{\x11\xa9\xef!\xd8=\x8e\xf29\x93\xed\xa7-\x93o\xff\x1bB\xb0\xd8\'u\x13\x1e=\x98\x14\x99\xcb\xcf\xf2\x18y+4\x00/L\xcc\xf9\xf6\\\x02\xe5\x87\xc1\xee\xd8\xd8\xcb\xb8`|z\x0c\x05\xa5Hx', PrivateKey=PrivateKey)
# OUTPUT: 'TPCyberSec'

RSACipher('RSA/ECB/PKCS1Padding').decrypt('@|Y"\x8eaF{\x0c\x9ehY%\xa9X\x10d{\x01\xae\xc8\x1d;I\xfc>\x19\xb1\x16\x88V\x06\'S\x01\xc3\x18S/\\\xa0\x0f\xbd\xaf\xfe\xf7\x1a\xaa\x927J2\xb2\xc7L\x1f\xc2\xf2@\xb1\xa0\x11?\xf6#\xfb\x17\xb1@~\x07{\x85\xc9\xee\xe2b\xf7}\xb7Ub\x07/S#\x8f\'\x01qI$\x91\x97\x9bp\x8a\xa1\xaf\xfc\xc5\xe7\xb3\xd8\xec\x1b\xed*\x9b\xe5\xb8\x07\x14gf\xef\x1a\xe0\x9b\x9ft\x81\x19\xff\xc4&\xb7\xa3A\xd27\xbd\x95>>\xfe\xda\x80u\xb8\xb0\xb9\x84\xfe\xd0\xc2\x06N\x8e\x0c\xb0k\x13\x91\xb9\x8c\xcb\xde{\x0b\xbd\x85A\xado\xd8\xd4\x18i+\x05I\x07\xa0\xa6\x04]\x14>\x15I\xf24h\xd2kB\xcd\xbck\xf8\xf8lZ\xed\xc3=\x95\xb4\x8a\x96\xf9\xb5\xad>&\xff\xc2\x88\xf6\x156\x96\x80~\xf6\x1e\x9a\x13\x9f\x1c\x0fn\xdc.\xa2rJ\x88\xb5\xf31(\x82\xa2\xbc\x14\xa5\xed\x13\x03\xe8\xd9\xda\xc0\x15\x1e\x90\xe4~\xd6\xee\xfb\xc2\x1a\x8c', PublicKey=PublicKey)
# OUTPUT: 'TPCyberSec'
```

#### `RSACipher(algorithm :str, provider :str=None).signature(message :str, PrivateKey :str)` -> str
```
RSACipher('SHA256withRSA').signature('TPCyberSec', '-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5PCykHq5vFUMEhvsgvuxKKccOZkuT/tFjM5bNWYtmjt3MEqI6YBu8UwwZFcVn/ft5OFDtU/fWp7owIfs+G24/4oo4Wl+BBzc726ajvxC63g0a4Jg2K5GtHHaO/UoRJL7MjGWV6XH8mYRu2swTdugxkntb/L9Ivx1+Fi4Zli6qsY57ZlHB6RaTEBQmUCUdP+R4NTypTegYOBUifoKTkxbSjzIGgyybujUt+8AZ23mN3EBNfLWnMiLdOv9stVWQ4+ZpiuZFDUxxAtJ6QYDT6Gf8xIxMgpEEDgm1ItpDtg9lA+rCW9ibnr3nwuvwU9xDt3PcpdZFjnAb4pJ/7e9adFndAgMBAAECggEAAQJP5/D22EoQXGTz10DS/rBtkimCfeLkdxrf1myHct6SXLs5QQInBIabSUOyGJfsl8NzxWcwsW2meP6mZLc3iYeNYzMy0/wbE+tlY/z1dV8iSSQyEBF6sKu4BZ1hmuhNVcXqA8AKy+p2Kzhr5is+po56t4yP6jCIU5iBVchYprtggIeLUDAKIGterKEYxJt/N8pdJ0oGhx4cNxcRBDylqdm0HJphyP19BtBOsFtdT9cN6khNpsWGl7UirvlI8eoJxfkXzSgRLn0XoZhl1gDKAD9XCWnII9nzZyINUY1ICG2fISMMGGCNs9YmaY0wzMkhNvty8fPoWH+XrvNyomxIQQKBgQDiMQqPsRYZEw51CsGyyJFALHUfCxsLv6lXeFgCzBY74rksF4CrrNR1rcrvbMe06P54el+dtGevnpb+C1x/iFUkncGW6hNZii/dpKlxUvFTnYYWAITOiOJltDliFlXt7jCZEkGO9WcYRmTibve3pgjxB79MxEo4bJQCRSHTd6ZaLQKBgQDRpWUxaA5IdwuX7/pxG9ekFvxkJCpjDj14rkA832SLs1Zoq/d4D6/0WTp+c6wHL7fzU1DFbgCwB560ktlAvI77J6tapl1hps6RYh9H3bz+Hb6d6eFlhdyUKuTX1XXw6RcK3pYtYOltavl3bwAal/7TEKjrdS59qwx2BlsbQvQ8cQKBgQCHjjRyIQLJTC5h3mxvJNxHxVz7mcA/rkFidnDoXD8G7L1ku0EVoaJCVEFGc77LoMbAlTYwYSmyiiybW1u34pCEPTcDpoyqILLG9iPGEpsmLUVqci0lScvEf9nT+ubMjO77DYHUlyWN2sIjIbW7jfnV2XrAGvMQFaIuKhg3j4FWkQKBgQCYfp2QBae2EFnviBD864q9AjdOxHvMl9QhD2cMoFZrw+SLuOMGgyqzK6B/0LYGeDBvH2B2a+C2KqTHprW/ACllCWL8Sl1MpeBGIkCsrt9FXO+FwFVC2s8rO9RAJzZmKbaoImbM1VyWSaTyulwx+/PRJaIpu5A4uw4SX+cvelFcEQKBgHz2GicI/2cgYlRaeeR8tDSrfVNkhkF1qQZpC3GlTLMjmzZQzLXkjxvYRjNfSJaTZ9CMlaD1PFnqu7Uk9KhUwkClGnSsvFBO2MrRh6P32XS5eDVoP7jZ1pk5/dvuB1RSJqLT63FRaBi8XPSPeT/9po9lCfipK2tlNnggFMPZf3qQ-----END PRIVATE KEY-----')
# OUTPUT: '\xae\x9bYl\xcc\xf1is\xc7\xff8\xf4\x9d\x97C%\xd1\xd5\x8b8p\x98V\xc1\xd3Z\xdb\xec\x05`\xdb\xa3\x15>W\t\xd1&<\xffc\x0b)7\x8e\xc3\xaf\x92\xe3\x83JV\x80J\x14\n\x03\xa5Y\xd0\xf6\xeefx\x1dG\x14\xe8q{\x1b\xe8\x15\xdc!S\x96\xf4\x1bdC)|o\x12\xe2\x9fW\xfc\x03\xd2\xf7)\x10\x02\xe7\x96@\n0\xc7\x06\xb9\x98l\x1d\xfe\xdaD\xf4?p\x13\xc8H\xffV\xbe\x0b\x07\x85\x92\x089\xab\xf4\xa5} {\xf2\xd7+~\x95\xb9\x14^\xba\xe5K0\xf1\x7f\x94c\xdd%\xe0L\x9f\xa2[)\x9c\xe1NE\xd7G\x9e\xb5\x96\xf5a\x92s,8W\x80.Zm\xf3\x04\x89\xfc\x0e\xe3\x81\xa2\xf3\x01\xd95\x1d\xfa\xba\xd4\xc3\x05f\xbet\xc6\xb8\xb2\xe3\x04\xbb\x11\n\xb4\xce\xbe\xf1\xb8\xff\xf2\x9a\x06;\xba\x99o\x13\x96\x98\x1d\xb5\xb0!\xce\x18S\x16\x94r\xd2\xa1\x82\xd8\xeaS\xe3R\xfe-\x89z\xd9\xcfVfh\xcaa\x7f`\xaa\x14o(g!'
```

#### `RSACipher(algorithm :str, provider :str=None).verify(message :str, signedData :str, PublicKey :str)` -> boolean
```
RSACipher('SHA256withRSA').verify('TPCyberSec', '\xae\x9bYl\xcc\xf1is\xc7\xff8\xf4\x9d\x97C%\xd1\xd5\x8b8p\x98V\xc1\xd3Z\xdb\xec\x05`\xdb\xa3\x15>W\t\xd1&<\xffc\x0b)7\x8e\xc3\xaf\x92\xe3\x83JV\x80J\x14\n\x03\xa5Y\xd0\xf6\xeefx\x1dG\x14\xe8q{\x1b\xe8\x15\xdc!S\x96\xf4\x1bdC)|o\x12\xe2\x9fW\xfc\x03\xd2\xf7)\x10\x02\xe7\x96@\n0\xc7\x06\xb9\x98l\x1d\xfe\xdaD\xf4?p\x13\xc8H\xffV\xbe\x0b\x07\x85\x92\x089\xab\xf4\xa5} {\xf2\xd7+~\x95\xb9\x14^\xba\xe5K0\xf1\x7f\x94c\xdd%\xe0L\x9f\xa2[)\x9c\xe1NE\xd7G\x9e\xb5\x96\xf5a\x92s,8W\x80.Zm\xf3\x04\x89\xfc\x0e\xe3\x81\xa2\xf3\x01\xd95\x1d\xfa\xba\xd4\xc3\x05f\xbet\xc6\xb8\xb2\xe3\x04\xbb\x11\n\xb4\xce\xbe\xf1\xb8\xff\xf2\x9a\x06;\xba\x99o\x13\x96\x98\x1d\xb5\xb0!\xce\x18S\x16\x94r\xd2\xa1\x82\xd8\xeaS\xe3R\xfe-\x89z\xd9\xcfVfh\xcaa\x7f`\xaa\x14o(g!', '-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuTwspB6ubxVDBIb7IL7sSinHDmZLk/7RYzOWzVmLZo7dzBKiOmAbvFMMGRXFZ/37eThQ7VP31qe6MCH7PhtuP+KKOFpfgQc3O9umo78Qut4NGuCYNiuRrRx2jv1KESS+zIxllelx/JmEbtrME3boMZJ7W/y/SL8dfhYuGZYuqrGOe2ZRwekWkxAUJlAlHT/keDU8qU3oGDgVIn6Ck5MW0o8yBoMsm7o1LfvAGdt5jdxATXy1pzIi3Tr/bLVVkOPmaYrmRQ1McQLSekGA0+hn/MSMTIKRBA4JtSLaQ7YPZQPqwlvYm56958Lr8FPcQ7dz3KXWRY5wG+KSf+3vWnRZ3QIDAQAB-----END PUBLIC KEY-----')
# OUTPUT: True
```

### Crypto.Hash modules
#### `CRC32().checksum(message :str)` -> str
```
CRC32().checksum('TPCyberSec')
# OUTPUT: '88d65e56'
```

#### `HMAC_MD5().digest(message :str, SECRET_KEY :str)` -> str
```
HMAC_MD5().digest('TPCyberSec', 'TPCS')
# OUTPUT: '\xe8e\xe8\xfc\xb2\xd5\xfd\xee!\xdd\xfc\x05D\x04\t\x0e'
```

#### `HMAC_MD5().hexdigest(message :str, SECRET_KEY :str)` -> str
```
HMAC_MD5().hexdigest('TPCyberSec', 'TPCS')
# OUTPUT: 'e865e8fcb2d5fdee21ddfc054404090e'
```

#### `HMAC_SHA1().digest(message :str, SECRET_KEY :str)` -> str
```
HMAC_SHA1().digest('TPCyberSec', 'TPCS')
# OUTPUT: ' :rd\xed\xac|^\xe8\xf8h\xd8\xd0\x8e\x11\x1a%\x81\x85\xf6'
```

#### `HMAC_SHA1().hexdigest(message :str, SECRET_KEY :str)` -> str
```
HMAC_SHA1().hexdigest('TPCyberSec', 'TPCS')
# OUTPUT: '203a7264edac7c5ee8f868d8d08e111a258185f6'
```

#### `HMAC_SHA224().digest(message :str, SECRET_KEY :str)` -> str
```
HMAC_SHA224().digest('TPCyberSec', 'TPCS')
# OUTPUT: 't\xf3j\xc1\xbf\x8a%\xa6r\xabB\xa0ci5N\x99\xf7\xf2\xc5\x92T:%\x8b8\xb0\xf2'
```

#### `HMAC_SHA224().hexdigest(message :str, SECRET_KEY :str)` -> str
```
HMAC_SHA224().hexdigest('TPCyberSec', 'TPCS')
# OUTPUT: '74f36ac1bf8a25a672ab42a06369354e99f7f2c592543a258b38b0f2'
```

#### `HMAC_SHA256().digest(message :str, SECRET_KEY :str)` -> str
```
HMAC_SHA256().digest('TPCyberSec', 'TPCS')
# OUTPUT: ">-\x914{y\xb7\x1fKS{\xdc\x15R\xb1'I\x08\x92*\x89\x1a$}\x85-u4=\x1bN\xea"
```

#### `HMAC_SHA256().hexdigest(message :str, SECRET_KEY :str)` -> str
```
HMAC_SHA256().hexdigest('TPCyberSec', 'TPCS')
# OUTPUT: '3e2d91347b79b71f4b537bdc1552b1274908922a891a247d852d75343d1b4eea'
```

#### `HMAC_SHA384().digest(message :str, SECRET_KEY :str)` -> str
```
HMAC_SHA384().digest('TPCyberSec', 'TPCS')
# OUTPUT: '\xaa\x98\xf0\xc4#D\xc1\xc3\xc9\x96\x11\xde\xa8\x92\xa7\x88;m\x92\x9f\xc6\x86\x1e\xae\x8bl\xf4\x08\x13\xf8u)\xc9kq\xa2O\x97\xa3C\x84O\xbc\x17\xf5\xe7\x19\xe1'
```

#### `HMAC_SHA384().hexdigest(message :str, SECRET_KEY :str)` -> str
```
HMAC_SHA384().hexdigest('TPCyberSec', 'TPCS')
# OUTPUT: 'aa98f0c42344c1c3c99611dea892a7883b6d929fc6861eae8b6cf40813f87529c96b71a24f97a343844fbc17f5e719e1'
```

#### `HMAC_SHA512().digest(message :str, SECRET_KEY :str)` -> str
```
HMAC_SHA512().digest('TPCyberSec', 'TPCS')
# OUTPUT: 'C\t\x16\xe09r\n\x0bH2{?q\xe2\xd4\xeb[\xf8\x8d\x1e\xc7\xfe_\xab2\x98\x99\xf8\x00\xe9<Bd]x\x87\x1c\x9fS\ti3\x11\xba\xcc\xc3\xa8\x0e\xdaNOR\x1e\xd39\n\xf9sG0\xeb,Yy'
```

#### `HMAC_SHA512().hexdigest(message :str, SECRET_KEY :str)` -> str
```
HMAC_SHA512().hexdigest('TPCyberSec', 'TPCS')
# OUTPUT: '430916e039720a0b48327b3f71e2d4eb5bf88d1ec7fe5fab329899f800e93c42645d78871c9f5309693311baccc3a80eda4e4f521ed3390af9734730eb2c5979'
```

#### `MD2().digest(message :str)` -> str
```
MD2().digest('TPCyberSec')
# OUTPUT: '\xbd\xeb.\x07l\x0c\x85\xd1I\x8d~t\xeej\xdb\xa4'
```

#### `MD2().hexdigest(message :str)` -> str
```
MD2().hexdigest('TPCyberSec')
# OUTPUT: 'bdeb2e076c0c85d1498d7e74ee6adba4'
```

#### `MD5().digest(message :str)` -> str
```
MD5().digest('TPCyberSec')
# OUTPUT: 'm\xaeKjs\xc427\xf0\x05h\x7f\x84\xb1\x02\xda'
```

#### `MD5().hexdigest(message :str)` -> str
```
MD5().hexdigest('TPCyberSec')
# OUTPUT: '6dae4b6a73c43237f005687f84b102da'
```

#### `SHA1().digest(message :str)` -> str
```
SHA1().digest('TPCyberSec')
# OUTPUT: '\x9f\xa1\xa6\xed<\xdc\xff\xff\xefA3tFb\xd8m\xc8\x8c\x92\xac'
```

#### `SHA1().hexdigest(message :str)` -> str
```
SHA1().hexdigest('TPCyberSec')
# OUTPUT: '9fa1a6ed3cdcffffef4133744662d86dc88c92ac'
```

#### `SHA224().digest(message :str)` -> str
```
SHA224().digest('TPCyberSec')
# OUTPUT: '.\xc1\xb9\xb4A[/\x90\xd7\xec_\xb35f\x7f\xec\xba9\xa4O\x18?\xfb\xaa*\xf9\x93\xa1'
```

#### `SHA224().hexdigest(message :str)` -> str
```
SHA224().hexdigest('TPCyberSec')
# OUTPUT: '2ec1b9b4415b2f90d7ec5fb335667fecba39a44f183ffbaa2af993a1'
```

#### `SHA256().digest(message :str)` -> str
```
SHA256().digest('TPCyberSec')
# OUTPUT: 'L\n\x99\xe8khH\xa5\x05*\xdcT\xd90\x81\x18U\xf8\x8e\xe5\xd7|F\x8b/U\xc18\x88 \xe6\xeb'
```

#### `SHA256().hexdigest(message :str)` -> str
```
SHA256().hexdigest('TPCyberSec')
# OUTPUT: '4c0a99e86b6848a5052adc54d930811855f88ee5d77c468b2f55c1388820e6eb'
```

#### `SHA384().digest(message :str)` -> str
```
SHA384().digest('TPCyberSec')
# OUTPUT: '\xca\xec^\x17b\x10\xd6\x9d\xa5Gy\rZR\xd5\x9a\xadv\x94\x9fD\x89IyK\xb9Y\xce&H\xdc\xa6|I\xd0hHL\x9f\x9c"2@/\x9f\x19\xc0\x1a'
```

#### `SHA384().hexdigest(message :str)` -> str
```
SHA384().hexdigest('TPCyberSec')
# OUTPUT: 'caec5e176210d69da547790d5a52d59aad76949f448949794bb959ce2648dca67c49d068484c9f9c2232402f9f19c01a'
```

#### `SHA512().digest(message :str)` -> str
```
SHA512().digest('TPCyberSec')
# OUTPUT: '\xbeue=?I\xe7\x9cD4G\xc2\xf3}Z_M\x11k\xb3e\xb3-\x9b\xea\x1d\xc3\xd3g\xe550&\xe1\xb7\xd0B\xeb\x05\x87\x84Nl]\t `\x05*0H\xa7\r\xb1\xd5\xf7\xfa\x11\x89*,\xf42Y'
```

#### `SHA512().hexdigest(message :str)` -> str
```
SHA512().hexdigest('TPCyberSec')
# OUTPUT: 'be75653d3f49e79c443447c2f37d5a5f4d116bb365b32d9bea1dc3d367e5353026e1b7d042eb0587844e6c5d092060052a3048a70db1d5f7fa11892a2cf43259'
```

---
# Contributors
<style>
	@keyframes blinkBorder {
		0% { border-color: transparent; }
		50% { border-color: red; }
		100% { border-color: transparent; }
	}
</style>
<p align="left">
	<a href="https://github.com/toannguyen3107"><img src="https://avatars.githubusercontent.com/u/99452100" width="50" height="50" alt="toannguyen3107" style="border: 3px solid transparent; border-radius: 50%; animation: blinkBorder 1s infinite; padding: 5px;"></a>
</p>

---