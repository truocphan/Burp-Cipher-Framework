from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IHttpListener
from burp import IMessageEditorTab
from burp import IBurpExtenderCallbacks
from burp import IExtensionStateListener

from java.lang import Runnable
from javax.swing.event import MenuListener
from javax.swing import SwingUtilities
from javax.swing import JMenu
from javax.swing import JCheckBoxMenuItem
from javax.swing import UIManager
from java.awt import Frame

import os
ROOTDIR = os.getcwd()
CONF_PATH = os.path.join(os.path.expanduser("~"), ".bcf", "BCFconf.json")
os.system("pip install -r {} --target={}".format(os.path.join(ROOTDIR, "requirements.txt"), os.path.join(ROOTDIR, "bcf-site-packages")))
import site
site.addsitedir(os.path.join(ROOTDIR, "bcf-site-packages"))
import re
from datetime import datetime
import json_duplicate_keys as jdks
from TP_HTTP_Request_Response_Parser import *

from modules.SpecialCharacters import *
from modules.Utilities import Utilities
from modules.Crypto.Symmetric.AESCipher import AESCipher
from modules.Crypto.Symmetric.DESCipher import DESCipher
from modules.Crypto.Asymmetric.RSACipher import RSACipher
from modules.Crypto.Hash.CRC32 import CRC32
from modules.Crypto.Hash.HMAC_MD5 import HMAC_MD5
from modules.Crypto.Hash.HMAC_SHA1 import HMAC_SHA1
from modules.Crypto.Hash.HMAC_SHA224 import HMAC_SHA224
from modules.Crypto.Hash.HMAC_SHA256 import HMAC_SHA256
from modules.Crypto.Hash.HMAC_SHA384 import HMAC_SHA384
from modules.Crypto.Hash.HMAC_SHA512 import HMAC_SHA512
from modules.Crypto.Hash.MD2 import MD2
from modules.Crypto.Hash.MD5 import MD5
from modules.Crypto.Hash.SHA1 import SHA1
from modules.Crypto.Hash.SHA224 import SHA224
from modules.Crypto.Hash.SHA256 import SHA256
from modules.Crypto.Hash.SHA384 import SHA384
from modules.Crypto.Hash.SHA512 import SHA512

import java.security.KeyPairGenerator as KeyPairGenerator

def generateRSAKey():
	import base64
	keyPairGenerator = KeyPairGenerator.getInstance("RSA")
	keyPairGenerator.initialize(2048)
	keyPair = keyPairGenerator.generateKeyPair()
	publicKey = keyPair.getPublic()
	privateKey = keyPair.getPrivate()
	return base64.b64encode(publicKey.getEncoded()), base64.b64encode(privateKey.getEncoded())

PROD = True
TARGET = "tpcybersec.com"
EXTENSION_NAME = "Burp Cipher Framework"
EXTENSION_VERSION = "2024.11.28"
serverPublicKey = []
serverPrivateKey = []
serverSecretKey = []
serverIV = []
serverSalt = []
serverPassword = []

if PROD:
	publicKey, privateKey = generateRSAKey()
	myPublicKey = [ "-----BEGIN PUBLIC KEY-----"+publicKey+"-----END PUBLIC KEY-----" ]
	myPrivateKey = [ "-----BEGIN PRIVATE KEY-----"+privateKey+"-----END PRIVATE KEY-----" ]
	mySecretKey = [ Utilities.RandomString(32) ]
	myIV = [ Utilities.RandomString(16) ]
	mySalt = [ Utilities.RandomString(16) ]
	myPassword = [ Utilities.RandomString(16) ]
else:
	myPublicKey = [ "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuTwspB6ubxVDBIb7IL7sSinHDmZLk/7RYzOWzVmLZo7dzBKiOmAbvFMMGRXFZ/37eThQ7VP31qe6MCH7PhtuP+KKOFpfgQc3O9umo78Qut4NGuCYNiuRrRx2jv1KESS+zIxllelx/JmEbtrME3boMZJ7W/y/SL8dfhYuGZYuqrGOe2ZRwekWkxAUJlAlHT/keDU8qU3oGDgVIn6Ck5MW0o8yBoMsm7o1LfvAGdt5jdxATXy1pzIi3Tr/bLVVkOPmaYrmRQ1McQLSekGA0+hn/MSMTIKRBA4JtSLaQ7YPZQPqwlvYm56958Lr8FPcQ7dz3KXWRY5wG+KSf+3vWnRZ3QIDAQAB-----END PUBLIC KEY-----" ]
	myPrivateKey = [ "-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5PCykHq5vFUMEhvsgvuxKKccOZkuT/tFjM5bNWYtmjt3MEqI6YBu8UwwZFcVn/ft5OFDtU/fWp7owIfs+G24/4oo4Wl+BBzc726ajvxC63g0a4Jg2K5GtHHaO/UoRJL7MjGWV6XH8mYRu2swTdugxkntb/L9Ivx1+Fi4Zli6qsY57ZlHB6RaTEBQmUCUdP+R4NTypTegYOBUifoKTkxbSjzIGgyybujUt+8AZ23mN3EBNfLWnMiLdOv9stVWQ4+ZpiuZFDUxxAtJ6QYDT6Gf8xIxMgpEEDgm1ItpDtg9lA+rCW9ibnr3nwuvwU9xDt3PcpdZFjnAb4pJ/7e9adFndAgMBAAECggEAAQJP5/D22EoQXGTz10DS/rBtkimCfeLkdxrf1myHct6SXLs5QQInBIabSUOyGJfsl8NzxWcwsW2meP6mZLc3iYeNYzMy0/wbE+tlY/z1dV8iSSQyEBF6sKu4BZ1hmuhNVcXqA8AKy+p2Kzhr5is+po56t4yP6jCIU5iBVchYprtggIeLUDAKIGterKEYxJt/N8pdJ0oGhx4cNxcRBDylqdm0HJphyP19BtBOsFtdT9cN6khNpsWGl7UirvlI8eoJxfkXzSgRLn0XoZhl1gDKAD9XCWnII9nzZyINUY1ICG2fISMMGGCNs9YmaY0wzMkhNvty8fPoWH+XrvNyomxIQQKBgQDiMQqPsRYZEw51CsGyyJFALHUfCxsLv6lXeFgCzBY74rksF4CrrNR1rcrvbMe06P54el+dtGevnpb+C1x/iFUkncGW6hNZii/dpKlxUvFTnYYWAITOiOJltDliFlXt7jCZEkGO9WcYRmTibve3pgjxB79MxEo4bJQCRSHTd6ZaLQKBgQDRpWUxaA5IdwuX7/pxG9ekFvxkJCpjDj14rkA832SLs1Zoq/d4D6/0WTp+c6wHL7fzU1DFbgCwB560ktlAvI77J6tapl1hps6RYh9H3bz+Hb6d6eFlhdyUKuTX1XXw6RcK3pYtYOltavl3bwAal/7TEKjrdS59qwx2BlsbQvQ8cQKBgQCHjjRyIQLJTC5h3mxvJNxHxVz7mcA/rkFidnDoXD8G7L1ku0EVoaJCVEFGc77LoMbAlTYwYSmyiiybW1u34pCEPTcDpoyqILLG9iPGEpsmLUVqci0lScvEf9nT+ubMjO77DYHUlyWN2sIjIbW7jfnV2XrAGvMQFaIuKhg3j4FWkQKBgQCYfp2QBae2EFnviBD864q9AjdOxHvMl9QhD2cMoFZrw+SLuOMGgyqzK6B/0LYGeDBvH2B2a+C2KqTHprW/ACllCWL8Sl1MpeBGIkCsrt9FXO+FwFVC2s8rO9RAJzZmKbaoImbM1VyWSaTyulwx+/PRJaIpu5A4uw4SX+cvelFcEQKBgHz2GicI/2cgYlRaeeR8tDSrfVNkhkF1qQZpC3GlTLMjmzZQzLXkjxvYRjNfSJaTZ9CMlaD1PFnqu7Uk9KhUwkClGnSsvFBO2MrRh6P32XS5eDVoP7jZ1pk5/dvuB1RSJqLT63FRaBi8XPSPeT/9po9lCfipK2tlNnggFMPZf3qQ-----END PRIVATE KEY-----" ]
	mySecretKey = [ "C]$L)D}Sd<s!eRkW.hZT`MK9jQGN[4z~" ]
	myIV = [ "X.4njY@(,RN&~f*W" ]
	mySalt = [ "z#}k%>v'53^P<4Ky" ]
	myPassword = [ "We4K=T!q@F#98zPw" ]





if not os.path.isfile(CONF_PATH):
	if not os.path.isdir(os.path.join(os.path.expanduser("~"), ".bcf")): os.mkdir(os.path.join(os.path.expanduser("~"), ".bcf"))

	f = open(CONF_PATH, "w")

	JDKSObject_BCFconf = jdks.loads(Utilities.base64Decode("eyJjb25maWciOnsiZXh0ZW5zaW9uX25hbWUiOiJCdXJwIENpcGhlciBGcmFtZXdvcmsiLCJleHRlbnNpb25fdmVyc2lvbiI6IjIwMjQuMTEuMjgiLCJzZXJ2ZXJQdWJsaWNLZXkiOltdLCJzZXJ2ZXJQcml2YXRlS2V5IjpbXSwic2VydmVyU2VjcmV0S2V5IjpbXSwic2VydmVySVYiOltdLCJzZXJ2ZXJTYWx0IjpbXSwic2VydmVyUGFzc3dvcmQiOltdLCJteVB1YmxpY0tleSI6W10sIm15UHJpdmF0ZUtleSI6W10sIm15U2VjcmV0S2V5IjpbXSwibXlJViI6W10sIm15U2FsdCI6W10sIm15UGFzc3dvcmQiOltdfSwiUHJvY2Vzc01lc3NhZ2UiOnsiUmVxdWVzdCI6W3siQ09NTUVOVCI6IiIsIlRBUkdFVCI6InRwY3liZXJzZWMuY29tIiwiUEFUVEVSTiI6W10sIkRBVEEiOlt7Ik9VVFBVVCI6W3siQ09NTUVOVCI6IkdldCBSZXF1ZXN0IFBhdGgiLCJleGVjX2Z1bmMiOmZhbHNlLCJjb2RlIjoiUmVxdWVzdFBhcnNlci5yZXF1ZXN0X3BhdGgifV19XX1dLCJSZXNwb25zZSI6W3siQ09NTUVOVCI6IiIsIlRBUkdFVCI6InRwY3liZXJzZWMuY29tIiwiUEFUVEVSTiI6W10sIkRBVEEiOlt7Ik9VVFBVVCI6W3siQ09NTUVOVCI6IkdldCBTdGF0dXMgQ29kZSIsImV4ZWNfZnVuYyI6ZmFsc2UsImNvZGUiOiJSZXNwb25zZVBhcnNlci5yZXNwb25zZV9zdGF0dXNDb2RlIn1dfV19XX0sIkNpcGhlclRhYiI6eyJEZWNyeXB0UmVxdWVzdCI6W3siQ09NTUVOVCI6IiIsIlRBUkdFVCI6InRwY3liZXJzZWMuY29tIiwiUEFUVEVSTiI6W10sIkRBVEEiOlt7Ik9VVFBVVCI6W3siQ09NTUVOVCI6IkdldCBSZXF1ZXN0IE1ldGhvZCIsImV4ZWNfZnVuYyI6ZmFsc2UsImNvZGUiOiJSZXF1ZXN0UGFyc2VyLnJlcXVlc3RfbWV0aG9kIn1dfV19XSwiRW5jcnlwdFJlcXVlc3QiOlt7IkNPTU1FTlQiOiIiLCJUQVJHRVQiOiJ0cGN5YmVyc2VjLmNvbSIsIlBBVFRFUk4iOltdLCJEQVRBIjpbeyJPVVRQVVQiOlt7IkNPTU1FTlQiOiJVcGRhdGUgUmVxdWVzdCBIZWFkZXIgJ1JlZmVyZXInIiwiZXhlY19mdW5jIjpmYWxzZSwiY29kZSI6IlJlcXVlc3RQYXJzZXIucmVxdWVzdF9oZWFkZXJzLnVwZGF0ZSgnUmVmZXJlcicsICdodHRwczovL3RwY3liZXJzZWMuYmNmLycpIn1dfV19XSwiRGVjcnlwdFJlc3BvbnNlIjpbeyJDT01NRU5UIjoiIiwiVEFSR0VUIjoidHBjeWJlcnNlYy5jb20iLCJQQVRURVJOIjpbXSwiREFUQSI6W3siT1VUUFVUIjpbeyJDT01NRU5UIjoiR2V0IFJlc3BvbnNlIEJvZHkgT2JqZWN0IiwiZXhlY19mdW5jIjpmYWxzZSwiY29kZSI6IlJlc3BvbnNlUGFyc2VyLnJlc3BvbnNlX2JvZHkifV19XX1dLCJFbmNyeXB0UmVzcG9uc2UiOlt7IkNPTU1FTlQiOiIiLCJUQVJHRVQiOiJ0cGN5YmVyc2VjLmNvbSIsIlBBVFRFUk4iOltdLCJEQVRBIjpbeyJPVVRQVVQiOlt7IkNPTU1FTlQiOiJVcGRhdGUgUmVxdWVzdCBoZWFkZXIgJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbiciLCJleGVjX2Z1bmMiOmZhbHNlLCJjb2RlIjoiUmVzcG9uc2VQYXJzZXIucmVzcG9uc2VfaGVhZGVycy51cGRhdGUoJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbicsICcqJykifV19XX1dfX0=").decode(), ordered_dict=True, _isDebug_=True)
	JDKSObject_BCFconf.update("config||extension_name", EXTENSION_NAME)
	JDKSObject_BCFconf.update("config||extension_version", EXTENSION_VERSION)
	JDKSObject_BCFconf.update("config||myPublicKey", [re.findall("-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----", myPublicKey[0])[0]])
	JDKSObject_BCFconf.update("config||myPrivateKey", [re.findall("-----BEGIN PRIVATE KEY-----(.+?)-----END PRIVATE KEY-----", myPrivateKey[0])[0]])
	JDKSObject_BCFconf.update("config||mySecretKey", mySecretKey)
	JDKSObject_BCFconf.update("config||myIV", myIV)
	JDKSObject_BCFconf.update("config||mySalt", mySalt)
	JDKSObject_BCFconf.update("config||myPassword", myPassword)
	JDKSObject_BCFconf.update("ProcessMessage||Request||$0$||TARGET", TARGET)
	JDKSObject_BCFconf.update("ProcessMessage||Response||$0$||TARGET", TARGET)
	JDKSObject_BCFconf.update("CipherTab||DecryptRequest||$0$||TARGET", TARGET)
	JDKSObject_BCFconf.update("CipherTab||EncryptRequest||$0$||TARGET", TARGET)
	JDKSObject_BCFconf.update("CipherTab||DecryptResponse||$0$||TARGET", TARGET)
	JDKSObject_BCFconf.update("CipherTab||EncryptResponse||$0$||TARGET", TARGET)

	f.write(JDKSObject_BCFconf.dumps(indent=4))
	f.close()


print(Utilities.base64Decode("CiAgIF9fXyAgICAgICAgICAgICAgICAgICAgICAgICBfX18gIF8gICAgICAgICBfICAgICAgICAgICAgICAgICAgICAgX19fICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIF8KICAvIF9fXCBfICAgXyAgXyBfXyAgXyBfXyAgICAgLyBfX1woXykgXyBfXyAgfCB8X18gICAgX19fICBfIF9fICAgIC8gX19cIF8gX18gICBfXyBfICBfIF9fIF9fXyAgICBfX18gX18gICAgICBfXyAgX19fICAgXyBfXyB8IHwgX18KIC9fX1wvL3wgfCB8IHx8ICdfX3x8ICdfIFwgICAvIC8gICB8IHx8ICdfIFwgfCAnXyBcICAvIF8gXHwgJ19ffCAgLyBfXCAgfCAnX198IC8gX2AgfHwgJ18gYCBfIFwgIC8gXyBcXCBcIC9cIC8gLyAvIF8gXCB8ICdfX3x8IHwvIC8KLyBcLyAgXHwgfF98IHx8IHwgICB8IHxfKSB8IC8gL19fXyB8IHx8IHxfKSB8fCB8IHwgfHwgIF9fL3wgfCAgICAvIC8gICAgfCB8ICAgfCAoX3wgfHwgfCB8IHwgfCB8fCAgX18vIFwgViAgViAvIHwgKF8pIHx8IHwgICB8ICAgPApcX19fX18vIFxfXyxffHxffCAgIHwgLl9fLyAgXF9fX18vIHxffHwgLl9fLyB8X3wgfF98IFxfX198fF98ICAgIFwvICAgICB8X3wgICAgXF9fLF98fF98IHxffCB8X3wgXF9fX3wgIFxfL1xfLyAgIFxfX18vIHxffCAgIHxffFxfXAogICAgICAgICAgICAgICAgICAgIHxffCAgICAgICAgICAgICAgIHxffAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZ7dmVyc2lvbn0gYnkgVHJ1b2MgUGhhbiAoQHRydW9jcGhhbikKCg==").decode().format(version=EXTENSION_VERSION))



ConfigInfo = jdks.load(CONF_PATH, _isDebug_=True).get("config")["value"]
if type(ConfigInfo["extension_name"]) in [unicode, str] and len(ConfigInfo["extension_name"]) > 0: EXTENSION_NAME = ConfigInfo["extension_name"]
if type(ConfigInfo["extension_version"]) in [unicode, str] and len(ConfigInfo["extension_version"]) > 0: EXTENSION_VERSION = ConfigInfo["extension_version"]
if type(ConfigInfo["serverPublicKey"]) == list and len(ConfigInfo["serverPublicKey"]) > 0: serverPublicKey = ConfigInfo["serverPublicKey"]
if type(ConfigInfo["serverPrivateKey"]) == list and len(ConfigInfo["serverPrivateKey"]) > 0: serverPrivateKey = ConfigInfo["serverPrivateKey"]
if type(ConfigInfo["serverSecretKey"]) == list and len(ConfigInfo["serverSecretKey"]) > 0: serverSecretKey = ConfigInfo["serverSecretKey"]
if type(ConfigInfo["serverIV"]) == list and len(ConfigInfo["serverIV"]) > 0: serverIV = ConfigInfo["serverIV"]
if type(ConfigInfo["serverSalt"]) == list and len(ConfigInfo["serverSalt"]) > 0: serverSalt = ConfigInfo["serverSalt"]
if type(ConfigInfo["serverPassword"]) == list and len(ConfigInfo["serverPassword"]) > 0: serverPassword = ConfigInfo["serverPassword"]
if type(ConfigInfo["myPublicKey"]) == list and len(ConfigInfo["myPublicKey"]) > 0: myPublicKey = ConfigInfo["myPublicKey"]
if type(ConfigInfo["myPrivateKey"]) == list and len(ConfigInfo["myPrivateKey"]) > 0: myPrivateKey = ConfigInfo["myPrivateKey"]
if type(ConfigInfo["mySecretKey"]) == list and len(ConfigInfo["mySecretKey"])> 0: mySecretKey = ConfigInfo["mySecretKey"]
if type(ConfigInfo["myIV"]) == list and len(ConfigInfo["myIV"]) > 0: myIV = ConfigInfo["myIV"]
if type(ConfigInfo["mySalt"]) == list and len(ConfigInfo["mySalt"]) > 0: mySalt = ConfigInfo["mySalt"]
if type(ConfigInfo["myPassword"]) == list and len(ConfigInfo["myPassword"]) > 0: myPassword = ConfigInfo["myPassword"]



class MenuBar(Runnable, MenuListener, IExtensionStateListener):
	def __init__(self, callbacks): 
		self.callbacks = callbacks
		self.callbacks.registerExtensionStateListener(self);
		self.menu_scanner_encReq_item = None
		self.menu_scanner_decRes_item = None
		self.menu_proxy_encReq_item = None
		self.menu_proxy_decRes_item = None
		self.menu_intruder_encReq_item = None
		self.menu_intruder_decRes_item = None
		self.menu_repeater_encReq_item = None
		self.menu_repeater_decRes_item = None
		self.menu_extender_encReq_item = None
		self.menu_extender_decRes_item = None
		self.menu_all_encReq_item = None
		self.menu_all_decRes_item = None

	def run(self):
		self.menu_button = JMenu(EXTENSION_NAME+" v"+EXTENSION_VERSION)

		self.menu_encReq = JMenu("Encrypt Request")
		self.menu_decRes = JMenu("Decrypt Response")

		self.menu_scanner_encReq_item = JCheckBoxMenuItem("Scanner")
		self.menu_proxy_encReq_item = JCheckBoxMenuItem("Proxy")
		self.menu_intruder_encReq_item = JCheckBoxMenuItem("Intruder")
		self.menu_repeater_encReq_item = JCheckBoxMenuItem("Repeater")
		self.menu_extender_encReq_item = JCheckBoxMenuItem("Extender")
		self.menu_all_encReq_item = JCheckBoxMenuItem("All Tools")
		self.menu_all_encReq_item.setSelected(True)

		self.menu_scanner_decRes_item = JCheckBoxMenuItem("Scanner")
		self.menu_proxy_decRes_item = JCheckBoxMenuItem("Proxy")
		self.menu_intruder_decRes_item = JCheckBoxMenuItem("Intruder")
		self.menu_repeater_decRes_item = JCheckBoxMenuItem("Repeater")
		self.menu_extender_decRes_item = JCheckBoxMenuItem("Extender")
		self.menu_all_decRes_item = JCheckBoxMenuItem("All Tools")
		self.menu_all_decRes_item.setSelected(True)

		self.menu_encReq.add(self.menu_scanner_encReq_item)
		self.menu_encReq.add(self.menu_proxy_encReq_item)
		self.menu_encReq.add(self.menu_intruder_encReq_item)
		self.menu_encReq.add(self.menu_repeater_encReq_item)
		self.menu_encReq.add(self.menu_extender_encReq_item)
		self.menu_encReq.add(self.menu_all_encReq_item)

		self.menu_decRes.add(self.menu_scanner_decRes_item)
		self.menu_decRes.add(self.menu_proxy_decRes_item)
		self.menu_decRes.add(self.menu_intruder_decRes_item)
		self.menu_decRes.add(self.menu_repeater_decRes_item)
		self.menu_decRes.add(self.menu_extender_decRes_item)
		self.menu_decRes.add(self.menu_all_decRes_item)

		self.menu_button.add(self.menu_encReq)
		self.menu_button.add(self.menu_decRes)

		UIManager.put("CheckBoxMenuItem.doNotCloseOnMouseClick", True)

		def get_burp_jframe():
			frames = Frame.getFrames()
			for frame in frames:
				if frame.isVisible() and frame.getTitle().startswith("Burp Suite"):
					return frame
			return None

		burp_jmenu_bar = get_burp_jframe().getJMenuBar()
		burp_jmenu_bar.add(self.menu_button)
		burp_jmenu_bar.repaint()

	def menuSelected(self, e):
		pass

	def menuDeselected(self, e):
		pass

	def menuCanceled(self, e):
		pass

	def extensionUnloaded(self):
		try:
			def get_burp_jframe():
				frames = Frame.getFrames()
				for frame in frames:
					if frame.isVisible() and frame.getTitle().startswith("Burp Suite"):
						return frame
				return None

			jMenuBar = get_burp_jframe().getJMenuBar();
			jMenuBar.remove(self.menu_button);
			jMenuBar.repaint();
		except:
			pass



class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IHttpListener):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks

		self._helpers = callbacks.getHelpers()

		self.config_menu = MenuBar(self._callbacks)

		SwingUtilities.invokeLater(self.config_menu)

		callbacks.setExtensionName(EXTENSION_NAME+" v"+EXTENSION_VERSION)

		callbacks.registerMessageEditorTabFactory(self)

		callbacks.registerHttpListener(self)

	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		target = messageInfo.getHttpService().getHost() + ":" + str(messageInfo.getHttpService().getPort())
		url = str(messageInfo.getHttpService().getProtocol()) + "//" + target + self._helpers.analyzeRequest(messageInfo.getRequest()).getHeaders()[0].split(" ")[1]
		ExtenderHelpers = self._helpers

		if messageIsRequest:
			if (self.config_menu.menu_all_encReq_item.getState() and toolFlag in [IBurpExtenderCallbacks.TOOL_SCANNER, IBurpExtenderCallbacks.TOOL_PROXY, IBurpExtenderCallbacks.TOOL_INTRUDER, IBurpExtenderCallbacks.TOOL_REPEATER, IBurpExtenderCallbacks.TOOL_EXTENDER]) \
			or (self.config_menu.menu_scanner_encReq_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER) \
			or (self.config_menu.menu_proxy_encReq_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) \
			or (self.config_menu.menu_intruder_encReq_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER) \
			or (self.config_menu.menu_repeater_encReq_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER) \
			or (self.config_menu.menu_extender_encReq_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER):
				try:
					oriRequest = messageInfo.getRequest()

					newRequest = ExtenderHelpers.bytesToString(oriRequest)
					for k,v in SpecialCharacters.items():
						newRequest = newRequest.replace(k,v)

					RequestParser = TP_HTTP_REQUEST_PARSER(newRequest, ordered_dict=True)

					ProcessMessage = jdks.load(CONF_PATH, _isDebug_=True).get("ProcessMessage")["value"]
					Request = ProcessMessage["Request"]

					for i in range(len(Request)):
						match = True
						for pattern in Request[i]["PATTERN"]:
							if not re.search(pattern, newRequest):
								match = False
								break

						if not re.search(Request[i]["TARGET"], target): match = False

						if match:
							print("-"*128)
							print("["+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"] Request (processHttpMessage): "+url)

							O = list()
							for j in range(len(Request[i]["DATA"])):
								O.append("")

								for k in range(len(Request[i]["DATA"][j]["OUTPUT"])):
									if type(Request[i]["DATA"][j]["OUTPUT"][k]["code"]) in [str, unicode] and len(Request[i]["DATA"][j]["OUTPUT"][k]["code"]) > 0:
										if Request[i]["DATA"][j]["OUTPUT"][k]["exec_func"]:
											exec Request[i]["DATA"][j]["OUTPUT"][k]["code"]
										else:
											O[j] = eval(Request[i]["DATA"][j]["OUTPUT"][k]["code"])
								print("- O["+str(j)+"]: {}".format(repr(str(O[j])) if type(O[j]) in [str, unicode] else repr(O[j])))
							break

					RequestParser.request_headers.delete("X-BCF-SESSION", case_insensitive=True)
					RequestParser.request_headers.delete("X-BCF-ENCRYPTED", case_insensitive=True)
					RequestParser.request_headers.delete("X-BCF-ENABLED", case_insensitive=True)

					newRequest = RequestParser.unparse(update_content_length=True)

					newRequest = ExtenderHelpers.stringToBytes(newRequest)
					messageInfo.setRequest(newRequest)
				except Exception as e:
					print("processHttpMessage - Request:", e)
					messageInfo.setRequest(oriRequest)
		else:
			if (self.config_menu.menu_all_decRes_item.getState() and toolFlag in [IBurpExtenderCallbacks.TOOL_SCANNER, IBurpExtenderCallbacks.TOOL_PROXY, IBurpExtenderCallbacks.TOOL_INTRUDER, IBurpExtenderCallbacks.TOOL_REPEATER, IBurpExtenderCallbacks.TOOL_EXTENDER]) \
			or (self.config_menu.menu_scanner_decRes_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER) \
			or (self.config_menu.menu_proxy_decRes_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) \
			or (self.config_menu.menu_intruder_decRes_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER) \
			or (self.config_menu.menu_repeater_decRes_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER) \
			or (self.config_menu.menu_extender_decRes_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER):
				try:
					oriResponse = messageInfo.getResponse()

					newResponse = ExtenderHelpers.bytesToString(oriResponse)
					for k,v in SpecialCharacters.items():
						newResponse = newResponse.replace(k,v)

					ResponseParser = TP_HTTP_RESPONSE_PARSER(newResponse, ordered_dict=True)

					ProcessMessage = jdks.load(CONF_PATH, _isDebug_=True).get("ProcessMessage")["value"]
					Response = ProcessMessage["Response"]

					for i in range(len(Response)):
						match = True
						for pattern in Response[i]["PATTERN"]:
							if not re.search(pattern, newResponse):
								match = False
								break

						if not re.search(Response[i]["TARGET"], target): match = False

						if match:
							print("-"*128)
							print("["+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"] Response (processHttpMessage): "+url)

							O = list()
							for j in range(len(Response[i]["DATA"])):
								O.append("")

								for k in range(len(Response[i]["DATA"][j]["OUTPUT"])):
									if type(Response[i]["DATA"][j]["OUTPUT"][k]["code"]) in [str, unicode] and len(Response[i]["DATA"][j]["OUTPUT"][k]["code"]) > 0:
										if Response[i]["DATA"][j]["OUTPUT"][k]["exec_func"]:
											exec Response[i]["DATA"][j]["OUTPUT"][k]["code"]
										else:
											O[j] = eval(Response[i]["DATA"][j]["OUTPUT"][k]["code"])
								print("- O["+str(j)+"]: {}".format(repr(str(O[j])) if type(O[j]) in [str, unicode] else repr(O[j])))
							break

					newResponse = ResponseParser.unparse(update_content_length=True)
					for k,v in SpecialCharacters.items():
						newResponse = newResponse.replace(v,k)

					newResponse = ExtenderHelpers.stringToBytes(newResponse)
					messageInfo.setResponse(newResponse)
				except Exception as e:
					print("processHttpMessage - Response:", e)
					messageInfo.setResponse(oriResponse)

	def createNewInstance(self, controller, editable):
		return CipherMessageEditorTab(self, controller, editable)



class CipherMessageEditorTab(IMessageEditorTab):
	def __init__(self, extender, controller, editable):
		self._txtInput = extender._callbacks.createMessageEditor(controller, editable)
		self._extender = extender
		self.editable = editable
		self.CipherTab = jdks.load(CONF_PATH, _isDebug_=True).get("CipherTab")["value"]
		with open(CONF_PATH, "rb") as Jfile: self.BCFconf_hash = MD5().hexdigest(Utilities.base64Encode(Jfile.read()))


	def getUiComponent(self):
		return self._txtInput.getComponent()


	def getTabCaption(self):
		return EXTENSION_NAME+" v"+EXTENSION_VERSION


	def isEnabled(self, content, isRequest):
		match = False
		if content:
			global TARGET
			analyzeTraffic = self._extender._helpers.analyzeRequest(content)

			for header in analyzeTraffic.getHeaders()[1:]:
				if header.split(": ", 1)[0].upper() == "X-BCF-ENABLED":
					return False
				elif header.split(": ", 1)[0] == "Host":
					TARGET = header.split(": ", 1)[1] if len(header.split(": ", 1)) == 2 else ""
					TARGET = (TARGET if len(TARGET.split(":", 1)) == 2 else TARGET+":443")


			with open(CONF_PATH, "rb") as Jfile:
				try:
					BCFconf_hash = MD5().hexdigest(Utilities.base64Encode(Jfile.read()))
					if self.BCFconf_hash != BCFconf_hash:
						self.CipherTab = jdks.load(CONF_PATH, _isDebug_=True).get("CipherTab")["value"]
						self.BCFconf_hash = BCFconf_hash
				except Exception as e:
					pass

			if isRequest:
				DecryptRequest = self.CipherTab["DecryptRequest"]

				for i in range(len(DecryptRequest)):
					match = True
					for pattern in DecryptRequest[i]["PATTERN"]:
						if not re.search(pattern, content):
							match = False
							break

					if not re.search(DecryptRequest[i]["TARGET"], TARGET): match = False
				return match
			else:
				DecryptResponse = self.CipherTab["DecryptResponse"]

				for i in range(len(DecryptResponse)):
					match = True
					for pattern in DecryptResponse[i]["PATTERN"]:
						if not re.search(pattern, content):
							match = False
							break

					if not re.search(DecryptResponse[i]["TARGET"], TARGET): match = False
				return match

		return match


	def setMessage(self, content, isRequest):
		if content:
			self._isRequest = isRequest
			ExtenderHelpers = self._extender._helpers

			if isRequest:
				try:
					newContent = ExtenderHelpers.bytesToString(content)
					for k,v in SpecialCharacters.items():
						newContent = newContent.replace(k,v)

					RequestParser = TP_HTTP_REQUEST_PARSER(newContent, ordered_dict=True)

					DecryptRequest = self.CipherTab["DecryptRequest"]

					for i in range(len(DecryptRequest)):
						match = True
						for pattern in DecryptRequest[i]["PATTERN"]:
							if not re.search(pattern, newContent):
								match = False
								break

						if not re.search(DecryptRequest[i]["TARGET"], TARGET): match = False

						if match:
							print("-"*128)
							print("["+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"] Request (DecryptRequestTab)")

							O = list()
							for j in range(len(DecryptRequest[i]["DATA"])):
								O.append("")

								for k in range(len(DecryptRequest[i]["DATA"][j]["OUTPUT"])):
									if type(DecryptRequest[i]["DATA"][j]["OUTPUT"][k]["code"]) in [str, unicode] and len(DecryptRequest[i]["DATA"][j]["OUTPUT"][k]["code"]) > 0:
										if DecryptRequest[i]["DATA"][j]["OUTPUT"][k]["exec_func"]:
											exec DecryptRequest[i]["DATA"][j]["OUTPUT"][k]["code"]
										else:
											O[j] = eval(DecryptRequest[i]["DATA"][j]["OUTPUT"][k]["code"])
								print("- O["+str(j)+"]: {}".format(repr(str(O[j])) if type(O[j]) in [str, unicode] else repr(O[j])))
							break

					RequestParser.request_headers.update("X-BCF-Enabled", True, case_insensitive=True, allow_new_key=True)
					newContent = RequestParser.unparse(update_content_length=True)
					for k, v in SpecialCharacters.items():
						newContent = newContent.replace(v,k)

					newContent = ExtenderHelpers.stringToBytes(newContent)
					self._txtInput.setMessage(newContent, isRequest)
				except Exception as e:
					print("CipherMessageEditorTab - DecryptRequest:", e)
					self._txtInput.setMessage(content, isRequest)
			else:
				try:
					newContent = ExtenderHelpers.bytesToString(content)
					for k,v in SpecialCharacters.items():
						newContent = newContent.replace(k,v)

					ResponseParser = TP_HTTP_RESPONSE_PARSER(newContent, ordered_dict=True)

					DecryptResponse = self.CipherTab["DecryptResponse"]

					for i in range(len(DecryptResponse)):
						match = True
						for pattern in DecryptResponse[i]["PATTERN"]:
							if not re.search(pattern, newContent):
								match = False
								break

						if not re.search(DecryptResponse[i]["TARGET"], TARGET): match = False

						if match:
							print("-"*128)
							print("["+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"] Response (DecryptResponseTab)")

							O = list()
							for j in range(len(DecryptResponse[i]["DATA"])):
								O.append("")

								for k in range(len(DecryptResponse[i]["DATA"][j]["OUTPUT"])):
									if type(DecryptResponse[i]["DATA"][j]["OUTPUT"][k]["code"]) in [str, unicode] and len(DecryptResponse[i]["DATA"][j]["OUTPUT"][k]["code"]) > 0:
										if DecryptResponse[i]["DATA"][j]["OUTPUT"][k]["exec_func"]:
											exec DecryptResponse[i]["DATA"][j]["OUTPUT"][k]["code"]
										else:
											O[j] = eval(DecryptResponse[i]["DATA"][j]["OUTPUT"][k]["code"])
								print("- O["+str(j)+"]: {}".format(repr(str(O[j])) if type(O[j]) in [str, unicode] else repr(O[j])))
							break

					ResponseParser.response_headers.update("X-BCF-Enabled", True, case_insensitive=True, allow_new_key=True)
					newContent = ResponseParser.unparse(update_content_length=True)
					for k, v in SpecialCharacters.items():
						newContent = newContent.replace(v,k)

					newContent = ExtenderHelpers.stringToBytes(newContent)
					self._txtInput.setMessage(newContent, isRequest)
				except Exception as e:
					print("CipherMessageEditorTab - DecryptResponse:", e)
					self._txtInput.setMessage(content, isRequest)


	def getMessage(self):
		content = self._txtInput.getMessage()
		if self.editable and content:
			ExtenderHelpers = self._extender._helpers

			if self._isRequest:
				newContent = ExtenderHelpers.bytesToString(content)
				for k,v in SpecialCharacters.items():
					newContent = newContent.replace(k,v)

				RequestParser = TP_HTTP_REQUEST_PARSER(newContent, ordered_dict=True)

				EncryptRequest = self.CipherTab["EncryptRequest"]

				for i in range(len(EncryptRequest)):
					match = True
					for pattern in EncryptRequest[i]["PATTERN"]:
						if not re.search(pattern, newContent):
							match = False
							break

					if not re.search(EncryptRequest[i]["TARGET"], TARGET): match = False

					if match:
						print("-"*128)
						print("["+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"] Request (EncryptRequestTab)")

						O = list()
						for j in range(len(EncryptRequest[i]["DATA"])):
							O.append("")

							for k in range(len(EncryptRequest[i]["DATA"][j]["OUTPUT"])):
								if type(EncryptRequest[i]["DATA"][j]["OUTPUT"][k]["code"]) in [str, unicode] and len(EncryptRequest[i]["DATA"][j]["OUTPUT"][k]["code"]) > 0:
									if EncryptRequest[i]["DATA"][j]["OUTPUT"][k]["exec_func"]:
										exec EncryptRequest[i]["DATA"][j]["OUTPUT"][k]["code"]
									else:
										O[j] = eval(EncryptRequest[i]["DATA"][j]["OUTPUT"][k]["code"])
							print("- O["+str(j)+"]: {}".format(repr(str(O[j])) if type(O[j]) in [str, unicode] else repr(O[j])))
						break

				RequestParser.request_headers.delete("X-BCF-ENABLED", case_insensitive=True)
				newContent = RequestParser.unparse(update_content_length=True)
				for k,v in SpecialCharacters.items():
					newContent = newContent.replace(v,k)

				newContent = ExtenderHelpers.stringToBytes(newContent)
				return newContent
			else:
				newContent = ExtenderHelpers.bytesToString(content)
				for k,v in SpecialCharacters.items():
					newContent = newContent.replace(k,v)

				ResponseParser = TP_HTTP_RESPONSE_PARSER(newContent, ordered_dict=True)

				EncryptResponse = self.CipherTab["EncryptResponse"]

				for i in range(len(EncryptResponse)):
					match = True
					for pattern in EncryptResponse[i]["PATTERN"]:
						if not re.search(pattern, newContent):
							match = False
							break

					if not re.search(EncryptResponse[i]["TARGET"], TARGET): match = False

					if match:
						print("-"*128)
						print("["+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"] Response (EncryptResponseTab)")

						O = list()
						for j in range(len(EncryptResponse[i]["DATA"])):
							O.append("")

							for k in range(len(EncryptResponse[i]["DATA"][j]["OUTPUT"])):
								if type(EncryptResponse[i]["DATA"][j]["OUTPUT"][k]["code"]) in [str, unicode] and len(EncryptResponse[i]["DATA"][j]["OUTPUT"][k]["code"]) > 0:
									if EncryptResponse[i]["DATA"][j]["OUTPUT"][k]["exec_func"]:
										exec EncryptResponse[i]["DATA"][j]["OUTPUT"][k]["code"]
									else:
										O[j] = eval(EncryptResponse[i]["DATA"][j]["OUTPUT"][k]["code"])
							print("- O["+str(j)+"]: {}".format(repr(str(O[j])) if type(O[j]) in [str, unicode] else repr(O[j])))
						break

				RequestParser.request_headers.delete("X-BCF-ENABLED", case_insensitive=True)
				newContent = ResponseParser.unparse(update_content_length=True)
				for k,v in SpecialCharacters.items():
					newContent = newContent.replace(v,k)

				newContent = ExtenderHelpers.stringToBytes(newContent)
				return newContent


	def isModified(self):
		return self.editable


	def getSelectedData(self):
		return self._txtInput.getSelectedData()