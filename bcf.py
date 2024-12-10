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
from java.awt.event import ActionEvent
from java.awt.event import ActionListener

import os
ROOTDIR = os.getcwd()
CONF_PATH = os.path.join(os.path.expanduser("~"), ".bcf", "BCFconf.json")
os.system("pip install -r {} --target={} --no-user".format(os.path.join(ROOTDIR, "requirements.txt"), os.path.join(ROOTDIR, "bcf-site-packages")))
import site
site.addsitedir(os.path.join(ROOTDIR, "bcf-site-packages"))
import re
from datetime import datetime
import json_duplicate_keys as jdks
from TP_HTTP_Request_Response_Parser import TP_HTTP_REQUEST_PARSER, TP_HTTP_RESPONSE_PARSER
from TP_Generator import Utils, MFA_Generator, Nonce_Generator

from modules.SpecialCharacters import *
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

TARGET = "tpcybersec.com"
EXTENSION_NAME = "Burp Cipher Framework"
EXTENSION_VERSION = "2024.11.28"
serverPublicKeys = []
serverPrivateKeys = []
serverSecretKeys = []
serverIVs = []
serverSalts = []
serverPasswords = []

publicKey, privateKey = generateRSAKey()
clientPublicKeys = [ "-----BEGIN PUBLIC KEY-----"+publicKey+"-----END PUBLIC KEY-----" ]
clientPrivateKeys = [ "-----BEGIN PRIVATE KEY-----"+privateKey+"-----END PRIVATE KEY-----" ]
clientSecretKeys = [ Utils.RandomString(32) ]
clientIVs = [ Utils.RandomString(16) ]
clientSalts = [ Utils.RandomString(16) ]
clientPasswords = [ Utils.RandomString(16) ]



if not os.path.isfile(CONF_PATH):
	if not os.path.isdir(os.path.join(os.path.expanduser("~"), ".bcf")): os.mkdir(os.path.join(os.path.expanduser("~"), ".bcf"))

	JDKSObject_BCFconf = jdks.loads(Utils.base64Decode("eyJjb25maWciOnsiZXh0ZW5zaW9uX25hbWUiOiIiLCJleHRlbnNpb25fdmVyc2lvbiI6IiIsInNlcnZlclB1YmxpY0tleXMiOltdLCJzZXJ2ZXJQcml2YXRlS2V5cyI6W10sInNlcnZlclNlY3JldEtleXMiOltdLCJzZXJ2ZXJJVnMiOltdLCJzZXJ2ZXJTYWx0cyI6W10sInNlcnZlclBhc3N3b3JkcyI6W10sImNsaWVudFB1YmxpY0tleXMiOltdLCJjbGllbnRQcml2YXRlS2V5cyI6W10sImNsaWVudFNlY3JldEtleXMiOltdLCJjbGllbnRJVnMiOltdLCJjbGllbnRTYWx0cyI6W10sImNsaWVudFBhc3N3b3JkcyI6W119LCJQcm9jZXNzTWVzc2FnZSI6eyJSZXF1ZXN0IjpbeyJDT01NRU5UIjoiIiwiVEFSR0VUIjoidHBjeWJlcnNlYy5jb20iLCJQQVRURVJOIjpbXSwiREFUQSI6W3siQ09ORElUSU9OIjoiIiwiT1VUUFVUIjpbeyJDT01NRU5UIjoiR2V0IFJlcXVlc3QgUGF0aCIsIkxPT1BEQVRBIjoiIiwiZXhlY19mdW5jIjpmYWxzZSwiY29kZSI6IlJlcXVlc3RQYXJzZXIucmVxdWVzdF9wYXRoIn1dfV19XSwiUmVzcG9uc2UiOlt7IkNPTU1FTlQiOiIiLCJUQVJHRVQiOiJ0cGN5YmVyc2VjLmNvbSIsIlBBVFRFUk4iOltdLCJEQVRBIjpbeyJDT05ESVRJT04iOiIiLCJPVVRQVVQiOlt7IkNPTU1FTlQiOiJHZXQgU3RhdHVzIENvZGUiLCJMT09QREFUQSI6IiIsImV4ZWNfZnVuYyI6ZmFsc2UsImNvZGUiOiJSZXNwb25zZVBhcnNlci5yZXNwb25zZV9zdGF0dXNDb2RlIn1dfV19XX0sIkNpcGhlclRhYiI6eyJEZWNyeXB0UmVxdWVzdCI6W3siQ09NTUVOVCI6IiIsIlRBUkdFVCI6InRwY3liZXJzZWMuY29tIiwiUEFUVEVSTiI6W10sIkRBVEEiOlt7IkNPTkRJVElPTiI6IiIsIk9VVFBVVCI6W3siQ09NTUVOVCI6IkdldCBSZXF1ZXN0IE1ldGhvZCIsIkxPT1BEQVRBIjoiIiwiZXhlY19mdW5jIjpmYWxzZSwiY29kZSI6IlJlcXVlc3RQYXJzZXIucmVxdWVzdF9tZXRob2QifV19XX1dLCJFbmNyeXB0UmVxdWVzdCI6W3siQ09NTUVOVCI6IiIsIlRBUkdFVCI6InRwY3liZXJzZWMuY29tIiwiUEFUVEVSTiI6W10sIkRBVEEiOlt7IkNPTkRJVElPTiI6IiIsIk9VVFBVVCI6W3siQ09NTUVOVCI6IlVwZGF0ZSBSZXF1ZXN0IEhlYWRlciAnUmVmZXJlciciLCJMT09QREFUQSI6IiIsImV4ZWNfZnVuYyI6ZmFsc2UsImNvZGUiOiJSZXF1ZXN0UGFyc2VyLnJlcXVlc3RfaGVhZGVycy51cGRhdGUoJ1JlZmVyZXInLCAnaHR0cHM6Ly90cGN5YmVyc2VjLmJjZi8nKSJ9XX1dfV0sIkRlY3J5cHRSZXNwb25zZSI6W3siQ09NTUVOVCI6IiIsIlRBUkdFVCI6InRwY3liZXJzZWMuY29tIiwiUEFUVEVSTiI6W10sIkRBVEEiOlt7IkNPTkRJVElPTiI6IiIsIk9VVFBVVCI6W3siQ09NTUVOVCI6IkdldCBSZXNwb25zZSBCb2R5IE9iamVjdCIsIkxPT1BEQVRBIjoiIiwiZXhlY19mdW5jIjpmYWxzZSwiY29kZSI6IlJlc3BvbnNlUGFyc2VyLnJlc3BvbnNlX2JvZHkifV19XX1dLCJFbmNyeXB0UmVzcG9uc2UiOlt7IkNPTU1FTlQiOiIiLCJUQVJHRVQiOiJ0cGN5YmVyc2VjLmNvbSIsIlBBVFRFUk4iOltdLCJEQVRBIjpbeyJDT05ESVRJT04iOiIiLCJPVVRQVVQiOlt7IkNPTU1FTlQiOiJVcGRhdGUgUmVxdWVzdCBoZWFkZXIgJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbiciLCJMT09QREFUQSI6IiIsImV4ZWNfZnVuYyI6ZmFsc2UsImNvZGUiOiJSZXNwb25zZVBhcnNlci5yZXNwb25zZV9oZWFkZXJzLnVwZGF0ZSgnQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJywgJyonKSJ9XX1dfV19fQ=="), ordered_dict=True, _isDebug_=True)

	JDKSObject_BCFconf.update("config||extension_name", EXTENSION_NAME)
	JDKSObject_BCFconf.update("config||extension_version", EXTENSION_VERSION)
	JDKSObject_BCFconf.update("config||clientPublicKeys", [re.findall("-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----", clientPublicKeys[0])[0]])
	JDKSObject_BCFconf.update("config||clientPrivateKeys", [re.findall("-----BEGIN PRIVATE KEY-----(.+?)-----END PRIVATE KEY-----", clientPrivateKeys[0])[0]])
	JDKSObject_BCFconf.update("config||clientSecretKeys", clientSecretKeys)
	JDKSObject_BCFconf.update("config||clientIVs", clientIVs)
	JDKSObject_BCFconf.update("config||clientSalts", clientSalts)
	JDKSObject_BCFconf.update("config||clientPasswords", clientPasswords)
	JDKSObject_BCFconf.update("ProcessMessage||Request||$0$||TARGET", TARGET)
	JDKSObject_BCFconf.update("ProcessMessage||Response||$0$||TARGET", TARGET)
	JDKSObject_BCFconf.update("CipherTab||DecryptRequest||$0$||TARGET", TARGET)
	JDKSObject_BCFconf.update("CipherTab||EncryptRequest||$0$||TARGET", TARGET)
	JDKSObject_BCFconf.update("CipherTab||DecryptResponse||$0$||TARGET", TARGET)
	JDKSObject_BCFconf.update("CipherTab||EncryptResponse||$0$||TARGET", TARGET)

	JDKSObject_BCFconf.dump(CONF_PATH, indent=4)


print(Utils.base64Decode("CiAgIF9fXyAgICAgICAgICAgICAgICAgICAgICAgICBfX18gIF8gICAgICAgICBfICAgICAgICAgICAgICAgICAgICAgX19fICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIF8KICAvIF9fXCBfICAgXyAgXyBfXyAgXyBfXyAgICAgLyBfX1woXykgXyBfXyAgfCB8X18gICAgX19fICBfIF9fICAgIC8gX19cIF8gX18gICBfXyBfICBfIF9fIF9fXyAgICBfX18gX18gICAgICBfXyAgX19fICAgXyBfXyB8IHwgX18KIC9fX1wvL3wgfCB8IHx8ICdfX3x8ICdfIFwgICAvIC8gICB8IHx8ICdfIFwgfCAnXyBcICAvIF8gXHwgJ19ffCAgLyBfXCAgfCAnX198IC8gX2AgfHwgJ18gYCBfIFwgIC8gXyBcXCBcIC9cIC8gLyAvIF8gXCB8ICdfX3x8IHwvIC8KLyBcLyAgXHwgfF98IHx8IHwgICB8IHxfKSB8IC8gL19fXyB8IHx8IHxfKSB8fCB8IHwgfHwgIF9fL3wgfCAgICAvIC8gICAgfCB8ICAgfCAoX3wgfHwgfCB8IHwgfCB8fCAgX18vIFwgViAgViAvIHwgKF8pIHx8IHwgICB8ICAgPApcX19fX18vIFxfXyxffHxffCAgIHwgLl9fLyAgXF9fX18vIHxffHwgLl9fLyB8X3wgfF98IFxfX198fF98ICAgIFwvICAgICB8X3wgICAgXF9fLF98fF98IHxffCB8X3wgXF9fX3wgIFxfL1xfLyAgIFxfX18vIHxffCAgIHxffFxfXAogICAgICAgICAgICAgICAgICAgIHxffCAgICAgICAgICAgICAgIHxffAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZ7dmVyc2lvbn0gYnkgVHJ1b2MgUGhhbiAoQHRydW9jcGhhbikKCg==").format(version=EXTENSION_VERSION))



with open(CONF_PATH, "rb") as Jfile: BCFconf_hash = MD5().hexdigest(Utils.base64Encode(Jfile.read()))
JDKSObject_BCFconf = jdks.load(CONF_PATH, _isDebug_=True)

ConfigInfo = JDKSObject_BCFconf.get("config")["value"]
if type(ConfigInfo["extension_name"]) in [unicode, str] and len(ConfigInfo["extension_name"]) > 0: EXTENSION_NAME = ConfigInfo["extension_name"]
if type(ConfigInfo["extension_version"]) in [unicode, str] and len(ConfigInfo["extension_version"]) > 0: EXTENSION_VERSION = ConfigInfo["extension_version"]
if type(ConfigInfo["serverPublicKeys"]) == list and len(ConfigInfo["serverPublicKeys"]) > 0: serverPublicKeys = ConfigInfo["serverPublicKeys"]
if type(ConfigInfo["serverPrivateKeys"]) == list and len(ConfigInfo["serverPrivateKeys"]) > 0: serverPrivateKeys = ConfigInfo["serverPrivateKeys"]
if type(ConfigInfo["serverSecretKeys"]) == list and len(ConfigInfo["serverSecretKeys"]) > 0: serverSecretKeys = ConfigInfo["serverSecretKeys"]
if type(ConfigInfo["serverIVs"]) == list and len(ConfigInfo["serverIVs"]) > 0: serverIVs = ConfigInfo["serverIVs"]
if type(ConfigInfo["serverSalts"]) == list and len(ConfigInfo["serverSalts"]) > 0: serverSalts = ConfigInfo["serverSalts"]
if type(ConfigInfo["serverPasswords"]) == list and len(ConfigInfo["serverPasswords"]) > 0: serverPasswords = ConfigInfo["serverPasswords"]
if type(ConfigInfo["clientPublicKeys"]) == list and len(ConfigInfo["clientPublicKeys"]) > 0: clientPublicKeys = ConfigInfo["clientPublicKeys"]
if type(ConfigInfo["clientPrivateKeys"]) == list and len(ConfigInfo["clientPrivateKeys"]) > 0: clientPrivateKeys = ConfigInfo["clientPrivateKeys"]
if type(ConfigInfo["clientSecretKeys"]) == list and len(ConfigInfo["clientSecretKeys"])> 0: clientSecretKeys = ConfigInfo["clientSecretKeys"]
if type(ConfigInfo["clientIVs"]) == list and len(ConfigInfo["clientIVs"]) > 0: clientIVs = ConfigInfo["clientIVs"]
if type(ConfigInfo["clientSalts"]) == list and len(ConfigInfo["clientSalts"]) > 0: clientSalts = ConfigInfo["clientSalts"]
if type(ConfigInfo["clientPasswords"]) == list and len(ConfigInfo["clientPasswords"]) > 0: clientPasswords = ConfigInfo["clientPasswords"]

ProcessMessage_Request = JDKSObject_BCFconf.get("ProcessMessage")["value"]["Request"]
ProcessMessage_Response = JDKSObject_BCFconf.get("ProcessMessage")["value"]["Response"]
CipherTab = JDKSObject_BCFconf.get("CipherTab")["value"]


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
		self.menu_AutoRefesh_BCFconf_item = None

	class AllToolsListener(ActionListener):
		def __init__(self, checkboxes):
			self.checkboxes = checkboxes
	   
		def actionPerformed(self, event):
			all_checkbox = event.getSource()
			is_selected = all_checkbox.isSelected()
			for checkbox in self.checkboxes:
				checkbox.setSelected(is_selected)
			self.repaint_burp_jmenu_bar()
 
		def repaint_burp_jmenu_bar(self):
			burp_jframe = self.get_burp_jframe()
			burp_jframe.repaint()
 
		def get_burp_jframe(self):
			frames = Frame.getFrames()
			for frame in frames:
				if frame.isVisible() and frame.getTitle().startswith("Burp Suite"):
					return frame
			return None
 
	class IndividualToolListener(ActionListener):
		def __init__(self, all_checkbox, checkboxes):
			self.all_checkbox = all_checkbox
			self.checkboxes = checkboxes
	   
		def actionPerformed(self, event):
			all_selected = all(checkbox.isSelected() for checkbox in self.checkboxes)
			self.all_checkbox.setSelected(all_selected)
			self.repaint_burp_jmenu_bar()
 
		def repaint_burp_jmenu_bar(self):
			burp_jframe = self.get_burp_jframe()
			burp_jframe.repaint()
 
		def get_burp_jframe(self):
			frames = Frame.getFrames()
			for frame in frames:
				if frame.isVisible() and frame.getTitle().startswith("Burp Suite"):
					return frame
			return None

	def run(self):
		self.menu_button = JMenu(EXTENSION_NAME+" v"+EXTENSION_VERSION)

		self.menu_encReq = JMenu("Encrypt Request")
		self.menu_decRes = JMenu("Decrypt Response")
		self.menu_AutoRefesh_BCFconf_item = JCheckBoxMenuItem("Auto Refresh BCFconf")
		self.menu_AutoRefesh_BCFconf_item.setSelected(True)

		self.menu_all_encReq_item = JCheckBoxMenuItem("All Tools")
		self.menu_scanner_encReq_item = JCheckBoxMenuItem("Scanner")
		self.menu_proxy_encReq_item = JCheckBoxMenuItem("Proxy")
		self.menu_intruder_encReq_item = JCheckBoxMenuItem("Intruder")
		self.menu_repeater_encReq_item = JCheckBoxMenuItem("Repeater")
		self.menu_extender_encReq_item = JCheckBoxMenuItem("Extender")
		self.menu_all_encReq_item.setSelected(True)

		self.menu_all_decRes_item = JCheckBoxMenuItem("All Tools")
		self.menu_scanner_decRes_item = JCheckBoxMenuItem("Scanner")
		self.menu_proxy_decRes_item = JCheckBoxMenuItem("Proxy")
		self.menu_intruder_decRes_item = JCheckBoxMenuItem("Intruder")
		self.menu_repeater_decRes_item = JCheckBoxMenuItem("Repeater")
		self.menu_extender_decRes_item = JCheckBoxMenuItem("Extender")
		self.menu_all_decRes_item.setSelected(True)

		self.menu_encReq.add(self.menu_all_encReq_item)
		self.menu_encReq.add(self.menu_scanner_encReq_item)
		self.menu_encReq.add(self.menu_proxy_encReq_item)
		self.menu_encReq.add(self.menu_intruder_encReq_item)
		self.menu_encReq.add(self.menu_repeater_encReq_item)
		self.menu_encReq.add(self.menu_extender_encReq_item)

		self.menu_decRes.add(self.menu_all_decRes_item)
		self.menu_decRes.add(self.menu_scanner_decRes_item)
		self.menu_decRes.add(self.menu_proxy_decRes_item)
		self.menu_decRes.add(self.menu_intruder_decRes_item)
		self.menu_decRes.add(self.menu_repeater_decRes_item)
		self.menu_decRes.add(self.menu_extender_decRes_item)

		self.menu_button.add(self.menu_encReq)
		self.menu_button.add(self.menu_decRes)
		self.menu_button.add(self.menu_AutoRefesh_BCFconf_item)

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

		encReq_items = [
			self.menu_scanner_encReq_item,
			self.menu_proxy_encReq_item,
			self.menu_intruder_encReq_item,
			self.menu_repeater_encReq_item,
			self.menu_extender_encReq_item
		]
 
		decRes_items = [
			self.menu_scanner_decRes_item,
			self.menu_proxy_decRes_item,
			self.menu_intruder_decRes_item,
			self.menu_repeater_decRes_item,
			self.menu_extender_decRes_item
		]

		for tool in encReq_items: tool.setSelected(True)
 		for tool in decRes_items: tool.setSelected(True)
 
		self.menu_all_encReq_item.addActionListener(MenuBar.AllToolsListener(encReq_items))
		self.menu_all_decRes_item.addActionListener(MenuBar.AllToolsListener(decRes_items))
 
		for item in encReq_items:
			item.addActionListener(MenuBar.IndividualToolListener(self.menu_all_encReq_item, encReq_items))
	   
		for item in decRes_items:
			item.addActionListener(MenuBar.IndividualToolListener(self.menu_all_decRes_item, decRes_items))

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
		global BCFconf_hash, ProcessMessage_Request, ProcessMessage_Response, CipherTab, serverPublicKeys, serverPrivateKeys, serverSecretKeys, serverIVs, serverSalts, serverPasswords, clientPublicKeys, clientPrivateKeys, clientSecretKeys, clientIVs, clientSalts, clientPasswords

		target = messageInfo.getHttpService().getHost() + ":" + str(messageInfo.getHttpService().getPort())
		url = str(messageInfo.getHttpService().getProtocol()) + "//" + target + self._helpers.analyzeRequest(messageInfo.getRequest()).getHeaders()[0].split(" ")[1]

		if messageIsRequest:
			if (self.config_menu.menu_all_encReq_item.getState() and toolFlag in [IBurpExtenderCallbacks.TOOL_SCANNER, IBurpExtenderCallbacks.TOOL_PROXY, IBurpExtenderCallbacks.TOOL_INTRUDER, IBurpExtenderCallbacks.TOOL_REPEATER, IBurpExtenderCallbacks.TOOL_EXTENDER]) \
			or (self.config_menu.menu_scanner_encReq_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER) \
			or (self.config_menu.menu_proxy_encReq_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) \
			or (self.config_menu.menu_intruder_encReq_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER) \
			or (self.config_menu.menu_repeater_encReq_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER) \
			or (self.config_menu.menu_extender_encReq_item.getState() and toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER):
				try:
					oriRequest = messageInfo.getRequest()

					newRequest = self._helpers.bytesToString(oriRequest)
					for k,v in SpecialCharacters.items():
						newRequest = newRequest.replace(k,v)

					RequestParser = TP_HTTP_REQUEST_PARSER(newRequest, ordered_dict=True)

					if self.config_menu.menu_AutoRefesh_BCFconf_item.getState():
						with open(CONF_PATH, "rb") as Jfile:
							md5_hash = MD5().hexdigest(Utils.base64Encode(Jfile.read()))
							if BCFconf_hash != md5_hash:
								BCFconf_hash = md5_hash

								JDKSObject_BCFconf = jdks.load(CONF_PATH, _isDebug_=True)
								ConfigInfo = JDKSObject_BCFconf.get("config")["value"]
								if type(ConfigInfo["serverPublicKeys"]) == list and len(ConfigInfo["serverPublicKeys"]) > 0: serverPublicKeys = ConfigInfo["serverPublicKeys"]
								if type(ConfigInfo["serverPrivateKeys"]) == list and len(ConfigInfo["serverPrivateKeys"]) > 0: serverPrivateKeys = ConfigInfo["serverPrivateKeys"]
								if type(ConfigInfo["serverSecretKeys"]) == list and len(ConfigInfo["serverSecretKeys"]) > 0: serverSecretKeys = ConfigInfo["serverSecretKeys"]
								if type(ConfigInfo["serverIVs"]) == list and len(ConfigInfo["serverIVs"]) > 0: serverIVs = ConfigInfo["serverIVs"]
								if type(ConfigInfo["serverSalts"]) == list and len(ConfigInfo["serverSalts"]) > 0: serverSalts = ConfigInfo["serverSalts"]
								if type(ConfigInfo["serverPasswords"]) == list and len(ConfigInfo["serverPasswords"]) > 0: serverPasswords = ConfigInfo["serverPasswords"]
								if type(ConfigInfo["clientPublicKeys"]) == list and len(ConfigInfo["clientPublicKeys"]) > 0: clientPublicKeys = ConfigInfo["clientPublicKeys"]
								if type(ConfigInfo["clientPrivateKeys"]) == list and len(ConfigInfo["clientPrivateKeys"]) > 0: clientPrivateKeys = ConfigInfo["clientPrivateKeys"]
								if type(ConfigInfo["clientSecretKeys"]) == list and len(ConfigInfo["clientSecretKeys"])> 0: clientSecretKeys = ConfigInfo["clientSecretKeys"]
								if type(ConfigInfo["clientIVs"]) == list and len(ConfigInfo["clientIVs"]) > 0: clientIVs = ConfigInfo["clientIVs"]
								if type(ConfigInfo["clientSalts"]) == list and len(ConfigInfo["clientSalts"]) > 0: clientSalts = ConfigInfo["clientSalts"]
								if type(ConfigInfo["clientPasswords"]) == list and len(ConfigInfo["clientPasswords"]) > 0: clientPasswords = ConfigInfo["clientPasswords"]

								ProcessMessage_Request = JDKSObject_BCFconf.get("ProcessMessage")["value"]["Request"]
								ProcessMessage_Response = JDKSObject_BCFconf.get("ProcessMessage")["value"]["Response"]
								CipherTab = JDKSObject_BCFconf.get("CipherTab")["value"]


					for i in range(len(ProcessMessage_Request)):
						match = True
						for pattern in ProcessMessage_Request[i]["PATTERN"]:
							if not re.search(pattern, newRequest):
								match = False
								break

						if not re.search(ProcessMessage_Request[i]["TARGET"], target): match = False

						if match:
							print("-"*128)
							print("["+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"] Request (processHttpMessage): "+url)

							O = list()
							for j in range(len(ProcessMessage_Request[i]["DATA"])):
								O.append("")
								ProcessMessage_Request_CONDITION = ProcessMessage_Request[i]["DATA"][j]["CONDITION"]
								if len(ProcessMessage_Request_CONDITION) == 0 or eval(ProcessMessage_Request_CONDITION):
									for ProcessMessage_Request_OUTPUT in ProcessMessage_Request[i]["DATA"][j]["OUTPUT"]:
										if type(ProcessMessage_Request_OUTPUT["code"]) in [str, unicode] and len(ProcessMessage_Request_OUTPUT["code"]) > 0:
											LOOPDATA = [""]
											if type(ProcessMessage_Request_OUTPUT["LOOPDATA"]) in [str, unicode] and len(ProcessMessage_Request_OUTPUT["LOOPDATA"]) > 0:
												LOOPDATA = eval(ProcessMessage_Request_OUTPUT["LOOPDATA"])

											for LOOPVALUE in LOOPDATA:
												if ProcessMessage_Request_OUTPUT["exec_func"]:
													exec ProcessMessage_Request_OUTPUT["code"]
												else:
													O[j] = eval(ProcessMessage_Request_OUTPUT["code"])

								print("- O["+str(j)+"]: {}".format(repr(str(O[j])) if type(O[j]) in [str, unicode] else repr(O[j])))
							break

					RequestParser.request_headers.delete("X-BCF-SESSION", case_insensitive=True)
					RequestParser.request_headers.delete("X-BCF-ENCRYPTED", case_insensitive=True)
					RequestParser.request_headers.delete("X-BCF-ENABLED", case_insensitive=True)
					newRequest = RequestParser.unparse(update_content_length=True)

					newRequest = self._helpers.stringToBytes(newRequest)
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

					newResponse = self._helpers.bytesToString(oriResponse)
					for k,v in SpecialCharacters.items():
						newResponse = newResponse.replace(k,v)

					ResponseParser = TP_HTTP_RESPONSE_PARSER(newResponse, ordered_dict=True)

					if self.config_menu.menu_AutoRefesh_BCFconf_item.getState():
						with open(CONF_PATH, "rb") as Jfile:
							md5_hash = MD5().hexdigest(Utils.base64Encode(Jfile.read()))
							if BCFconf_hash != md5_hash:
								BCFconf_hash = md5_hash

								JDKSObject_BCFconf = jdks.load(CONF_PATH, _isDebug_=True)
								ConfigInfo = JDKSObject_BCFconf.get("config")["value"]
								if type(ConfigInfo["serverPublicKeys"]) == list and len(ConfigInfo["serverPublicKeys"]) > 0: serverPublicKeys = ConfigInfo["serverPublicKeys"]
								if type(ConfigInfo["serverPrivateKeys"]) == list and len(ConfigInfo["serverPrivateKeys"]) > 0: serverPrivateKeys = ConfigInfo["serverPrivateKeys"]
								if type(ConfigInfo["serverSecretKeys"]) == list and len(ConfigInfo["serverSecretKeys"]) > 0: serverSecretKeys = ConfigInfo["serverSecretKeys"]
								if type(ConfigInfo["serverIVs"]) == list and len(ConfigInfo["serverIVs"]) > 0: serverIVs = ConfigInfo["serverIVs"]
								if type(ConfigInfo["serverSalts"]) == list and len(ConfigInfo["serverSalts"]) > 0: serverSalts = ConfigInfo["serverSalts"]
								if type(ConfigInfo["serverPasswords"]) == list and len(ConfigInfo["serverPasswords"]) > 0: serverPasswords = ConfigInfo["serverPasswords"]
								if type(ConfigInfo["clientPublicKeys"]) == list and len(ConfigInfo["clientPublicKeys"]) > 0: clientPublicKeys = ConfigInfo["clientPublicKeys"]
								if type(ConfigInfo["clientPrivateKeys"]) == list and len(ConfigInfo["clientPrivateKeys"]) > 0: clientPrivateKeys = ConfigInfo["clientPrivateKeys"]
								if type(ConfigInfo["clientSecretKeys"]) == list and len(ConfigInfo["clientSecretKeys"])> 0: clientSecretKeys = ConfigInfo["clientSecretKeys"]
								if type(ConfigInfo["clientIVs"]) == list and len(ConfigInfo["clientIVs"]) > 0: clientIVs = ConfigInfo["clientIVs"]
								if type(ConfigInfo["clientSalts"]) == list and len(ConfigInfo["clientSalts"]) > 0: clientSalts = ConfigInfo["clientSalts"]
								if type(ConfigInfo["clientPasswords"]) == list and len(ConfigInfo["clientPasswords"]) > 0: clientPasswords = ConfigInfo["clientPasswords"]

								ProcessMessage_Request = JDKSObject_BCFconf.get("ProcessMessage")["value"]["Request"]
								ProcessMessage_Response = JDKSObject_BCFconf.get("ProcessMessage")["value"]["Response"]
								CipherTab = JDKSObject_BCFconf.get("CipherTab")["value"]


					for i in range(len(ProcessMessage_Response)):
						match = True
						for pattern in ProcessMessage_Response[i]["PATTERN"]:
							if not re.search(pattern, newResponse):
								match = False
								break

						if not re.search(ProcessMessage_Response[i]["TARGET"], target): match = False

						if match:
							print("-"*128)
							print("["+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"] Response (processHttpMessage): "+url)

							O = list()
							for j in range(len(ProcessMessage_Response[i]["DATA"])):
								O.append("")
								ProcessMessage_Response_CONDITION = ProcessMessage_Response[i]["DATA"][j]["CONDITION"]
								if len(ProcessMessage_Response_CONDITION) == 0 or eval(ProcessMessage_Response_CONDITION):
									for ProcessMessage_Response_OUTPUT in ProcessMessage_Response[i]["DATA"][j]["OUTPUT"]:
										if type(ProcessMessage_Response_OUTPUT["code"]) in [str, unicode] and len(ProcessMessage_Response_OUTPUT["code"]) > 0:
											LOOPDATA = [""]
											if type(ProcessMessage_Response_OUTPUT["LOOPDATA"]) in [str, unicode] and len(ProcessMessage_Response_OUTPUT["LOOPDATA"]) > 0:
												LOOPDATA = eval(ProcessMessage_Response_OUTPUT["LOOPDATA"])

											for LOOPVALUE in LOOPDATA:
												if ProcessMessage_Response_OUTPUT["exec_func"]:
													exec ProcessMessage_Response_OUTPUT["code"]
												else:
													O[j] = eval(ProcessMessage_Response_OUTPUT["code"])

								print("- O["+str(j)+"]: {}".format(repr(str(O[j])) if type(O[j]) in [str, unicode] else repr(O[j])))
							break

					newResponse = ResponseParser.unparse(update_content_length=True)
					for k,v in SpecialCharacters.items():
						newResponse = newResponse.replace(v,k)

					newResponse = self._helpers.stringToBytes(newResponse)
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


	def getUiComponent(self):
		return self._txtInput.getComponent()


	def getTabCaption(self):
		return EXTENSION_NAME+" v"+EXTENSION_VERSION


	def isEnabled(self, content, isRequest):
		global TARGET, BCFconf_hash, ProcessMessage_Request, ProcessMessage_Response, CipherTab, serverPublicKeys, serverPrivateKeys, serverSecretKeys, serverIVs, serverSalts, serverPasswords, clientPublicKeys, clientPrivateKeys, clientSecretKeys, clientIVs, clientSalts, clientPasswords

		match = False
		if content:
			analyzeTraffic = self._extender._helpers.analyzeRequest(content)

			for header in analyzeTraffic.getHeaders()[1:]:
				if header.split(": ", 1)[0].upper() == "X-BCF-ENABLED":
					return False
				elif header.split(": ", 1)[0] == "Host":
					TARGET = header.split(": ", 1)[1] if len(header.split(": ", 1)) == 2 else ""
					TARGET = (TARGET if len(TARGET.split(":", 1)) == 2 else TARGET+":443")


			if self._extender.config_menu.menu_AutoRefesh_BCFconf_item.getState():
				with open(CONF_PATH, "rb") as Jfile:
					md5_hash = MD5().hexdigest(Utils.base64Encode(Jfile.read()))
					if BCFconf_hash != md5_hash:
						BCFconf_hash = md5_hash

						JDKSObject_BCFconf = jdks.load(CONF_PATH, _isDebug_=True)
						ConfigInfo = JDKSObject_BCFconf.get("config")["value"]
						if type(ConfigInfo["serverPublicKeys"]) == list and len(ConfigInfo["serverPublicKeys"]) > 0: serverPublicKeys = ConfigInfo["serverPublicKeys"]
						if type(ConfigInfo["serverPrivateKeys"]) == list and len(ConfigInfo["serverPrivateKeys"]) > 0: serverPrivateKeys = ConfigInfo["serverPrivateKeys"]
						if type(ConfigInfo["serverSecretKeys"]) == list and len(ConfigInfo["serverSecretKeys"]) > 0: serverSecretKeys = ConfigInfo["serverSecretKeys"]
						if type(ConfigInfo["serverIVs"]) == list and len(ConfigInfo["serverIVs"]) > 0: serverIVs = ConfigInfo["serverIVs"]
						if type(ConfigInfo["serverSalts"]) == list and len(ConfigInfo["serverSalts"]) > 0: serverSalts = ConfigInfo["serverSalts"]
						if type(ConfigInfo["serverPasswords"]) == list and len(ConfigInfo["serverPasswords"]) > 0: serverPasswords = ConfigInfo["serverPasswords"]
						if type(ConfigInfo["clientPublicKeys"]) == list and len(ConfigInfo["clientPublicKeys"]) > 0: clientPublicKeys = ConfigInfo["clientPublicKeys"]
						if type(ConfigInfo["clientPrivateKeys"]) == list and len(ConfigInfo["clientPrivateKeys"]) > 0: clientPrivateKeys = ConfigInfo["clientPrivateKeys"]
						if type(ConfigInfo["clientSecretKeys"]) == list and len(ConfigInfo["clientSecretKeys"])> 0: clientSecretKeys = ConfigInfo["clientSecretKeys"]
						if type(ConfigInfo["clientIVs"]) == list and len(ConfigInfo["clientIVs"]) > 0: clientIVs = ConfigInfo["clientIVs"]
						if type(ConfigInfo["clientSalts"]) == list and len(ConfigInfo["clientSalts"]) > 0: clientSalts = ConfigInfo["clientSalts"]
						if type(ConfigInfo["clientPasswords"]) == list and len(ConfigInfo["clientPasswords"]) > 0: clientPasswords = ConfigInfo["clientPasswords"]

						ProcessMessage_Request = JDKSObject_BCFconf.get("ProcessMessage")["value"]["Request"]
						ProcessMessage_Response = JDKSObject_BCFconf.get("ProcessMessage")["value"]["Response"]
						CipherTab = JDKSObject_BCFconf.get("CipherTab")["value"]

			if isRequest:
				DecryptRequest = CipherTab["DecryptRequest"]

				for i in range(len(DecryptRequest)):
					match = True
					for pattern in DecryptRequest[i]["PATTERN"]:
						if not re.search(pattern, content):
							match = False
							break

					if not re.search(DecryptRequest[i]["TARGET"], TARGET): match = False
				return match
			else:
				DecryptResponse = CipherTab["DecryptResponse"]

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
		self._txtInput.setMessage("", isRequest)
		if content:
			self._isRequest = isRequest

			if isRequest:
				try:
					newContent = self._extender._helpers.bytesToString(content)
					for k,v in SpecialCharacters.items():
						newContent = newContent.replace(k,v)

					RequestParser = TP_HTTP_REQUEST_PARSER(newContent, ordered_dict=True)

					DecryptRequest = CipherTab["DecryptRequest"]

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
								DecryptRequest_CONDITION = DecryptRequest[i]["DATA"][j]["CONDITION"]
								if len(DecryptRequest_CONDITION) == 0 or eval(DecryptRequest_CONDITION):
									for DecryptRequest_OUTPUT in DecryptRequest[i]["DATA"][j]["OUTPUT"]:
										if type(DecryptRequest_OUTPUT["code"]) in [str, unicode] and len(DecryptRequest_OUTPUT["code"]) > 0:
											LOOPDATA = [""]
											if type(DecryptRequest_OUTPUT["LOOPDATA"]) in [str, unicode] and len(DecryptRequest_OUTPUT["LOOPDATA"]) > 0:
												LOOPDATA = eval(DecryptRequest_OUTPUT["LOOPDATA"])

											for LOOPVALUE in LOOPDATA:
												if DecryptRequest_OUTPUT["exec_func"]:
													exec DecryptRequest_OUTPUT["code"]
												else:
													O[j] = eval(DecryptRequest_OUTPUT["code"])

								print("- O["+str(j)+"]: {}".format(repr(str(O[j])) if type(O[j]) in [str, unicode] else repr(O[j])))
							break

					RequestParser.request_headers.update("X-BCF-Enabled", True, case_insensitive=True, allow_new_key=True)
					newContent = RequestParser.unparse(update_content_length=True)
					for k, v in SpecialCharacters.items():
						newContent = newContent.replace(v,k)

					newContent = self._extender._helpers.stringToBytes(newContent)
					self._txtInput.setMessage(newContent, isRequest)
				except Exception as e:
					print("CipherMessageEditorTab - DecryptRequest:", e)
			else:
				try:
					newContent = self._extender._helpers.bytesToString(content)
					for k,v in SpecialCharacters.items():
						newContent = newContent.replace(k,v)

					ResponseParser = TP_HTTP_RESPONSE_PARSER(newContent, ordered_dict=True)

					DecryptResponse = CipherTab["DecryptResponse"]

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
								DecryptResponse_CONDITION = DecryptResponse[i]["DATA"][j]["CONDITION"]
								if len(DecryptResponse_CONDITION) == 0 or eval(DecryptResponse_CONDITION):
									for DecryptResponse_OUTPUT in DecryptResponse[i]["DATA"][j]["OUTPUT"]:
										if type(DecryptResponse_OUTPUT["code"]) in [str, unicode] and len(DecryptResponse_OUTPUT["code"]) > 0:
											LOOPDATA = [""]
											if type(DecryptResponse_OUTPUT["LOOPDATA"]) in [str, unicode] and len(DecryptResponse_OUTPUT["LOOPDATA"]) > 0:
												LOOPDATA = eval(DecryptResponse_OUTPUT["LOOPDATA"])

											for LOOPVALUE in LOOPDATA:
												if DecryptResponse_OUTPUT["exec_func"]:
													exec DecryptResponse_OUTPUT["code"]
												else:
													O[j] = eval(DecryptResponse_OUTPUT["code"])

								print("- O["+str(j)+"]: {}".format(repr(str(O[j])) if type(O[j]) in [str, unicode] else repr(O[j])))
							break

					ResponseParser.response_headers.update("X-BCF-Enabled", True, case_insensitive=True, allow_new_key=True)
					newContent = ResponseParser.unparse(update_content_length=True)
					for k, v in SpecialCharacters.items():
						newContent = newContent.replace(v,k)

					newContent = self._extender._helpers.stringToBytes(newContent)
					self._txtInput.setMessage(newContent, isRequest)
				except Exception as e:
					print("CipherMessageEditorTab - DecryptResponse:", e)


	def getMessage(self):
		content = self._txtInput.getMessage()
		if self.editable and content:
			if self._isRequest:
				newContent = self._extender._helpers.bytesToString(content)
				for k,v in SpecialCharacters.items():
					newContent = newContent.replace(k,v)

				RequestParser = TP_HTTP_REQUEST_PARSER(newContent, ordered_dict=True)

				EncryptRequest = CipherTab["EncryptRequest"]

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
							EncryptRequest_CONDITION = EncryptRequest[i]["DATA"][j]["CONDITION"]
							if len(EncryptRequest_CONDITION) == 0 or eval(EncryptRequest_CONDITION):
								for EncryptRequest_OUTPUT in EncryptRequest[i]["DATA"][j]["OUTPUT"]:
									if type(EncryptRequest_OUTPUT["code"]) in [str, unicode] and len(EncryptRequest_OUTPUT["code"]) > 0:
										LOOPDATA = [""]
										if type(EncryptRequest_OUTPUT["LOOPDATA"]) in [str, unicode] and len(EncryptRequest_OUTPUT["LOOPDATA"]) > 0:
											LOOPDATA = eval(EncryptRequest_OUTPUT["LOOPDATA"])

										for LOOPVALUE in LOOPDATA:
											if EncryptRequest_OUTPUT["exec_func"]:
												exec EncryptRequest_OUTPUT["code"]
											else:
												O[j] = eval(EncryptRequest_OUTPUT["code"])

							print("- O["+str(j)+"]: {}".format(repr(str(O[j])) if type(O[j]) in [str, unicode] else repr(O[j])))
						break

				RequestParser.request_headers.delete("X-BCF-ENABLED", case_insensitive=True)
				newContent = RequestParser.unparse(update_content_length=True)
				for k,v in SpecialCharacters.items():
					newContent = newContent.replace(v,k)

				newContent = self._extender._helpers.stringToBytes(newContent)
				return newContent
			else:
				newContent = self._extender._helpers.bytesToString(content)
				for k,v in SpecialCharacters.items():
					newContent = newContent.replace(k,v)

				ResponseParser = TP_HTTP_RESPONSE_PARSER(newContent, ordered_dict=True)

				EncryptResponse = CipherTab["EncryptResponse"]

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
							EncryptResponse_CONDITION = EncryptResponse[i]["DATA"][j]["CONDITION"]
							if len(EncryptResponse_CONDITION) == 0 or eval(EncryptResponse_CONDITION):
								for EncryptResponse_OUTPUT in EncryptResponse[i]["DATA"][j]["OUTPUT"]:
									if type(EncryptResponse_OUTPUT["code"]) in [str, unicode] and len(EncryptResponse_OUTPUT["code"]) > 0:
										LOOPDATA = [""]
										if type(EncryptResponse_OUTPUT["LOOPDATA"]) in [str, unicode] and len(EncryptResponse_OUTPUT["LOOPDATA"]) > 0:
											LOOPDATA = eval(EncryptResponse_OUTPUT["LOOPDATA"])

										for LOOPVALUE in LOOPDATA:
											if EncryptResponse_OUTPUT["exec_func"]:
												exec EncryptResponse_OUTPUT["code"]
											else:
												O[j] = eval(EncryptResponse_OUTPUT["code"])

							print("- O["+str(j)+"]: {}".format(repr(str(O[j])) if type(O[j]) in [str, unicode] else repr(O[j])))
						break

				ResponseParser.response_headers.delete("X-BCF-ENABLED", case_insensitive=True)
				newContent = ResponseParser.unparse(update_content_length=True)
				for k,v in SpecialCharacters.items():
					newContent = newContent.replace(v,k)

				newContent = self._extender._helpers.stringToBytes(newContent)
				return newContent


	def isModified(self):
		return self.editable


	def getSelectedData(self):
		return self._txtInput.getSelectedData()