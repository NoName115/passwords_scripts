from abc import ABCMeta, abstractmethod
from passStruct import PassData, Password

import subprocess

class Library(object):
	
	__metaclass__ = ABCMeta

	@abstractmethod
	def __init__(self):
		pass

	@abstractmethod
	def checkResult(self, passwordData, delimeter=None, *args):
		for x in passwordData.passwordList:
			#Get output from library
			p = subprocess.Popen(args, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
			output = p.communicate(input = x.password)[0].rstrip('\n')

			#Split and save output to PassData
			if (delimeter == None):
				x.addLibOutput(self.__class__.__name__, output)
			else:
				x.addLibOutput(self.__class__.__name__, output.split(delimeter)[1])



class CrackLib(Library):
	def __init__(self):
		super(CrackLib, self).__init__()

	def checkResult(self, passwordData, delimeter=None):
		super(CrackLib, self).checkResult(passwordData, delimeter, "cracklib-check")

class PassWDQC(Library):
	def __init__(self):
		super(PassWDQC, self).__init__()

	def checkResult(self, passwordData):
		super(PassWDQC, self).checkResult(passwordData, None, "pwqcheck", "-1")
