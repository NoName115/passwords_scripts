from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassData, Password

import scripts.errorPrinter as errorPrinter
import subprocess

class Library(object):
	
	__metaclass__ = ABCMeta

	@abstractmethod
	def __init__(self):
		pass

	@abstractmethod
	def checkResult(self, passwordData, delimiter=None, *args):
		"""Get output of library and save it to passwordData

		passwordData -- type PassData
		delimiter -- optional argument, if is necessary to split library output
		*args -- arguments for run/call library
		"""
		try:
			for x in passwordData.passwordList:
				#Get output from library
				p = subprocess.Popen(args, stdin = subprocess.PIPE, stdout = subprocess.PIPE,stderr = subprocess.PIPE)
				output = p.communicate(input = bytes(x.password, 'UTF-8'))[0].rstrip(bytes('\n', 'UTF-8'))

				#Split and save output to PassData
				if (delimiter == None):
					x.addLibOutput(self.__class__.__name__, output)
				else:
					x.addLibOutput(self.__class__.__name__, output.split(bytes(delimiter, 'UTF-8'))[1])
		except AttributeError:
			errorPrinter.printWarning(self.__class__.__name__, "Wrong input data instance")
		except IndexError:
			errorPrinter.printWarning(self.__class__.__name__, "")



class CrackLib(Library):
	def __init__(self):
		super(CrackLib, self).__init__()

	def checkResult(self, passwordData):
		super(CrackLib, self).checkResult(passwordData, ": ", "cracklib-check")

class PassWDQC(Library):
	def __init__(self):
		super(PassWDQC, self).__init__()

	def checkResult(self, passwordData):
		super(PassWDQC, self).checkResult(passwordData, None, "pwqcheck", "-1")
