from abc import ABCMeta, abstractmethod
from passStruct import PassData, Password

import subprocess, errorPrinter

class Library(object):
	
	__metaclass__ = ABCMeta

	@abstractmethod
	def __init__(self):
		pass

	#Method get output of library and store it to passData
	#Arguments: passwordData(PassData), delimeter(char/string) - optional argument, *args(strings) - arguments for calling library
	@abstractmethod
	def checkResult(self, passwordData, delimiter=None, *args):
		try:
			for x in passwordData.passwordList:
				#Get output from library
				p = subprocess.Popen(args, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
				output = p.communicate(input = x.password)[0].rstrip('\n')

				#Split and save output to PassData
				if (delimiter == None):
					x.addLibOutput(self.__class__.__name__, output)
				else:
					x.addLibOutput(self.__class__.__name__, output.split(delimiter)[1])
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
