from abc import ABCMeta, abstractmethod
from passStruct import PassData

import sys, errorPrinter

class Load(object):

	__metaclas__ = ABCMeta

	@abstractmethod
	def __init__(self):
		pass

	@abstractmethod
	def loadData(self, passwordData):
		pass


#Method 'loadData' load passwords from stdin (without entropy)
#Method arguments: passwordData (PassData)
class LoadFromStdin(Load):

	def __init__(self):
		super(LoadFromStdin, self).__init__()

	def loadData(self):
		passwordData = PassData()

		for line in sys.stdin:
			data = line.rstrip('\n').split()
			try:
				if (len(data) == 2):
					passwordData.add(data[0], float(data[1]))
				elif (len(data) == 1):
					passwordData.add(data[0])
				else:
					errorPrinter.printWarning(self.__class__.__name__, "Invalid line in input file: Too many items at line")
			except ValueError:
				errorPrinter.printWarning(self.__class__.__name__, 'Wrong input \'{0:1}\' have to be number'.format(data[1]))

		return passwordData


#Method 'loadData' load passwords from file (with/without entropy)
#Method arguments: passwordData (PassData)
class LoadFromFile(Load):

	def __init__(self, fileName=None):
		self.fileName = fileName

	def loadData(self):
		passwordData = PassData()

		try:
			with open(self.fileName, 'r') as inputFile:
				for line in inputFile:
					data = line.rstrip('\n').split()
					try:
						if (len(data) == 2):
							passwordData.add(data[0], float(data[1]))
						elif (len(data) == 1):
							passwordData.add(data[0])
						else:
							errorPrinter.printWarning(self.__class__.__name__, "Invalid line in input file: Too many items at line")
					except ValueError:
						errorPrinter.printWarning(self.__class__.__name__, 'Wrong input \'{0:1}\' have to be number'.format(data[1]))
		except IOError:
			errorPrinter.printError(self.__class__.__name__, 'File \'{0:1}\' doesn\'t exist'.format(self.fileName))

		return passwordData
