from abc import ABCMeta, abstractmethod

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

	def loadData(self, passwordData):
		for line in sys.stdin:
			passwordData.add(line.rstrip('\n'))


#Method 'loadData' load passwords from file (with/without entropy)
#Method arguments: passwordData (PassData)
class LoadFromFile(Load):

	def __init__(self, fileName=None):
		self.fileName = fileName

	def loadData(self, passwordData):
		if self.fileName == None:
			errorPrinter.printError(self.__class__.__name__, "Argument fileName is empty")
			return

		try:
			with open(self.fileName, 'r') as inputFile:
				for line in inputFile:
					vys = line.rstrip('\n').split()

					if (len(vys) == 2):
						passwordData.add(vys[0], float(vys[1]))
					elif (len(vys) == 1):
						passwordData.add(vys[0])
					else:
						errorPrinter.printWarning(self.__class__.__name__, "Invalid line in input file: Too many items at line")
		except IOError:
			errorPrinter.printError(self.__class__.__name__, 'File \'{0:1}\' doesn\'t exist'.format(self.fileName))
