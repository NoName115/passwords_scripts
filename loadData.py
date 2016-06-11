from abc import ABCMeta, abstractmethod
import sys

class Load(object):

	__metaclas__ = ABCMeta

	@abstractmethod
	def __init__(self):
		pass

	@abstractmethod
	def loadData(self, passwordData):
		pass



class LoadFromStdin(Load):

	def __init__(self):
		super(LoadFromStdin, self).__init__()

	def loadData(self, passwordData):
		for line in sys.stdin:
			passwordData.add(line.rstrip('\n'))


class LoadFromFile(Load):

	def __init__(self, fileName=None):
		if (fileName is None):
			print("LoadFromFile: Invalid argument - fileName is None")
		else:
			self.fileName = fileName

	def loadData(self, passwordData):
		if hasattr(self, 'fileName') == False:
			print("Class was not created - Invalid argument fileName")
			return

		with open(self.fileName, 'r') as inputFile:
			for line in inputFile:
				vys = line.rstrip('\n').split()

				if (len(vys) == 2):
					passwordData.add(vys[0], float(vys[1]))
				elif (len(vys) == 1):
					passwordData.add(vys[0])
				else:
					print("Invalid line in input file: Too many items at line")
