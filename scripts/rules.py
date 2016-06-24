from abc import ABCMeta, abstractmethod
from passStruct import PassData, Password

import random, errorPrinter


class Rule(object):

	__metaclass__ = ABCMeta

	@abstractmethod
	def __init__(self):
		pass

	@abstractmethod
	def transform(self, passwordData):
		pass

	@abstractmethod
	def estimateNewEntropyAndSaveTransformData(self):
		pass


class l33t(Rule):

	#Method load l33t table from file
	#Return library (key, value is list)
	#@abstractmethod
	def loadToDict(self, fileName):
		try:
			with open(fileName, 'r') as l33tInput:
				l33tDict = {}
				try:
					for line in l33tInput:
						line = line.strip('\n').split(' ')

						if (line[0] in l33tDict):
							for i in range(1, len(line)):
								l33tDict[line[0]].append(line[i])
						else:
							l33tDict.update({line[0] : [line[1]]})
							for i in range(2, len(line)):
								l33tDict[line[0]].append(line[i])
				except IndexError:
					errorPrinter.printWarning(self.__class__.__name__, 'Wrong format of line in input file \'{0:1}\''.format(line))
					return None
			return l33tDict
		except IOError:
			errorPrinter.printWarning(self.__class__.__name__, 'File \'{0:1}\' doesn\'t exist'.format(fileName))
			return None



#Method 'transform' apply simple l33t at passwords
#Method arguments: passwordData (Type is PassData or Password)
class ApplySimplel33t(l33t):
	def __init__(self):
		super(ApplySimplel33t, self).__init__()

	def transform(self, passwordData):
		try:
			l33tDict = self.loadToDict("Simple_l33t")

			for x in passwordData.passwordList:
				occur = 0

				for key in l33tDict:
					occur += x.password.count(key)
					x.password = x.password.replace(key, l33tDict[key][random.randint(0, len(l33tDict[key]) - 1)])

				self.estimateNewEntropyAndSaveTransformData(occur, x)

		except TypeError:
			errorPrinter.printWarning(self.__class__.__name__, "l33t table is empty", True)
		except AttributeError:
			errorPrinter.printWarning(self.__class__.__name__, "Wrong input data instance", True)

	#Change entropy - 1
	def estimateNewEntropyAndSaveTransformData(self, occurCount, password):
		entropyChange = 0
		if (occurCount > 0):
			entropyChange = 1

		password.actualEntropy += entropyChange
		password.transformRules.append([self.__class__.__name__, password.actualEntropy])



#Method 'transform' apply advanced l33t at passwords
#Method arguments: passwordData (Type is PassData or Password)
class ApplyAdvancedl33t(l33t):
	def __init__(self):
		super(ApplyAdvancedl33t, self).__init__()

	def transform(self, passwordData):
		try:
			l33tDict = self.loadToDict("Advanced_l33t")

			for x in passwordData.passwordList:
				occur = 0

				for key in l33tDict:
					occur += x.password.count(key)
					x.password = x.password.replace(key, l33tDict[key][random.randint(0, len(l33tDict[key]) - 1)])

				self.estimateNewEntropyAndSaveTransformData(occur, x)

		except TypeError:
			errorPrinter.printWarning(self.__class__.__name__, "l33t table is empty", True)
		except AttributeError:
			errorPrinter.printWarning(self.__class__.__name__, "Wrong input data instance", True)

	#Change entropy - 2
	def estimateNewEntropyAndSaveTransformData(self, occurCount, password):
		entropyChange = 0
		if (occurCount > 0):
			entropyChange = 2

		password.actualEntropy += entropyChange
		password.transformRules.append([self.__class__.__name__, password.actualEntropy])


#Method 'transform' capitalize all letters in password
#Method arguments: passwordData (Type is PassData or Password)
class CapitalizeAllLetters(Rule):
	def __init__(self):
		super(CapitalizeAllLetters, self).__init__()

	def transform(self, passwordData):
		try:
			for x in passwordData.passwordList:
				transformedPassword = x.password.upper()
				self.estimateNewEntropyAndSaveTransformData(transformedPassword, x)
				x.password = transformedPassword

		except AttributeError:
			errorPrinter.printWarning(self.__class__.__name__, "Wrong input data instance", True)

	#Change entropy - 1
	def estimateNewEntropyAndSaveTransformData(self, transformedPassword, password):
		entropyChange = 0
		if (any(c.islower() for c in password.password) and transformedPassword.isupper()):
			entropyChange = 1

		password.actualEntropy += entropyChange
		password.transformRules.append([self.__class__.__name__, password.actualEntropy])


#Method 'transform' lower all letters in password
#Method arguments: passwordData (Type is PassData or Password)
class LowerAllLetters(Rule):
	def __init__(self):
		super(LowerAllLetters, self).__init__()

	def transform(self, passwordData):
		try:
			for x in passwordData.passwordList:
				transformedPassword = x.password.lower()
				self.estimateNewEntropyAndSaveTransformData(transformedPassword, x)
				x.password = transformedPassword

		except AttributeError:
			errorPrinter.printWarning(self.__class__.__name__, "Wrong input data instance", True)

	#Change entropy - 1
	def estimateNewEntropyAndSaveTransformData(self, transformedPassword, password):
		entropyChange = 0
		if (any(c.isupper() for c in password.password) and transformedPassword.islower()):
			entropyChange = 1
		
		password.actualEntropy += entropyChange
		password.transformRules.append([self.__class__.__name__, password.actualEntropy])


##############################################################################################################
#TODO... errorHandle --> transformList
#Capitalize one letter from password at certain index
#Arguments: Index(number)
class CapitalizeLetterAtIndex(Rule):
 	def __init__(self, indx=None):
 		self.indx = indx

 	#@saveTransformData
 	def transform(self, passwordData):
 		try:
			for x in passwordData.passwordList:
				try:
					x.password = x.password[:self.indx] + x.password[self.indx].upper() + x.password[self.indx + 1:]
				except IndexError:
					errorPrinter.printWarning(self.__class__.__name__, '\'{0:1}\' - Index out of range'.format(x.password))

		except AttributeError:
			errorPrinter.printWarning(self.__class__.__name__, "Wrong input data instance")
			return 1
		except TypeError:
			errorPrinter.printWarning(self.__class__.__name__, "Arguemnt 'indx' in contructor is Empty or is not a number")
			return 1


#Delete letter at index from password
#Arguments: Index(number)
class DeleteLetter(Rule):
	def __init__(self, indx):
		self.indx = indx

	#@saveTransformData
	def transform(self, passwordData):
		try:
			for x in passwordData.passwordList:
				try:
					x.password = re.sub(x.password[self.indx], '', x.password)
				except IndexError:
					errorPrinter.printWarning(self.__class__.__name__, '\'{0:1}\' - Index out of range'.format(x.password))

		except AttributeError:
			errorPrinter.printWarning(self.__class__.__name__, "Wrong input data instance")
			return 1
		except TypeError:
			errorPrinter.printWarning(self.__class__.__name__, "Arguemnt 'indx' in contructor is Empty or is not a number")
			return 1
