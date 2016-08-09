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

	#@abstractmethod
	def loadToDict(self, fileName):
		"""Load l33t table from file

		Arguments:
		fileName -- file from which data are loaded

		Return value:
		dictionary -- key(char), value(list)
		"""
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


class ApplySimplel33t(l33t):
	def __init__(self):
		super(ApplySimplel33t, self).__init__()

	def transform(self, passwordData):
		"""Apply simple l33t at passwords

		Arguments:
		passwordData -- type of PassData
		"""
		try:
			l33tDict = self.loadToDict("Simple_l33t")

			for x in passwordData.passwordList:
				occur = 0

				for key in l33tDict:
					occur += x.password.count(key)
					x.password = x.password.replace(key, l33tDict[key][random.randint(0, len(l33tDict[key]) - 1)])

				self.estimateNewEntropyAndSaveTransformData(occur, x)

		except TypeError:
			errorPrinter.printRuleWarning(self.__class__.__name__, "l33t table is empty")
		except AttributeError:
			errorPrinter.printRuleWarning(self.__class__.__name__, "Wrong input data instance")

	#Change entropy - 1
	def estimateNewEntropyAndSaveTransformData(self, occurCount, password):
		entropyChange = 0
		if (occurCount > 0):
			entropyChange = 1

		password.entropy += entropyChange
		password.transformRules.append([self.__class__.__name__, entropyChange])


class ApplyAdvancedl33t(l33t):
	def __init__(self):
		super(ApplyAdvancedl33t, self).__init__()

	def transform(self, passwordData):
		"""Apply advanced l33t at passwords

		Arguments:
		passwordData -- (PassData)
		"""
		try:
			l33tDict = self.loadToDict("Advanced_l33t")

			for x in passwordData.passwordList:
				occur = 0

				for key in l33tDict:
					occur += x.password.count(key)
					x.password = x.password.replace(key, l33tDict[key][random.randint(0, len(l33tDict[key]) - 1)])

				self.estimateNewEntropyAndSaveTransformData(occur, x)

		except TypeError:
			errorPrinter.printRuleWarning(self.__class__.__name__, "l33t table is empty")
		except AttributeError:
			errorPrinter.printRuleWarning(self.__class__.__name__, "Wrong input data instance")

	#Change entropy - 2
	def estimateNewEntropyAndSaveTransformData(self, occurCount, password):
		entropyChange = 0
		if (occurCount > 0):
			entropyChange = 2

		password.entropy += entropyChange
		password.transformRules.append([self.__class__.__name__, entropyChange])


class CapitalizeAllLetters(Rule):
	def __init__(self):
		super(CapitalizeAllLetters, self).__init__()

	def transform(self, passwordData):
		"""Capitalize all letters in password

		Arguments:
		passwordData -- (PassData)
		"""
		try:
			for x in passwordData.passwordList:
				transformedPassword = x.password.upper()
				self.estimateNewEntropyAndSaveTransformData(transformedPassword, x)
				x.password = transformedPassword

		except AttributeError:
			errorPrinter.printRuleWarning(self.__class__.__name__, "Wrong input data instance")

	#Change entropy - 1
	def estimateNewEntropyAndSaveTransformData(self, transformedPassword, password):
		entropyChange = 0
		if (any(c.islower() for c in password.password) and transformedPassword.isupper()):
			entropyChange = 1

		password.entropy += entropyChange
		password.transformRules.append([self.__class__.__name__, entropyChange])


class LowerAllLetters(Rule):
	def __init__(self):
		super(LowerAllLetters, self).__init__()

	def transform(self, passwordData):
		"""Lower all letters in password

		Arguments:
		passwordData -- (PassData)
		"""
		try:
			for x in passwordData.passwordList:
				transformedPassword = x.password.lower()
				self.estimateNewEntropyAndSaveTransformData(transformedPassword, x)
				x.password = transformedPassword

		except AttributeError:
			errorPrinter.printRuleWarning(self.__class__.__name__, "Wrong input data instance")

	#Change entropy - 1
	def estimateNewEntropyAndSaveTransformData(self, transformedPassword, password):
		entropyChange = 0
		if (any(c.isupper() for c in password.password) and transformedPassword.islower()):
			entropyChange = 1
		
		password.entropy += entropyChange
		password.transformRules.append([self.__class__.__name__, entropyChange])


class CapitalizeLetterAtIndex(Rule):
 	def __init__(self, indx=None):
 		"""
 		Arguments:
 		indx -- Index of letter to which the rule is applied
 		"""
 		self.indx = indx

 	def transform(self, passwordData):
 		"""Capitalize one letter in password at certain index

		Arguments:
		passwordData -- (PassData)
		"""
 		try:
			for x in passwordData.passwordList:
				try:
					x.password = x.password[:self.indx] + x.password[self.indx].upper() + x.password[self.indx + 1:]
					estimateNewEntropyAndSaveTransformData()
				except IndexError:
					errorPrinter.printRuleWarning(self.__class__.__name__, '\'{0:1}\' - Index out of range'.format(x.password))

		except AttributeError:
			errorPrinter.printRuleWarning(self.__class__.__name__, "Wrong input data instance")
		except TypeError:
			errorPrinter.printRuleWarning(self.__class__.__name__, "Arguemnt 'indx' in contructor is Empty or is not a number")

	#Change entropy - 1
	def estimateNewEntropyAndSaveTransformData(self):
		entropyChange = 1

		password.entropy += entropyChange
		password.transformRules.append([self.__class__.__name__, entropyChange])


class DeleteLetter(Rule):
	def __init__(self, indx):
		"""
 		Arguments:
 		indx -- Index of letter to which the rule is applied
 		"""
		self.indx = indx

	def transform(self, passwordData):
		"""Delete one letter in password at certain index

		Arguments:
		passwordData -- (PassData)
		"""
		try:
			for x in passwordData.passwordList:
				try:
					x.password = re.sub(x.password[self.indx], '', x.password)
					estimateNewEntropyAndSaveTransformData()
				except IndexError:
					errorPrinter.printRuleWarning(self.__class__.__name__, '\'{0:1}\' - Index out of range'.format(x.password))

		except AttributeError:
			errorPrinter.printRuleWarning(self.__class__.__name__, "Wrong input data instance")
		except TypeError:
			errorPrinter.printRuleWarning(self.__class__.__name__, "Arguemnt 'indx' in contructor is Empty or is not a number")

	#Change entropy - 1
	def estimateNewEntropyAndSaveTransformData(self):
		entropyChange = 1

		password.entropy += entropyChange
		password.transformRules.append([self.__class__.__name__, entropyChange])
