from abc import ABCMeta, abstractmethod
from passStruct import PassData

import random, errorPrinter
import re

class Rule(object):

	__metaclass__ = ABCMeta

	@abstractmethod
	def __init__(self):
		pass

	@abstractmethod
	def transform(self, passwordData):
		try:
			for xPassword in passwordData.passwordList:
				self.uniqueTransform(xPassword)

		except AttributeError:
			errorPrinter.printRuleWarning(self.__class__.__name__, "Wrong input data instance")
		except TypeError:
			errorPrinter.printRuleWarning(self.__class__.__name__, "Arguemnt 'indx' in contructor is Empty or is not a number")

	@abstractmethod
	def uniqueTransform(self, passwordData):
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

	def transform(self, passwordData, tableName):
		"""Apply l33t at passwords

		Arguments:
		passwordData -- type of PassData
		tableName -- name of l33tTable to be loaded
		"""
		try:
			l33tDict = self.loadToDict(tableName)

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

	def uniqueTransform(self, passwordData):
		pass

class ApplySimplel33t(l33t):
	def __init__(self):
		super(ApplySimplel33t, self).__init__()

	def transform(self, passwordData):
		super(ApplySimplel33t, self).transform(passwordData, "Simple_l33t")
		
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
		super(ApplySimplel33t, self).transform(passwordData, "Advanced_l33t")

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
		super(CapitalizeAllLetters, self).transform(passwordData)
		
	def uniqueTransform(self, xPassword):
		"""Capitalize all letters in password

		Arguments:
		passwordData -- (PassData)
		"""
		transformedPassword = xPassword.password.upper()
		self.estimateNewEntropyAndSaveTransformData(transformedPassword, xPassword)
		xPassword.password = transformedPassword

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
		super(LowerAllLetters, self).transform(passwordData)

	def uniqueTransform(self, xPassword):
		"""Lower all letters in password

		Arguments:
		passwordData -- (PassData)
		"""
		transformedPassword = xPassword.password.lower()
		self.estimateNewEntropyAndSaveTransformData(transformedPassword, xPassword)
		xPassword.password = transformedPassword

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
 		super(CapitalizeLetterAtIndex, self).transform(passwordData)

	def uniqueTransform(self, xPassword):
		"""Capitalize one letter in password at certain index

		Arguments:
		passwordData -- (PassData)
		"""
		try:
			transformedPassword = xPassword.password[:self.indx] + \
								xPassword.password[self.indx].upper() + \
								xPassword.password[self.indx + 1:]
			self.estimateNewEntropyAndSaveTransformData(transformedPassword, xPassword)
			xPassword.password = transformedPassword
		except IndexError:
			errorPrinter.printRuleWarning(self.__class__.__name__, '\'{0:1}\' - Index out of range'.format(xPassword.password))

	#Change entropy - 1
	def estimateNewEntropyAndSaveTransformData(self, transformedPassword, password):
		entropyChange = 0
		if (transformedPassword[self.indx].isupper() and password.password[self.indx].islower()):
			entropyChange = 1

		password.entropy += entropyChange
		password.transformRules.append([self.__class__.__name__, entropyChange])


class DeleteLetterAtIndex(Rule):
	def __init__(self, indx):
		"""
 		Arguments:
 		indx -- Index of letter to which the rule is applied
 		"""
		self.indx = indx

	def transform(self, passwordData):
		super(DeleteLetterAtIndex, self).transform(passwordData)

	def uniqueTransform(self, xPassword):
		"""Delete one letter in password at certain index

		Arguments:
		passwordData -- (PassData)
		"""
		try:
			transformedPassword = xPassword.password[:self.indx] + xPassword.password[(self.indx+1):]
			self.estimateNewEntropyAndSaveTransformData(transformedPassword, xPassword)
			xPassword.password = transformedPassword
		except IndexError:
			errorPrinter.printRuleWarning(self.__class__.__name__, '\'{0:1}\' - Index out of range'.format(xPassword.password))

	#Change entropy - 1
	def estimateNewEntropyAndSaveTransformData(self, transformedPassword, password):
		entropyChange = 0
		if (len(transformedPassword) < len(password.password)):
			entropyChange = 1

		password.entropy += entropyChange
		password.transformRules.append([self.__class__.__name__, entropyChange])
