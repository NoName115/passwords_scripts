from abc import ABCMeta, abstractmethod
from passStruct import PassData

import random, errorPrinter
import re


ruleEntropyValue = {
					'ApplySimplel33t' : 1,
					'ApplyAdvancedl33t' : 2,
					'CapitalizeAllLetters' : 1,
					'LowerAllLetters' : 1,
					'CapitalizeLetterAtIndex' : 1,
					'DeleteLetterAtIndex' : 1
}


class Rule(object):

	__metaclass__ = ABCMeta

	@abstractmethod
	def __init__(self):
		pass

	@abstractmethod
	def transform(self, passwordData):
		try:
			for xPassword in passwordData.passwordList:
				transformedPassword = self.uniqueTransform(xPassword)

				self.estimateEntropyChangeAndSaveTransformData(transformedPassword, xPassword)
				xPassword.password = transformedPassword

		except AttributeError:
			raise
			#errorPrinter.printRuleWarning(self.__class__.__name__, "Wrong input data instance")
		except TypeError:
			raise
			#errorPrinter.printRuleWarning(self.__class__.__name__, "Arguemnt 'indx' in contructor is Empty or is not a number")
			#errorPrinter.printRuleWarning(self.__class__.__name__, "l33t table is empty")

	@abstractmethod
	def uniqueTransform(self, xPassword):
		'''
		Return:
		zip(transformedPassword -- String, xPassword -- passStruct.Password)
		'''
		pass

	@abstractmethod
	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		entropyChange = ruleEntropyValue[self.__class__.__name__] if self.entropyCondition(transformedPassword, xPassword) else 0

		xPassword.entropy += entropyChange
		xPassword.transformRules.append([self.__class__.__name__, entropyChange])

	@abstractmethod
	def entropyCondition(self, transformedPassword, xPassword):
		pass


class RuleFromIndexToIndex(Rule):

	__metaclass__ = ABCMeta

	@abstractmethod
	def __init__(self, fromIndex, toIndex):
		self.fromIndex = fromIndex
		self.toIndex = toIndex

	@abstractmethod
	def transform(self, passwordData):
		super(RuleFromIndexToIndex, self).transform(passwordData)

	@abstractmethod
	def uniqueTransform(self, xPassword):
		pass

	@abstractmethod
	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		super(RuleFromIndexToIndex, self).estimateEntropyChangeAndSaveTransformData(transformedPassword, xPassword)

	@abstractmethod
	def entropyCondition(self, transformedPassword, xPassword):
		super(RuleFromIndexToIndex, self).entropyCondition(transformedPassword, xPassword)
		

class l33t(Rule):

	__metaclass__ = ABCMeta

	@abstractmethod
	def __init__(self, fileName):
		"""Load l33t table from file

		Arguments:
		fileName -- file from which data are loaded

		self.Variables:
		l33tDict -- key(char), value(list)
		"""
		try:
			with open(fileName, 'r') as l33tInput:
				self.l33tDict = {}
				try:
					for line in l33tInput:
						line = line.strip('\n').split(' ')

						if (line[0] in self.l33tDict):
							for i in range(1, len(line)):
								self.l33tDict[line[0]].append(line[i])
						else:
							self.l33tDict.update({line[0] : [line[1]]})
							for i in range(2, len(line)):
								self.l33tDict[line[0]].append(line[i])
				except IndexError:
					errorPrinter.printWarning(self.__class__.__name__, 'Wrong format of line in input file \'{0:1}\''.format(line))
					#Raise rule wasnt applied
		except IOError:
			errorPrinter.printWarning(self.__class__.__name__, 'File \'{0:1}\' doesn\'t exist'.format(fileName))
			#Raise rule wasnt applied

	@abstractmethod
	def transform(self, passwordData):
		super(l33t, self).transform(passwordData)

	@abstractmethod
	def uniqueTransform(self, xPassword):
		pass

	@abstractmethod
	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		super(l33t, self).estimateEntropyChangeAndSaveTransformData(transformedPassword, xPassword)

	@abstractmethod
	def entropyCondition(self, transformedPassword, xPassword):
		super(l33t, self).entropyCondition(transformedPassword, xPassword)




class ApplySimplel33t(l33t):
	def __init__(self):
		super(ApplySimplel33t, self).__init__("Simple_l33t")

	def transform(self, passwordData):
		super(ApplySimplel33t, self).transform(passwordData)

	def uniqueTransform(self, xPassword):
		"""Apply simple l33t at passwords

		Arguments:
		passwordData -- type of PassData
		tableName -- name of l33tTable to be loaded
		"""
		transformedPassword = xPassword.password
		for key in self.l33tDict:
			transformedPassword = transformedPassword.replace(key, self.l33tDict[key][random.randint(0, len(self.l33tDict[key]) - 1)])

		return transformedPassword
		
	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		super(ApplySimplel33t, self).estimateEntropyChangeAndSaveTransformData(transformedPassword, xPassword)

	def entropyCondition(self, transformedPassword, xPassword):
		if (transformedPassword is xPassword.password):
			return False
		else:
			return True


class ApplyAdvancedl33t(l33t):
	def __init__(self):
		super(ApplyAdvancedl33t, self).__init__("Advanced_l33t")

	def transform(self, passwordData):
		super(ApplyAdvancedl33t, self).transform(passwordData)

	def uniqueTransform(self, xPassword):
		"""Apply advanced l33t at passwords

		Arguments:
		passwordData -- type of PassData
		tableName -- name of l33tTable to be loaded
		"""
		transformedPassword = xPassword.password
		for key in self.l33tDict:
			transformedPassword = transformedPassword.replace(key, self.l33tDict[key][random.randint(0, len(self.l33tDict[key]) - 1)])

		return transformedPassword

	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		super(ApplyAdvancedl33t, self).estimateEntropyChangeAndSaveTransformData(transformedPassword, xPassword)

	def entropyCondition(self, transformedPassword, xPassword):
		if (transformedPassword is xPassword.password):
			return False
		else:
			return True


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

		return transformedPassword

	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		super(CapitalizeAllLetters, self).estimateEntropyChangeAndSaveTransformData(transformedPassword, xPassword)

	def entropyCondition(self, transformedPassword, xPassword):
		if (any(c.islower() for c in xPassword.password) and transformedPassword.isupper()):
			return True
		else:
			return False


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

		return transformedPassword

	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		super(LowerAllLetters, self).estimateEntropyChangeAndSaveTransformData(transformedPassword, xPassword)

	def entropyCondition(self, transformedPassword, xPassword):
		if (any(c.isupper() for c in xPassword.password) and transformedPassword.islower()):
			return True
		else:
			return False


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

			return transformedPassword
		except IndexError:
			errorPrinter.printRuleWarning(self.__class__.__name__, '\'{0:1}\' - Index out of range'.format(xPassword.password))

	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		super(CapitalizeLetterAtIndex, self).estimateEntropyChangeAndSaveTransformData(transformedPassword, xPassword)

	def entropyCondition(self, transformedPassword, xPassword):
		if (transformedPassword[self.indx].isupper() and xPassword.password[self.indx].islower()):
			return True
		else:
			return False


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
			transformedPassword = xPassword.password[:self.indx] + xPassword.password[(self.indx + 1):]

			return transformedPassword
		except IndexError:
			errorPrinter.printRuleWarning(self.__class__.__name__, '\'{0:1}\' - Index out of range'.format(xPassword.password))

	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		super(DeleteLetterAtIndex, self).estimateEntropyChangeAndSaveTransformData(transformedPassword, xPassword)

	def entropyCondition(self, transformedPassword, xPassword):
		if (len(transformedPassword) < len(xPassword.password)):
			return True
		else:
			return False
