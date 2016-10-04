from abc import ABCMeta, abstractmethod
from passStruct import PassData

import random, errorPrinter, config
import re


class Rule(object):

	__metaclass__ = ABCMeta

	@abstractmethod
	def __init__(self, inputFromIndex, inputToIndex):
		self.inputFromIndex = inputFromIndex
		self.inputToIndex = inputToIndex

	@abstractmethod
	def transform(self, passwordData):
		try:
			for xPassword in passwordData.passwordList:
				fromIndex = self.inputFromIndex if self.inputFromIndex != -1 else (len(xPassword.password) - 1)
				toIndex = self.inputToIndex if self.inputToIndex != -1 else (len(xPassword.password) - 1)

				transformedPassword = self.uniqueTransform(xPassword, fromIndex, toIndex)

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
	def uniqueTransform(self, xPassword, fromIndex, toIndex):
		'''
		Return:
		transformedPassword -- string
		'''
		pass

	@abstractmethod
	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		entropyChange = config.ruleEntropyValue[self.__class__.__name__] if self.entropyCondition(transformedPassword, xPassword) else 0

		xPassword.entropy += entropyChange
		xPassword.transformRules.append([self.__class__.__name__, entropyChange])

	@abstractmethod
	def entropyCondition(self, transformedPassword, xPassword):
		pass




class ApplySimplel33tFromIndexToIndex(Rule):
	def __init__(self, fromIndex, toIndex):
		super(ApplySimplel33tFromIndexToIndex, self).__init__(fromIndex, toIndex)

	def transform(self, passwordData):
		super(ApplySimplel33tFromIndexToIndex, self).transform(passwordData)

	def uniqueTransform(self, xPassword, fromIndex, toIndex):
		"""Apply simple l33t at passwords

		Arguments:
		passwordData -- type of PassData
		tableName -- name of l33tTable to be loaded
		"""
		transformedPassword = xPassword.password
		for key in config.simpleL33tTable:
			transformedPassword = transformedPassword[ : fromIndex] + \
								transformedPassword[fromIndex : toIndex + 1].replace(key, config.simpleL33tTable[key][random.randint(0, len(config.simpleL33tTable[key]) - 1)]) + \
								transformedPassword[toIndex + 1 : ]

		return transformedPassword
		
	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		super(ApplySimplel33tFromIndexToIndex, self).estimateEntropyChangeAndSaveTransformData(transformedPassword, xPassword)

	def entropyCondition(self, transformedPassword, xPassword):
		if (transformedPassword == xPassword.password):
			return False
		else:
			return True


class ApplyAdvancedl33tFromIndexToIndex(Rule):
	def __init__(self, fromIndex, toIndex):
		super(ApplyAdvancedl33tFromIndexToIndex, self).__init__(fromIndex, toIndex)

	def transform(self, passwordData):
		super(ApplyAdvancedl33tFromIndexToIndex, self).transform(passwordData)

	def uniqueTransform(self, xPassword, fromIndex, toIndex):
		"""Apply advanced l33t at passwords

		Arguments:
		passwordData -- type of PassData
		tableName -- name of l33tTable to be loaded
		"""
		transformedPassword = xPassword.password
		for key in config.advancedL33tTable:
			transformedPassword = transformedPassword[ : fromIndex] + \
								transformedPassword[fromIndex : toIndex + 1].replace(key, config.advancedL33tTable[key][random.randint(0, len(config.advancedL33tTable[key]) - 1)]) + \
								transformedPassword[toIndex + 1: ]

		return transformedPassword

	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		super(ApplyAdvancedl33tFromIndexToIndex, self).estimateEntropyChangeAndSaveTransformData(transformedPassword, xPassword)

	def entropyCondition(self, transformedPassword, xPassword):
		if (transformedPassword == xPassword.password):
			return False
		else:
			return True


class CapitalizeFromIndexToIndex(Rule):
	def __init__(self, fromIndex, toIndex):
		super(CapitalizeFromIndexToIndex, self).__init__(fromIndex, toIndex)

	def transform(self, passwordData):
		super(CapitalizeFromIndexToIndex, self).transform(passwordData)
	
	def uniqueTransform(self, xPassword, fromIndex, toIndex):
		"""Capitalize all letters in password

		Arguments:
		passwordData -- (PassData)
		"""
		transformedPassword = xPassword.password[ : fromIndex] + \
							xPassword.password[fromIndex : toIndex + 1].upper() + \
							xPassword.password[toIndex + 1 : ]

		return transformedPassword

	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		super(CapitalizeFromIndexToIndex, self).estimateEntropyChangeAndSaveTransformData(transformedPassword, xPassword)

	def entropyCondition(self, transformedPassword, xPassword):
		if (any(c.islower() for c in xPassword.password) and transformedPassword.isupper()):
			return True
		else:
			return False


class LowerFromIndexToIndex(Rule):
	def __init__(self, fromIndex, toIndex):
		super(LowerFromIndexToIndex, self).__init__(fromIndex, toIndex)

	def transform(self, passwordData):
		super(LowerFromIndexToIndex, self).transform(passwordData)

	def uniqueTransform(self, xPassword, fromIndex, toIndex):
		"""Lower all letters in password

		Arguments:
		passwordData -- (PassData)
		"""
		transformedPassword = xPassword.password[ : fromIndex] + \
							xPassword.password[fromIndex : toIndex + 1].lower() + \
							xPassword.password[toIndex + 1 : ]

		return transformedPassword

	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		super(LowerFromIndexToIndex, self).estimateEntropyChangeAndSaveTransformData(transformedPassword, xPassword)

	def entropyCondition(self, transformedPassword, xPassword):
		if (any(c.isupper() for c in xPassword.password) and transformedPassword.islower()):
			return True
		else:
			return False
