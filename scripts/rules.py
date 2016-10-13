from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassData

import scripts.errorPrinter as errorPrinter
import scripts.config as config
import random, re, sys

class Rule(object):

	__metaclass__ = ABCMeta

	@abstractmethod
	def __init__(self, inputFromIndex, inputToIndex):
		self.inputFromIndex = inputFromIndex
		self.inputToIndex = inputToIndex

	@abstractmethod
	def transform(self, passwordData):
		"""Main method for password transformation

		Method catch errors, calculate indexes,
		call uniqueTransform method and
		estimateEntropyChangeAndSaveTransformData method
		"""
		try:
			for xPassword in passwordData.passwordList:
				fromIndex = self.inputFromIndex if self.inputFromIndex != -1 else (len(xPassword.password) - 1)
				toIndex = self.inputToIndex if self.inputToIndex != -1 else (len(xPassword.password) - 1)

				if (fromIndex > toIndex):
					passwordData.errorLog.addError(self.__class__.__name__,
												"Wrong value of input data. " + \
												'\n' + \
												"'fromIndex' must be same or lower then 'toIndex'"
												)
					continue

				transformedPassword = self.uniqueTransform(xPassword, fromIndex, toIndex)

				self.estimateEntropyChangeAndSaveTransformData(transformedPassword, xPassword)
				xPassword.password = transformedPassword

		except TypeError:
			passwordData.errorLog.addError(self.__class__.__name__,
										"Argument 'fromIndex' or 'toIndex' is not a number. " + \
										'\n ' + \
										"Input format: rules.rule_name(fromIndex, toIndex).transform(passwordData)"
										)

		except AttributeError:
			errorPrinter.addMainError(self.__class__.__name__,
									"Wrong input type of data. " + \
									'\n' + \
									"Input must be of type 'passStruct.PassData'"
									)

	@abstractmethod
	def uniqueTransform(self, xPassword, fromIndex, toIndex):
		"""
		Return:
		transformedPassword -- string
		"""
		pass

	@abstractmethod
	def estimateEntropyChangeAndSaveTransformData(self, transformedPassword, xPassword):
		"""By result of entropyCondition method
		estimate entropy change.

		Entropy values are store in config.py file
		"""
		entropyChange = config.ruleEntropyValue[self.__class__.__name__] if self.entropyCondition(transformedPassword, xPassword) else 0

		xPassword.entropy += entropyChange
		xPassword.transformRules.append([self.__class__.__name__, entropyChange])

	@abstractmethod
	def entropyCondition(self, transformedPassword, xPassword):
		"""
		Return:
		condition result -- boolean
		"""
		pass




class ApplySimplel33tFromIndexToIndex(Rule):
	def __init__(self, fromIndex, toIndex):
		super(ApplySimplel33tFromIndexToIndex, self).__init__(fromIndex, toIndex)

	def transform(self, passwordData):
		super(ApplySimplel33tFromIndexToIndex, self).transform(passwordData)

	def uniqueTransform(self, xPassword, fromIndex, toIndex):
		"""Apply simple l33t table at X letters in password

		Arguments:
		xPassword -- type of passStruct.Password
		fromIndex -- start index of applying the rule
		toIndex -- last index of applying the rule
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
		"""Apply advanced l33t table at X letters in password

		Arguments:
		xPassword -- type of passStruct.Password
		fromIndex -- start index of applying the rule
		toIndex -- last index of applying the rule
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
		"""Captalize X letters in password

		Arguments:
		xPassword -- type of passStruct.Password
		fromIndex -- start index of applying the rule
		toIndex -- last index of applying the rule
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
		"""Lower X letters in password

		Arguments:
		xPassword -- type of passStruct.Password
		fromIndex -- start index of applying the rule
		toIndex -- last index of applying the rule
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
