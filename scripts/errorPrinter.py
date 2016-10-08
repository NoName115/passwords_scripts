from sys import exit
from termcolor import colored


"""Dictionary that store main errors

Especcialy, wrong type of input data
"""
mainError = {}

def addMainError(className, errorText):
	"""Store mainError message

	Arguments:
		className -- name of the class in which error occured
		errorText -- details about error
	"""
	mainError.update({className : errorText})

class RuleError():
	def __init__(self):
		"""Iniatialize class for storing errors

		Self:
		errorLog -- dictionary of errors ({className : errorDetails})
		"""
		self.errorLog = {}

	def addError(self, className, errorText):
		"""Store error message

		Arguments:
		className -- name of the class in which error occured
		errorText -- details about error
		"""
		self.errorLog.update({className : errorText})


def printError(className, errorText):
	"""Print error message and terminate program

	Arguments:
	className -- name of the class that called this method
	errorText -- details about error
	"""
	print colored("Error: ", "red"), '{0:13} - {1:30}'.format(className, errorText)
	exit(0)

def printWarning(className, errorText):
	"""Print warning message
	
	Arguments:
	className -- name of the class that called this method
	errorText -- details about error
	"""
	print colored("Warning: ", "yellow"), '{0:13} - {1:30}'.format(className, errorText)

def printRuleWarning(className, errorText):
	"""Print error, and info that rule wasn't applied to password
	
	Arguments:
	className -- name of the class that called this method
	errorText -- details about error
	"""
	printWarning(className, errorText)
	printWarning('transform \'{0:1}\''.format(className), "wasn't applied")
