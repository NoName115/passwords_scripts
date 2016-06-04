from abc import ABCMeta, abstractmethod
from passStruct import PassData, Password


class Rule(object):

	__metaclass__ = ABCMeta

	@abstractmethod
	def __init__(self):
		pass

	@abstractmethod
	def transform(self, passwordData):
		pass



#Method 'transform' capitalize all letters in password
#Method arguments: passwordData (Type is PassData or Password)
class CapitalizeAllLetters(Rule):
	def __init__(self):
		super(CapitalizeAllLetters, self).__init__()

	def transform(self, passwordData):
		if (isinstance(passwordData, PassData)):
			for x in passwordData.passwordList:
				x.password = x.password.upper()

		elif (isinstance(passwordData, Password)):
			Password.password = Password.password.upper()

		else:
			print "Wrong input password format"


#Method 'transform' lower all letters in password
#Method arguments: passwordData (Type is PassData or Password)
class LowerAllLetters(Rule):
	def __init__(self):
		super(LowerAllLetters, self).__init__()

	def transform(self, passwordData):
		if (isinstance(passwordData, PassData)):
			for x in passwordData.passwordList:
				x.password = x.password.lower()

		elif (isinstance(passwordData, Password)):
			Password.password = Password.password.lower()

		else:
			print "Wrong input password format"