from abc import ABCMeta, abstractmethod
from passStruct import PassData, Password

import random

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
			passwordData.password = passwordData.password.upper()

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
			passwordData.password = passwordData.password.lower()

		else:
			print "Wrong input password format"

#TODO.... Popis
#Simple/Advande l33t table
#Arguments: table(class l33tTable)
class Applyl33t(Rule):
	def __init__(self):
		super(Applyl33t, self).__init__()

	def transform(self, passwordData, l33tDict):
		if (isinstance(passwordData, PassData)):
			for x in passwordData.passwordList:
				for key in l33tDict:
					x.password = x.password.replace(key, l33tDict[key][random.randint(0, len(l33tDict[key]) - 1)])


#Capitalize one letter from password at certain index
#Arguments: Index(number)
class CapitalizeLetterAtIndex(Rule):
 	def __init__(self):
 		super(CapitalizeLetterAtIndex, self).__init__()

 	def transform(self, passwordData, indx):
 		if (isinstance(indx, int)) or (indx.isdigit()):
			if (isinstance(passwordData, PassData)):
				for x in passwordData.passwordList:
					x.password = x.password[:indx] + x.password[indx].upper() + self.password[indx + 1:]

			elif (isinstance(passwordData, Password)):
				passwordData.password = passwordData.password[:indx] + passwordData.password[indx].upper() + passwordData.password[indx + 1:]

			else:
				print "Wrong input password format"
		else:
			print "Wrong argument, index is not a number"


#Delete letter at index from password
#Arguments: Index(number)
class DeleteLetter(Rule):
	def __init__(self):
		super(DeleteLetter, self).__init__()

	def transform(self, passwordData, indx):
		if (isinstance(indx, int)) or (indx.isdigit()):
			if (isinstance(passwordData, PassData)):
				for x in passwordData.passwordList:
					x.password = re.sub(x.password[indx], '', x.password)

			elif (isinstance(passwordData, Password)):
				passwordData.password = re.sub(passwordData.password[indx], '', passwordData.password)

			else:
				print "Wrong input password format"
		else:
			print "Wrong argument, index is not a number"