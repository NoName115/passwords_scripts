from abc import ABCMeta, abstractmethod
from passStruct import PassData, Password

import random


#Decorator for saving transformData to passData
#TransformData: Name of the class(rule name), new password entropy
def saveTransformData(fun):
	def inner(self, passwordData):
		for x in passwordData:
			x.transformRules.append([self.__class__.__name__, x.entropy])
		return fun(self, passwordData)
	return inner


class Rule(object):

	__metaclass__ = ABCMeta

	@abstractmethod
	def __init__(self):
		pass

	@abstractmethod
	def transform(self, passwordData):
		pass


class l33t(object):

	__metaclass__ = ABCMeta

	@abstractmethod
	def __init__(self):
		pass

	@abstractmethod
	def transform(self, passwordData):
		pass

	#@abstractmethod
	def loadToDict(self, fileName):
		with open(fileName, 'r') as l33tInput:
			l33t = {}

			for line in l33tInput:
				line = line.strip('\n').split(' ')

				if (line[0] in l33t):
					for i in range(1, len(line)):
						l33t[line[0]].append(line[i])
				else:
					l33t.update({line[0] : [line[1]]})
					for i in range(2, len(line)):
						l33t[line[0]].append(line[i])
		return l33t


#Method 'transform' apply simple l33t at passwords
#Method arguments: passwordData (Type is PassData or Password)
class ApplySimplel33t(l33t):
	def __init__(self):
		super(ApplySimplel33t, self).__init__()

	@saveTransformData
	def transform(self, passwordData):
		l33tDict = self.loadToDict("Simple_l33t")

		if (isinstance(passwordData, PassData)):
			for x in passwordData.passwordList:
				for key in l33tDict:
					x.password = x.password.replace(key, l33tDict[key][random.randint(0, len(l33tDict[key]) - 1)])

		elif (isinstance(passwordData, Password)):
			passwordData.password = passwordData.password.replace(key, l33tDict[key][random.randint(0, len(l33tDict[key]) - 1)])

		else:
			print("Wrong input passwordData format")


#Method 'transform' apply advanced l33t at passwords
#Method arguments: passwordData (Type is PassData or Password)
class ApplyAdvancedl33t(l33t):
	def __init__(self):
		super(ApplyAdvancedl33t, self).__init__()

	@saveTransformData
	def transform(self, passwordData):
		l33tDict = self.loadToDict("Advanced_l33t")

		if (isinstance(passwordData, PassData)):
			for x in passwordData.passwordList:
				for key in l33tDict:
					x.password = x.password.replace(key, l33tDict[key][random.randint(0, len(l33tDict[key]) - 1)])

		elif (isinstance(passwordData, Password)):
			passwordData.password = passwordData.password.replace(key, l33tDict[key][random.randint(0, len(l33tDict[key]) - 1)])

		else:
			print("Wrong input passwordData format")



#Method 'transform' capitalize all letters in password
#Method arguments: passwordData (Type is PassData or Password)
class CapitalizeAllLetters(Rule):
	def __init__(self):
		super(CapitalizeAllLetters, self).__init__()

	@saveTransformData
	def transform(self, passwordData):
		if (isinstance(passwordData, PassData)):
			for x in passwordData.passwordList:
				x.password = x.password.upper()

		elif (isinstance(passwordData, Password)):
			passwordData.password = passwordData.password.upper()

		else:
			print("Wrong input passwordData format")


#Method 'transform' lower all letters in password
#Method arguments: passwordData (Type is PassData or Password)
class LowerAllLetters(Rule):
	def __init__(self):
		super(LowerAllLetters, self).__init__()

	@saveTransformData
	def transform(self, passwordData):
		if (isinstance(passwordData, PassData)):
			for x in passwordData.passwordList:
				x.password = x.password.lower()

		elif (isinstance(passwordData, Password)):
			passwordData.password = passwordData.password.lower()

		else:
			print("Wrong input passwordData format")


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
				print("Wrong input passwordData format")
		else:
			print("Wrong argument, index is not a number")


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
				print("Wrong input passwordData format")
		else:
			print("Wrong argument, index is not a number")
