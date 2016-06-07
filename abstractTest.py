import sys

from passStruct import PassData
import rules, libCheck



def Loadl33t(fileName, delimeter=' '):
	with open(fileName, 'r') as l33tInput:
		l33t = {}

		for line in l33tInput:
			line = line.strip('\n').split(delimeter)

			if (line[0] in l33t):
				for i in range(1, len(line)):
					l33t[line[0]].append(line[i])
			else:
				l33t.update({line[0] : [line[1]]})
				for i in range(2, len(line)):
					l33t[line[0]].append(line[i])
	return l33t

####################################################################
####################################################################

#Create passwordList and fill it
passwords = PassData()

for line in sys.stdin:
	passwords.add(line.rstrip('\n'))

#l33t Table
l33tDic = Loadl33t("Simple_l33t", ' ')

#Abstract rules called
rules.CapitalizeAllLetters().transform(passwords)
rules.LowerAllLetters().transform(passwords)
rules.Applyl33t().transform(passwords, l33tDic)

#Library-check called
libCheck.PassWDQC().checkResult(passwords)
libCheck.CrackLib().checkResult(passwords, ": ")

#Print passwordData
passwords.printData()