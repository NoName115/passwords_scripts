import sys
import random, subprocess

from passStruct import PassData
import rules


#Create passwordList and fill it
passwords = PassData()

for line in sys.stdin:
	passwords.add(line.rstrip('\n'))

#Abstract rules called
rules.CapitalizeAllLetters().transform(passwords)
rules.LowerAllLetters().transform(passwords)

passwords.printAll()
