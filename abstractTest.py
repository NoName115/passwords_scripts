import sys

import subprocess

from passStruct import PassData
import rules, libCheck


#Create passwordList and fill it
passwords = PassData()

for line in sys.stdin:
	passwords.add(line.rstrip('\n'))

#Abstract rules called
rules.CapitalizeAllLetters().transform(passwords)
rules.LowerAllLetters().transform(passwords)

#Library-check called
libCheck.PassWDQC().checkResult(passwords)
libCheck.CrackLib().checkResult(passwords, ":")

#Print passwordData
passwords.printData()
