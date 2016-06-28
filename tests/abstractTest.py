import unittest
import sys

from scripts.passStruct import PassData
import scripts.rules as rules
import scripts.libCheck as libCheck
import scripts.loadData as loadData

####################################################################
####################################################################

#LoadData
passwords = loadData.LoadFromFile("tests/simpleInput").loadData()

#Abstract rules called
rules.CapitalizeAllLetters().transform(passwords)
#rules.LowerAllLetters().transform(passwords)
#rules.ApplySimplel33t().transform(passwords)

#Library-check called
libCheck.PassWDQC().checkResult(passwords)
#libCheck.CrackLib().checkResult(passwords)

#Print passwordData
passwords.printData()
