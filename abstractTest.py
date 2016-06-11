import sys

from passStruct import PassData
import rules, libCheck, loadData

####################################################################
####################################################################

#Create passwordList and fill it
passwords = PassData()

#LoadData
loadData.LoadFromStdin().loadData(passwords)

#Abstract rules called
rules.CapitalizeAllLetters().transform(passwords)
rules.LowerAllLetters().transform(passwords)
rules.ApplySimplel33t().transform(passwords)

#Library-check called
libCheck.PassWDQC().checkResult(passwords)
libCheck.CrackLib().checkResult(passwords)

#Print passwordData
passwords.printData()

