import random

import scripts.rules as rules
import scripts.libCheck as libCheck
import scripts.loadData as loadData

#LoadData
passwords = loadData.LoadFromFile("tests/analytical/analyticInput").loadData()

#Apply rules to passwords
#rules.CapitalizeAllLetters().transform(passwords)
#rules.LowerAllLetters().transform(passwords)
#rules.CapitalizeLetterAtIndex(random.randint(0, 5)).transform(passwords)
rules.ApplyAdvancedl33t().transform(passwords)

#Check passwords throught 2 libs
libCheck.PassWDQC().checkResult(passwords)
libCheck.CrackLib().checkResult(passwords)

#Print outputData
passwords.printLibCheckData()