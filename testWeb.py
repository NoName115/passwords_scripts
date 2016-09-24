####################
### DEBUG script ###
####################

import scripts.rules as rules
import scripts.libCheck as libCheck
import scripts.loadData as loadData

import scripts.analyzer as analyzer

passwordList = loadData.LoadFromFile("10_million_password_list_top_1000.txt").loadData()
#passwordList = loadData.LoadFromStdin().loadData()

#rules.CapitalizeAllLetters().transform(passwordList)

libCheck.CrackLib().checkResult(passwordList)
libCheck.PassWDQC().checkResult(passwordList)

analyzer.Tager().tagPasswords(passwordList)
analyzer.Analyzer().simpleAnalyze(passwordList)

#passwordList.printLibCheckData()
