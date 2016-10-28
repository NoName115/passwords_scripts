#Example script to run a simple analysis

import scripts.rules as rules
import scripts.libCheck as libCheck
import scripts.loadData as loadData
import scripts.analyzer as analyzer

passwordList = loadData.LoadFromFile("tests/unit/simpleInput").loadData() #tests/unit/simpleInput #10_million_password_list_top_1000.txt

rules.ApplySimplel33tFromIndexToIndex(0, -1).transform(passwordList)
rules.ApplyAdvancedl33tFromIndexToIndex(0, -1).transform(passwordList)
rules.CapitalizeFromIndexToIndex(0, -1).transform(passwordList)
rules.LowerFromIndexToIndex(0, -1).transform(passwordList)

libCheck.CrackLib().checkResult(passwordList)
libCheck.PassWDQC().checkResult(passwordList)

passwordList.printData()

#analyzer.Analyzer().mainAnalysis(passwordList)
