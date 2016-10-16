#Example script to run a simple analysis

import scripts.rules as rules
import scripts.libCheck as libCheck
import scripts.loadData as loadData
import scripts.analyzer as analyzer

passwordList = loadData.LoadFromFile("tests/unit/simpleInput").loadData()

rules.ApplySimplel33tFromIndexToIndex(0, 2).transform(passwordList)
rules.ApplyAdvancedl33tFromIndexToIndex(0, 0).transform(passwordList)
rules.CapitalizeFromIndexToIndex(0, 0).transform(passwordList)
rules.LowerFromIndexToIndex(0, 0).transform(passwordList)

libCheck.CrackLib().checkResult(passwordList)
libCheck.PassWDQC().checkResult(passwordList)

passwordList.printData()

#analyzer.Analyzer().simpleAnalyze(passwordList)