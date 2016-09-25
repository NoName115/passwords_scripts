#Example script to run a simple analysis

import scripts.rules as rules
import scripts.libCheck as libCheck
import scripts.loadData as loadData
import scripts.analyzer as analyzer

passwordList = loadData.LoadFromFile("10_million_password_list_top_1000.txt").loadData()

rules.CapitalizeAllLetters().transform(passwordList)
rules.ApplySimplel33t().transform(passwordList)

libCheck.CrackLib().checkResult(passwordList)

analyzer.Analyzer().simpleAnalyze(passwordList)