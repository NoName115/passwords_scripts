# Example script to run a simple analysis

import scripts.rules as rules
import scripts.libCheck as libCheck
import scripts.loadData as loadData
import scripts.analyzer as analyzer
import scripts.analysisStruct as analysisStruct

#passwordList = loadData.LoadFromFile("inputs/10_million_password_list_top_1000").loadData()  # simpleInput	10_million_password_list_top_1000
passwordList = loadData.LoadFromJson("inputs/jsonData.json").loadData()
#passwordList = loadData.LoadFromStdin().loadData()

#rules.CapitalizeAllLetters().transform(passwordList)
#rules.CapitalizeFirstLetter().transform(passwordList)
#rules.CapitalizeLastLetter().transform(passwordList)
#rules.LowerAllLetters().transform(passwordList)
#rules.LowerFirstLetter().transform(passwordList)
#rules.LowerLastLetter().transform(passwordList)
#rules.ApplySimplel33tTable().transform(passwordList)
#rules.ApplyAdvancedl33tTable().transform(passwordList)

#libCheck.CrackLib().checkResult(passwordList)
#libCheck.PassWDQC().checkResult(passwordList)

#passwordList.storeDataToJson("inputs/jsonData.json")

#analyzer.Analyzer().mainAnalysis(passwordList)

analysis = analysisStruct.Analyzer()
analysis.mainAnalysis(passwordList)

analysisStruct.AnalyzerPrinter(analysis).printData()
