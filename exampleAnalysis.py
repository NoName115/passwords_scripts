# Example script to run a simple analysis
'''
import scripts.rules as rules
import scripts.libCheck as libCheck
import scripts.dataLoader as dataLoader
import scripts.analysisStruct as analysisStruct

import scripts.passStruct as passStruct
'''
from scripts.rules import *
from scripts.dataLoader import *
from scripts.libCheck import *
from scripts.analysisStruct import *

from scripts.passStruct import PassData


# Load data to list of tuple [password, entropy]
passwordList = LoadFromFile("inputs/10_million_password_list_top_1000").load()

# Create class that contain rules
transformation = Transformation()
transformation.add(CapitalizeFirstLetter())
transformation.add(ApplyAdvancedl33tTable())

# Applying transformations to passwords
passInfoList = list(map(
	lambda password: transformation.apply(password),
	passwordList
	))

# Create class that contain password checking libraries
pcl = PassCheckLib()
pcl.add(CrackLib())
pcl.add(PassWDQC())

# Check passwords with pcls
pclData = pcl.check(passInfoList)

# Analysis
analyzer = Analyzer(passInfoList, pclData)

#analyzer.addAnalysis(PCLOutputChanged_Ok2NotOK(analyzer))
analyzer.addAnalysis(PCLOutputChanged_NotOk2Ok(analyzer))
#analyzer.addAnalysis(PCLOutputChanged_NotOk2NotOk(analyzer))
#analyzer.addAnalysis(lowEntropyOriginalPasswordPassPCL(analyzer))
#analyzer.addAnalysis(highEntropyOriginalPasswordDontPassPCL(analyzer))
#analyzer.addAnalysis(lowEntropyTransformedPasswordPassPCL(analyzer))
#analyzer.addAnalysis(highEntropyTransformedPasswordDontPassPCL(analyzer))
#analyzer.addAnalysis(lowEntropyChangePassPCL(analyzer))
#analyzer.addAnalysis(overallSummary(analyzer))

analyzer.runAnalysis()
analyzer.printAnalysisOutput()
'''
analysis_1 = PCLOutputChanged_Ok2NotOK(analyzer)
analysis_1.runAnalysis()
print(analysis_1.getAnalysisOutput())

analysis_2 = PCLOutputChanged_NotOk2Ok(analyzer)
analysis_2.runAnalysis()
print(analysis_2.getAnalysisOutput())

analysis_2 = PCLOutputChanged_NotOk2NotOk(analyzer)
analysis_2.runAnalysis()
print(analysis_2.getAnalysisOutput())

analysis_2 = lowEntropyOriginalPasswordPassPCL(analyzer)
analysis_2.runAnalysis()
print(analysis_2.getAnalysisOutput())

analysis_2 = highEntropyOriginalPasswordDontPassPCL(analyzer)
analysis_2.runAnalysis()
print(analysis_2.getAnalysisOutput())

analysis_2 = lowEntropyTransformedPasswordPassPCL(analyzer)
analysis_2.runAnalysis()
print(analysis_2.getAnalysisOutput())

analysis_2 = highEntropyTransformedPasswordDontPassPCL(analyzer)
analysis_2.runAnalysis()
print(analysis_2.getAnalysisOutput())

analysis_2 = lowEntropyChangePassPCL(analyzer)
analysis_2.runAnalysis()
print(analysis_2.getAnalysisOutput())

analysis_2 = overallSummary(analyzer)
analysis_2.runAnalysis()
print(analysis_2.getAnalysisOutput())
'''

### TEST
'''
test = PassData(
	passDataList[0],
	pclData[passDataList[0].originalData[0]],
	pclData[passDataList[0].transformedData[0]]
	)
print(test.debugData())
'''

'''
# simpleInput	10_million_password_list_top_1000
passwordList = dataLoader.LoadFromFile(
    "inputs/10_million_password_list_top_1000").transformToPassData()
# passwordList = dataLoader.LoadFromJson("inputs/jsonData.json").transformToPassData()
# passwordList = dataLoader.LoadFromStdin().transformToPassData()

# rules.CapitalizeAllLetters().transform(passwordList)
rules.CapitalizeFirstLetter().transform(passwordList)
# rules.CapitalizeLastLetter().transform(passwordList)
# rules.LowerAllLetters().transform(passwordList)
# rules.LowerFirstLetter().transform(passwordList)
rules.LowerLastLetter().transform(passwordList)
rules.ApplySimplel33tTable().transform(passwordList)
# rules.ApplyAdvancedl33tTable().transform(passwordList)

libCheck.CrackLib().checkResult(passwordList)
libCheck.PassWDQC().checkResult(passwordList)

passwordList.storeDataToJson("inputs/jsonData.json")

analysis = analysisStruct.Analyzer(passwordList)
analysis.mainAnalysis()

analysisStruct.AnalyzerPrinter(analysis).printMainAnalysis()
'''
