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
analysis_1 = pclOutputChanged_Ok2NotOK(analyzer)
analysis_1.runAnalysis()
analysis_1.printAnalysisOutput()

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