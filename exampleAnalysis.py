# Example script to run a simple analysis
'''
import scripts.rules as rules
import scripts.libCheck as libCheck
import scripts.dataLoader as dataLoader
import scripts.analysisStruct as analysisStruct

import scripts.passSturct as passSturct
'''
from scripts.rules import *
from scripts.dataLoader import *
from scripts.libCheck import *


# Load data to list of tuple [password, entropy]
passwordList = LoadFromFile("inputs/simpleInput").load()

# Create class that contain rules
transformation = Transformation()
transformation.add(CapitalizeFirstLetter())
transformation.add(ApplySimplel33tTable())

# Applying transformations to passwords
passDataList = map(
	lambda password: transformation.apply(password),
	passwordList
	)


# Create class that contain password checking libraries
pcl = PassCheckLib()
pcl.add(CrackLib())
pcl.add(PassWDQC())

# Check passwords with pcls
pclData = pcl.check(passDataList)

print(pclData)

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