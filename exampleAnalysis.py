# Example script to run a simple analysis
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

# Store data to Json
StoreDataToJson().store(passInfoList, pclData)

# Analysis
analyzer = Analyzer(passInfoList, pclData)

analyzer.addAnalysis(PCLOutputChanged_Ok2NotOK(analyzer))
analyzer.addAnalysis(PCLOutputChanged_NotOk2Ok(analyzer))
analyzer.addAnalysis(PCLOutputChanged_NotOk2NotOk(analyzer))
analyzer.addAnalysis(lowEntropyOriginalPasswordPassPCL(analyzer))
analyzer.addAnalysis(highEntropyOriginalPasswordDontPassPCL(analyzer))
analyzer.addAnalysis(lowEntropyTransformedPasswordPassPCL(analyzer))
analyzer.addAnalysis(highEntropyTransformedPasswordDontPassPCL(analyzer))
analyzer.addAnalysis(lowEntropyChangePassPCL(analyzer))
analyzer.addAnalysis(overallSummary(analyzer))

analyzer.runAnalyzes()
analyzer.printAnalyzesOutput()
