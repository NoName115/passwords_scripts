# Example script to run a simple analysis
import scripts.rules as rules
import scripts.dataLoader as dataLoader
import scripts.libCheck as libCheck
import scripts.analysisStruct as analysisStruct


# Load data to list of tuples [password, entropy]
passwordList = dataLoader.LoadFromFile(
	"inputs/10_million_password_list_top_1000"
	).load()

# Create class that contain rules
transformation = rules.Transformation()
transformation.add(rules.CapitalizeFirstLetter())
transformation.add(rules.ApplyAdvancedl33tTable())

# Applying transformations to passwords
passInfoList = list(map(
	lambda password: transformation.apply(password),
	passwordList
	))

# Create class that contain password checking libraries
pcl = libCheck.PassCheckLib()
pcl.add(libCheck.CrackLib())
pcl.add(libCheck.PassWDQC())

# Check passwords with pcls
pclData = pcl.check(passInfoList)

# Store data to Json
dataLoader.StoreDataToJson().store(passInfoList, pclData)

# Analysis
analyzer = analysisStruct.Analyzer(passInfoList, pclData)

analyzer.addAnalysis(analysisStruct.PCLOutputChangedFromOk2NotOK())
analyzer.addAnalysis(analysisStruct.PCLOutputChangedFromNotOk2Ok())
analyzer.addAnalysis(analysisStruct.PCLOutputChangedFromNotOk2NotOk())
analyzer.addAnalysis(analysisStruct.LowEntropyOriginalPasswordPassPCL())
analyzer.addAnalysis(analysisStruct.HighEntropyOriginalPasswordDontPassPCL())
analyzer.addAnalysis(analysisStruct.LowEntropyTransformedPasswordPassPCL())
analyzer.addAnalysis(analysisStruct.HighEntropyTransformedPasswordDontPassPCL())
analyzer.addAnalysis(analysisStruct.LowEntropyChangePassPCL())
analyzer.addAnalysis(analysisStruct.OverallSummary())

analyzer.runAnalyzes()
analyzer.printAnalyzesOutput()
