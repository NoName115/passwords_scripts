import scripts.rules as rules
import scripts.dataLoader as dataLoader
import scripts.libCheck as libCheck
import scripts.analysisStruct as analysisStruct

# Load passwords
password_list = dataLoader.LoadFromFile("inputs/noNumberPasswords").load()

# Transform passwords
transformation = rules.Transformation()
#transformation.add(rules.LowerAllLetters())
transformation.add(rules.AddTwoRandomDigitsAsPrefix())
transformation.add(rules.ChangeRandomLetterToRandomLetter())
transformation.add(rules.CapitalizeLastLetter())
passInfo_List = list(map(lambda password: transformation.apply(password), password_list))

# Check passwords with PCLs
pcl = libCheck.PassCheckLib()
pcl.add(libCheck.CrackLib())
pcl.add(libCheck.PassWDQC())
pcl.add(libCheck.Zxcvbn())
pcl_data = pcl.check(passInfo_List)

# Store data
#dataLoader.StoreDataToJson(filename="inputs/countData.json").store(passInfo_List, pcl_data)

#passInfo_List, pcl_data = dataLoader.LoadFromJson('inputs/countData.json').load()

# Analysis
analyzer = analysisStruct.Analyzer(passInfo_List, pcl_data)
analyzer.addAnalysis(analysisStruct.OverallSummary())
#analyzer.addAnalysis(analysisStruct.CountOkAndNotOkPasswords())
#analyzer.addAnalysis(analysisStruct.AllOkPasswords())
analyzer.addAnalysis(analysisStruct.AllPasswordsWithPCLOutputs())
#analyzer.addAnalysis(analysisStruct.AllPasswordsWithPCLNames())
#analyzer.addAnalysis(analysisStruct.TransformedPasswordCrackLibOkPassWDQCNotOk())
#analyzer.addAnalysis(analysisStruct.LowEntropyTransformedPasswordPassPCL())

analyzer.runAnalyzes()
analyzer.printAnalyzesOutput()
