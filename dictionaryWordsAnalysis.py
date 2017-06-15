import scripts.rules as rules
import scripts.dataLoader as dataLoader
import scripts.libCheck as libCheck
import scripts.analysisStruct as analysisStruct

# Load passwords
password_list = dataLoader.LoadFromFile("inputs/noNumberPasswords").load()

# Transform passwords
transformation = rules.Transformation()
transformation.add(rules.LowerAllLetters())
transformation.add(rules.AddTwoRandomDigitsAsPrefix())
#transformation.add(rules.ChangeRandomLetterToRandomLetter())
transformation.add(rules.CapitalizeLastLetter())
passInfo_List = list(map(lambda password: transformation.apply(password), password_list))

# Check passwords with PCLs
pcl = libCheck.PassCheckLib()
pcl.add(libCheck.CrackLib())
pcl.add(libCheck.PassWDQC())
pcl_data = pcl.check(passInfo_List)

# Analysis
analyzer = analysisStruct.Analyzer(passInfo_List, pcl_data)
analyzer.addAnalysis(analysisStruct.OverallSummary())
analyzer.addAnalysis(analysisStruct.CountOkAndNotOkPasswords())
analyzer.addAnalysis(analysisStruct.TransformedPasswordCrackLibOkPassWDQCNotOk())

analyzer.runAnalyzes()
analyzer.printAnalyzesOutput()
