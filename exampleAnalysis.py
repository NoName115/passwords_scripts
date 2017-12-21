# Example script to run a simple analysis
import scripts.rules as rules
import scripts.dataLoader as dataLoader
import scripts.libCheck as libCheck
import scripts.analysisStruct as analysisStruct


# Load data
passinfo_list, pcl_data = dataLoader.LoadFromCSV(
	'outputs/RockYou_3used_5pcl.csv', #'RockYou_3used_5pcl.csv',
	).load()
'''
# Load data to list [pass_0, pass_1]
password_list = dataLoader.LoadFromFile(
	"inputs/wordlist_trim.txt",
	"UTF-8"
	).load()

# Create class that contain rules
transformation = rules.Transformation()
transformation.add(rules.CapitalizeFirstLetter())
transformation.add(rules.CapitalizeLastLetter())
transformation.add(rules.AddTwoRandomDigitsAsPostfixOrPrefix())
transformation.add(rules.ApplyAdvancedl33tTable())
transformation.add(rules.ChangeRandomLetterToRandomLetter())
transformation.add(rules.AddRandomLetterAsPostfixOrPrefix())
# Applying transformations to passwordsq
passinfo_list = transformation.apply(password_list)

# Create class that contain password checking libraries
pcl = libCheck.PassCheckLib()
#pcl.add(libCheck.CrackLib())
#pcl.add(libCheck.PassWDQC())
pcl.add(libCheck.Pwscore())
#pcl.add(libCheck.Zxcvbn())
#pcl.add(libCheck.Passfault())

# Check passwords with pcls
pcl_data = pcl.check(passinfo_list)

# Store data to JSON
#dataLoader.SaveDataToJson().save(passinfo_list, pcl_data)
#dataLoader.SaveDataToCSV(file_path='outputs/Transform_2pcl_advanced.csv').save(passinfo_list, pcl_data)
dataLoader.AppendDataToCSV(file_path='outputs/Transform_4pcl_advanced.csv').save(passinfo_list, pcl_data)
'''

# Run analyzes
analyzer = analysisStruct.Analyzer(passinfo_list, pcl_data)

#analyzer.addAnalysis(analysisStruct.PassfaultScoring())
#analyzer.addAnalysis(analysisStruct.ZxcvbnPalindrom())
#analyzer.addAnalysis(analysisStruct.ZxcvbnDictionary())
#analyzer.addAnalysis(analysisStruct.PassfaultKeyboardSequence())
#analyzer.addAnalysis(analysisStruct.PassWDQCPasswordPattern())
#analyzer.addAnalysis(analysisStruct.ZxcvbnPasswordPattern())
#analyzer.addAnalysis(analysisStruct.ZxcvbnPwscorePasswordPattern())

# New analyzes
#analyzer.addAnalysis(analysisStruct.PassfaultOneMatch())
#analyzer.addAnalysis(analysisStruct.PassfaultMatchWorstPasswords())
#analyzer.addAnalysis(analysisStruct.ZxcvbnCommonPasswords())
#analyzer.addAnalysis(analysisStruct.EmailAddresses())
#analyzer.addAnalysis(analysisStruct.CracklibPwscorePattern())
#analyzer.addAnalysis(analysisStruct.PassWDQCPasswordLength())

# Analyzes for PCLs comparison
#analyzer.addAnalysis(analysisStruct.LibrariesSummary())
#analyzer.addAnalysis(analysisStruct.LibrariesTopOkPasswords())
analyzer.addAnalysis(analysisStruct.AllRejectedOneAccepted())
#analyzer.addAnalysis(analysisStruct.AllAccepted())

#analyzer.addAnalysis(analysisStruct.LibrariesCrackLibTopRejection())
#analyzer.addAnalysis(analysisStruct.LibrariesPassWDQCTopRejection())
#analyzer.addAnalysis(analysisStruct.LibrariesPassfaulTopRejection())
#analyzer.addAnalysis(analysisStruct.LibrariesPwscoreTopRejection())
#analyzer.addAnalysis(analysisStruct.LibrariesZxcvbnTopRejection())

#analyzer.addAnalysis(analysisStruct.PassfaultOriginalOverallSummary())

#analyzer.addAnalysis(analysisStruct.TestAnalysis())

analyzer.runAnalyzes()

'''
# Load data
passinfo_list, pcl_data = dataLoader.LoadFromCSV(
	'outputs/Transform_4pcl_advanced.csv', #'RockYou_3used_5pcl.csv',
	).load()

analyzer = analysisStruct.Analyzer(passinfo_list, pcl_data)

# Analyzes for transformed passwords, for PCLs comparison
analyzer.addAnalysis(analysisStruct.LibrariesSummaryTransformedPass())
analyzer.addAnalysis(analysisStruct.AllAcceptedOneRejected())

#analyzer.addAnalysis(analysisStruct.PassfaultTransformedOverallSummary())

analyzer.runAnalyzes()
'''
