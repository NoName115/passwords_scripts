# Example script to run a simple analysis
from scripts.analysisBase import Analyzer

import scripts.rules as rules
import scripts.dataLoader as dataLoader
import scripts.libCheck as libCheck
import scripts.analyzes as analyzes


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
analyzer = Analyzer(passinfo_list, pcl_data)

#analyzer.addAnalysis(analyzes.PassfaultScoring())
#analyzer.addAnalysis(analyzes.ZxcvbnPalindrom())
#analyzer.addAnalysis(analyzes.ZxcvbnDictionary())
#analyzer.addAnalysis(analyzes.PassfaultKeyboardSequence())
#analyzer.addAnalysis(analyzes.PassWDQCPasswordPattern())
#analyzer.addAnalysis(analyzes.ZxcvbnPasswordPattern())
#analyzer.addAnalysis(analyzes.ZxcvbnPwscorePasswordPattern())

# New analyzes
#analyzer.addAnalysis(analyzes.PassfaultOneMatch())
#analyzer.addAnalysis(analyzes.PassfaultMatchWorstPasswords())
#analyzer.addAnalysis(analyzes.ZxcvbnCommonPasswords())
#analyzer.addAnalysis(analyzes.EmailAddresses())
#analyzer.addAnalysis(analyzes.CracklibPwscorePattern())
#analyzer.addAnalysis(analyzes.PassWDQCPasswordLength())

# Analyzes for PCLs comparison
analyzer.addAnalysis(analyzes.LibrariesSummary())
#analyzer.addAnalysis(analyzes.LibrariesTopOkPasswords())
#analyzer.addAnalysis(analyzes.AllRejectedOneAccepted())
#analyzer.addAnalysis(analyzes.AllAccepted())
#analyzer.addAnalysis(analyzes.LibrariesCrackLibTopRejection())
#analyzer.addAnalysis(analyzes.LibrariesPassWDQCTopRejection())
#analyzer.addAnalysis(analyzes.LibrariesPassfaulTopRejection())
#analyzer.addAnalysis(analyzes.LibrariesPwscoreTopRejection())
#analyzer.addAnalysis(analyzes.LibrariesZxcvbnTopRejection())
#analyzer.addAnalysis(analyzes.PassfaultOriginalOverallSummary())
#analyzer.addAnalysis(analyzes.TestAnalysis())

analyzer.runAnalyzes()
