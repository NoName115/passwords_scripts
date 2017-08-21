# Example script to run a simple analysis
import scripts.rules as rules
import scripts.dataLoader as dataLoader
import scripts.libCheck as libCheck
import scripts.analysisStruct as analysisStruct


# Load data to list of tuples [password, entropy]
password_list = dataLoader.LoadFromFile(
	"inputs/500-worst-passwords.txt"
	).load()

# Create class that contain rules
transformation = rules.Transformation()
transformation.add(rules.CapitalizeFirstLetter())
transformation.add(rules.ApplyAdvancedl33tTable())

# Applying transformations to passwords
passinfo_list = transformation.apply(password_list)

# Create class that contain password checking libraries
pcl = libCheck.PassCheckLib()
pcl.add(libCheck.CrackLib())
pcl.add(libCheck.PassWDQC())
pcl.add(libCheck.Pwscore())
pcl.add(libCheck.Zxcvbn())

# Check passwords with pcls
pcl_data = pcl.check(passinfo_list)

# Store data to JSON
dataLoader.SaveDataToJson(filename="outputs/temp").save(passinfo_list, pcl_data)

'''
# Load data from JSON
passinfo_list, pcl_data = dataLoader.LoadFromJson(
	'outputs/Ashley_Madison.json'
	).load()
'''

# Run analyzes
analyzer = analysisStruct.Analyzer(passinfo_list, pcl_data)
analyzer.addAnalysis(analysisStruct.SecondAnalysis())
analyzer.runAnalyzes()
