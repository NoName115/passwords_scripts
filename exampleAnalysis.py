# Example script to run a simple analysis
import scripts.rules as rules
import scripts.dataLoader as dataLoader
import scripts.libCheck as libCheck
import scripts.analysisStruct as analysisStruct


# Load data to list of tuples [password, entropy]
print("Loading...")
password_list = dataLoader.LoadFromFile(
	"inputs/10_million_password_list_top_1000.txt"
	).load()
print("Loading Done")

# Create class that contain rules
print("Transformation...")
transformation = rules.Transformation()
transformation.add(rules.CapitalizeFirstLetter())
transformation.add(rules.ApplyAdvancedl33tTable())

# Applying transformations to passwords
passinfo_list = transformation.apply(password_list)
print("Transformation Done")

# Create class that contain password checking libraries
print("Checking passwords...")
pcl = libCheck.PassCheckLib()
pcl.add(libCheck.CrackLib())
pcl.add(libCheck.PassWDQC())
pcl.add(libCheck.Pwscore())
pcl.add(libCheck.Zxcvbn())

# Check passwords with pcls
pcl_data = pcl.check(passinfo_list)
print("Checking passwords Done")

# Load data from JSON
#passinfo_list, pcl_data = dataLoader.LoadFromJson(
#	'inputs/passData.json'
#	).load()

# Store data to JSON
dataLoader.StoreDataToJson().store(passinfo_list, pcl_data)

print("Analyzing...")
# Run analyzes
analyzer = analysisStruct.Analyzer(passinfo_list, pcl_data)
analyzer.addAnalysis(analysisStruct.TestNewAnalysis())
analyzer.runAnalyzes()
print("Done")
