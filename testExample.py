import scripts.rules as rules
import scripts.libCheck as libCheck
import scripts.dataLoader as dataLoader
import scripts.analysisStruct as analysisStruct

import scripts.passStruct as passStruct


# Vratit list[] hesiel
passwordList = dataLoader.LoadFromFile("path").loadData()

# Vytvorenie triedy Transformation ktore uchovava transformacie
transformation = Transformation()
transformation.add(rules.CapitalizeFirstLetter)
transformation.add(rules.ApplySimplel33tTable)

# (Mixer) Aplikovanie pravidiel na list hesiel
# funkcia vrati list tried Password z passStruct.Password
passDataList = map(lambda password: transformation.apply(password), passwordList)

# Rovnaky princip ako pri Transformation
pcl = PassCheckLib()
pcl.add(libCheck.CrackLib)
pcl.add(libCheck.PassWDQC)

# Prehnanie hesiel cez passworch checking libraries
passDataList = map(lambda password: pcl.check(password), passDataList)

# Ukladanie dat aj analyza ostava ako bola
passwordData.storeDataToJson('path')

analysis = analysisStruct.Analyzer(passwordList)
analysis.run()

analysisPrinter = analysisStruct.AnalyzerPrinter(analysis)
analysisPrinter.print()


###### Priklad implementacie novych tried
class PassCheckLib():

	def __init__(self):
		self.pchlList = []

	def add(self, pchl):
		self.pchlList.append(pchl)

	def checkPasswords(self, passInfo):
		for pchl in self.pchlList:
			pchl.checkResult(passInfo)

		return passInfo
