import scripts.rules as rules
import scripts.libCheck as libCheck
import scripts.loadData as loadData
import scripts.analysisStruct as analysisStruct

import scripts.passStruct as passStruct

# passwordList - list ktory obsahuje dvojice [Heslo, Entropia]
passwordList = loadData.LoadFromFile("inputs/10_million_password_list_top_1000").loadData()

# Vytvorenie triedy Transform ktora si ukochovava vsetky
# transformacie ktore maju byt aplikovane
transList = Transform()
transList.add(rules.CapitalizeFirstLetter)
transList.add(rules.ApplySimplel33tTable)

# (Mixer) Aplikovanie pravidiel na list hesiel
# funkcia vrati triedu PassData z passStruct.PassData
passwordData = transList.applyTransformations(passwordList)

# Rovnako ako trieda Transform, na rovnaky sposob
# aj trieda passCheckLib
pchl = PassCheckLib()
pchl.add(libCheck.CrackLib)
pchl.add(libCheck.PassWDQC)

# Prehnanie hesiel cez password Checking Libraries
pchl.checkPasswords(passwordData)


# Ukladanie dat aj analyza ostava ako bola
passwordData.storeDataToJson('path')

analysis = analysisStruct.Analyzer(passwordList)
analysis.mainAnalysis()

analysisPrinter = analysisStruct.AnalyzerPrinter(analysis)
analysisPrinter.printMainAnalysis()



###### Priklad implementacie novych tried
class Transform():

	def __init__(self):
		self.transList = []

	def add(self, rule):
		self.transList.append(rule)

	def applyTransformations(self, passList):
		passwordData = passStruct.PassData()

		# pridat data z passList do passwordData
		for passTuple in passList:
			passwordData.add(passTuple[0], passTuple[1])
		for trans in self.transList:
			trans.transform(passwordData)

		return passwordData


class PassCheckLib():

	def __init__(self):
		self.pchlList = []

	def add(self, pchl):
		self.pchlList.append(pchl)

	def checkPasswords(self, passData):
		for pchl in self.pchlList:
			pchl.checkResult(passData)
