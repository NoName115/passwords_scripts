

analysisFunctions = [
    'PCHLOutputChanged_Ok2NotOk',
    'PCHLOutputChanged_NotOk2Ok',
    'PCHLOutputChanged_NotOk2NotOk',
    'lowEntropyTransformedPasswordPassPCHL',
    'lowEntropyOriginalPasswordPassPCHL',
    'highEntropyTransformedPasswordDontPassPCHL',
    'highEntropyOriginalPasswordDontPassPCHL',
    'lowEntropyChangePassPCHL',
    'overallSummary'
]


class PassInfoGroup():

    def __init__(self):
        self.groupDic = {}

    def addPassInfo(self, PCHL, passInfo):
        if (PCHL not in self.groupDic):
            self.groupDic.update({PCHL: []})

        if (passInfo is not None):
            self.groupDic[PCHL].append(passInfo)

    def getPassInfoAttribute(self, PCHL, shortOutput, attribute, isCallable):
        if (shortOutput):
            returnInfo = self.groupDic[PCHL][0].__getattribute__(attribute)
            return returnInfo() if (isCallable) else returnInfo
        else:
            print('NIE')

            '''
    def getPassInfoAttribute(self, PCHL, shortOutput, attribute, isCallable):
        print('HA')
		if (getShortOutput):
			returnInfo = self.groupDic[PCHL][0].__getattribute__(attribute)
			return returnInfo() if (isCallable) else returnInfo
		else:
			return "  ".join(
				[passInfo.__getattribute__(attribute)() if (isCallable) else passInfo.__getattribute__(attribute)]
				for passInfo in self.libraryPassword[PCHL]
				)
    '''


class Analyzer():

    def __init__(self):
        self.analysisDic = {}
        self.analysisDone = False

    def addAnalysisOutput(self, analysisName, PCHL, passInfo):
        if (analysisName not in self.analysisDic):
            self.analysisDic.update({analysisName: PassInfoGroup()})

        self.analysisDic[analysisName].addPassInfo(PCHL, passInfo)

    def mainAnalysis(self, passwordData):
        for passInfo in passwordData:
            self.PCHLOutputChanged(passInfo)
            self.lowEntropyPassPCHL(passInfo)
            self.highEntropyDontPassPCHL(passInfo)
            self.overallSummary(passInfo)

        self.analysisDone = True

    def PCHLOutputChanged(self, passInfo):
        for key in passInfo.originalLibOutput:
            if (passInfo.originalLibOutput[key] ==
               passInfo.transformedLibOutput[key]):
                continue
            elif (passInfo.originalLibOutput[key] == "OK"):
                self.addAnalysisOutput(
                    analysisFunctions[0],
                    key,
                    passInfo
                    )
            elif (passInfo.transformedLibOutput[key] == "OK"):
                self.addAnalysisOutput(
                    analysisFunctions[1],
                    key,
                    passInfo
                    )
            else:
                self.addAnalysisOutput(
                    analysisFunctions[2],
                    key,
                    passInfo
                    )

    def lowEntropyPassPCHL(self, passInfo):
        if (passInfo.entropy < 36):
            for key in passInfo.transformedLibOutput:
                if (passInfo.transformedLibOutput[key] ==
                   "OK"):
                    self.addAnalysisOutput(
                        analysisFunctions[3],
                        key,
                        passInfo
                        )

        if (passInfo.calculateInitialEntropy() < 36):
            for key in passInfo.originalLibOutput:
                if (passInfo.originalLibOutput[key] ==
                   "OK"):
                    self.addAnalysisOutput(
                        analysisFunctions[4],
                        key,
                        passInfo
                        )

    def highEntropyDontPassPCHL(self, passInfo):
        if (passInfo.entropy > 60):
            for key in passInfo.transformedLibOutput:
                if (passInfo.transformedLibOutput[key] !=
                   "OK"):
                    self.addAnalysisOutput(
                        analysisFunctions[5],
                        key,
                        passInfo
                        )

        if (passInfo.calculateInitialEntropy() > 60):
            for key in passInfo.originalLibOutput:
                if (passInfo.originalLibOutput[key] !=
                   "OK"):
                    self.addAnalysisOutput(
                        analysisFunctions[6],
                        key,
                        passInfo
                        )

    # Check outputChanged method
    def lowEntropyChangePassPCHL(self, passInfo):
        def outputChanged(passInfo, pchl):
            if (passInfo.originalLibOutput[pchl] !=
               passInfo.transformedLibOutput[pchl] and
               passInfo.transformedLibOutput[pchl] == "OK"):
                return True
            else:
                return False

        for key in passInfo.transformedLibOutput:
            if (outputChanged(passInfo, key) and
               passInfo.calculateChangedEntropy() < 2):
                self.addAnalysisOutput(
                    analysisFunctions[7],
                    key,
                    passInfo
                    )

    def overallSummary(self, passInfo):
        for key in passInfo.transformedLibOutput:
            if (passInfo.transformedLibOutput[key] == "OK"):
                self.addAnalysisOutput(
                    analysisFunctions[8],
                    key,
                    passInfo
                    )


class AnalyzerPrinter():

    def __init__(self, analysisData):
        self.analysisData = analysisData

    def printData(self):
        if (self.analysisData.analysisDic):
            for analysisFuncName, analysisPassData in self.analysisData.analysisDic.items():
                if (hasattr(self, analysisFuncName)):
                    for PCHL in analysisPassData.groupDic:
                        print(self.__getattribute__(analysisFuncName)(analysisPassData, PCHL, True))

    def PCHLOutputChanged_Ok2NotOk(self, groupInfo, PCHL, shortOutput):
        return (
            "Original password " +
            groupInfo.getPassInfoAttribute(    #getPassInfoAttribute(self, PCHL, shortOutput, attribute, isCallable)
                PCHL,
                shortOutput,
                'originalPassword',
                False
                ) +
            " pass through " + PCHL + "." + '\n'
            "But transformed password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedPassword',
                False
                ) +
            ", did not pass through " + PCHL + "." + '\n' +
            "And the reason of rejection is: " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedLibOutput',
                False
                )[PCHL] +
            '\n'
            )
