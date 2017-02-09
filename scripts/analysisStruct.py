import datetime


analysisFunctions = [
    'PCHLOutputChanged_Ok2NotOk',
    'PCHLOutputChanged_NotOk2Ok',
    'PCHLOutputChanged_NotOk2NotOk',
    'lowEntropyOriginalPasswordPassPCHL',
    'lowEntropyTransformedPasswordPassPCHL',
    'highEntropyOriginalPasswordDontPassPCHL',
    'highEntropyTransformedPasswordDontPassPCHL',
    'withLowEntropyChangePassPCHL',
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
        returnInfo = self.groupDic[PCHL][0].__getattribute__(attribute)() if (isCallable) else self.groupDic[PCHL][0].__getattribute__(attribute)

        if (shortOutput):
            return returnInfo[PCHL] if (type(returnInfo) is dict) else returnInfo
        else:
            if (type(returnInfo) is dict):
                return "  ".join(
                    (passInfo.__getattribute__(attribute)()[PCHL] if (isCallable) else passInfo.__getattribute__(attribute)[PCHL])
                    for passInfo in self.groupDic[PCHL]
                    )
            else:
                if (isCallable):
                    return "  ".join(str(passInfo.__getattribute__(attribute)()) for passInfo in self.groupDic[PCHL])
                else:
                    return "  ".join(str(passInfo.__getattribute__(attribute)) for passInfo in self.groupDic[PCHL])

    def intersection(self, other):
        intersectionGroup = PassInfoGroup()
        for PCHL in self.groupDic:
            for passInfo in self.groupDic[PCHL]:
                if (passInfo in other.groupDic[PCHL]):
                    intersectionGroup.addPassInfo(PCHL, passInfo)

        return intersectionGroup


class Analyzer():

    def __init__(self, passwordData):
        self.defaultAnalysis = {
            'AllPasswords': PassInfoGroup(),
            'originalPassword_Ok': PassInfoGroup(),
            'originalPassword_NotOk': PassInfoGroup(),
            'transformedPassword_Ok': PassInfoGroup(),
            'transformedPassword_NotOk': PassInfoGroup()
        }
        self.defaultGroupAnalysis(passwordData)

        self.passwordData = passwordData
        self.analysisDic = {}

    def defaultGroupAnalysis(self, passwordData):
        for passInfo in passwordData:
            for PCHL in passInfo.originalLibOutput:
                self.defaultAnalysis['AllPasswords'].addPassInfo(PCHL, passInfo)

                if (passInfo.originalLibOutput[PCHL] == "OK"):
                    self.defaultAnalysis['originalPassword_Ok'].addPassInfo(PCHL, passInfo)
                else:
                    self.defaultAnalysis['originalPassword_NotOk'].addPassInfo(PCHL, passInfo)

                if (passInfo.transformedLibOutput[PCHL] == "OK"):
                    self.defaultAnalysis['transformedPassword_Ok'].addPassInfo(PCHL, passInfo)
                else:
                    self.defaultAnalysis['transformedPassword_NotOk'].addPassInfo(PCHL, passInfo)

    def addPasswordToAnalysisOutput(self, analysisName, PCHL, passInfo):
        if (analysisName not in self.analysisDic):
            self.analysisDic.update({analysisName: PassInfoGroup()})

        self.analysisDic[analysisName].addPassInfo(PCHL, passInfo)

    def addGroupToAnalysisOutput(self, analysisName, groupInfo):
        self.analysisDic.update({analysisName: groupInfo})

    def mainAnalysis(self):
        self.PCHLOutputChanged()
        self.lowAndHighEntropyAnalysis()
        self.lowEntropyChangePassPCHL()
        self.overallSummary()

    def PCHLOutputChanged(self):
        self.addGroupToAnalysisOutput(
            analysisFunctions[0],
            self.defaultAnalysis['originalPassword_Ok'].intersection(
                self.defaultAnalysis['transformedPassword_NotOk']
                )
            )

        self.addGroupToAnalysisOutput(
            analysisFunctions[1],
            self.defaultAnalysis['originalPassword_NotOk'].intersection(
                self.defaultAnalysis['transformedPassword_Ok']
                )
            )

        for PCHL, passInfoList in (self.defaultAnalysis['originalPassword_NotOk'].intersection(
            self.defaultAnalysis['transformedPassword_NotOk'])).groupDic.items():
            for passInfo in passInfoList:
                if (passInfo.originalLibOutput[PCHL] != passInfo.transformedLibOutput[PCHL]):
                    self.addPasswordToAnalysisOutput(
                        analysisFunctions[2],
                        PCHL,
                        passInfo
                        )

    def lowAndHighEntropyAnalysis(self):
        for PCHL, passInfoList in self.defaultAnalysis['originalPassword_Ok'].groupDic.items():
            for passInfo in passInfoList:
                if (passInfo.calculateInitialEntropy() < 36):
                    self.addPasswordToAnalysisOutput(
                        analysisFunctions[3],
                        PCHL,
                        passInfo
                        )
                if (passInfo.calculateInitialEntropy() > 60):
                    self.addPasswordToAnalysisOutput(
                        analysisFunctions[5],
                        PCHL,
                        passInfo
                        )

        for PCHL, passInfoList in self.defaultAnalysis['transformedPassword_Ok'].groupDic.items():
            for passInfo in passInfoList:
                if (passInfo.entropy < 36):
                    self.addPasswordToAnalysisOutput(
                        analysisFunctions[4],
                        PCHL,
                        passInfo
                        )
                if (passInfo.entropy > 60):
                    self.addPasswordToAnalysisOutput(
                        analysisFunctions[6],
                        PCHL,
                        passInfo
                        )

    def lowEntropyChangePassPCHL(self):
        for PCHL, passInfoList in (self.defaultAnalysis['originalPassword_NotOk'].intersection(
            self.defaultAnalysis['transformedPassword_Ok'])).groupDic.items():
            for passInfo in passInfoList:
                if (passInfo.calculateChangedEntropy() < 2):
                    self.addPasswordToAnalysisOutput(
                        analysisFunctions[7],
                        PCHL,
                        passInfo
                        )

    def overallSummary(self):
        self.addGroupToAnalysisOutput(
            analysisFunctions[8],
            self.defaultAnalysis['AllPasswords']
            )


class AnalyzerPrinter():

    def __init__(self, analysisData):
        self.analysisData = analysisData

    def printMainAnalysis(self):
        # Create outputFile name by current time and date
        now = datetime.datetime.now()
        time = now.strftime("%Y-%m-%d_%H:%M:%S")
        filename = "outputs/analysis_" + time + ".output"

        # Open file to store analysis output
        outputFile = open(filename, "w")

        # Print main information to file
        outputFile.write("\nTransformations applied:" + '\n')
        outputFile.write(self.analysisData.passwordData.getTransformRules() + '\n')

        # Print analysis output to StdOut and outputFile
        if (self.analysisData.analysisDic):
            for analysisFuncName, analysisPassData in self.analysisData.analysisDic.items():
                if (hasattr(self, analysisFuncName)):
                    for PCHL in analysisPassData.groupDic:
                        print(self.__getattribute__(analysisFuncName)(analysisPassData, PCHL, True))
                        outputFile.write(self.__getattribute__(analysisFuncName)(analysisPassData, PCHL, False) + '\n')

        # Close output file
        outputFile.close()

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
                ) +
            '\n'
            )

    def PCHLOutputChanged_NotOk2Ok(self, groupInfo, PCHL, shortOutput):
        return (
            "Original password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalPassword',
                False
                ) +
            " did not pass throught " + PCHL + ", because \n" +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalLibOutput',
                False
                ) + '\n'
            "But after applying transformations, trasformed password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedPassword',
                False
                ) +
            " pass throught " + PCHL + ".\n"
            )

    def PCHLOutputChanged_NotOk2NotOk(self, groupInfo, PCHL, shortOutput):
        return (
            "Neither original " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalPassword',
                False
                ) + " or transformed " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedPassword',
                False
                ) + " password, did not pass throught " + PCHL + '\n' +
            "But the reason of rejection changed from \n" +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalLibOutput',
                False
                ) + "\nto\n" +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedLibOutput',
                False
                )+ ".\n"
            )

    def lowEntropyTransformedPasswordPassPCHL(self, groupInfo, PCHL, shortOutput):
        return (
            "Transformed password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedPassword',
                False
                ) + " with low entropy " +
            str(groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'entropy',
                False
                )) + ",\n" +
            "lower then 36.0, sucesfully pass through " + PCHL + ".\n"
            )

    def lowEntropyOriginalPasswordPassPCHL(self, groupInfo, PCHL, shortOutput):
        return (
            "Original password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalPassword',
                False
                ) + " with low entropy " +
            str(groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'calculateInitialEntropy',
                True
                )) + ",\n" +
            "lower than 36.0, sucesfully pass through " + PCHL + ".\n"
            )

    def highEntropyTransformedPasswordDontPassPCHL(self, groupInfo, PCHL, shortOutput):
        return (
            "Transformed password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedPassword',
                False
                ) + " with high entropy " +
            str(groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'entropy',
                False
                )) + ",\n" +
            "higher than 60.0, did not pass throught " + PCHL + ".\n"
            )

    def highEntropyOriginalPasswordDontPassPCHL(self, groupInfo, PCHL, shortOutput):
        return (
            "Original password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalPassword',
                False
                ) + " with high entropy " +
            str(groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'calculateInitialEntropy',
                True
                )) + ",\n" +
            "higher than 60.0, did not pass throught " + PCHL + ".\n"
            )

    def withLowEntropyChangePassPCHL(self, groupInfo, PCHL, shortOutput):
        return (
            "Transformed password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedPassword',
                False
                ) + " with applied transformations: \n" +
            groupInfo.groupDic[PCHL][0].getAppliedTransformation() +
            "\nand with a low entropy-change, entropy value changed" +
            " from " +
            str(groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'calculateInitialEntropy',
                True
                )) + " to " +
            str(groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'entropy',
                False
                )) + ", pass through " + PCHL + ".\n"
            )

    def overallSummary(self, groupInfo, PCHL, shortOutput):
        percentChange = (
            len(self.analysisData.defaultAnalysis['transformedPassword_Ok'].groupDic[PCHL]) /
            len(groupInfo.groupDic[PCHL]) * 100
            )

        rejectionDic = {}
        for passInfo in self.analysisData.defaultAnalysis['transformedPassword_NotOk'].groupDic[PCHL]:
            if (passInfo.transformedLibOutput[PCHL] not in rejectionDic):
                rejectionDic.update({passInfo.transformedLibOutput[PCHL]: 1})
            else:
                rejectionDic[passInfo.transformedLibOutput[PCHL]] += 1

        return (
            str(round(percentChange, 2)) +
            "% of transformed passwords pass through " + PCHL + " .\n" +
            "Most common reason(" +
            str(round(
                    (max(rejectionDic.values()) / len(groupInfo.groupDic[PCHL])) * 100,
                    2
                    )) +
            "%) for rejection is:\n" +
            str(max(rejectionDic, key=rejectionDic.get)) + '\n'
            )
