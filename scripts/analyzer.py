import datetime


analysisFunctions = [
    'changedLibOutputAfterTransformation1',
    'changedLibOutputAfterTransformation2',
    'changedLibOutputAfterTransformation3',
    'lowEntropyPassLibrary1',
    'lowEntropyPassLibrary2',
    'highEntropyNotPassLibrary1',
    'highEntropyNotPassLibrary2',
    'lowEntropyChangePassLibrary1',
    'overallCategorySummary'
]


class AnalysisOutput(object):

    def __init__(self):
        self.libraryPassword = {}

        # TODO
        self.outputText = ""

    def addData(self, PCHL, passInfo):
        if (PCHL not in self.libraryPassword):
            self.libraryPassword.update({PCHL: []})

        if (passInfo is not None):
            self.libraryPassword[PCHL].append(passInfo)

    def getPasswordTransformations(self, PCHL):
        return " -> ".join(trans for trans in self.libraryPassword[PCHL][0].transformRules)

    def getOriginalPassword(self, PCHL, getShortOutput):
        if (getShortOutput):
            return self.libraryPassword[PCHL][0].originalPassword
        else:
            return "  ".join(passInfo.originalPassword for passInfo in self.libraryPassword[PCHL])

    def getTransformedPassword(self, PCHL, getShortOutput):
        if (getShortOutput):
            return self.libraryPassword[PCHL][0].transformedPassword
        else:
            return "  ".join(passInfo.transformedPassword for passInfo in self.libraryPassword[PCHL])

    def getOriginalPasswordPCHLOutput(self, PCHL, getShortOutput):
        if (getShortOutput):
            return self.libraryPassword[PCHL][0].originalLibOutput[PCHL]
        else:
            return "  ".join(passInfo.originalLibOutput[PCHL] for passInfo in self.libraryPassword[PCHL])

    def getTransformedPasswordPCHLOutput(self, PCHL, getShortOutput):
        if (getShortOutput):
            return self.libraryPassword[PCHL][0].transformedLibOutput[PCHL]
        else:
            return "  ".join(passInfo.transformedLibOutput[PCHL] for passInfo in self.libraryPassword[PCHL])

    def getTransformedPasswordEntropy(self, PCHL, getShortOutput):
        if (getShortOutput):
            return str(self.libraryPassword[PCHL][0].entropy)
        else:
            return "  ".join(str(passInfo.entropy) for passInfo in self.libraryPassword[PCHL])

    def getOriginalPasswordEntropy(self, PCHL, getShortOutput):
        if (getShortOutput):
            return str(self.libraryPassword[PCHL][0].calculateInitialEntropy())
        else:
            return "  ".join(str(passInfo.calculateInitialEntropy()) for passInfo in self.libraryPassword[PCHL])


class Analyzer(object):

    def __init__(self):
        self.analysisDic = {}

    def addAnalysisOutput(self, funcName, key, passInfo):
        if (funcName not in self.analysisDic):
            self.analysisDic.update({funcName: AnalysisOutput()})

        self.analysisDic[funcName].addData(key, passInfo)

    def mainAnalysis(self, passwordData):
        """Main analysis of input Passwords

        Analysis collect several information:
            If password, after applying transformations change
            his password checking library output
            If password with low entropy pass through PCHL
            If password with high entropy didnt pass through PCHL
            If transformation with low entropy-change, change output
            of password checking library for certain password
            And overallSummary, how many password didnt pass through
            PCHL, and after transformation they did.
        """

        for passInfo in passwordData:
            self.changedLibOutputAfterTransformation(passInfo)
            self.lowEntropyPassLibrary(passInfo)
            self.highEntropyNotPassLibrary(passInfo)
            self.lowEntropyChangePassLibrary(passInfo)
            self.overallCategorySummary(passInfo)

        # Create outputFile name by current time and date
        now = datetime.datetime.now()
        time = now.strftime("%Y-%m-%d_%H:%M:%S")
        filename = "outputs/analysis_" + time + ".output"

        # Open file to store analysis output
        outputFile = open(filename, "w")

        # Print main information to file
        outputFile.write("Transformations applied:" + '\n')
        outputFile.write(passwordData.getTransformRules() + '\n')

        # Print analysis output to StdOut and outputFile
        for key in self.analysisDic:
            self.printData(key, passwordData, outputFile)

        outputFile.close()

        # Store passData to Json
        passwordData.storeDataToJson(time)

    def printData(self, key, passwordData, outputFile):

        # changedLibOutputAfterTransformation1
        if (key == analysisFunctions[0]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_ChLibOutAfterTrans_1_output(key, PCHL, True)
                    )
                outputFile.write(
                    self.get_ChLibOutAfterTrans_1_output(key, PCHL, False) +
                    '\n'
                    )

        # changedLibOutputAfterTransformation2
        elif (key == analysisFunctions[1]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_ChLibOutAfterTrans_2_output(key, PCHL, True)
                    )
                outputFile.write(
                    self.get_ChLibOutAfterTrans_2_output(key, PCHL, False) +
                    '\n'
                    )

        # changedLibOutputAfterTransformation3
        elif (key == analysisFunctions[2]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_ChLibOutAfterTrans_3_output(key, PCHL, True)
                    )
                outputFile.write(
                    self.get_ChLibOutAfterTrans_3_output(key, PCHL, False) +
                    '\n'
                    )

        # lowEntropyPassLibrary1
        elif (key == analysisFunctions[3]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_LowEntropyPassLib_1_output(key, PCHL, True)
                    )
                outputFile.write(
                    self.get_LowEntropyPassLib_1_output(key, PCHL, False) +
                    '\n'
                    )

        # lowEntropyPassLibrary2
        elif (key == analysisFunctions[4]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_LowEntropyPassLib_2_output(key, PCHL, True)
                    )
                outputFile.write(
                    self.get_LowEntropyPassLib_2_output(key, PCHL, False) +
                    '\n'
                    )

        # highEntropyNotPassLibrary1
        elif (key == analysisFunctions[5]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_HighEntropyPassLib_1_output(key, PCHL, True)
                    )
                outputFile.write(
                    self.get_HighEntropyPassLib_1_output(key, PCHL, False) +
                    '\n'
                    )

        # highEntropyNotPassLibrary2
        elif (key == analysisFunctions[6]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_HighEntropyPassLib_2_output(key, PCHL, True)
                    )
                outputFile.write(
                    self.get_HighEntropyPassLib_2_output(key, PCHL, False) +
                    '\n'
                    )

        # lowEntropyChangePassLibrary1
        elif (key == analysisFunctions[7]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_LowEntropyChPassLib_1_output(key, PCHL, True)
                    )
                outputFile.write(
                    self.get_LowEntropyChPassLib_1_output(key, PCHL, False) +
                    '\n'
                    )

        # Analysis summary
        elif (key == analysisFunctions[8]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_OverallCategSummary_1_output(
                        key,
                        PCHL,
                        passwordData
                        )
                    )
                outputFile.write(
                    self.get_OverallCategSummary_1_output(
                        key,
                        PCHL,
                        passwordData
                        ) + '\n'
                    )

    def changedLibOutputAfterTransformation(self, passInfo):
        for key in passInfo.originalLibOutput:
            # Output of password checking libraries is same at
            # original and transformed password
            if (passInfo.originalLibOutput[key] ==
               passInfo.transformedLibOutput[key]):
                continue
            elif (passInfo.originalLibOutput[key] == "OK"):
                self.addAnalysisOutput(
                    self.changedLibOutputAfterTransformation.__name__ + "1",
                    key,
                    passInfo
                    )
            elif (passInfo.transformedLibOutput[key] == "OK"):
                self.addAnalysisOutput(
                    self.changedLibOutputAfterTransformation.__name__ + "2",
                    key,
                    passInfo
                    )
            else:
                self.addAnalysisOutput(
                    self.changedLibOutputAfterTransformation.__name__ + "3",
                    key,
                    passInfo
                    )

    def get_ChLibOutAfterTrans_1_output(self, key, PCHL, getShortOutput):
        return (
            "Original password " +
            self.analysisDic[key].getOriginalPassword(
                PCHL,
                getShortOutput
                ) +
            " pass through " + PCHL + "." + '\n'
            "But transformed password " +
            self.analysisDic[key].getTransformedPassword(
                PCHL,
                getShortOutput
                ) +
            ", did not pass through " + PCHL + "." + '\n' +
            "And the reason of rejection is: " +
            self.analysisDic[key].getTransformedPasswordPCHLOutput(
                PCHL,
                getShortOutput
                ) +
            '\n'
            )

    def get_ChLibOutAfterTrans_2_output(self, key, PCHL, getShortOutput):
        return (
            "Original password " +
            self.analysisDic[key].getOriginalPassword(
                PCHL,
                getShortOutput
                ) +
            " did not pass throught " + PCHL + ", because \n" +
            self.analysisDic[key].getOriginalPasswordPCHLOutput(
                PCHL,
                getShortOutput
                ) + '\n'
            "But after applying transformations, trasformed password " +
            self.analysisDic[key].getTransformedPassword(
                PCHL,
                getShortOutput
                ) +
            " pass throught " + PCHL + ".\n"
            )

    def get_ChLibOutAfterTrans_3_output(self, key, PCHL, getShortOutput):
        return (
            "Neither original " +
            self.analysisDic[key].getOriginalPassword(
                PCHL,
                getShortOutput
                ) + " or transformed " +
            self.analysisDic[key].getTransformedPassword(
                PCHL,
                getShortOutput
                ) + " password, did not pass throught " + PCHL + '\n' +
            "But the reason of rejection changed from \n" +
            self.analysisDic[key].getOriginalPasswordPCHLOutput(
                PCHL,
                getShortOutput
                ) + "\nto\n" +
            self.analysisDic[key].getTransformedPasswordPCHLOutput(
                PCHL,
                getShortOutput
                ) + ".\n"
            )

    def lowEntropyPassLibrary(self, passInfo):
        if (passInfo.entropy < 36):
            for key in passInfo.transformedLibOutput:
                if (passInfo.transformedLibOutput[key] ==
                   "OK"):
                    self.addAnalysisOutput(
                        self.lowEntropyPassLibrary.__name__ + "1",
                        key,
                        passInfo
                        )

        if (passInfo.calculateInitialEntropy() < 36):
            for key in passInfo.originalLibOutput:
                if (passInfo.originalLibOutput[key] ==
                   "OK"):
                    self.addAnalysisOutput(
                        self.lowEntropyPassLibrary.__name__ + "2",
                        key,
                        passInfo
                        )

    def get_LowEntropyPassLib_1_output(self, key, PCHL, getShortOutput):
        return (
            "Transformed password " +
            self.analysisDic[key].getTransformedPassword(
                PCHL,
                getShortOutput
                ) + " with low entropy " +
            self.analysisDic[key].getTransformedPasswordEntropy(
                PCHL,
                getShortOutput
                ) + ",\n" +
            "lower then 36.0, sucesfully pass through " + PCHL + ".\n"
            )

    def get_LowEntropyPassLib_2_output(self, key, PCHL, getShortOutput):
        return (
            "Original password " +
            self.analysisDic[key].getOriginalPassword(
                PCHL,
                getShortOutput
                ) + " with low entropy " +
            self.analysisDic[key].getOriginalPasswordEntropy(
                PCHL,
                getShortOutput
                ) + ",\n" +
            "lower than 36.0, sucesfully pass through " + PCHL + ".\n"
            )

    def highEntropyNotPassLibrary(self, passInfo):
        if (passInfo.entropy > 60):
            for key in passInfo.transformedLibOutput:
                if (passInfo.transformedLibOutput[key] !=
                   "OK"):
                    self.addAnalysisOutput(
                        self.highEntropyNotPassLibrary.__name__ + "1",
                        key,
                        passInfo
                        )

        if (passInfo.calculateInitialEntropy() > 60):
            for key in passInfo.originalLibOutput:
                if (passInfo.originalLibOutput[key] !=
                   "OK"):
                    self.addAnalysisOutput(
                        self.highEntropyNotPassLibrary.__name__ + "2",
                        key,
                        passInfo
                        )

    def get_HighEntropyPassLib_1_output(self, key, PCHL, getShortOutput):
        return (
            "Transformed password " +
            self.analysisDic[key].getTransformedPassword(
                PCHL,
                getShortOutput
                ) + " with high entropy " +
            self.analysisDic[key].getTransformedPasswordEntropy(
                PCHL,
                getShortOutput
                ) + ",\n" +
            "higher than 60.0, did not pass throught " + PCHL + ".\n"
            )

    def get_HighEntropyPassLib_2_output(self, key, PCHL, getShortOutput):
        return (
            "Original password " +
            self.analysisDic[key].getTransformedPassword(
                PCHL,
                getShortOutput
                ) + " with high entropy " +
            self.analysisDic[key].getTransformedPasswordEntropy(
                PCHL,
                getShortOutput
                ) + ",\n" +
            "higher than 60.0, did not pass throught " + PCHL + ".\n"
            )

    def lowEntropyChangePassLibrary(self, passInfo):
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
                        self.lowEntropyChangePassLibrary.__name__ + "1",
                        key,
                        passInfo
                        )

    def get_LowEntropyChPassLib_1_output(self, key, PCHL, getShortOutput):
        return (
            "Transformed password " +
            self.analysisDic[key].getTransformedPassword(
                PCHL,
                getShortOutput
                ) + " with applied transformations: \n" +
            self.analysisDic[key].getPasswordTransformations(
                PCHL,
                getShortOutput
                ) + "\nand with a low entropy-change, entropy value changed" +
                "from " +
            self.analysisDic[key].getOriginalPasswordEntropy(
                PCHL,
                getShortOutput
                ) + " to " +
            self.analysisDic[key].getTransformedPasswordEntropy(
                PCHL,
                getShortOutput
                ) + ", pass through " + PCHL + ".\n"
            )

    def overallCategorySummary(self, passInfo):
        for key in passInfo.transformedLibOutput:
            if (passInfo.transformedLibOutput[key] == "OK"):
                self.addAnalysisOutput(
                    self.overallCategorySummary.__name__,
                    key,
                    passInfo
                    )

    def get_OverallCategSummary_1_output(self, key, PCHL, passwordData):
        percentChange = (
            len(self.analysisDic[key].libraryPassword[PCHL]) /
            len(passwordData) * 100
            )

        rejectionDic = {}
        for passInfo in passwordData:
            output = passInfo.transformedLibOutput[PCHL]
            if (output != "OK"):
                if (output not in rejectionDic):
                    rejectionDic.update({output : 1})
                else:
                    rejectionDic[output] += 1

        return (
            str(round(percentChange, 2)) +
            "% of transformed passwords pass through " + PCHL + " .\n" +
            "Most common reason(" +
            str(round((max(rejectionDic.values()) / len(passwordData)) * 100, 2)) +
            "%) for rejection is:\n" +
            str(max(rejectionDic, key=rejectionDic.get)) + '\n'
            )
