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
        self.outputText = ""

    def addData(self, PCHL, passInfo):
        if (PCHL not in self.libraryPassword):
            self.libraryPassword.update({PCHL: []})

        if (passInfo is not None):
            self.libraryPassword[PCHL].append(passInfo)

    def getOriginalPasswords(self, PCHL, getShortOutput):
        output = ""
        counter = 0
        arrayLength = len(self.libraryPassword[PCHL])

        for passInfo in self.libraryPassword[PCHL]:
            output += passInfo.originalPassword

            if (counter != arrayLength - 1):
                output += '   '
            counter += 1

            if (not getShortOutput and counter > 4):
                output += "..."
                return output

        return output

    def getTransformedPasswords(self, PCHL, getShortOutput):
        output = ""
        counter = 0
        arrayLength = len(self.libraryPassword[PCHL])

        for passInfo in self.libraryPassword[PCHL]:
            output += passInfo.transformedPassword

            if (counter != arrayLength - 1):
                output += '   '
            counter += 1

            if (not getShortOutput and counter > 4):
                output += "..."
                return output

        return output

    def getTransformedPasswordsEntropy(self, PCHL, getShortOutput):
        output = ""
        counter = 0
        arrayLength = len(self.libraryPassword[PCHL])

        for passInfo in self.libraryPassword[PCHL]:
            output += str(passInfo.entropy)

            if (counter != arrayLength - 1):
                output += '   '
            counter += 1

            if (not getShortOutput and counter > 4):
                output += "..."
                return output

        return output

    def getOriginalPasswordsEntropy(self, PCHL, getShortOutput):
        output = ""
        counter = 0
        arrayLength = len(self.libraryPassword[PCHL])

        for passInfo in self.libraryPassword[PCHL]:
            output += str(passInfo.calculateInitialEntropy())

            if (counter != arrayLength - 1):
                output += '   '
            counter += 1

            if (not getShortOutput and counter > 4):
                output += "..."
                return output

        return output


class Analyzer(object):

    def __init__(self):
        self.analysisDic = {}

    def addAnalysisOutput(self, funcName, key, passInfo):
        if (funcName not in self.analysisDic):
            self.analysisDic.update({funcName: AnalysisOutput()})

        self.analysisDic[funcName].addData(key, passInfo)

    def mainAnalysis(self, passwordData):
        """Main analysis of input passwords

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

        # Print main information
        outputFile.write("Transformations applied:" + '\n')
        outputFile.write(passwordData.getTransformRules() + '\n')

        for key in self.analysisDic:
            self.printData(key, passwordData, outputFile)

        outputFile.close()

        # Store passData
        passwordData.storeDataToJson(time)

    def printData(self, key, passwordData, outputFile):

        # changedLibOutputAfterTransformation1
        if (key == analysisFunctions[0]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_ChLibOutAfterTrans_1_output(key, PCHL, False)
                    )
                outputFile.write(
                    self.get_ChLibOutAfterTrans_1_output(key, PCHL, True) +
                    '\n'
                    )

        # changedLibOutputAfterTransformation2
        elif (key == analysisFunctions[1]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_ChLibOutAfterTrans_2_output(key, PCHL, False)
                    )
                outputFile.write(
                    self.get_ChLibOutAfterTrans_2_output(key, PCHL, True) +
                    '\n'
                    )

        # changedLibOutputAfterTransformation3
        elif (key == analysisFunctions[2]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_ChLibOutAfterTrans_3_output(key, PCHL, False)
                    )
                outputFile.write(
                    self.get_ChLibOutAfterTrans_3_output(key, PCHL, True) +
                    '\n'
                    )

        # lowEntropyPassLibrary1
        elif (key == analysisFunctions[3]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_LowEntropyPassLib_1_output(key, PCHL, False)
                    )
                outputFile.write(
                    self.get_LowEntropyPassLib_1_output(key, PCHL, True) +
                    '\n'
                    )

        # lowEntropyPassLibrary2
        elif (key == analysisFunctions[4]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_LowEntropyPassLib_2_output(key, PCHL, False)
                    )
                outputFile.write(
                    self.get_LowEntropyPassLib_2_output(key, PCHL, True) +
                    '\n'
                    )

        # highEntropyNotPassLibrary1
        elif (key == analysisFunctions[5]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_HighEntropyPassLib_1_output(key, PCHL, False)
                    )
                outputFile.write(
                    self.get_HighEntropyPassLib_1_output(key, PCHL, True) +
                    '\n'
                    )

        # highEntropyNotPassLibrary2
        elif (key == analysisFunctions[6]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_HighEntropyPassLib_2_output(key, PCHL, False)
                    )
                outputFile.write(
                    self.get_HighEntropyPassLib_2_output(key, PCHL, True) +
                    '\n'
                    )

        # lowEntropyChangePassLibrary1
        elif (key == analysisFunctions[7]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    self.get_LowEntropyChPassLib_1_output(key, PCHL, False)
                    )
                outputFile.write(
                    self.get_LowEntropyChPassLib_1_output(key, PCHL, True) +
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
            "Output of PCHL " + PCHL + " changed." + '\n' +
            "The output of original passwords:" + '\n' +
            self.analysisDic[key].getOriginalPasswords(
                PCHL,
                getShortOutput
                ) +
            '\n' +
            "is OK, but after applying transformations," + '\n' +
            "passwords changed to:" + '\n' +
            self.analysisDic[key].getTransformedPasswords(
                PCHL,
                getShortOutput
                ) +
            '\n' + "And output of " + PCHL + " is not OK" +
            '\n'
            )

    def get_ChLibOutAfterTrans_2_output(self, key, PCHL, getShortOutput):
        return (
            "Output of PCHL " + PCHL + " changed." + '\n' +
            "Orignally passwords:" + '\n' +
            self.analysisDic[key].getOriginalPasswords(
                PCHL,
                getShortOutput
                ) +
            '\n' + "didn\'t pass through " + PCHL + "." + '\n' +
            "But after applying transformations, " +
            "passwords changed to:" + "\n" +
            self.analysisDic[key].getTransformedPasswords(
                PCHL,
                getShortOutput
                ) +
            '\n' + "And now, they passed through " + PCHL +
            " PCHL." +
            '\n'
            )

    def get_ChLibOutAfterTrans_3_output(self, key, PCHL, getShortOutput):
        return(
            "Passwords:" + '\n' +
            self.analysisDic[key].getOriginalPasswords(
                PCHL,
                getShortOutput
                ) +
            '\n' + "did\'t pass through " + PCHL + " PCHL." + '\n' +
            "Either before or after applying transformations." +
            '\n' + "But the output of " + PCHL + " has changed." +
            '\n'
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
        return(
            "Transformed passwords:" + '\n' +
            self.analysisDic[key].getTransformedPasswords(
                PCHL,
                getShortOutput
                ) +
            '\n' + "with low entopy (< 36):" + '\n' +
            self.analysisDic[key].getTransformedPasswordsEntropy(
                PCHL,
                getShortOutput
                ) +
            '\n' + "pass through " + PCHL + " ." +
            '\n'
            )

    def get_LowEntropyPassLib_2_output(self, key, PCHL, getShortOutput):
        return(
            "original passwords:" + '\n' +
            self.analysisDic[key].getOriginalPasswords(
                PCHL,
                getShortOutput
                ) +
            '\n' + "with low entropy (< 36):" + '\n' +
            self.analysisDic[key].getOriginalPasswordsEntropy(
                PCHL,
                getShortOutput
                ) +
            '\n' + "pass through " + PCHL + " ." +
            '\n'
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
        return(
            "Transformed passwords:" + '\n' +
            self.analysisDic[key].getTransformedPasswords(
                PCHL,
                getShortOutput
                ) +
            '\n' + "with high entropy (> 60):" + '\n' +
            self.analysisDic[key].getTransformedPasswordsEntropy(
                PCHL,
                getShortOutput
                ) +
            '\n' + "didn\'t pass through " + PCHL + " ." +
            '\n'
            )

    def get_HighEntropyPassLib_2_output(self, key, PCHL, getShortOutput):
        return(
            "original passwords:" + '\n' +
            self.analysisDic[key].getOriginalPasswords(
                PCHL,
                getShortOutput
                ) +
            '\n' + "with high entropy (> 60):" + '\n' +
            self.analysisDic[key].getOriginalPasswordsEntropy(
                PCHL,
                getShortOutput
                ) +
            '\n' + "didn\'t pass through " + PCHL + " ." +
            '\n'
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
        return(
            "Transformed passwords: " + '\n' +
            self.analysisDic[key].getTransformedPasswords(
                PCHL,
                getShortOutput
                ) +
            '\n' + "with low entopy-change." + '\n' +
            "Pass through " + PCHL + " ." +
            '\n'
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
        return(
            str(round(percentChange, 2)) +
            "% of transformed passwords pass through " +
            PCHL + " ." +
            '\n'
            )
