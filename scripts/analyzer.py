from termcolor import colored


# Urobim for in self.analysisDic
# kde bude printInfo(key)
# PrintInfo(key) bude mat switch a podla
# toho vypise output

analysisFunctions = [
    'changedLibOutputAfterTransformation1',
    'changedLibOutputAfterTransformation2',
    'changedLibOutputAfterTransformation3',
    'lowEntropyPassLibrary1',
    'lowEntropyPassLibrary2',
    'highEntropyNotPassLibrary1',
    'highEntropyNotPassLibrary2',
    'lowEntropyChangePassLibrary1',
    'overallCategorySummary1',
    'overallCategorySummary2',
    'overallCategorySummary3'
]


class AnalysisOutput(object):

    def __init__(self):
        self.libraryPassword = {}
        self.outputText = ""

    def addData(self, PCHL, passInfo):
        if (PCHL not in self.libraryPassword):
            self.libraryPassword.update({PCHL : []})

        if (passInfo != None):
            self.libraryPassword[PCHL].append(passInfo)

    def getOriginallyPasswords(self, PCHL):
        output = ""
        counter = 0
        arrayLength = len(self.libraryPassword[PCHL])

        for passInfo in self.libraryPassword[PCHL]:
            output += passInfo.originallyPassword

            if (counter != arrayLength - 1):
                output += ', '
            counter += 1

            if (counter == 5):
                output += "..."
                return output

        return output

    def getTransformedPasswords(self, PCHL):
        output = ""
        counter = 0
        arrayLength = len(self.libraryPassword[PCHL])

        for passInfo in self.libraryPassword[PCHL]:
            output += passInfo.transformedPassword

            if (counter != arrayLength - 1):
                output += ', '
            counter += 1

            if (counter == 5):
                output += "..."
                return output

        return output


class Analyzer(object):

    def __init__(self):
        self.analysisDic = {}

    def addAnalysisOutput(self, funcName, key, passInfo):
        if (funcName not in self.analysisDic):
            self.analysisDic.update({funcName : AnalysisOutput()})

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

        for key in self.analysisDic:
            self.printData(key)

        print ("---------------END----------------")

    def printData(self, key):
        if (key == analysisFunctions[0]):
            for PCHL in self.analysisDic[key].libraryPassword:
                print(
                    "Output of PCHL " + PCHL + " changed." + '\n'
                    "The output of originally passwords: " + '\n' +
                    self.analysisDic[key].getOriginallyPasswords(PCHL) +
                    '\n' +
                    "is OK, but after applying transformations," + '\n' +
                    "passwords changed to: " + '\n' +
                    self.analysisDic[key].getTransformedPasswords(PCHL) +
                    '\n' + "And output of PCHL is not OK"
                    )


    def changedLibOutputAfterTransformation(self, passInfo):
        for key in passInfo.originallyLibOutput:
            # Output of password checking libraries is same at
            # originally and transformed password
            if (passInfo.originallyLibOutput[key] ==
               passInfo.transformedLibOutput[key]):
                continue
            elif (passInfo.originallyLibOutput[key].decode('UTF-8') == "OK"):
                self.addAnalysisOutput(
                    self.changedLibOutputAfterTransformation.__name__ + "1",
                    key,
                    passInfo
                    )
            elif (passInfo.transformedLibOutput[key].decode('UTF-8') == "OK"):
                self.addAnalysisOutput(
                    self.changedLibOutputAfterTransformation.__name__ + "2",
                    key,
                    passInfo
                    )
                '''
                passInfo.addAnalysisOutput(
                    4,
                    "Output of PCHL " + key + " changed." + '\n',
                    "Originally password: " + passInfo.originallyPassword +
                    " didn\'t pass through PCHL," + '\n' + "The output is: " +
                    passInfo.originallyLibOutput[key].decode('UTF-8') +
                    '\n' + "But after applying transformations," +
                    " password changed to: " + passInfo.transformedPassword +
                    '\n' + "And it pass through " + key + " PCHL."
                    )
                    '''
            else:
                self.addAnalysisOutput(
                    self.changedLibOutputAfterTransformation.__name__ + "3",
                    key,
                    passInfo
                    )
                '''
                passInfo.addAnalysisOutput(
                    2,
                    "Password " + passInfo.originallyPassword +
                    " didn\'t pass through password checking library " + key,
                    '\n' + "Either before or after applying transformations." +
                    '\n' + "But the output has changed, output before" +
                    " transformations: " + '\n' +
                    passInfo.originallyLibOutput[key].decode('UTF-8') +
                    '\n' + "And the output after transformations: " + '\n' +
                    passInfo.transformedLibOutput[key].decode('UTF-8')
                    )
                    '''

    def lowEntropyPassLibrary(self, passInfo):
        if (passInfo.entropy < 36):
            for key in passInfo.transformedLibOutput:
                if (passInfo.transformedLibOutput[key].decode('UTF-8') ==
                   "OK"):
                    self.addAnalysisOutput(
                        self.lowEntropyPassLibrary.__name__ + "1",
                        key,
                        passInfo
                        )
                    '''
                    passInfo.addAnalysisOutput(
                        1,
                        "After transformations, password: " +
                        passInfo.transformedPassword + '\n' +
                        "With low entropy: " + str(passInfo.entropy) +
                        " pass through " + key + " PCHL.",
                        ""
                        )
                        '''
        if (passInfo.calculateInitialEntropy() < 36):
            for key in passInfo.originallyLibOutput:
                if (passInfo.originallyLibOutput[key].decode('UTF-8') ==
                   "OK"):
                    self.addAnalysisOutput(
                        self.lowEntropyPassLibrary.__name__ + "2",
                        key,
                        passInfo
                        )
                '''
                    passInfo.addAnalysisOutput(
                        2,
                        "Originally password: " + passInfo.originallyPassword +
                        '\n' + "With low entropy: " +
                        str(passInfo.calculateInitialEntropy()) +
                        " pass through " + key + " PCHL.",
                        ""
                        )
                        '''

    def highEntropyNotPassLibrary(self, passInfo):
        if (passInfo.entropy > 60):
            for key in passInfo.transformedLibOutput:
                if (passInfo.transformedLibOutput[key].decode('UTF-8') !=
                   "OK"):
                    self.addAnalysisOutput(
                        self.highEntropyNotPassLibrary.__name__ + "1",
                        key,
                        passInfo
                        )
                    '''
                    passInfo.addAnalysisOutput(
                        2,
                        "Password: " + passInfo.transformedPassword +
                        '\n' + "After transformations and with high entropy " +
                        passInfo.entropy + '\n' + "Didn\'t pass through " +
                        key + " PCHL.",
                        ""
                        )
                        '''

        if (passInfo.calculateInitialEntropy() > 60):
            for key in passInfo.originallyLibOutput:
                if (passInfo.originallyLibOutput[key].decode('UTF-8') !=
                   "OK"):
                    self.addAnalysisOutput(
                        self.highEntropyNotPassLibrary.__name__ + "2",
                        key,
                        passInfo
                        )
                    '''
                    passInfo.addAnalysisOutput(
                        1,
                        "Password: " + passInfo.originallyPassword +
                        '\n' + "With no transformations and high entropy " +
                        passInfo.entropy + '\n' + "Didn\'t pass through " +
                        key + " PCHL.",
                        ""
                        )
                        '''

    def lowEntropyChangePassLibrary(self, passInfo):
        def outputChanged(passInfo, pchl):
            for key in passInfo.analysisOutput:
                if (key == (
                        "Output of password checking library " + pchl +
                        " changed." + '\n')):
                    return True
            return False

        for key in passInfo.transformedLibOutput:
            if (outputChanged(passInfo, key) and
               passInfo.calculateChangedEntropy() < 2):
                self.addAnalysisOutput(
                        self.lowEntropyChangePassLibrary.__name__ + "1",
                        key,
                        passInfo
                        )
                '''
                passInfo.addAnalysisOutput(
                    8,
                    "Transformed password: " + passInfo.transformedPassword +
                    '\n' + "Pass through " + key + " PCHL.",
                    "When we applied transformations with " +
                    "low change entropy." + '\n' + "Transforms applied: " +
                    passInfo.getAppliedTransformations()
                    )
                    '''

    def overallCategorySummary(self, passwordData):
        pchlOkCounter = {}
        for passInfo in passwordData:
            for key in passInfo.originallyLibOutput:
                if (key not in pchlOkCounter):
                    pchlOkCounter.update({key: 0})

                if (passInfo.originallyLibOutput[key].decode('UTF-8') !=
                    "OK" and
                    passInfo.transformedLibOutput[key].decode('UTF-8') ==
                   "OK"):
                    pchlOkCounter[key] += 1

        for key in pchlOkCounter:
            percentChange = (pchlOkCounter[key] / len(passwordData) * 100)
            if (percentChange < 15):
                self.addAnalysisOutput(
                        self.overallCategorySummary.__name__ + "1",
                        key,
                        None
                        )
                '''
                self.overallSummary.update({
                    "Less then 15% of passwords pass through " +
                    key + " PCHL":
                    '\n' + "After applying the transformations."
                    })
                    '''
            elif (percentChange < 45):
                self.addAnalysisOutput(
                        self.overallCategorySummary.__name__ + "2",
                        key,
                        None
                        )
                '''
                self.overallSummary.update({
                    "Less then 45% of passwords pass through " +
                    key + " PCHL":
                    '\n' + "After applying the transformations."
                    })
                    '''
            else:
                self.addAnalysisOutput(
                        self.overallCategorySummary.__name__ + "3",
                        key,
                        None
                        )
                '''
                self.overallSummary.update({
                    "More then 45% of passwords pass through " +
                    key + " PCHL":
                    '\n' + "After applying the transformations."
                    })
                    '''
