from termcolor import colored


class Analyzer(object):

    def __init__(self):
        pass

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

        # Vypise celkovy vystup z toho, vid. dokument
        self.overallSummary = {}
        self.overallCategorySummary(passwordData)

        # Print overall information
        print("Overall information:")
        for key in self.overallSummary:
            print(key + self.overallSummary[key])

        print("--------------------------------------")
        print("--------------------------------------")

        # Print information about password
        # with rating more then 12
        for passInfo in passwordData:
            printed = False
            if (passInfo.analysisRating > 20):
                for key in passInfo.analysisOutput:
                    print(key + passInfo.analysisOutput[key])
                    print()
                    printed = True
                if (printed):
                    print("Password-analysis Rating: " +
                          str(passInfo.analysisRating))
                    print("-------------------------------------")

    def changedLibOutputAfterTransformation(self, passInfo):
        for key in passInfo.originallyLibOutput:
            # Output of password checking libraries is same at
            # originally and transformed password
            if (passInfo.originallyLibOutput[key] ==
               passInfo.transformedLibOutput[key]):
                continue
            elif (passInfo.originallyLibOutput[key].decode('UTF-8') == "OK"):
                passInfo.addAnalysisOutput(
                    6,
                    "Output of PCHL " + key + " changed." + '\n',
                    "The output for originally password: " +
                    passInfo.originallyPassword + '\n' +
                    "is OK, but after applying transformations password " +
                    "changed to: " + passInfo.transformedPassword + '\n' +
                    "And the output changed to: " +
                    passInfo.transformedLibOutput[key].decode('UTF-8')
                    )
            elif (passInfo.transformedLibOutput[key].decode('UTF-8') == "OK"):
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
            else:
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

    def lowEntropyPassLibrary(self, passInfo):
        if (passInfo.entropy < 36):
            for key in passInfo.transformedLibOutput:
                if (passInfo.transformedLibOutput[key].decode('UTF-8') ==
                   "OK"):
                    passInfo.addAnalysisOutput(
                        1,
                        "After transformations, password: " +
                        passInfo.transformedPassword + '\n' +
                        "With low entropy: " + str(passInfo.entropy) +
                        " pass through " + key + " PCHL.",
                        ""
                        )
        if (passInfo.calculateInitialEntropy() < 36):
            for key in passInfo.originallyLibOutput:
                if (passInfo.originallyLibOutput[key].decode('UTF-8') ==
                   "OK"):
                    passInfo.addAnalysisOutput(
                        2,
                        "Originally password: " + passInfo.originallyPassword +
                        '\n' + "With low entropy: " +
                        str(passInfo.calculateInitialEntropy()) +
                        " pass through " + key + " PCHL.",
                        ""
                        )

    def highEntropyNotPassLibrary(self, passInfo):
        if (passInfo.entropy > 60):
            for key in passInfo.transformedLibOutput:
                if (passInfo.transformedLibOutput[key].decode('UTF-8') !=
                   "OK"):
                    passInfo.addAnalysisOutput(
                        2,
                        "Password: " + passInfo.transformedPassword +
                        '\n' + "After transformations and with high entropy " +
                        passInfo.entropy + '\n' + "Didn\'t pass through " +
                        key + " PCHL.",
                        ""
                        )

        if (passInfo.calculateInitialEntropy() > 60):
            for key in passInfo.originallyLibOutput:
                if (passInfo.originallyLibOutput[key].decode('UTF-8') !=
                   "OK"):
                    passInfo.addAnalysisOutput(
                        1,
                        "Password: " + passInfo.originallyPassword +
                        '\n' + "With no transformations and high entropy " +
                        passInfo.entropy + '\n' + "Didn\'t pass through " +
                        key + " PCHL.",
                        ""
                        )

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
                passInfo.addAnalysisOutput(
                    8,
                    "Transformed password: " + passInfo.transformedPassword +
                    '\n' + "Pass through " + key + " PCHL.",
                    "When we applied transformations with " +
                    "low change entropy." + '\n' + "Transforms applied: " +
                    passInfo.getAppliedTransformations()
                    )

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
                self.overallSummary.update({
                    "Less then 15% of passwords pass through " +
                    key + " PCHL":
                    '\n' + "After applying the transformations."
                    })
            elif (percentChange < 45):
                self.overallSummary.update({
                    "Less then 45% of passwords pass through " +
                    key + " PCHL":
                    '\n' + "After applying the transformations."
                    })
            else:
                self.overallSummary.update({
                    "More then 45% of passwords pass through " +
                    key + " PCHL":
                    '\n' + "After applying the transformations."
                    })
