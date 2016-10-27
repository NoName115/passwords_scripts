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
        for xPassword in passwordData:
            self.changedLibOutputAfterTransformation(xPassword)
            self.lowEntropyPassLibrary(xPassword)
            self.highEntropyNotPassLibrary(xPassword)
            self.lowEntropyChangePassLibrary(xPassword)

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
        for xPassword in passwordData:
            printed = False
            if (xPassword.analysisRating > 20):
                for key in xPassword.analysisOutput:
                    print(key + xPassword.analysisOutput[key])
                    print()
                    printed = True
                if (printed):
                    print("Password-analysis Rating: " +
                          str(xPassword.analysisRating))
                    print("-------------------------------------")

    def changedLibOutputAfterTransformation(self, xPassword):
        for key in xPassword.originallyLibOutput:
            # Output of password checking libraries is same at
            # originally and transformed password
            if (xPassword.originallyLibOutput[key] ==
               xPassword.transformedLibOutput[key]):
                continue
            elif (xPassword.originallyLibOutput[key].decode('UTF-8') == "OK"):
                xPassword.
                addAnalysisOutput(6,
                                  "Output of password checking library " +
                                  key + " changed." + '\n',
                                  "The output for originally password: " +
                                  xPassword.originallyPassword + '\n' +
                                  "is OK, but after applying " +
                                  "transformationspassword changed to: " +
                                  xPassword.transformedPassword + '\n' +
                                  "And the output changed to: " +
                                  xPassword.
                                  transformedLibOutput[key].decode('UTF-8'))
            elif (xPassword.transformedLibOutput[key].decode('UTF-8') == "OK"):
                xPassword.
                addAnalysisOutput(4,
                                  "Output of password checking library " +
                                  key + " changed." + '\n',
                                  "Originally password: " +
                                  xPassword.originallyPassword +
                                  " didn\'t pass through PCHL," + '\n' +
                                  "The output is: " +
                                  xPassword.
                                  originallyLibOutput[key].decode('UTF-8') +
                                  '\n' +
                                  "But after applying transformations," +
                                  " password changed to: " +
                                  xPassword.transformedPassword + '\n' +
                                  "And it pass through " + key + " PCHL.")
            else:
                xPassword.
                addAnalysisOutput(2,
                                  "Password " + xPassword.originallyPassword +
                                  " didn\'t pass through " +
                                  "password checking library " + key,
                                  '\n' + "Either before or after " +
                                  "applying transformations." + '\n' +
                                  "But the output has changed," +
                                  " output before transformations: " + '\n' +
                                  xPassword.
                                  originallyLibOutput[key].decode('UTF-8') +
                                  '\n' + "And the output after " +
                                  "transformations: " + '\n' +
                                  xPassword.
                                  transformedLibOutput[key].decode('UTF-8'))

    def lowEntropyPassLibrary(self, xPassword):
        if (xPassword.entropy < 36):
            for key in xPassword.transformedLibOutput:
                if (xPassword.transformedLibOutput[key].decode('UTF-8') ==
                   "OK"):
                    xPassword.
                    addAnalysisOutput(1,
                                      "After transformations, password: " +
                                      xPassword.transformedPassword + '\n' +
                                      "With low entropy: " +
                                      str(xPassword.entropy) +
                                      " pass through " + key + " PCHL.", "")
        if (xPassword.calculateInitialEntropy() < 36):
            for key in xPassword.originallyLibOutput:
                if (xPassword.originallyLibOutput[key].decode('UTF-8') ==
                   "OK"):
                    xPassword.
                    addAnalysisOutput(2,
                                      "Originally password: " +
                                      xPassword.originallyPassword + '\n' +
                                      "With low entropy: " +
                                      str(xPassword.
                                          calculateInitialEntropy()) +
                                      " pass through " + key + " PCHL.", "")

    def highEntropyNotPassLibrary(self, xPassword):
        if (xPassword.entropy > 60):
            for key in xPassword.transformedLibOutput:
                if (xPassword.transformedLibOutput[key].decode('UTF-8') !=
                   "OK"):
                    xPassword.
                    addAnalysisOutput(2,
                                      "Password: " +
                                      xPassword.transformedPassword + '\n' +
                                      "After transformations and " +
                                      "with high entropy " +
                                      xPassword.entropy + '\n' +
                                      "Didn\'t pass through " + key +
                                      " PCHL.", "")

        if (xPassword.calculateInitialEntropy() > 60):
            for key in xPassword.originallyLibOutput:
                if (xPassword.originallyLibOutput[key].decode('UTF-8') !=
                   "OK"):
                    xPassword.
                    addAnalysisOutput(1,
                                      "Password: " +
                                      xPassword.originallyPassword + '\n' +
                                      "With no transformations and " +
                                      "high entropy " +
                                      xPassword.entropy + '\n' +
                                      "Didn\'t pass through " + key +
                                      " PCHL.", "")

    def lowEntropyChangePassLibrary(self, xPassword):
        def outputChanged(xPassword, pchl):
            for key in xPassword.analysisOutput:
                if (key ==
                   ("Output of password checking library " + pchl +
                    " changed." + '\n')):
                    return True
            return False

        for key in xPassword.transformedLibOutput:
            if (outputChanged(xPassword, key) and
               xPassword.calculateChangedEntropy() < 2):
                xPassword.
                addAnalysisOutput(8,
                                  "Transformed password: " +
                                  xPassword.transformedPassword +
                                  '\n' + "Pass through " + key + " PCHL.",
                                  " When we applied transformations with " +
                                  "low change entropy." +
                                  '\n' + "Transforms applied: " +
                                  xPassword.getAppliedTransformations())

    def overallCategorySummary(self, passwordData):
        pchlOkCounter = {}
        for xPassword in passwordData:
            for key in xPassword.originallyLibOutput:
                if (key not in pchlOkCounter):
                    pchlOkCounter.update({key: 0})

                if (xPassword.originallyLibOutput[key].decode('UTF-8') !=
                    "OK" and
                    xPassword.transformedLibOutput[key].decode('UTF-8') ==
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
