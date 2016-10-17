from termcolor import colored


class Analyzer(object):

    def __init__(self):
        pass

    def mainAnalysis(self, passwordData):
        for xPassword in passwordData:
            self.changedLibOutputAfterTransformation(xPassword)
            self.lowEntropyPassLibrary(xPassword)
            #self.highEntropyNotPassLibrary(xPassword)
            #self.lowEntropyChangePassLibrary(xPassword)

            # Vypise celkovy vystup z toho, vid. dokument
            #self.overallCategorySummary(xPassword)

        #for xPassword in passwordData:
        #    print (xPassword.analysisOutput)

        #Tu vypisuje pre kazde heslo informacie ktore sa zistili
        #for xPassword in passwordData:
        #    xPassword.printAnalysisOutput()
        for xPassword in passwordData:
            printed = False
            if (xPassword.analysisRating >= 8):
                for key in xPassword.analysisOutput:
                    print (key + xPassword.analysisOutput[key])
                    print ()
                    printed = True
                if (printed):
                    print ("Rating: " + str(xPassword.analysisRating))
                    print ("-------------------------------------")

    def changedLibOutputAfterTransformation(self, xPassword):
        for key in xPassword.originallyLibOutput:
            # Output of password checking libraries is same at
            # originally and transformed password
            if (xPassword.originallyLibOutput[key] == \
                xPassword.transformedLibOutput[key]):
                continue;
            elif (xPassword.originallyLibOutput[key].decode('UTF-8') == "OK"):
                xPassword.addAnalysisOutput(6,
                    "Output of password checking library " + key + " changed." + '\n',
                    "The output for originally password: " + xPassword.originallyPassword + \
                    '\n' + \
                    "is OK, but after applying transformations password changed to: " + \
                    xPassword.transformedPassword + '\n' + \
                    "And the output changed to: " + \
                    xPassword.transformedLibOutput[key].decode('UTF-8'))
            elif (xPassword.transformedLibOutput[key].decode('UTF-8') == "OK"):
                xPassword.addAnalysisOutput(4,
                    "Output of password checking library(PCHL) " + key + " changed." + '\n',
                    "Originally password: " + xPassword.originallyPassword + \
                    " didn\'t pass through PCHL," + '\n' + "The output is: " + \
                    xPassword.originallyLibOutput[key].decode('UTF-8') + '\n' + \
                    "But after applying transformations, password changed to: " + \
                    xPassword.transformedPassword + '\n' + \
                    "And it pass through " + key + " PCHL.")
            else:
                xPassword.addAnalysisOutput(2,
                    "Password " + xPassword.originallyPassword + \
                    " didn\'t pass through password checking library " + key,
                    '\n' + "Either before or after applying transformations." + \
                    '\n' + "But the output has changed, output before transformations: " + \
                    '\n' + xPassword.originallyLibOutput[key].decode('UTF-8') + \
                    '\n' + "And the output after transformations: " + '\n' + \
                    xPassword.transformedLibOutput[key].decode('UTF-8'))

    def lowEntropyPassLibrary(self, xPassword):
        if (xPassword.entropy < 36):
            for key in xPassword.transformedLibOutput:
                if (xPassword.transformedLibOutput[key].decode('UTF-8') == "OK"):
                    xPassword.addAnalysisOutput(1,
                        "After transformations, password: " + \
                        xPassword.transformedPassword + '\n' + \
                        "With low entropy: " + str(xPassword.entropy) + \
                        " pass through " + key + " PCHL.",
                        "")
        if (xPassword.calculateInitialEntropy(xPassword) < 36):
            for key in xPassword.originallyLibOutput:
                if (xPassword.originallyLibOutput[key].decode('UTF-8') == "OK"):
                    xPassword.addAnalysisOutput(2,
                        "Originally password: " + xPassword.originallyPassword + '\n' + \
                        "With low entropy: " + str(xPassword.calculateInitialEntropy(xPassword)) + \
                        " pass through " + key + " PCHL.",
                        "")


    def highEntropyNotPassLibrary(self, xPassword):
        pass

    def lowEntropyChangePassLibrary(self, xPassword):
        pass

    def overallCategorySummary(self, xPassword):
        pass
