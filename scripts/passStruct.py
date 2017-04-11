import scripts.errorPrinter as errorPrinter
import re
import json


class Password():

    def __init__(self, password=None, entropy=None):
        """
        Arguments:
        password -- (string)
        entropy -- (float/integer)
        """
        self.originalData = [password, entropy]
        self.transformedData = [password, entropy]
        self.transformRules = []
        self.errorLog = errorPrinter.RuleError()

    def __str__(self):
        return '{0:15} ({1:.2f})'.format(
            self.originalData[0],
            self.originalData[1]
            ) + '\n' + \
            '{0:15} ({1:.2f})'.format(
            self.transformedData[0],
            self.transformedData[1]
            ) + '\n' + self.getAppliedTransformation() + '\n'

    def addTransformRule(self, className, entropy):
        self.transformRules.append({className: entropy})

    def getAppliedTransformation(self):
        """Return string of applied transformations
        """
        return " -> ".join(
            str(list(trans.keys())[0]) + '(' +
            str(list(trans.values())[0]) + ')'
            for trans in self.transformRules
            )

    def getOriginalPassword(self):
        return self.originalData[0]

    def getTransformedPassword(self):
        return self.transformedData[0]

    def getInitialEntropy(self):
        return self.originalData[1]

    def getActualEntropy(self):
        return self.transformedData[1]

    def getChangedEntropy(self):
        return self.transformedData[1] - self.originalData[1]


class PassData(Password):

    def __init__(self, passInfo, originalLibOutput, transformedLibOutput):
        self.originalData = passInfo.originalData
        self.transformedData = passInfo.transformedData
        self.transformRules = passInfo.transformRules
        self.originalLibOutput = originalLibOutput
        self.transformedLibOutput = transformedLibOutput

    def debugData(self):
        """Return all password data

        Output format:
        Original password   Transformed password : Entropy
        Transform : actualEntropy --> NextTransform
        LibraryName - OriginalPassword_LibraryOutput
        LibraryName - TransformedPassword_LibraryOutput
        """
        if (not self.transformRules):
            transformations = "No password transform"

        transformations = self.getAppliedTransformation()

        libOutput = ""
        for key in self.originalLibOutput:
            libOutput += '{0:8} - {1:20}'.format(
                key,
                self.originalLibOutput[key]
                ) + '\n'
            libOutput += '{0:8} - {1:20}'.format(
                key,
                self.transformedLibOutput[key]
                ) + '\n'

        return '{0:1} ({1:.2f}) {2:1} ({3:.2f})'.format(
            self.originalData[0],
            self.originalData[1],
            self.transformedData[0],
            self.transformedData[1]
            ) + '\n' + transformations + '\n' + libOutput

    def __str__(self):
        """Return password data

        Return format:
        Password : Entropy
        Transform : actualEntropy (entropyChange) --> NextTransform
        LibraryName - LibraryOutput
        """

        originalPCLOutputs = "    ".join(
            '{0:1}: {1:10}'.format(key, value)
            for key, value in self.originalLibOutput.items()
            )

        transformedPCLOutputs = "    ".join(
            '{0:1}: {1:10}'.format(key, value)
            for key, value in self.transformedLibOutput.items()
            )

        # Check if transformation take effect on password
        errorOutput = ""
        for trans in self.transformRules:
            for key, value in trans.items():
                if (value == 0):
                    errorOutput += (
                        "Transformation  " + key + "  wasn\'t applied" + '\n'
                        )

        return '{0:10} ({1:.2f})'.format(
            self.originalData[0],
            self.originalData[1]
            ) + " " + originalPCLOutputs + '\n' + \
            '{0:10} ({1:.2f})'.format(
                self.transformedData[0],
                self.transformedData[1]
                ) + " " + transformedPCLOutputs + '\n' + errorOutput

    def getOriginalLibOutput(self):
        return self.originalLibOutput

    def getTransformedLibOutput(self):
        return self.transformedLibOutput
