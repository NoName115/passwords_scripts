import scripts.errorPrinter as errorPrinter
import random
import re

from math import log


class Password():

    def __init__(self, password=None, entropy=None):
        """
        Arguments:
        password -- (string)
        entropy -- (float/integer)
        """
        self.originallyPassword = password
        self.transformedPassword = password
        self.entropy = entropy
        self.transformRules = []

        self.originallyLibOutput = {}
        self.transformedLibOutput = {}

        self.analysisOutput = {}
        self.analysisRating = 0

    def __str__(self):
        """Return password data

        Return format:
        Password : Entropy
        Transform : actualEntropy (entropyChange) --> NextTransform
        LibraryName - LibraryOutput
        """
        transformOutput = ''
        startEntropy = self.entropy

        for element in reversed(self.transformRules):
            transformOutput = '{0:15} : {1:.2f}, '.format(
                element[0], startEntropy) + transformOutput
            startEntropy -= int(element[1])

        if (len(self.transformRules) == 0):
            transformOutput = "No password transform"

        libOutput = ''
        for key in self.originallyLibOutput:
            libOutput += '{0:8} - {1:20}'.format(
                key,
                self.originallyLibOutput[key].decode('UTF-8')) + '\n'

        return '{0:15} {1:15} : {2:.2f}'.format(self.originallyPassword, self.transformedPassword, startEntropy) + \
               '\n' + transformOutput + '\n' + libOutput

    def libCheckData(self):
        """Return library output

        Return format:
        Password
        LibraryName - LibraryOutput
        """

        libOutput = ''
        for key in self.originallyLibOutput:
            libOutput += '{0:8} - {1:20}'.format(
                key,
                self.originallyLibOutput[key].decode('UTF-8')) + '\n'
            libOutput += '{0:8} - {1:20}'.format(
                key,
                self.transformedLibOutput[key].decode('UTF-8')) + '\n'

        return '{0:15} {1:15}'.format(self.originallyPassword, self.transformedPassword) + '\n' + libOutput

    def addOriginallyLibOutput(self, libraryName, libOutput):
        """Add library output to dictionary

        Arguments:
        libraryName -- name of the library
        libOutput -- output of the library
        """
        self.originallyLibOutput.update({libraryName: libOutput})

    def addTransformedLibOutput(self, libraryName, libOutput):
        """Add library output to dictionary

        Arguments:
        libraryName -- name of the library
        libOutput -- output of the library
        """
        self.transformedLibOutput.update({libraryName: libOutput})

    def addAnalysisOutput(self, analysisRating, analysisKey, analysisValue):
        """Add analysis output to dictionary

        Arguments:
        analysisRating -- rating for certain analysis method
        analysisKey -- main infromation about analysis output
        analysisValue -- more detailed infromation about analysis output
        """
        self.analysisOutput.update({analysisKey: analysisValue})
        self.analysisRating += analysisRating

    def calculateInitialEntropy(self):
        """Calculate initial entropy, entropy of
        originally password
        """
        startEntropy = self.entropy

        for element in reversed(self.transformRules):
            startEntropy -= int(element[1])

        return startEntropy

    def calculateChangedEntropy(self):
        """Calculate changed entropy,

        Calculation:
        Actual entropy (entropy after transformations)
        minus initial entropy
        """
        return self.entropy - self.calculateInitialEntropy()

    def getAppliedTransformations(self):
        """Method return all transformations
        applied at password
        """
        output = ""
        for x in self.transformRules:
            output += x[0] + '\n'
        return output


class PassData():

    def __init__(self):
        """Initialize list(list of objects of type Password)
        """
        self.passwordList = []
        self.isTagged = False

        self.errorLog = errorPrinter.RuleError()

    def add(self, *args):
        """Add new password to list

        Arguments:
        password -- (string)
        entropy -- value of entropy(float/integer) - optional argument
        """
        if (len(args) == 1):
            self.passwordList.append(
                Password(args[0], self.generateEntropy(args[0])))
        elif (len(args) == 2):
            try:
                self.passwordList.append(Password(args[0], round(args[1], 2)))
            except ValueError:
                errorPrinter.printWarning(
                    "Adding password to passwordData",
                    '\'{0:1}\' is not a number'.format(args[1]))
        else:
            errorPrinter.printWarning(
                "Adding password to passwordData",
                "Wrong number of arguments,",
                "Correct: password(String), entropy(Number) - optional argument")

    def printData(self):
        """Print every password data from list

        Output format:
        Password : Entropy
        Transform : actualEntropy (entropyChange) --> NextTransform
        LibraryName - LibraryOutput
        """
        if (len(self.passwordList) == 0):
            errorPrinter.printWarning(
                "printData",
                "PasswordData is empty... Nothing to write")
            return None

        for x in self.passwordList:
            print (x)

    def printLibCheckData(self):
        """Print only password and library output

        Output format:
        Password
        LibraryName - LibraryOutput
        """

        for x in self.passwordList:
            print (x.libCheckData())

    def __iter__(self):
        for x in self.passwordList:
            yield x

    def __len__(self):
        counter = 0
        for x in self:
            counter += 1

        return counter

    def generateEntropy(self, inputPassword):
        """Method calculate password entropy

        Arguments:
        inputPassword -- password

        Entropy calculated by formula
        first calculate charEntropy.
        charEntropy is increased by upperCase characters,
        digits, special symbols and by symbols out of ASCII table

        Return value:
        entropy -- float number
        """
        charEntropy = 0

        # Lowercase character in password
        if (any(c.islower() for c in inputPassword)):
            charEntropy += 26

        # Uppercase character in password
        if (any(c.isupper() for c in inputPassword)):
            charEntropy += 26

        # Digit character in password
        if (any(c.isdigit() for c in inputPassword)):
            charEntropy += 10

        # Special
        if (any((c in '!@#$%^&*()') for c in inputPassword)):
            charEntropy += 10

        # Special2
        if (any((c in "`~-_=+[{]}\\|;:'\",<.>/?") for c in inputPassword)):
            charEntropy += 20

        # Space contain
        if (any((c in ' ') for c in inputPassword)):
            charEntropy += 1

        # Other symbols
        if (any(((c > '~' or c < ' ')) for c in inputPassword)):
            charEntropy += 180

        return round(len(inputPassword) / 1.5 * log(charEntropy, 2), 2)
