import scripts.errorPrinter as errorPrinter
import random
import re
import json

from math import log


class Password():

    def __init__(self, password=None, entropy=None):
        """
        Arguments:
        password -- (string)
        entropy -- (float/integer)
        """
        self.originalPassword = password
        self.transformedPassword = password
        self.entropy = entropy
        self.transformRules = []

        self.originalLibOutput = {}
        self.transformedLibOutput = {}

    def debugData(self):
        """Return all password data

        Output format:
        Original password   Transformed password : Entropy
        Transform : actualEntropy --> NextTransform
        LibraryName - OriginalPassword_LibraryOutput
        LibraryName - TransformedPassword_LibraryOutput
        """
        transformations = ''
        startEntropy = self.entropy

        for element in reversed(self.transformRules):
            transformations = '{0:15} : {1:.2f}, '.format(
                element[0], startEntropy) + transformations
            startEntropy -= int(element[1])

        if (len(self.transformRules) == 0):
            transformations = "No password transform"

        libOutput = ''
        for key in self.originalLibOutput:
            libOutput += '{0:8} - {1:20}'.format(
                key,
                self.originalLibOutput[key]
                ) + '\n'
            libOutput += '{0:8} - {1:20}'.format(
                key,
                self.transformedLibOutput[key]
                ) + '\n'

        return '{0:15} {1:15}'.format(
            self.originalPassword,
            self.transformedPassword
            ) + '\n' + transformations + '\n' + libOutput

    def __str__(self):
        """Return password data

        Return format:
        Password : Entropy
        Transform : actualEntropy (entropyChange) --> NextTransform
        LibraryName - LibraryOutput
        """

        originalPCHLOutputs = ""
        for key in self.originalLibOutput:
            originalPCHLOutputs += '{0:8}: {1:20}   '.format(
                key,
                self.originalLibOutput[key]
                )

        transformedPCHLOutputs = ""
        for key in self.transformedLibOutput:
            transformedPCHLOutputs += '{0:8}: {1:20}   '.format(
                key,
                self.transformedLibOutput[key]
                )

        errorOutput = ""
        for trans in self.transformRules:
            # Check if transformation take effect on password
            if (trans[1] == 0):
                errorOutput += "Transformation  " + trans[0] + \
                    "  wasn\'t applied" + '\n'

        return self.originalPassword + " (" + \
            '{0:.2f}'.format(self.calculateInitialEntropy()) + \
            ") " + originalPCHLOutputs + '\n' + \
            self.transformedPassword + " (" + \
            '{0:.2f}'.format(self.entropy) + ") " + \
            transformedPCHLOutputs + '\n' + \
            errorOutput + '\n'

    def addOriginalLibOutput(self, libraryName, libOutput):
        """Add library output to dictionary

        Arguments:
        libraryName -- name of the library
        libOutput -- output of the library
        """
        self.originalLibOutput.update({libraryName: libOutput})

    def addTransformedLibOutput(self, libraryName, libOutput):
        """Add library output to dictionary

        Arguments:
        libraryName -- name of the library
        libOutput -- output of the library
        """
        self.transformedLibOutput.update({libraryName: libOutput})

    def calculateInitialEntropy(self):
        """Calculate initial entropy, entropy of
        original password
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


class PassData():

    def __init__(self):
        """Initialize list(list of objects of type Password)
        """
        self.passwordList = []
        self.transformRules = []
        self.usedPCHL = []
        self.errorLog = errorPrinter.RuleError()

    def __str__(self):
        return '\n'.join(str(x) for x in self.passwordList)

    def __iter__(self):
        for x in self.passwordList:
            yield x

    def __len__(self):
        return len(self.passwordList)

    def add(self, *args):
        """Add new password to list

        Arguments:
        password -- (string)
        entropy -- value of entropy(float/integer) - optional argument
        """
        if (len(args) == 1):
            self.passwordList.append(
                Password(args[0], self.generateEntropy(args[0]))
                )
        elif (len(args) == 2):
            try:
                self.passwordList.append(
                    Password(args[0], round(args[1], 2))
                    )
            except ValueError:
                errorPrinter.printWarning(
                    "Adding password to passwordData",
                    '\'{0:1}\' is not a number'.format(args[1])
                    )
        else:
            errorPrinter.printWarning(
                "Adding password to passwordData",
                "Wrong number of arguments,",
                "Correct: password(String)," +
                " entropy(Number) - optional argument"
                )

    def getTransformRules(self):
        return ", ".join(str(x) for x in self.transformRules) + '\n'

    def storeDataToJson(self, filename):
        outputFile = open(filename, "w")

        passwordJsonList = []
        for passInfo in self:
            passwordJsonList.append({
                'originalPassword': passInfo.originalPassword,
                'transformedPassword': passInfo.transformedPassword,
                'entropy': passInfo.entropy,
                'transformRules': passInfo.transformRules,
                'originalLibOutput': passInfo.originalLibOutput,
                'transformedLibOutput': passInfo.transformedLibOutput
            })

        outputFile.write(
            json.dumps(
                {
                    'passwordList': passwordJsonList,
                    'transformRules': self.transformRules,
                    'usedPCHL': self.usedPCHL,
                    'errorLog': self.errorLog.errorLog
                },
                sort_keys=True,
                indent=4,
                separators=(',', ': ')
            )
        )

        outputFile.close()

    def printDebugData(self):
        """Print every password data from list

        Output format:
        Original password   Transformed password : Entropy
        Transform : actualEntropy --> NextTransform
        LibraryName - OriginalPassword_LibraryOutput
        LibraryName - TransformedPassword_LibraryOutput
        """
        if (len(self) == 0):
            errorPrinter.printWarning(
                "printData",
                "PasswordData is empty... Nothing to write")
            return None

        for x in self.passwordList:
            print(x.debugData())

    def generateEntropy(self, inputPassword):
        """Method calculate password entropy

        Arguments:
        inputPassword -- password

        Entropy calculated by formula
            len(inputPassword) / 1.5 * log(charEntropy, 2), 2
        First calculate charEntropy,
        'charEntropy' is increased by upperCase characters,
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
