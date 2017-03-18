from abc import ABCMeta, abstractmethod
from math import log
from scripts.passStruct import Password

import scripts.errorPrinter as errorPrinter
import sys
import json


class Loader(object):

    __metaclas__ = ABCMeta

    @abstractmethod
    def __init__(self):
        """Check Python version
        """
        req_version = (3, 0)
        cur_version = sys.version_info

        if (cur_version < req_version):
            errorText = ("Update your Python\n" +
                "You need Python 3.x to run this program\n")
            if (cur_version < (2, 7)):
                errorText += "Your version is lower then 2.7"
            else:
                errorText += ("Your version is: " +
                    str(cur_version.major) + '.' +
                    str(cur_version.minor) + '.' +
                    str(cur_version.micro))

            errorPrinter.printError(
                self.__class__.__name__,
                errorText
                )

    @abstractmethod
    def load(self, passwordData):
        pass

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


class LoadFromStdin(Loader):

    def __init__(self):
        super(LoadFromStdin, self).__init__()

    def load(self):
        """Load passwords and entropy from stdin

        Input format -- password(string), space, entropy(float, integer)

        Method return -- passwordData of type PassData
        """
        passwordData = []

        for line in sys.stdin:
            data = line.rstrip('\n').split()
            try:
                if (len(data) == 2):
                    passwordData.append([
                        data[0],
                        round(float(data[1]), 2)
                        ])
                    #passwordData.add(data[0], float(data[1]))
                elif (len(data) == 1):
                    passwordData.append([
                        data[0],
                        self.generateEntropy(data[0])
                        ])
                    #passwordData.add(data[0])
                else:
                    errorPrinter.printWarning(
                        self.__class__.__name__,
                        "Invalid line in input file: Too many items at line"
                        )
            except ValueError:
                errorPrinter.printWarning(
                    self.__class__.__name__,
                    'Wrong input \'{0:1}\' have to be number'.format(data[1])
                    )

        return passwordData


class LoadFromFile(Loader):

    def __init__(self, fileName=None):
        super(LoadFromFile, self).__init__()
        self.fileName = fileName

    def load(self):
        """Load passwords and entropy from file

        Input format -- password(string), space, entropy(float, integer)

        Method return -- passwordData of type PassData
        """
        passwordData = []

        try:
            with open(self.fileName, 'r') as inputFile:
                for line in inputFile:
                    data = line.rstrip('\n').split()
                    try:
                        if (len(data) == 2):
                            passwordData.append([
                                data[0],
                                round(float(data[1]))
                                ])
                        elif (len(data) == 1):
                            passwordData.append([
                                data[0],
                                self.generateEntropy(data[0])
                                ])
                        else:
                            errorPrinter.printWarning(
                                self.__class__.__name__,
                                "Invalid line in input file:" +
                                " Too many items at line"
                                )
                    except ValueError:
                        errorPrinter.printWarning(
                            self.__class__.__name__,
                            'Wrong input \'{0:1}\' have to be number'.
                            format(data[1])
                            )
        except IOError:
            errorPrinter.printError(
                self.__class__.__name__,
                'File \'{0:1}\' doesn\'t exist'.format(self.fileName)
                )

        return passwordData


class LoadFromJson(Loader):

    def __init__(self, fileName=None):
        super(LoadFromJson, self).__init__()
        self.fileName = fileName

    def load(self):
        """Load passData from input file

        Method return -- passwordData of type PassData
        """
        passwordData = PassData()

        try:
            with open(self.fileName) as jsonFile:
                data = json.load(jsonFile)

            # Parse json data
            for passInfo in data["passwordList"]:
                newPassword = Password(
                    passInfo["originalPassword"],
                    passInfo["entropy"]
                    )
                newPassword.transformedPassword = passInfo[
                    "transformedPassword"
                    ]
                newPassword.transformRules = passInfo[
                    "transformRules"
                    ]
                newPassword.originalLibOutput = passInfo[
                    "originalLibOutput"
                    ]
                newPassword.transformedLibOutput = passInfo[
                    "transformedLibOutput"
                    ]

                passwordData.passwordList.append(
                    newPassword
                    )

            passwordData.transformRules = data["transformRules"]
            passwordData.usedPCHL = data["usedPCHL"]
            passwordData.errorLog.errorLog = data["errorLog"]

        except IOError:
            errorPrinter.printError(
                self.__class__.__name__,
                'File \'{0:1}\' doesn\'t exist'.format(self.fileName)
                )

        return passwordData
