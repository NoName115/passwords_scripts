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
            errorText = (
                "Update your Python\n" +
                "You need Python 3.x to run this program\n"
                )
            if (cur_version < (2, 7)):
                errorText += "Your version is lower then 2.7"
            else:
                errorText += (
                    "Your version is: " +
                    str(cur_version.major) + '.' +
                    str(cur_version.minor) + '.' +
                    str(cur_version.micro)
                    )

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
                elif (len(data) == 1):
                    passwordData.append([
                        data[0],
                        self.generateEntropy(data[0])
                        ])
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

        Method return -- tuple [passInfoList, pclData]
                         passInfoList - list of PassInfo classes
                         pclData - dictionary of passwords and PCL outputs
        """

        try:
            with open(self.fileName) as jsonFile:
                data = json.load(jsonFile)

            passInfoList = []
            pclData = {}
            #Parse json data
            for passData in data['passwordList']:
                newPassword = Password(
                        passData['originalPassword'],
                        passData['initialEntropy']
                        )
                newPassword.transformedData = [
                    passData['transformedPassword'],
                    passData['actualEntropy']
                    ]
                newPassword.transformRules = passData['transformRules']
                newPassword.errorLog = errorPrinter.RuleError(
                    passData['errorLog']
                    )
                passInfoList.append(newPassword)

                pclData.update({
                    passData['originalPassword']: passData['originalLibOutput'],
                    passData['transformedPassword']: passData['transformedLibOutput']
                })

            return passInfoList, pclData

        except IOError:
            errorPrinter.printError(
                self.__class__.__name__,
                'File \'{0:1}\' doesn\'t exist'.format(self.fileName)
            )


class StoreDataToJson():

    def __init__(self, filename=None):
        self.fileName = filename

    def store(self, passInfoList, pclData):
        """Store passInfoList and pclData to Json

        Arguments:
        passInfoList -- list of PassInfo classes
        pclData -- dictionary of passwords and pcl outputs
        """
        self.fileName = self.fileName if (self.fileName) else "inputs/passData.json"
        outputFile = open(self.fileName, 'w')

        passwordJsonList = []
        for passInfo in passInfoList:
            passwordJsonList.append({
                'originalPassword': passInfo.getOriginalPassword(),
                'transformedPassword': passInfo.getTransformedPassword(),
                'initialEntropy': passInfo.getInitialEntropy(),
                'actualEntropy': passInfo.getActualEntropy(),
                'transformRules': passInfo.transformRules,
                'originalLibOutput': pclData[passInfo.getOriginalPassword()],
                'transformedLibOutput': pclData[passInfo.getTransformedPassword()],
                'errorLog': passInfo.errorLog.getLog()
            })

        outputFile.write(
            json.dumps(
                {
                    'passwordList': passwordJsonList
                },
                sort_keys=True,
                indent=4,
                separators=(',', ':')
            )
        )

        outputFile.close()
