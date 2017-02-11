from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassData
from scripts.passStruct import Password

import scripts.errorPrinter as errorPrinter
import sys
import json


class Load(object):

    __metaclas__ = ABCMeta

    @abstractmethod
    def __init__(self):
        """Check Python version
        """
        req_version = (3, 0)
        cur_version = sys.version_info

        if (cur_version) < req_version:
            errorPrinter.printError(
                self.__class__.__name__,
                "Update your Python" + '\n'
                "You need Python 3.x to run this program" + '\n' +
                "Your version is: " +
                str(cur_version.major) + '.' +
                str(cur_version.minor) + '.' +
                str(cur_version.micro)
                )

    @abstractmethod
    def loadData(self, passwordData):
        pass


class LoadFromStdin(Load):

    def __init__(self):
        super(LoadFromStdin, self).__init__()

    def loadData(self):
        """Load passwords and entropy from stdin

        Input format -- password(string), space, entropy(float, integer)

        Method return -- passwordData of type PassData
        """
        passwordData = PassData()

        for line in sys.stdin:
            data = line.rstrip('\n').split()
            try:
                if (len(data) == 2):
                    passwordData.add(data[0], float(data[1]))
                elif (len(data) == 1):
                    passwordData.add(data[0])
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


class LoadFromFile(Load):

    def __init__(self, fileName=None):
        super(LoadFromFile, self).__init__()
        self.fileName = fileName

    def loadData(self):
        """Load passwords and entropy from file

        Input format -- password(string), space, entropy(float, integer)

        Method return -- passwordData of type PassData
        """
        passwordData = PassData()

        try:
            with open(self.fileName, 'r') as inputFile:
                for line in inputFile:
                    data = line.rstrip('\n').split()
                    try:
                        if (len(data) == 2):
                            passwordData.add(data[0], float(data[1]))
                        elif (len(data) == 1):
                            passwordData.add(data[0])
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


class LoadFromJson(Load):

    def __init__(self, fileName=None):
        super(LoadFromJson, self).__init__()
        self.fileName = fileName

    def loadData(self):
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
