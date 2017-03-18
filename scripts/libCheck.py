from abc import ABCMeta, abstractmethod
from scripts.passStruct import Password

import scripts.errorPrinter as errorPrinter
import subprocess


class PassCheckLib():

    def __init__(self):
        self.pclList = []

    def add(self, pcl):
        self.pclList.append(pcl)

    def check(self, passInfo):
        pass


class Library(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def checkResult(self, passwordData, delimiter=None, *args):
        """Get output of library and save it to passwordData

        Arguments:
        passwordData -- type PassData
        delimiter -- optional argument, if is necessary to split library output
        *args -- arguments for run/call library
        """
        try:
            for x in passwordData:
                self.setPCHLOutput(
                    x.transformedPassword,
                    x,
                    x.addTransformedLibOutput,
                    delimiter,
                    *args
                    )
                self.setPCHLOutput(
                    x.originalPassword,
                    x,
                    x.addOriginalLibOutput,
                    delimiter,
                    *args
                    )

            # Store PCHL name to PassData class
            passwordData.usedPCHL.append(self.__class__.__name__)

        except Exception as err:
            errorPrinter.printWarning(
                self.__class__.__name__,
                err
                )

    def setPCHLOutput(self, password, passInfo,
                      libraryOutputMethod, delimiter, *args):
        """Function get output of library and store it to passwordData

        Arguments:
        password -- input password, type string
        passInfo -- type passStruct.Password
        libraryOutputMethod -- method called to store PCHL output
        delimiter -- split library output
        *args -- arguments for run/call library
        """
        p = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
            )

        output = p.communicate(
            input=bytes(password, 'UTF-8')
            )[0].decode('UTF-8').rstrip('\n')

        if (delimiter is None):
            libraryOutputMethod(
                self.__class__.__name__,
                output
                )
        else:
            libraryOutputMethod(
                self.__class__.__name__,
                output.split(delimiter)[1]
                )


class CrackLib(Library):

    def __init__(self):
        super(CrackLib, self).__init__()

    def checkResult(self, passwordData):
        super(CrackLib, self).checkResult(
            passwordData,
            ": ",
            "cracklib-check")


class PassWDQC(Library):

    def __init__(self):
        super(PassWDQC, self).__init__()

    def checkResult(self, passwordData):
        super(PassWDQC, self).checkResult(
            passwordData,
            None,
            "pwqcheck", "-1")
