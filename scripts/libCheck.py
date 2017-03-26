from abc import ABCMeta, abstractmethod
from scripts.passStruct import Password

import scripts.errorPrinter as errorPrinter
import subprocess


class PassCheckLib():

    def __init__(self):
        self.pclList = []

    def add(self, pcl):
        self.pclList.append(pcl)

    def check(self, passInfoList):
        pclDic = {}

        for passInfo in passInfoList:
            pclDic.update({ passInfo.originalData[0]: {} })
            pclDic.update({ passInfo.transformedData[0]: {} })

            for pcl in self.pclList:
                pcl.checkResult(passInfo, pclDic)

        return pclDic


class Library(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def checkResult(self, passInfo, pclDic, delimiter=None, *args):
        """Get output of library and save it to passwordData

        Arguments:
        passwordData -- type PassData
        delimiter -- optional argument, if is necessary to split library output
        *args -- arguments for run/call library
        """
        try:
            output = self.getPCHLOutput(
                passInfo.originalData[0],
                delimiter,
                *args
                )
            pclDic[passInfo.originalData[0]].update({
                self.__class__.__name__: output
                })

            output = self.getPCHLOutput(
                passInfo.transformedData[0],
                delimiter,
                *args
                )
            pclDic[passInfo.transformedData[0]].update({
                self.__class__.__name__: output
                })

        except Exception as err:
            raise
            errorPrinter.printWarning(
                self.__class__.__name__,
                err
                )

    def getPCHLOutput(self, password, delimiter, *args):
        """Function get output of library and store it to passwordData

        Arguments:
        password -- input password, type string
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

        return output if (delimiter is None) else output.split(delimiter)[1]


class CrackLib(Library):

    def __init__(self):
        super(CrackLib, self).__init__()

    def checkResult(self, passInfo, pclDic):
        super(CrackLib, self).checkResult(
            passInfo,
            pclDic,
            ": ",
            "cracklib-check"
            )


class PassWDQC(Library):

    def __init__(self):
        super(PassWDQC, self).__init__()

    def checkResult(self, passInfo, pclDic):
        super(PassWDQC, self).checkResult(
            passInfo,
            pclDic,
            None,
            "pwqcheck", "-1"
            )
