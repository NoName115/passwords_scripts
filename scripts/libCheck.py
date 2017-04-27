from abc import ABCMeta, abstractmethod

import scripts.errorPrinter as errorPrinter
import subprocess


class PassCheckLib():

    def __init__(self):
        """Initialize list of password checking libraries
        """
        self.pclList = []

    def add(self, pcl):
        """Add password checking library to list
        """
        self.pclList.append(pcl)

    def check(self, passinfo_list):
        """Check every password with every
        password checking library from list

        Arguments:
        passinfo_list -- list, list of PassInfo classes

        Return value:
        pcl_dic -- dictionary, key=string value=dictionary
        """
        pcl_dic = {}

        for passinfo in passinfo_list:
            pcl_dic.update({passinfo.original_data[0]: {}})
            pcl_dic.update({passinfo.transformed_data[0]: {}})

            for pcl in self.pclList:
                pcl.checkResult(passinfo, pcl_dic)

        return pcl_dic


class Library(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def checkResult(self, passinfo, pcl_dic, delimiter=None, *args):
        """Get output of library and save it to passwordData

        Arguments:
        passinfo -- type Password from passStruct.py
        pcl_dic -- dictionary
        delimiter -- optional argument, if is necessary to split library output
        *args -- arguments for run/call library
        """
        try:
            output = self.getPCLOutput(
                passinfo.original_data[0],
                delimiter,
                *args
                )
            pcl_dic[passinfo.original_data[0]].update({
                self.__class__.__name__: output
                })

            output = self.getPCLOutput(
                passinfo.transformed_data[0],
                delimiter,
                *args
                )
            pcl_dic[passinfo.transformed_data[0]].update({
                self.__class__.__name__: output
                })

        except Exception as err:
            errorPrinter.printWarning(
                self.__class__.__name__,
                err
                )

    @staticmethod
    def getPCLOutput(password, delimiter, *args):
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

    def checkResult(self, passinfo, pcl_dic):
        super(CrackLib, self).checkResult(
            passinfo,
            pcl_dic,
            ": ",
            "cracklib-check"
            )


class PassWDQC(Library):

    def __init__(self):
        super(PassWDQC, self).__init__()

    def checkResult(self, passinfo, pcl_dic):
        super(PassWDQC, self).checkResult(
            passinfo,
            pcl_dic,
            None,
            "pwqcheck", "-1"
            )
