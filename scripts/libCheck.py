from abc import ABCMeta, abstractmethod
from zxcvbn import zxcvbn

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
            pcl_dic.update({passinfo.password: {}})

            for pcl in self.pclList:
                pcl.checkPassword(passinfo, pcl_dic)

        return pcl_dic


class Library():

    __metaclass__ = ABCMeta

    @abstractmethod
    def checkPassword(self, passinfo, pcl_dic, delimiter=None, *args):
        """Get output of library and save it to passwordData

        Arguments:
        passinfo -- type Password from passStruct.py
        pcl_dic -- dictionary
        delimiter -- optional argument, if is necessary to split library output
        *args -- arguments for run/call library
        """
        try:
            output = self.getPCLOutput(
                passinfo.password,
                delimiter,
                *args
                )
            output = self.convertOutput(
                output
            )
            self.storePCLOutput(
                pcl_dic,
                passinfo.password,
                output
                )

        except Exception as err:
            raise
            errorPrinter.printWarning(
                self.__class__.__name__,
                err
                )

    def storePCLOutput(self, pcl_dic, password, pcl_output):
        pcl_dic[password].update({
            self.__class__.__name__: pcl_output
        })

    @abstractmethod
    def convertOutput(self, input_output):
        return input_output

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

        output = p.communicate(input=bytes(password, 'UTF-8'))

        # Check if output is printed to stdout or stderr
        output = output[0].decode('UTF-8').rstrip('\n') if (output[0]) \
            else output[1].decode('UTF-8').rstrip('\n')

        if (delimiter):
            output_split = output.split(delimiter)

            return (output_split[0], None) if (len(output_split) == 1) \
                else (output_split[1], None)

        return (output, None)


class CrackLib(Library):

    def checkPassword(self, passinfo, pcl_dic):
        super(CrackLib, self).checkPassword(
            passinfo,
            pcl_dic,
            ": ",
            "cracklib-check"
            )


class PassWDQC(Library):

    def checkPassword(self, passinfo, pcl_dic):
        super(PassWDQC, self).checkPassword(
            passinfo,
            pcl_dic,
            None,
            "pwqcheck", "-1"
            )


class Zxcvbn(Library):

    def checkPassword(self, passinfo, pcl_dic):
        result = zxcvbn(passinfo.password)
        warning = result['feedback']['warning']
        suggestions = result['feedback']['suggestions']

        output = ''
        if (warning):
            output = warning + ' '
        if (suggestions):
            output += ' '.join(str(sugg) for sugg in suggestions)

        self.storePCLOutput(
            pcl_dic,
            passinfo.password,
            (output, result['score'])
            )


class Pwscore(Library):

    def checkPassword(self, passinfo, pcl_dic):
        super(Pwscore, self).checkPassword(
            passinfo,
            pcl_dic,
            ":\n ",
            "pwscore"
        )

    def convertOutput(self, input_output):
        if (input_output[0].isdigit()):
            return (
                '',
                int(input_output[0])
                )

        return (input_output[0], 0)
