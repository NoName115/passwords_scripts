from abc import ABCMeta, abstractmethod
from zxcvbn import zxcvbn

import scripts.errorPrinter as errorPrinter
import subprocess


class PassCheckLib():

    def __init__(self):
        """Initialize list of password checking libraries
        """
        self.single_pcl_list = []
        self.multi_pcl_list = []

    def add(self, pcl):
        """Add password checking library to list
        """
        if (pcl.single_pass):
            self.single_pcl_list.append(pcl)
        else:
            self.multi_pcl_list.append(pcl)

    def check(self, passinfo_list):
        """Check every password with every
        password checking library from list

        Arguments:
        passinfo_list -- list, list of PassInfo classes

        Return value:
        pcl_dic -- dictionary, key=string value=dictionary
        """

        # Dat vsetko do __init__
        # Vytvorit tak dictionary zo vsetkych hesiel
        # Viem tak rozlisit ktore PCL idu na single a ktore nie
        # rozlisit to vem uz pri add methode v tomto objekte

        # Najprv urobim single PCL a potom multi

        # Stym ze dictionary sa vytvori pri single
        # alebo na zaciatku kompletna dictionary
        # alebo dam podmienku do storePCLOutput ze ak tam v dict nieje
        # dane heslo tak ho tam prida
        # (je mozne ze bude vela krat kontrolovat nepotrebne)

        # Create pcl dictionary and check password with single_pcl_list
        pcl_dic = {}
        for passinfo in passinfo_list:
            pcl_dic.update({passinfo.password: {}})
            for pcl in self.single_pcl_list:
                pcl.checkPassword(passinfo.password, pcl_dic)

        # Check passwords with multi_pcl_list
        for pcl in self.multi_pcl_list:
            pcl.checkPassword(
                [passinfo.password for passinfo in passinfo_list],
                pcl_dic
                )

        return pcl_dic


class Library():

    __metaclass__ = ABCMeta

    def __init__(
        self, single_pass=True,
        delimiter=None, delimiter_index=None, *args
        ):
        self.single_pass = single_pass
        self.delimiter = (delimiter, delimiter_index)
        self.args = args

    @abstractmethod
    def checkPassword(self, password_input, pcl_dic):
        """Get output of library and save it to passwordData

        Arguments:
        password_input -- string or list, password(s)
        pcl_dic -- dictionary
        single_pass -- boolean, if true check one password with one subprocess
        delimiter -- optional argument, if is necessary to split library output
        *args -- arguments for run/call library
        """
        try:
            output = self.getPCLOutput(
                password_input,
                self.single_pass,
                self.delimiter,
                self.args
                )
            output = self.convertOutput(
                output
            )
            self.storePCLOutput(
                pcl_dic,
                password_input,
                output
                )

        except Exception as err:
            raise
            errorPrinter.printWarning(
                self.__class__.__name__,
                err
                )

    def storePCLOutput(self, pcl_dic, password_input, pcl_output):
        if (type(password_input) is list):
            for password, output in zip(password_input, pcl_output):
                pcl_dic[password].update({
                    self.__class__.__name__: output
                })
        else:
            pcl_dic[password_input].update({
                self.__class__.__name__: pcl_output
            })

    @abstractmethod
    def convertOutput(self, input_output):
        return input_output

    @staticmethod
    def getPCLOutput(password_input, single_pass, delimiter, args):
        """Function get output of library and store it to passwordData

        Arguments:
        password -- input password, type string
        single_pass -- boolean, if true check one password with one subprocess
        delimiter -- split library output
        args -- arguments for run/call library
        """
        def resolveOutput(password_data, delimiter):
            password_data = password_data.rstrip('\n')
            if (delimiter[0]):
                output_split = password_data.split(delimiter[0])

                return (output_split[0], None) if (len(output_split) == 1) \
                    else (output_split[delimiter[1]], None)

            return (password_data, None)

        p = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
            )

        output = p.communicate(input=bytes(
            password_input if (single_pass) else '\n'.join(password_input),
            'UTF-8'
            ))
        output = output[0].decode('UTF-8')

        if (single_pass):
            return resolveOutput(output, delimiter)

        # Resolve all passwords from output & return list
        password_list = []
        output_list = output.split('\n')

        for password_output in output_list:
            password_list.append(resolveOutput(
                password_output,
                delimiter
                ))

        return password_list


class CrackLib(Library):

    def __init__(self):
        super(CrackLib, self).__init__(
            False,
            ": ",
            1,
            "cracklib-check"
        )


class PassWDQC(Library):

    def __init__(self):
        super(PassWDQC, self).__init__(
            False,
            ": ",
            0,
            "pwqcheck", "--multi", "-1"
        )


class Zxcvbn(Library):

    def __init__(self):
        super(Zxcvbn, self).__init__()

    def checkPassword(self, password, pcl_dic):
        result = zxcvbn(password)
        warning = result['feedback']['warning']
        suggestions = result['feedback']['suggestions']

        output = ''
        if (warning):
            output = warning + ' '
        if (suggestions):
            output += ' '.join(str(sugg) for sugg in suggestions)

        self.storePCLOutput(
            pcl_dic,
            password,
            (output, result['score'])
            )


class Pwscore(Library):

    def __init__(self):
        super(Pwscore, self).__init__(
            True,
            ":\n ",
            1,
            "pwscore"
        )

    def convertOutput(self, input_output):
        if (input_output[0].isdigit()):
            return (
                '',
                int(input_output[0])
                )

        return (input_output[0], 0)
