from abc import ABCMeta, abstractmethod
from math import log
from scripts.passStruct import PassInfo

import scripts.errorPrinter as errorPrinter
import sys
import json


class Loader(object):

    __metaclas__ = ABCMeta

    def __init__(self):
        """Check Python version, must be greater or equal then 3.0
        """
        req_version = (3, 0)
        cur_version = sys.version_info

        if (cur_version < req_version):
            error_text = (
                "Update your Python\n" +
                "You need Python 3.x to run this program\n"
                )
            if (cur_version < (2, 7)):
                error_text += "Your version is lower than 2.7"
            else:
                error_text += (
                    "Your version is: " +
                    str(cur_version.major) + '.' +
                    str(cur_version.minor) + '.' +
                    str(cur_version.micro)
                    )

            errorPrinter.printError(
                self.__class__.__name__,
                error_text
                )

    @abstractmethod
    def load(self):
        pass

    @staticmethod
    def generateEntropy(input_password):
        """Method calculate password entropy

        Arguments:
        input_password -- password

        Entropy calculated by formula
            len(input_password) / 1.5 * log(char_entropy, 2), 2
        First calculate char_entropy,
        'char_entropy' is increased by upperCase characters,
        digits, special symbols and by symbols out of ASCII table

        Return value:
        entropy -- float number
        """
        char_entropy = 0

        # Lowercase character in password
        if (any(c.islower() for c in input_password)):
            char_entropy += 26

        # Uppercase character in password
        if (any(c.isupper() for c in input_password)):
            char_entropy += 26

        # Digit character in password
        if (any(c.isdigit() for c in input_password)):
            char_entropy += 10

        # Special
        if (any((c in '!@#$%^&*()') for c in input_password)):
            char_entropy += 10

        # Special2
        if (any((c in "`~-_=+[{]}\\|;:'\",<.>/?") for c in input_password)):
            char_entropy += 20

        # Space contain
        if (any((c in ' ') for c in input_password)):
            char_entropy += 1

        # Other symbols
        if (any((not (' ' < c < '~')) for c in input_password)):
            char_entropy += 180

        return round(len(input_password) / 1.5 * log(char_entropy, 2), 2)


class LoadFromStdin(Loader):

    def load(self):
        """Load passwords and entropy from stdin

        Input format -- password(string), space, entropy(float, integer)

        Method return -- password_data of type PassData
        """
        password_data = []

        for line in sys.stdin:
            data = line.rstrip('\n').split()
            try:
                if (len(data) == 2):
                    password_data.append([
                        data[0],
                        round(float(data[1]), 2)
                        ])
                elif (len(data) == 1):
                    password_data.append([
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

        return password_data


class LoadFromFile(Loader):

    def __init__(self, filename=None):
        super(LoadFromFile, self).__init__()
        self.filename = filename

    def load(self):
        """Load passwords and entropy from file

        Input format -- password(string), space, entropy(float, integer)

        Method return -- password_data of type PassData
        """
        password_data = []

        try:
            with open(self.filename, 'r') as inputfile:
                for line in inputfile:
                    data = line.rstrip('\n').split()
                    try:
                        if (len(data) == 2):
                            password_data.append([
                                data[0],
                                round(float(data[1]), 2)
                                ])
                        elif (len(data) == 1):
                            password_data.append([
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
                'File \'{0:1}\' doesn\'t exist'.format(self.filename)
                )

        return password_data


# TODO
# Prerobit podla StoreToJson
class LoadFromJson(Loader):

    def __init__(self, filename=None):
        super(LoadFromJson, self).__init__()
        self.filename = filename

    def load(self):
        """Load passData from input json file

        Method return -- tuple [passInfoList, pcl_data]
                         passinfo_list - list of PassInfo classes
                         pcl_data - dictionary of passwords and PCL outputs
        """

        try:
            with open(self.filename) as jsonfile:
                data = json.load(jsonfile)

            passinfo_list = []
            pcl_data = {}

            # Parse json data
            for passData in data['passwordList']:
                new_password = PassInfo(
                        passData['originalPassword'],
                        passData['initialEntropy']
                        )
                new_password.transformed_data = [
                    passData['transformedPassword'],
                    passData['actualEntropy']
                    ]
                new_password.transform_rules = passData['transformRules']
                new_password.error_log = errorPrinter.RuleError(
                    passData['errorLog']
                    )
                passinfo_list.append(new_password)

                pcl_data.update({
                    passData['originalPassword']:
                        passData['originalLibOutput'],
                    passData['transformedPassword']:
                        passData['transformedLibOutput']
                })

            return passinfo_list, pcl_data

        except IOError:
            errorPrinter.printError(
                self.__class__.__name__,
                'File \'{0:1}\' doesn\'t exist'.format(self.filename)
            )


# TODO
# Pridat odkaz pri transformed password akoze transformed bude mat este
# original password asi
# Alebo to nechat ako to je akurat ze nejako vyriesit originalne heslo,
# povedzme ze nebude mat transformedPassword... zrejme
class StoreDataToJson():

    def __init__(self, filename="inputs/passData.json"):
        self.filename = filename

    def store(self, passinfo_list, pcl_data):
        """Store passinfo_list and pcl_data to Json

        Arguments:
        passinfo_list -- list of PassInfo classes
        pcl_data -- dictionary of passwords and pcl outputs
        """
        outputfile = open(self.filename, 'w')

        password_json_list = []
        for passinfo in passinfo_list:
            password_json_list.append({
                'originalPassword': passinfo.getOriginalPassword(),
                'transformedPassword': passinfo.getTransformedPassword(),
                'initialEntropy': passinfo.getInitialEntropy(),
                'actualEntropy': passinfo.getActualEntropy(),
                'transformRules': passinfo.transform_rules,
                'originalLibOutput': pcl_data[
                    passinfo.getOriginalPassword()
                    ],
                'transformedLibOutput': pcl_data[
                    passinfo.getTransformedPassword()
                    ],
                'errorLog': passinfo.error_log.getLog()
            })

        outputfile.write(
            json.dumps(
                {
                    'passwordList': password_json_list
                },
                sort_keys=True,
                indent=4,
                separators=(',', ':')
            )
        )

        outputfile.close()
