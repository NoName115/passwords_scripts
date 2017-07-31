from abc import ABCMeta, abstractmethod
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


class LoadFromStdin(Loader):

    def load(self):
        """Load passwords from stdin

        Input format -- password(string)

        Method return -- password_list of type list
        """
        password_list = []

        for line in sys.stdin:
            password = line.rstrip('\n')
            password_list.append(password)

        return password_list


class LoadFromFile(Loader):

    def __init__(self, filename=None):
        super(LoadFromFile, self).__init__()
        self.filename = filename

    def load(self):
        """Load passwords from file

        Input format -- password(string)

        Method return -- password_list of type list
        """
        password_list = []

        try:
            with open(self.filename, 'r') as inputfile:
                for line in inputfile:
                    password = line.rstrip('\n')
                    password_list.append(password)
        except IOError:
            errorPrinter.printError(
                self.__class__.__name__,
                'File \'{0:1}\' doesn\'t exist'.format(self.filename)
                )

        return password_list


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
            for passdata in data['password_list']:
                if ('transform_rules' in passdata):
                    trans_passinfo = PassInfo(
                        passdata['password'],
                        orig_passinfo
                        )
                    trans_passinfo.transform_rules = passdata[
                        'transform_rules'
                        ]
                    passinfo_list.append(trans_passinfo)
                else:
                    orig_passinfo = PassInfo(passdata['password'])
                    passinfo_list.append(orig_passinfo)

                pcl_output = {}
                for pcl, pcl_tuple in passdata['pcl_output'].items():
                    pcl_output.update({pcl: tuple(pcl_tuple)})

                pcl_data.update({
                    passdata['password']: pcl_output
                })

            return passinfo_list, pcl_data

        except IOError:
            errorPrinter.printError(
                self.__class__.__name__,
                'File \'{0:1}\' doesn\'t exist'.format(self.filename)
            )


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
            passdata_dic = {
                'password': passinfo.password,
                'pcl_output': pcl_data[passinfo.password]
            }
            if (hasattr(passinfo, 'transform_rules')):
                passdata_dic.update({
                    'transform_rules': passinfo.transform_rules
                })

            password_json_list.append(passdata_dic)

        outputfile.write(
            json.dumps(
                {
                    'password_list': password_json_list
                },
                sort_keys=True,
                indent=4,
                separators=(',', ':')
            )
        )

        outputfile.close()
