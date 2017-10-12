from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassInfo

import scripts.errorPrinter as errorPrinter
import sys
import os
import json
import csv
import copy
import re


class Loader():

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

    def load(self):
        print('Loading data... using ' + self.__class__.__name__)

        try:
            data = self.load_data()
        except IOError:
            errorPrinter.printError(
                self.__class__.__name__,
                'File \'{0:1}\' doesn\'t exist'.format(self.file_path)
                )

        print('Loading DONE\n')
        return data

    @abstractmethod
    def load_data(self):
        pass


class LoadFromStdin(Loader):

    def load_data(self):
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

    def __init__(self, file_path=None):
        super(LoadFromFile, self).__init__()
        self.file_path = file_path

    def load_data(self):
        """Load passwords from file

        Input format -- password(string)

        Method return -- password_list of type list
        """
        password_list = []

        with open(self.file_path, 'r', encoding='latin1') as inputfile:
            for line in inputfile:
                password = line.rstrip('\n')
                password_list.append(password)

        return password_list


class LoadRockYou(Loader):

    def __init__(self, file_path=None, start=0, end=0, users_used=3):
        super(LoadRockYou, self).__init__()
        self.file_path = file_path
        self.start = start
        self.end = end
        self.users_used = users_used

    def load_data(self):
        password_list = []

        printed = False

        with open(self.file_path, 'r', encoding='latin1') as inputfile:
            regex_object = re.compile(r" *(\d+) (.*)")
            linecounter = 0

            for line in inputfile:
                linecounter += 1
                if (linecounter < self.start):
                    continue
                if (linecounter > self.end):
                    break

                match = regex_object.match(line.rstrip('\n'))
                if (match and
                   int(match.group(1)) >= self.users_used and match.group(2)):
                    password_list.append(match.group(2))

        return password_list


class LoadFromJson(Loader):

    def __init__(self, file_path=None):
        super(LoadFromJson, self).__init__()
        self.file_path = file_path

    def load_data(self):
        """Load passData from input json file

        Method return -- tuple [passInfoList, pcl_data]
                         passinfo_list - list of PassInfo classes
                         pcl_data - dictionary of passwords and PCL outputs
        """

        with open(self.file_path) as jsonfile:
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


class LoadFromCSV(Loader):

    def __init__(self, file_path=None, from_row=None, to_row=None):
        super(LoadFromCSV, self).__init__()
        self.file_path = file_path
        self.from_row = from_row
        self.to_row = to_row

        if (from_row and from_row < 0):
            errorPrinter.printError(
                'Argument \'from_row\' is lower than 0',
                self.__class__.__name__
            )
            self.from_row = 0

        if (to_row and to_row < 0):
            errorPrinter.printError(
                'Argument \'to_row\' is lower than 0',
                self.__class__.__name__
            )
            self.to_row = 0

    def load_data(self):
        def getTransformRules(transform_rules_string):
            transform_rules = []
            rules_splited = transform_rules_string.split(',')

            for rule in rules_splited:
                rule_splited = rule.split(':')
                transform_rules.append({
                    rule_splited[0]: float(rule_splited[1])
                    })

            return transform_rules

        csv_file = open(self.file_path, 'r')
        csv_reader = csv.reader(
            csv_file,
            delimiter=',',
            quotechar='\"',
            quoting=csv.QUOTE_MINIMAL
        )

        header = next(csv_reader)
        passinfo_list = []
        pcl_data = {}

        row_counter = 0
        for row in csv_reader:
            row_counter += 1

            if (not row[1]):
                orig_passinfo = PassInfo(row[0])

            # Check from and to index
            if (self.from_row and row_counter < self.from_row):
                continue
            if (self.to_row and row_counter > self.to_row):
                break

            if (row[1]):
                trans_passinfo = PassInfo(
                    row[0],
                    orig_passinfo
                )
                trans_passinfo.transform_rules = getTransformRules(row[1])

                passinfo_list.append(trans_passinfo)
            else:
                passinfo_list.append(orig_passinfo)

            pcl_output = {}
            for i in range(2, len(header), 2):
                pcl_output.update({
                    header[i]: (
                        row[i],
                        float(row[i + 1]) if (row[i + 1]) else None
                        )
                    })

            pcl_data.update({row[0]: pcl_output})

        return passinfo_list, pcl_data


class Saver():

    __metaclas__ = ABCMeta

    def __init__(self, file_path=None, file_extension='.out'):
        self.file_path = file_path if (file_path) \
            else 'outputs/temp' + file_extension

        # Check if extention exists
        if (self.file_path[-len(file_extension):] != file_extension):
            self.file_path += file_extension

        self.file_extension = file_extension

    def save(self, passinfo_list, pcl_data):
        print("Saving data... using " + self.__class__.__name__)

        try:
            self.save_data(passinfo_list, pcl_data)
        except IOError:
            errorPrinter.printError(
                self.__class__.__name__,
                'File \'{0:1}\' doesn\'t exist'.format(self.file_path)
                )

        print("Saving DONE\n")

    @abstractmethod
    def save_data(self, passinfo_list, pcl_data):
        pass


class SaveDataToJson(Saver):

    def __init__(self, file_path=None):
        super(SaveDataToJson, self).__init__(
            file_path,
            ".json"
        )

    def save_data(self, passinfo_list, pcl_data):
        """Store passinfo_list and pcl_data to Json

        Arguments:
        passinfo_list -- list of PassInfo classes
        pcl_data -- dictionary of passwords and pcl outputs
        """
        json_file = open(self.file_path, 'w')

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

        json_file.write(
            json.dumps(
                {
                    'password_list': password_json_list
                },
                sort_keys=True,
                indent=4,
                separators=(',', ':')
            )
        )

        json_file.close()


class SaveDataToCSV(Saver):

    def __init__(self, file_path=None):
        super(SaveDataToCSV, self).__init__(
            file_path,
            '.csv'
        )

    def save_data(self, passinfo_list, pcl_data):
        pcl_list = sorted(pcl_data[passinfo_list[0].password].keys())

        csv_file = open(self.file_path, 'w')
        csv_writer = csv.writer(
            csv_file,
            delimiter=',',
            quotechar='\"',
            quoting=csv.QUOTE_MINIMAL
            )

        # Print header to file
        header = ['password', 'transform_rules']
        for pcl in pcl_list:
            header += [pcl, pcl + ' - score']

        csv_writer.writerow(header)

        # Print data to csv_file
        for passinfo in passinfo_list:
            row = [
                passinfo.password,
                ', '.join(
                    list(rule.keys())[0] + ':' + str(list(rule.values())[0])
                        for rule in passinfo.transform_rules)
                    if (hasattr(passinfo, 'transform_rules')) else None,
                ]
            for pcl in pcl_list:
                pass_pcl_data = pcl_data[passinfo.password][pcl]
                row += [pass_pcl_data[0], pass_pcl_data[1]]

            csv_writer.writerow(row)

        csv_file.close()


class AppendDataToCSV(Saver):

    def __init__(self, file_path):
        super(AppendDataToCSV, self).__init__(
            file_path,
            '.csv'
        )

    def save_data(self, passinfo_list, pcl_data):
        # File with old data
        csv_file_old = open(self.file_path, 'r')

        # File with new data
        file_path_new = self.file_path[:-len(self.file_extension)] + \
            "_new" + self.file_extension
        csv_file_new = open(file_path_new, 'w')

        csv_reader = csv.reader(
            csv_file_old,
            delimiter=',',
            quotechar='\"',
            quoting=csv.QUOTE_MINIMAL
        )
        csv_writer = csv.writer(
            csv_file_new,
            delimiter=',',
            quotechar='\"',
            quoting=csv.QUOTE_MINIMAL
        )

        # Copy pcl_data, coz i am poping password from this dictionary
        pcl_data_copy = copy.copy(pcl_data)

        # Read header
        header_old = next(csv_reader)
        header_new = ['password', 'transform_rules']

        pcl_list_old = header_old[2::2]
        pcl_list_new = list(pcl_data_copy[passinfo_list[0].password].keys())

        pcl_list = sorted(list(set(pcl_list_old + pcl_list_new)))
        for pcl in pcl_list:
            header_new += [pcl, pcl + ' - score']

        # Write new header
        csv_writer.writerow(header_new)

        for line in csv_reader:
            # Create dictionary from header and row
            table_dic = {}
            for head, item in zip(header_old, line):
                table_dic.update({head: item})

            password = line[0]
            if (password in pcl_data_copy):
                row = [password, line[1]]
                for pcl in pcl_list:
                    # Check and add new data
                    if (pcl in pcl_data_copy[password]):
                        row += [
                            pcl_data_copy[password][pcl][0],
                            pcl_data_copy[password][pcl][1]
                        ]
                    else:
                        row += [
                            table_dic[pcl],
                            table_dic[pcl + ' - score']
                        ]

                # Pop password from pcl_data_copy
                pcl_data_copy.pop(password, None)

                # Write row to the new file
                csv_writer.writerow(row)
            else:
                row = [password, line[1]]
                for pcl in pcl_list:
                    if (pcl in table_dic):
                        row += [table_dic[pcl], table_dic[pcl + ' - score']]
                    else:
                        row += [None, None]

                csv_writer.writerow(row)

        # Add unassigned passwords to the table
        for passinfo in passinfo_list:
            if (passinfo.password in pcl_data_copy):
                row = [
                    passinfo.password,
                    ', '.join(
                        list(rule.keys())[0] + ':' + str(list(rule.values())[0])
                            for rule in passinfo.transform_rules)
                        if (hasattr(passinfo, 'transform_rules')) else None
                    ]
                for pcl in pcl_list:
                    if (pcl in pcl_data_copy[passinfo.password]):
                        row += [
                            pcl_data_copy[passinfo.password][pcl][0],
                            pcl_data_copy[passinfo.password][pcl][1]
                            ]
                    else:
                        row += [None, None]

                csv_writer.writerow(row)

        csv_file_old.close()
        csv_file_new.close()
