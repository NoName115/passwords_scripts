from abc import ABCMeta, abstractmethod
from prettytable import PrettyTable

import scripts.errorPrinter as errorPrinter
import math
import re


class FilterTemplate():

    __metaclass__ = ABCMeta

    def __init__(self, variable, need_variable=False, variable_type=None):
        self.variable = variable
        self.need_variable = need_variable
        self.variable_type = variable_type

    def apply_check(self, data):
        # Check input data
        if (not data):
            errorPrinter.printWarning(
                self.__class__.__name__,
                'No input data to be filtered'
            )
            return []

        # Check variable
        if (self.need_variable):
            try:
                if (self.variable is not None):
                    if (type(self.variable) != self.variable_type):
                        raise Exception(
                            'Wrong datatype of input argument, must be ' +
                            self.variable_type.__name__
                        )
                else:
                    raise Exception(
                            'Input argument is None, must be ' +
                            self.variable_type.__name__
                        )
            except Exception as err:
                errorPrinter.printWarning(
                    self.__class__.__name__,
                    err
                )
                return data
        try:
            return self.apply(data)
        except Exception as err:
            errorPrinter.printWarning(
                self.__class__.__name__,
                err
            )
            return data

    @abstractmethod
    def apply(self, data):
        pass


class LowEntropyChange(FilterTemplate):

    def __init__(self, variable=None):
        super(LowEntropyChange, self).__init__(variable, True, int)

    def apply(self, data):
        return list(filter(
            lambda passdata: hasattr(passdata, 'orig_pass') and
            passdata.getEntropyChange() <= self.variable,
            data
        ))


class PCLOutputChangedFromOk2NotOk(FilterTemplate):

    def __init__(self, variable=None):
        super(PCLOutputChangedFromOk2NotOk, self).__init__(
            variable, True, list
            )

    def apply(self, data):
        return list(filter(
            lambda passdata: hasattr(passdata, 'orig_pass') and
            any(
                passdata.orig_pass.getPCLOutput(pcl) == "OK" and
                 passdata.getPCLOutput(pcl) != "OK"
                for pcl in self.variable
            ),
            data
        ))


class PCLOutputChangedFromNotOk2Ok(FilterTemplate):

    def __init__(self, variable=None):
        super(PCLOutputChangedFromNotOk2Ok, self).__init__(
            variable, True, list
        )

    def apply(self, data):
        return list(filter(
            lambda passdata: hasattr(passdata, 'orig_pass') and
            any(
                passdata.orig_pass.getPCLOutput(pcl) != "OK" and
                 passdata.getPCLOutput(pcl) == "OK"
                for pcl in self.variable
            ),
            data
        ))


class PCLOutputsAreNotAllSame(FilterTemplate):

    def __init__(self):
        super(PCLOutputsAreNotAllSame, self).__init__(None)

    def apply(self, data):
        filtered_data = []

        pcl_list = data[0].pcl_output.keys()
        for passdata in data:
            counter_ok = 0
            counter_not_ok = 0
            for pcl in pcl_list:
                if (passdata.getPCLOutput(pcl) == "OK"):
                    counter_ok += 1
                else:
                    counter_not_ok += 1
            if (counter_ok != len(pcl_list) and
               counter_not_ok != len(pcl_list)):
                filtered_data.append(passdata)

        return filtered_data


class TransformationHadEffect(FilterTemplate):

    def __init__(self, variable=None):
        super(TransformationHadEffect, self).__init__(
            variable, True, list
        )

    def check_transformation(self, passdata):
        for transformation in passdata.transform_rules:
            for input_transformation in self.variable:
                if (input_transformation in transformation and
                   transformation[input_transformation] != 0):
                    return passdata

        return None

    def apply(self, data):
        filtered_data = []

        for passdata in data:
            if (hasattr(passdata, 'transform_rules')):
                check_output = self.check_transformation(passdata)
                if (check_output):
                    filtered_data.append(check_output)

        return filtered_data


class OriginalPCLOutputIsOk(FilterTemplate):

    def __init__(self, variable=None):
        super(OriginalPCLOutputIsOk, self).__init__(variable, True, list)

    def apply(self, data):
        return list(filter(
            lambda passdata: any(
                passdata.getPCLOutput(pcl) == "OK"
                    if (not hasattr(passdata, 'orig_pass'))
                    else passdata.orig_pass.getPCLOutput(pcl) == "OK"
                for pcl in self.variable
            ),
            data
        ))


class TransformedPCLOutputIsOk(FilterTemplate):

    def __init__(self, variable=None):
        super(TransformedPCLOutputIsOk, self).__init__(variable, True, list)

    def apply(self, data):
        return list(filter(
            lambda passdata: hasattr(passdata, 'orig_pass') and
            any(
                passdata.getPCLOutput(pcl) == "OK" for pcl in self.variable
            ),
            data
        ))


class OriginalPCLOutputIsNotOk(FilterTemplate):

    def __init__(self, variable=None):
        super(OriginalPCLOutputIsNotOk, self).__init__(variable, True, list)

    def apply(self, data):
        return list(filter(
            lambda passdata: any(
                passdata.getPCLOutput(pcl) != "OK"
                    if (not hasattr(passdata, 'orig_pass'))
                    else passdata.orig_pass.getPCLOutput(pcl) != "OK"
                for pcl in self.variable
            ),
            data
        ))


class TransformedPCLOutputIsNotOk(FilterTemplate):

    def __init__(self, variable=None):
        super(TransformedPCLOutputIsNotOk, self).__init__(variable, True, list)

    def apply(self, data):
        return list(filter(
            lambda passdata: hasattr(passdata, 'orig_pass') and
            any(
                passdata.getPCLOutput(pcl) != "OK" for pcl in self.variable
            ),
            data
        ))


class ScoreHigher(FilterTemplate):

    def __init__(self, variable=None):
        super(ScoreHigher, self).__init__(variable, True, dict)

    def apply(self, data):
        key_errors = []
        filtered_data = []

        for passdata in data:
            for pcl, threshold in self.variable.items():
                try:
                    pcl_score = passdata.getPCLScore(pcl)
                    if (pcl_score is not None and int(pcl_score) >= threshold):
                        filtered_data.append(passdata)
                        break
                except KeyError:
                    if (pcl not in key_errors):
                        errorPrinter.printWarning(
                            self.__class__.__name__,
                            "Key \'" + pcl + "\' does not exist."
                        )
                        key_errors.append(pcl)

            # Remove undefined keys from dictionary before next iteration
            for key_error in key_errors:
                self.variable.pop(key_error, None)
                key_errors = []

        return filtered_data


class ScoreLower(FilterTemplate):

    def __init__(self, variable=None):
        super(ScoreLower, self).__init__(variable, True, dict)

    def apply(self, data):
        key_errors = []
        filtered_data = []

        for passdata in data:
            for pcl, threshold in self.variable.items():
                try:
                    pcl_score = passdata.getPCLScore(pcl)
                    if (pcl_score is not None and int(pcl_score) < threshold):
                        filtered_data.append(passdata)
                        break
                except KeyError:
                    if (pcl not in key_errors):
                        errorPrinter.printWarning(
                            self.__class__.__name__,
                            "Key \'" + pcl + "\' does not exist."
                        )
                        key_errors.append(pcl)

            # Remove undefined keys from dictionary before next iteration
            for key_error in key_errors:
                self.variable.pop(keyError, None)
                key_errors = []

        return filtered_data


class ChangePCLOutputByScore(FilterTemplate):

    def __init__(self, variable=None):
        super(ChangePCLOutputByScore, self).__init__(variable)

    def apply(self, data):
        # Use default threshold
        if (not self.variable):
            self.variable = {
                'Pwscore': 40,
                'Zxcvbn': 3,
                'Passfault': 100000000000
            }

        key_errors = []

        for passdata in data:
            for pcl, threshold in self.variable.items():
                try:
                    pcl_score = passdata.getPCLScore(pcl)
                    pcl_output = passdata.getPCLOutput(pcl)

                    if (pcl_score is not None):
                        if (not pcl_output and int(pcl_score) < threshold):
                            passdata.pcl_output[pcl] = (
                                'Low password score',
                                pcl_score
                            )
                        elif (int(pcl_score) >= threshold):
                            passdata.pcl_output[pcl] = (
                                'OK',
                                pcl_score
                            )
                except KeyError:
                    if (pcl not in key_errors):
                        errorPrinter.printWarning(
                            self.__class__.__name__,
                            "Key \'" + pcl + "\' does not exist."
                        )
                        key_errors.append(pcl)

            # Remove undefined keys from dictionary before next iteration
            for key_error in key_errors:
                self.variable.pop(key_error, None)
                key_errors = []

        return data


class PasswordLengthLower(FilterTemplate):

    def __init__(self, variable=None):
        super(PasswordLengthLower, self).__init__(variable, True, int)

    def apply(self, data):
        return list(filter(
            lambda passdata: len(passdata.password) < self.variable,
            data
        ))


class PasswordLengthHigher(FilterTemplate):

    def __init__(self, variable=None):
        super(PasswordLengthHigher, self).__init__(variable, True, int)

    def apply(self, data):
        return list(filter(
            lambda passdata: len(passdata.password) >= self.variable,
            data
        ))


class PasswordContainString(FilterTemplate):

    def __init__(self, variable=None):
        super(PasswordContainString, self).__init__(variable, True, str)

    def apply(self, data):
        return list(filter(
            lambda passdata: self.variable in passdata.password,
            data
        ))


class PCLOutputDoesNotContainString(FilterTemplate):

    def __init__(self, variable=None):
        super(PCLOutputDoesNotContainString, self).__init__(
            variable, True, dict
        )

    def apply(self, data):
        key_errors = []
        filtered_data = []

        for passdata in data:
            for pcl, not_contain_string in self.variable.items():
                try:
                    if (not_contain_string not in passdata.pcl_output[pcl][0]):
                        filtered_data.append(passdata)
                        break
                except KeyError:
                    if (pcl not in key_errors):
                        errorPrinter.printWarning(
                            self.__class__.__name__,
                            "Key \'" + pcl + "\' does not exist."
                        )
                        key_errors.append(pcl)

            # Remove undefined keys from list before next iteration
            for key_error in key_errors:
                self.variable.pop(key_error, None)
                key_errors = []

        return filtered_data


class NumberOfDifferentCharactersLower(FilterTemplate):

    def __init__(self, variable=None):
        super(NumberOfDifferentCharactersLower, self).__init__(
            variable, True, int
        )

    def apply(self, data):
        return list(filter(
            lambda passdata: passdata.diff_char < self.variable,
            data
        ))


class NumberOfDifferentCharactersHigher(FilterTemplate):

    def __init__(self, variable=None):
        super(NumberOfDifferentCharactersHigher, self).__init__(
            variable, True, int
        )

    def apply(self, data):
        return list(filter(
            lambda passdata: passdata.diff_char >= self.variable,
            data
        ))


class PasswordContainCharacterClass(FilterTemplate):

    def __init__(self, variable=None):
        super(PasswordContainCharacterClass, self).__init__(
            variable, True, list
        )

    def apply(self, data):
        return list(filter(
            lambda passdata: any(
                char_class in passdata.char_classes
                for char_class in self.variable
                ),
            data
        ))


class PasswordContainOnlyCharacterClass(FilterTemplate):

    def __init__(self, variable=None):
        super(PasswordContainOnlyCharacterClass, self).__init__(
            variable, True, list
        )

    def apply(self, data):
        return list(filter(
            lambda passdata: passdata.char_classes == self.variable,
            data
        ))


class NumberOfPasswordCharacterClass(FilterTemplate):

    def __init__(self, variable=None):
        super(NumberOfPasswordCharacterClass, self).__init__(
            variable, True, int
        )

    def apply(self, data):
        return list(filter(
            lambda passdata: len(passdata.char_classes) == self.variable,
            data
        ))


class PasswordRegex(FilterTemplate):

    def __init__(self, variable=None):
        super(PasswordRegex, self).__init__(
            variable, True, str
        )

    def apply(self, data):
        prog = re.compile(self.variable)

        return list(filter(
            lambda passdata: prog.search(passdata.password),
            data
        ))


class PCLOutputRegex(FilterTemplate):

    def __init__(self, variable=None):
        super(PCLOutputRegex, self).__init__(
            variable, True, dict
        )

    def apply(self, data):
        for pcl, regex in self.variable.items():
            self.variable[pcl] = re.compile(regex)

        key_errors = []
        filtered_data = []

        for passdata in data:
            for pcl, regex_object in self.variable.items():
                try:
                    if (regex_object.search(passdata.pcl_output[pcl][0])):
                        filtered_data.append(passdata)
                        break
                except KeyError:
                    if (pcl not in key_errors):
                        errorPrinter.printWarning(
                            self.__class__.__name__,
                            "Key \'" + pcl + "\' does not exist."
                        )
                        key_errors.append(pcl)

            # Remove undefined keys from list before next iteration
            for key_error in key_errors:
                self.variable.pop(key_error, None)
                key_error = []

        return filtered_data


class AddNumberOfUsesToPassData(FilterTemplate):

    def __init__(self, variable=None):
        super(AddNumberOfUsesToPassData, self).__init__(
            variable, True, str
        )

    def apply(self, data):
        regex_object = re.compile(r" *(\d+) (.*)")

        with open(self.variable, 'r', encoding='latin1') as inputfile:
            for passdata in data:
                for line in inputfile:
                    nous, password = regex_object.match(line.rstrip('\n')).groups()

                    if (password == passdata.password):
                        passdata.addAttribute({
                            'numberOfUses': int(nous)
                        })
                        break

        return data


class AllRejectedOneAccepted(FilterTemplate):

    def __init__(self, variable=None):
        super(AllRejectedOneAccepted, self).__init__(
            variable, True, str
        )
    
    def apply(self, data):
        filtered_data = []
        pcl_list = data[0].pcl_output.keys()

        if (self.variable not in pcl_list):
            errorPrinter.printWarning(
                self.__class__.__name__,
                'Password checking library \'' +
                    self.variable + '\' does not exist'
            )
            return []

        for passdata in data:
            counter_ok = 0
            pcl_ok = ''
            for pcl in pcl_list:
                if (passdata.getPCLOutput(pcl) == "OK"):
                    counter_ok += 1
                    pcl_ok = pcl
            if (counter_ok == 1 and pcl_ok == self.variable):
                filtered_data.append(passdata)

        return filtered_data


class AtLeastOneRejectedAtLeastOneAccepted(FilterTemplate):

    def __init__(self, variable=None):
        super(AtLeastOneRejectedAtLeastOneAccepted, self).__init__(
            variable, True, str
        )

    def apply(self, data):
        filtered_data = []
        pcl_list = data[0].pcl_output.keys()

        if (self.variable not in pcl_list):
            errorPrinter.printWarning(
                self.__class__.__name__,
                'Password checking library \'' +
                    self.variable + '\' does not exist'
            )
            return []

        for passdata in data:
            counter_ok = 0
            counter_not_ok = 0
            for pcl in pcl_list:
                if (passdata.getPCLOutput(pcl) != "OK"):
                    counter_not_ok += 1
                if (self.variable == pcl and
                   passdata.getPCLOutput(pcl) == "OK"):
                    counter_ok = 1
            if (counter_not_ok > 0 and counter_ok == 1):
                filtered_data.append(passdata)
        
        return filtered_data


class ConvertPassfaultScoreByLogBase(FilterTemplate):

    def __init__(self, variable=None):
        super(ConvertPassfaultScoreByLogBase, self).__init__(None)

    def apply(self, data):
        for passdata in data:
            try:
                pcl = 'Passfault'
                pcl_score = round(math.log(
                    passdata.getPCLScore(pcl),
                    2
                ))
                passdata.setPCLScore(pcl, pcl_score)
            except KeyError:
                errorPrinter.printWarning(
                    self.__class__.__name__,
                    "Input data does not contain output for Passfault PCL."
                )

        return data
