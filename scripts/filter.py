from abc import ABCMeta, abstractmethod
from prettytable import PrettyTable

import scripts.errorPrinter as errorPrinter


class FilterTemplate():

    __metaclass__ = ABCMeta

    def __init__(self, variable=None):
        if (variable):
            self.variable = variable

    def apply_check(self, data):
        if (not data):
            errorPrinter.printWarning(
                self.__class__.__name__,
                'No input data to be filtered'
            )
            return []

        return self.apply(data)

    @abstractmethod
    def apply(self, data):
        pass


class LowEntropyChange(FilterTemplate):

    def apply(self, data):
        low_entropychange_data = list(filter(
            lambda passdata: hasattr(passdata, 'orig_pass') and
            passdata.getEntropyChange() <= self.variable,
            data
        ))

        return low_entropychange_data


class PCLOutputChangedFromOk2NotOk(FilterTemplate):

    def apply(self, data):
        filtered_data = []
        for passdata in data:
            if (hasattr(passdata, 'transform_rules')):
                # Check only one PCL or check it for all PCLs
                pcl_list = self.variable if (hasattr(self, 'variable')) \
                    else passdata.pcl_output.keys()

                for pcl in pcl_list:
                    if (passdata.orig_pass.getPCLOutput(pcl) == "OK" and
                       passdata.getPCLOutput(pcl) != "OK"):
                        filtered_data.append(passdata)
                        break

        return filtered_data


class PCLOutputChangedFromNotOk2Ok(FilterTemplate):

    def apply(self, data):
        filtered_data = []
        for passdata in data:
            if (hasattr(passdata, 'transform_rules')):
                # Check only one PCL or check it for all PCLs
                pcl_list = self.variable if (hasattr(self, 'variable')) \
                    else passdata.pcl_output.keys()

                for pcl in pcl_list:
                    if (passdata.orig_pass.getPCLOutput(pcl) != "OK" and
                       passdata.getPCLOutput(pcl) == "OK"):
                        filtered_data.append(passdata)
                        break

        return filtered_data


class PCLOutputsAreNotAllSame(FilterTemplate):

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

    def check_transformation(self, passdata):
        for transformation in passdata.transform_rules:
            for input_transformation in self.variable:
                if (input_transformation in transformation and
                   transformation[input_transformation] != 0):
                    return passdata

        return None

    def apply(self, data):
        filtered_data = []
        if (not hasattr(self, 'variable')):
            errorPrinter.printWarning(
                self.__class__.__name__,
                'Set list of names of transformation as the' +
                'first argument in constructor.'
            )
            return filtered_data

        for passdata in data:
            if (hasattr(passdata, 'transform_rules')):
                check_output = self.check_transformation(passdata)
                if (check_output):
                    filtered_data.append(check_output)

        return filtered_data


class PCLOutputIsOk(FilterTemplate):

    def apply(self, data):
        filtered_data = []
        pcl_list = self.variable if (hasattr(self, 'variable')) \
            else data[0].pcl_output.keys()

        for passdata in data:
            for pcl in pcl_list:
                if (passdata.getPCLOutput(pcl) == "OK"):
                    filtered_data.append(passdata)
                    break

        return filtered_data


class PCLOutputIsNotOk(FilterTemplate):

    def apply(self, data):
        filtered_data = []
        pcl_list = self.variable if (hasattr(self, 'variable')) \
            else data[0].pcl_output.keys()

        for passdata in data:
            for pcl in pcl_list:
                if (passdata.getPCLOutput(pcl) != "OK"):
                    filtered_data.append(passdata)
                    break

        return filtered_data


class HigherScoreThan(FilterTemplate):

    def apply(self, data):
        key_errors = []
        high_score_data = []

        for passdata in data:
            for pcl, threshold in self.variable.items():
                try:
                    pcl_score = passdata.getPCLScore(pcl)
                    if (pcl_score != None and int(pcl_score) >= threshold):
                        high_score_data.append(passdata)
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

        return high_score_data


class LowerScoreThan(FilterTemplate):

    def apply(self, data):
        key_errors = []
        low_score_data = []

        for passdata in data:
            for pcl, threshold in self.variable.items():
                try:
                    pcl_score = passdata.getPCLScore(pcl)
                    if (pcl_score != None and int(pcl_score) < threshold):
                        low_score_data.append(passdata)
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

        return low_score_data


class ChangePCLOutputByScore(FilterTemplate):

    def apply(self, data):
        # Use default threshold
        if (not hasattr(self, 'variable')):
            self.variable = {
                'Pwscore': 40,
                'Zxcvbn': 3,
                'Passfault': 10000001
            }

        key_errors = []

        for passdata in data:
            for pcl, threshold in self.variable.items():
                try:
                    pcl_score = passdata.getPCLScore(pcl)
                    pcl_output = passdata.getPCLOutput(pcl)

                    if (pcl_score != None):
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

    def apply(self, data):
        length_data = list(filter(
            lambda passdata: len(passdata.password) < self.variable,
            data
        ))

        return length_data


class PasswordLengthHigher(FilterTemplate):

    def apply(self, data):
        higher_length_data = list(filter(
            lambda passdata: len(passdata.password) >= self.variable,
            data
        ))

        return higher_length_data


class RemovePCLOutput(FilterTemplate):

    def apply(self, data):
        if (not hasattr(self, 'variable')):
            errorPrinter.printWarning(
                self.__class__.__name__,
                'Name of PCL was not set'
            )
            return data

        key_errors = []

        for passdata in data:
            for pcl in self.variable:
                try:
                    passdata.pcl_output.pop(pcl)
                except KeyError:
                    if (pcl not in key_errors):
                        errorPrinter.printWarning(
                            self.__class__.__name__,
                            "Key \'" + pcl + "\' does not exist."
                        )
                        key_errors.append(pcl)

            # Remove undefined keys from list before next iteration
            for key_error in key_errors:
                self.variable.remove(key_error)
                key_errors = []

        return data


class PasswordContainString(FilterTemplate):

    def apply(self, data):
        if (not hasattr(self, 'variable')):
            errorPrinter.printWarning(
                self.__class__.__name__,
                'Input string was not set'
            )
            return data

        containstring_data = []

        for passdata in data:
            if (self.variable in passdata.password):
                containstring_data.append(passdata)

        return containstring_data


class PCLOutputContainString(FilterTemplate):

    def apply(self, data):
        if (not hasattr(self, 'variable')):
            errorPrinter.printWarning(
                self.__class__.__name__,
                'Input string was not set'
            )
            return data

        key_errors = []
        containstring_data = []

        for passdata in data:
            for pcl, contain_string in self.variable.items():
                try:
                    if (contain_string in passdata.pcl_output[pcl][0]):
                        containstring_data.append(passdata)
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
                self.variable.remove(key_error)
                key_errors = []

        return containstring_data


class PCLOutputDoesNotContainString(FilterTemplate):

    def apply(self, data):
        if (not hasattr(self, 'variable')):
            errorPrinter.printWarning(
                self.__class__.__name__,
                'Input string was not set'
            )
            return data

        key_errors = []
        doesnot_contain_string = []

        for passdata in data:
            for pcl, not_contain_string in self.variable.items():
                try:
                    if (not_contain_string not in passdata.pcl_output[pcl][0]):
                        doesnot_contain_string.append(passdata)
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
                self.variable.remove(key_error)
                key_errors = []

        return doesnot_contain_string
