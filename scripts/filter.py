from abc import ABCMeta, abstractmethod
from prettytable import PrettyTable

import scripts.errorPrinter as errorPrinter


class FilterTemplate():

    __metaclass__ = ABCMeta

    def __init__(self, variable, need_variable=False, variable_type=None):
        self.variable = variable
        self.need_variable = variable
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
                if (self.variable != None):
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

        return self.apply(data)

    @abstractmethod
    def apply(self, data):
        pass


class LowEntropyChange(FilterTemplate):

    def __init__(self, variable=None):
        super(LowEntropyChange, self).__init__(variable, True, int)

    def apply(self, data):
        low_entropychange_data = list(filter(
            lambda passdata: hasattr(passdata, 'orig_pass') and
            passdata.getEntropyChange() <= self.variable,
            data
        ))

        return low_entropychange_data


class PCLOutputChangedFromOk2NotOk(FilterTemplate):

    def __init__(self, variable=None):
        super(PCLOutputChangedFromOk2NotOk, self).__init__(
            variable, True, list
            )

    def apply(self, data):
        filtered_data = []
        for passdata in data:
            if (hasattr(passdata, 'orig_pass')):
                '''
                # Check only one PCL or check it for all PCLs
                pcl_list = self.variable if (hasattr(self, 'variable')) \
                    else passdata.pcl_output.keys()
                '''

                for pcl in self.variable:
                    if (passdata.orig_pass.getPCLOutput(pcl) == "OK" and
                       passdata.getPCLOutput(pcl) != "OK"):
                        filtered_data.append(passdata)
                        break

        # Rewriten
        '''
        filtered_data = list(filter(
            lambda passdata: hasattr(passdata, 'orig_pass') and
            any(
                passdata.orig_pass.getPCLOutput(pcl) == "OK" and
                 passdata.getPCLOutput(pcl) != "OK"
                for pcl in self.variable
            ),
            data
        ))
        '''

        return filtered_data


class PCLOutputChangedFromNotOk2Ok(FilterTemplate):

    def __init__(self, variable=None):
        super(PCLOutputChangedFromNotOk2Ok, self).__init__(
            variable, True, list
        )

    def apply(self, data):
        filtered_data = []
        for passdata in data:
            if (hasattr(passdata, 'transform_rules')):
                '''
                # Check only one PCL or check it for all PCLs
                pcl_list = self.variable if (hasattr(self, 'variable')) \
                    else passdata.pcl_output.keys()
                '''

                for pcl in self.variable:
                    if (passdata.orig_pass.getPCLOutput(pcl) != "OK" and
                       passdata.getPCLOutput(pcl) == "OK"):
                        filtered_data.append(passdata)
                        break

        return filtered_data


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
            variable, True, dict
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
        '''
        if (not hasattr(self, 'variable')):
            errorPrinter.printWarning(
                self.__class__.__name__,
                'Set list of names of transformation as the' +
                'first argument in constructor.'
            )
            return filtered_data
        '''

        for passdata in data:
            if (hasattr(passdata, 'transform_rules')):
                check_output = self.check_transformation(passdata)
                if (check_output):
                    filtered_data.append(check_output)

        return filtered_data


class PCLOutputIsOk(FilterTemplate):

    def __init__(self, variable=None):
        super(PCLOutputIsOk, self).__init__(variable, True, list)

    def apply(self, data):
        filtered_data = []
        '''
        pcl_list = self.variable if (hasattr(self, 'variable')) \
            else data[0].pcl_output.keys()
        '''

        for passdata in data:
            for pcl in self.variable:
                if (passdata.getPCLOutput(pcl) == "OK"):
                    filtered_data.append(passdata)
                    break

        return filtered_data


class PCLOutputIsNotOk(FilterTemplate):

    def __init__(self, variable=None):
        super(PCLOutputIsNotOk, self).__init__(variable, True, list)

    def apply(self, data):
        filtered_data = []
        '''
        pcl_list = self.variable if (hasattr(self, 'variable')) \
            else data[0].pcl_output.keys()
        '''

        for passdata in data:
            for pcl in self.variable:
                if (passdata.getPCLOutput(pcl) != "OK"):
                    filtered_data.append(passdata)
                    break

        return filtered_data


class ScoreHigher(FilterTemplate):

    def __init__(self, variable=None):
        super(ScoreHigher, self).__init__(variable, True, dict)

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


class ScoreLower(FilterTemplate):

    def __init__(self, variable=None):
        super(ScoreLower, self).__init__(variable, True, dict)

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

    def __init__(self, variable=None):
        super(ChangePCLOutputByScore, self).__init__(variable)

    def apply(self, data):
        # Use default threshold
        if (not self.variable):
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

    def __init__(self, variable=None):
        super(PasswordLengthLower, self).__init__(variable, True, int)

    def apply(self, data):
        length_data = list(filter(
            lambda passdata: len(passdata.password) < self.variable,
            data
        ))

        return length_data


class PasswordLengthHigher(FilterTemplate):

    def __init__(self, variable=None):
        super(PasswordLengthHigher, self).__init__(variable, True, int)

    def apply(self, data):
        higher_length_data = list(filter(
            lambda passdata: len(passdata.password) >= self.variable,
            data
        ))

        return higher_length_data


class RemovePCLOutput(FilterTemplate):

    def __init__(self, variable=None):
        super(RemovePCLOutput, self).__init__(variable, True, list)

    def apply(self, data):
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

    def __init__(self, variable=None):
        super(PasswordContainString, self).__init__(variable, True, str)

    def apply(self, data):
        containstring_data = list(filter(
            lambda passdata: self.variable in passdata.password,
            data
        ))
        '''
        for passdata in data:
            if (self.variable in passdata.password):
                containstring_data.append(passdata)
        '''
        return containstring_data


class PCLOutputContainString(FilterTemplate):

    def __init__(self, variable=None):
        super(PCLOutputContainString, self).__init__(variable, True, dict)

    def apply(self, data):
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

    def __init__(self, variable=None):
        super(PCLOutputDoesNotContainString, self).__init__(
            variable, True, dict
        )

    def apply(self, data):
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


class NumberOfDifferentCharactersLower(FilterTemplate):

    def __init__(self, variable=None):
        super(NumberOfDifferentCharactersLower, self).__init__(
            variable, True, int
        )

    def apply(self, data):
        diff_char_data = list(filter(
            lambda passdata: passdata.diff_char < self.variable,
            data
        ))

        return diff_char_data


class NumberOfDifferentCharactersHigher(FilterTemplate):

    def __init__(self, variable=None):
        super(NumberOfDifferentCharactersHigher, self).__init__(
            variable, True, int
        )

    def apply(self, data):
        diff_char_data = list(filter(
            lambda passdata: passdata.diff_char >= self.variable,
            data
        ))

        return diff_char_data


class PasswordContainCharacterClass(FilterTemplate):

    def __init__(self, variable=None):
        super(PasswordContainCharacterClass, self).__init__(
            variable, True, list
        )

    def apply(self, data):
        contain_char_class = list(filter(
            lambda passdata: any(
                char_class in passdata.char_classes
                for char_class in self.variable
                ),
            data
        ))

        return contain_char_class


class PasswordContainOnlyCharacterClass(FilterTemplate):

    def __init__(self, variable=None):
        super(PasswordContainOnlyCharacterClass, self).__init__(
            variable, True, list
        )

    def apply(self, data):
        containonly_char_class = list(filter(
            lambda passdata: passdata.char_classes == self.variable,
            data
        ))

        return containonly_char_class
