from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassInfo
from random import randint

import scripts.errorPrinter as errorPrinter
import random
import re
import sys


class Transformation():

    def __init__(self):
        self.transformation_list = []

    def add(self, transformation):
        self.transformation_list.append(transformation)

    def apply(self, password):
        passinfo = PassInfo(password[0], password[1])

        for trans in self.transformation_list:
            trans.transform(passinfo)

        return passinfo


class Rule():

    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, input_from_index, input_to_index):
        self.input_from_index = input_from_index
        self.input_to_index = input_to_index

    def transform(self, passinfo):
        """Main method for password transformation

        Method catch errors, calculate indexes,
        call uniqueTransform method
        """
        try:
            from_index = self.calculateFromIndex(
                passinfo.getTransformedPassword()
                )
            to_index = self.calculateToIndex(
                passinfo.getTransformedPassword()
                )

            if (from_index > to_index):
                passinfo.error_log.addError(
                    self.__class__.__name__,
                    "Wrong value of input data. " + '\n' +
                    "'from_index' must be same or lower than 'to_index'"
                    )
                return

            # transformOutput obtain transformed_password and entropy_change
            transform_output = self.uniqueTransform(
                passinfo, from_index, to_index
                )

            passinfo.transformed_data[0] = transform_output[0]
            passinfo.transformed_data[1] = round(
                passinfo.transformed_data[1] + transform_output[1],
                2
                )

            passinfo.addTransformRule(
                self.__class__.__name__,
                transform_output[1]
                )

        except TypeError:
            raise
            passinfo.error_log.addError(
                self.__class__.__name__,
                "Argument 'from_index' or 'to_index' is not a number. " +
                '\n ' + "Input format: " +
                "rules.rule_name(from_index, to_index).transform(passwordData)"
                )
        except AttributeError:
            raise
            errorPrinter.addMainError(
                self.__class__.__name__,
                "Wrong input type of data. " + '\n' +
                "Input must be of type 'passStruct.PassData'"
                )

    @abstractmethod
    def uniqueTransform(self, passinfo, from_index, to_index):
        """
        Return:
        transformed_password -- string
        entropy_change -- float number
        """
        pass

    def calculateFromIndex(self, input_password):
        return self.input_from_index if self.input_from_index != -1 \
               else (len(input_password) - 1)

    def calculateToIndex(self, input_password):
        return self.input_to_index if self.input_to_index != -1 \
               else (len(input_password) - 1)


class ApplySimplel33tFromIndexToIndex(Rule):

    def __init__(self, from_index, to_index):
        super(ApplySimplel33tFromIndexToIndex,
              self).__init__(from_index, to_index)
        self.l33t_table = {
                'a': ['4', '@'],
                'b': ['8'],
                'e': ['3'],
                'g': ['6', '9', '&'],
                'h': ['#'],
                'i': ['1', '!', '|'],
                'l': ['1', '|'],
                'o': ['0'],
                's': ['5', '$'],
                't': ['7'],
                'z': ['2'],
        }

    def uniqueTransform(self, passinfo, from_index, to_index):
        """Apply simple l33t table at X letters in password

        Arguments:
        passinfo -- type of passStruct.Password
        from_index -- start index of applying the rule
        to_index -- last index of applying the rule
        """
        transformed_password = passinfo.transformed_data[0]

        for key in self.l33t_table:
            transformed_password = transformed_password[: from_index] + \
                transformed_password[from_index: to_index + 1]. \
                replace(key, self.l33t_table[key][random.randint(
                    0,
                    len(self.l33t_table[key]) - 1)]
                    ) + \
                transformed_password[to_index + 1:]

        # Check if transformation changed the password
        entropy_change = 0.0
        if (passinfo.transformed_data[0] != transformed_password):
            entropy_change = 1.0

        return [transformed_password, entropy_change]


class ApplyAdvancedl33tFromIndexToIndex(Rule):

    def __init__(self, from_index, to_index):
        super(ApplyAdvancedl33tFromIndexToIndex,
              self).__init__(from_index, to_index)
        self.l33t_table = {
                'a': ['4', '/-\\', '@', '^'],
                'b': ['8', ']3', '13'],
                'c': ['(', '{', '[[', '<'],
                'd': [')', '|)'],
                'g': ['6', '9', '&'],
                'h': ['#', '|-|', ')-(', '/-/', '|~|'],
                'i': ['1', '!', '|'],
                'j': ['_|', 'u|'],
                'k': ['|<', '|{'],
                'l': ['|', '1', '|_'],
                'm': ['/\\/\\', '|\\/|', '[\\/]'],
                'n': ['/\\/', '|\\|', '~'],
                'o': ['0', '()'],
                'p': ['|D', '|*', '|>'],
                'q': ['(,)', '0,', 'O,', 'O\\'],
                'r': ['|2', '|?', '|-'],
                's': ['5', '$'],
                't': ['7', '+', '7`', "']['"],
                'u': ['|_|', '\\_\\', '/_/', '(_)'],
                'v': ['\\/'],
                'w': ['\\/\\/', '|/\\|', 'VV', '///', '\\^/'],
                'x': ['><'],
                'y': ["'/", '%', '`/', 'j'],
                'z': ['2', '7_'],
                'f': ['|=', 'ph'],
                'e': ['3', 'ii'],
        }

    def uniqueTransform(self, passinfo, from_index, to_index):
        """Apply advanced l33t table at X letters in password

        Arguments:
        passinfo -- type of passStruct.Password
        from_index -- start index of applying the rule
        to_index -- last index of applying the rule
        """
        transformed_password = passinfo.transformed_data[0]
        for key in self.l33t_table:
            transformed_password = transformed_password[: from_index] + \
                transformed_password[from_index: to_index + 1]. \
                replace(key, self.l33t_table[key][random.randint(
                    0,
                    len(self.l33t_table[key]) - 1)]
                    ) + \
                transformed_password[to_index + 1:]

            # Calculate new from_index and to_index value,
            # password can be longer after transformation
            from_index = self.calculateFromIndex(transformed_password)
            to_index = self.calculateToIndex(transformed_password)

        # Check if transformation changed the password
        entropy_change = 0.0
        if (passinfo.transformed_data[0] != transformed_password):
            entropy_change = 2.0

        return [transformed_password, entropy_change]


class CapitalizeFromIndexToIndex(Rule):

    def __init__(self, from_index, to_index):
        super(CapitalizeFromIndexToIndex, self).__init__(from_index, to_index)

    def uniqueTransform(self, passinfo, from_index, to_index):
        """Captalize X letters in password

        Arguments:
        passinfo -- type of passStruct.Password
        from_index -- start index of applying the rule
        to_index -- last index of applying the rule
        """
        transformed_password = passinfo.transformed_data[0][: from_index] + \
            passinfo.transformed_data[0][from_index: to_index + 1].upper() + \
            passinfo.transformed_data[0][to_index + 1:]

        # Check if transformation changed the password
        entropy_change = 0.0
        if (passinfo.transformed_data[0] != transformed_password):
            entropy_change = 1.0

        return [transformed_password, entropy_change]


class LowerFromIndexToIndex(Rule):

    def __init__(self, from_index, to_index):
        super(LowerFromIndexToIndex, self).__init__(from_index, to_index)

    def uniqueTransform(self, passinfo, from_index, to_index):
        """Lower X letters in password

        Arguments:
        passinfo -- type of passStruct.Password
        from_index -- start index of applying the rule
        to_index -- last index of applying the rule
        """
        transformed_password = passinfo.transformed_data[0][: from_index] + \
            passinfo.transformed_data[0][from_index: to_index + 1].lower() + \
            passinfo.transformed_data[0][to_index + 1:]

        # Check if transformation changed the password
        entropy_change = 0.0
        if (passinfo.transformed_data[0] != transformed_password):
            entropy_change = 1.0

        return [transformed_password, entropy_change]


class CapitalizeAllLetters(CapitalizeFromIndexToIndex):

    def __init__(self):
        super(CapitalizeAllLetters, self).__init__(0, -1)


class CapitalizeFirstLetter(CapitalizeFromIndexToIndex):

    def __init__(self):
        super(CapitalizeFirstLetter, self).__init__(0, 0)


class CapitalizeLastLetter(CapitalizeFromIndexToIndex):

    def __init__(self):
        super(CapitalizeLastLetter, self).__init__(-1, -1)


class LowerAllLetters(LowerFromIndexToIndex):

    def __init__(self):
        super(LowerAllLetters, self).__init__(0, -1)


class LowerFirstLetter(LowerFromIndexToIndex):

    def __init__(self):
        super(LowerFirstLetter, self).__init__(0, 0)


class LowerLastLetter(LowerFromIndexToIndex):

    def __init__(self):
        super(LowerLastLetter, self).__init__(-1, -1)


class ApplySimplel33tTable(ApplySimplel33tFromIndexToIndex):

    def __init__(self):
        super(ApplySimplel33tTable, self).__init__(0, -1)


class ApplyAdvancedl33tTable(ApplyAdvancedl33tFromIndexToIndex):

    def __init__(self):
        super(ApplyAdvancedl33tTable, self).__init__(0, -1)

class AddTwoRandomDigitsAsPrefix(Rule):

    def __init__(self):
        super(AddTwoRandomDigitsAsPrefix, self).__init__(0, 0)

    def uniqueTransform(self, passinfo, from_index, to_index):
        digits = str(randint(0, 9)) + str(randint(0, 9))
        transformed_password = digits + passinfo.getTransformedPassword()
        entropy_change = 6.5

        return [transformed_password, entropy_change]


class ChangeFirstLetterToRandomLetter(Rule):

    def __init__(self):
        super(ChangeFirstLetterToRandomLetter, self).__init__(0, 0)
    
    def uniqueTransform(self, passinfo, from_index, to_index):
        transformed_password = passinfo.getTransformedPassword()
        entropy_change = 0

        for c, i in zip(transformed_password, range(0, len(transformed_password))):
            if (c.islower() or c.isupper()):
                transformed_password = transformed_password[0: i] + \
                    chr(randint(97, 122)) + transformed_password[i + 1: ]
                entropy_change = 4.5
                break

        return [transformed_password, entropy_change]


class ChangeRandomLetterToRandomLetter(Rule):

    def __init__(self):
        super(ChangeRandomLetterToRandomLetter, self).__init__(0, 0)

    def uniqueTransform(self, passinfo, from_index, to_index):
        transformed_password = passinfo.getTransformedPassword()
        entropy_change = 0
        characterIndexList = []

        for c, i in zip(transformed_password, range(0, len(transformed_password))):
            if (c.islower() or c.isupper()):
                characterIndexList.append(i)
        
        if (characterIndexList):
            random_index = characterIndexList[randint(
                0,
                len(characterIndexList) - 1
                )]
            transformed_password = transformed_password[0: random_index] + \
                chr(randint(97, 122)) + transformed_password[random_index + 1: ]
            entropy_change = 7.5

        return [transformed_password, entropy_change]
