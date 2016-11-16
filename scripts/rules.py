from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassData

import scripts.errorPrinter as errorPrinter
import random
import re
import sys


# Value of entropy that is added when rule is applied
ruleEntropyValue = {
        'ApplySimplel33tFromIndexToIndex': 1,
        'ApplyAdvancedl33tFromIndexToIndex': 2,
        'CapitalizeFromIndexToIndex': 1,
        'LowerFromIndexToIndex': 1,

        'ApplySimplel33tTable' : 1,
        'ApplyAdvancedl33tTable' : 2,
        'CapitalizeAllLetters' : 1,
        'CapitalizeFirstLetter' : 1,
        'CapitalizeLastLetter' : 1,
        'LowerAllLetters' : 1,
        'LowerFirstLetter' : 1,
        'LowerLastLetter' : 1,
}


class Rule(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, inputFromIndex, inputToIndex):
        self.inputFromIndex = inputFromIndex
        self.inputToIndex = inputToIndex

    def transform(self, passwordData):
        """Main method for password transformation

        Method catch errors, calculate indexes,
        call uniqueTransform method and
        estimateEntropyChangeAndSaveTransformData method
        """
        try:
            for passInfo in passwordData.passwordList:
                fromIndex = self.calculateFromIndex(
                    passInfo.originallyPassword
                    )
                toIndex = self.calculateToIndex(
                    passInfo.originallyPassword
                    )

                if (fromIndex > toIndex):
                    passwordData.errorLog.addError(self.__class__.__name__,
                                                   "Wrong value of input" +
                                                   " data. " + '\n' +
                                                   "'fromIndex' must be " +
                                                   "same or lower then" +
                                                   " 'toIndex'")
                    continue

                transformOutput = self.uniqueTransform(
                    passInfo, fromIndex, toIndex)

                passInfo.transformedPassword = transformOutput[0]

                # By result of entropyCondition method estimate entropy change
                entropyChange = ruleEntropyValue[self.__class__.__name__] \
                    if transformOutput[1] else 0

                passInfo.entropy += entropyChange
                passInfo.transformRules.append([self.__class__.__name__,
                                                entropyChange])

                print(transformOutput)

        except TypeError:
            raise
            passwordData.errorLog.addError(self.__class__.__name__,
                                           "Argument 'fromIndex' or " +
                                           "'toIndex' is not a number. " +
                                           '\n ' + "Input format: rules." +
                                           "rule_name(fromIndex, toIndex)." +
                                           "transform(passwordData)")
        except AttributeError:
            raise
            errorPrinter.addMainError(self.__class__.__name__,
                                      "Wrong input type of data. " + '\n' +
                                      "Input must be of type " +
                                      "'passStruct.PassData'")

    @abstractmethod
    def uniqueTransform(self, passInfo, fromIndex, toIndex):
        """
        Return:
        transformedPassword -- string
        """
        pass

    def calculateFromIndex(self, inputPassword):
        return self.inputFromIndex if self.inputFromIndex != -1 \
               else (len(inputPassword) - 1)

    def calculateToIndex(self, inputPassword):
        return self.inputToIndex if self.inputToIndex != -1 \
               else (len(inputPassword) - 1)


class ApplySimplel33tFromIndexToIndex(Rule):

    def __init__(self, fromIndex, toIndex):
        super(ApplySimplel33tFromIndexToIndex,
              self).__init__(fromIndex, toIndex)
        self.l33tTable = {
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

    def uniqueTransform(self, passInfo, fromIndex, toIndex):
        """Apply simple l33t table at X letters in password

        Arguments:
        passInfo -- type of passStruct.Password
        fromIndex -- start index of applying the rule
        toIndex -- last index of applying the rule
        """
        transformedPassword = passInfo.originallyPassword

        for key in self.l33tTable:
            transformedPassword = transformedPassword[: fromIndex] + \
                transformedPassword[fromIndex: toIndex + 1]. \
                replace(key, self.l33tTable[key][random.randint(
                    0,
                    len(self.l33tTable[key]) - 1)]
                    ) + \
                transformedPassword[toIndex + 1:]

        # Check if transformation changed the password
        entropyCondition = True
        if (transformedPassword == passInfo.originallyPassword):
            entropyCondition = False

        return [transformedPassword, entropyCondition]


class ApplyAdvancedl33tFromIndexToIndex(Rule):

    def __init__(self, fromIndex, toIndex):
        super(ApplyAdvancedl33tFromIndexToIndex,
              self).__init__(fromIndex, toIndex)
        self.l33tTable = {
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

    def uniqueTransform(self, passInfo, fromIndex, toIndex):
        """Apply advanced l33t table at X letters in password

        Arguments:
        passInfo -- type of passStruct.Password
        fromIndex -- start index of applying the rule
        toIndex -- last index of applying the rule
        """
        transformedPassword = passInfo.originallyPassword
        for key in self.l33tTable:
            transformedPassword = transformedPassword[: fromIndex] + \
                transformedPassword[fromIndex: toIndex + 1]. \
                replace(key, self.l33tTable[key][random.randint(
                    0,
                    len(self.l33tTable[key]) - 1)]
                    ) + \
                transformedPassword[toIndex + 1:]

            # Calculate new fromIndex and toIndex value,
            # password can be longer after transformation
            fromIndex = self.calculateFromIndex(transformedPassword)
            toIndex = self.calculateToIndex(transformedPassword)

        # Check if transformation changed the password
        entropyCondition = True
        if (transformedPassword == passInfo.originallyPassword):
            entropyCondition = False

        return [transformedPassword, entropyCondition]


class CapitalizeFromIndexToIndex(Rule):

    def __init__(self, fromIndex, toIndex):
        super(CapitalizeFromIndexToIndex, self).__init__(fromIndex, toIndex)

    def uniqueTransform(self, passInfo, fromIndex, toIndex):
        """Captalize X letters in password

        Arguments:
        passInfo -- type of passStruct.Password
        fromIndex -- start index of applying the rule
        toIndex -- last index of applying the rule
        """
        transformedPassword = passInfo.transformedPassword[: fromIndex] + \
            passInfo.transformedPassword[fromIndex: toIndex + 1].upper() + \
            passInfo.transformedPassword[toIndex + 1:]

        # Check if transformation changed the password
        entropyCondition = False
        if (passInfo.originallyPassword != transformedPassword):
            entropyCondition = True

        return [transformedPassword, entropyCondition]


class LowerFromIndexToIndex(Rule):

    def __init__(self, fromIndex, toIndex):
        super(LowerFromIndexToIndex, self).__init__(fromIndex, toIndex)

    def uniqueTransform(self, passInfo, fromIndex, toIndex):
        """Lower X letters in password

        Arguments:
        passInfo -- type of passStruct.Password
        fromIndex -- start index of applying the rule
        toIndex -- last index of applying the rule
        """
        transformedPassword = passInfo.transformedPassword[: fromIndex] + \
            passInfo.transformedPassword[fromIndex: toIndex + 1].lower() + \
            passInfo.transformedPassword[toIndex + 1:]

        # Check if transformation changed the password
        entropyCondition = False
        if (passInfo.originallyPassword != transformedPassword):
            entropyCondition = True

        return [transformedPassword, entropyCondition]


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
