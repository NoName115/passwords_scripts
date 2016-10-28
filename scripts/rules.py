from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassData

import scripts.errorPrinter as errorPrinter
import scripts.config as config
import random
import re
import sys


class Rule(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, inputFromIndex, inputToIndex):
        self.inputFromIndex = inputFromIndex
        self.inputToIndex = inputToIndex

    @abstractmethod
    def transform(self, passwordData):
        """Main method for password transformation

        Method catch errors, calculate indexes,
        call uniqueTransform method and
        estimateEntropyChangeAndSaveTransformData method
        """
        try:
            for xPassword in passwordData.passwordList:
                fromIndex = self.calculateFromIndex(xPassword.originallyPassword)
                toIndex = self.calculateToIndex(xPassword.originallyPassword)

                if (fromIndex > toIndex):
                    passwordData.errorLog.addError(self.__class__.__name__,
                                                   "Wrong value of input" +
                                                   " data. " + '\n' +
                                                   "'fromIndex' must be " +
                                                   "same or lower then" +
                                                   " 'toIndex'")
                    continue

                transformedPassword = self.uniqueTransform(
                    xPassword, fromIndex, toIndex)

                xPassword.transformedPassword = transformedPassword

                self.estimateEntropyChangeAndSaveTransformData(xPassword)

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
    def uniqueTransform(self, xPassword, fromIndex, toIndex):
        """
        Return:
        transformedPassword -- string
        """
        pass

    @abstractmethod
    def estimateEntropyChangeAndSaveTransformData(self, xPassword):
        """By result of entropyCondition method
        estimate entropy change.

        Entropy values are store in config.py file
        """
        entropyChange = config.ruleEntropyValue[self.__class__.__name__] \
            if self.entropyCondition(xPassword.transformedPassword,
                                     xPassword.originallyPassword) \
            else 0

        xPassword.entropy += entropyChange
        xPassword.transformRules.append([self.__class__.__name__,
                                        entropyChange])

    @abstractmethod
    def entropyCondition(self, transformedPassword, originallyPassword):
        """
        Return:
        condition result -- boolean
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

    def transform(self, passwordData):
        super(ApplySimplel33tFromIndexToIndex, self).transform(passwordData)

    def uniqueTransform(self, xPassword, fromIndex, toIndex):
        """Apply simple l33t table at X letters in password

        Arguments:
        xPassword -- type of passStruct.Password
        fromIndex -- start index of applying the rule
        toIndex -- last index of applying the rule
        """
        transformedPassword = xPassword.originallyPassword

        for key in self.l33tTable:
            transformedPassword = transformedPassword[: fromIndex] + \
                transformedPassword[fromIndex: toIndex + 1]. \
                replace(key, self.l33tTable[key][random.
                    randint(0, len(self.l33tTable[key]) - 1)]) + \
                transformedPassword[toIndex + 1:]

        return transformedPassword

    def estimateEntropyChangeAndSaveTransformData(self, xPassword):
        super(ApplySimplel33tFromIndexToIndex,
              self).estimateEntropyChangeAndSaveTransformData(xPassword)

    def entropyCondition(self, transformedPassword, originallyPassword):
        if (transformedPassword == originallyPassword):
            return False
        else:
            return True


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

    def transform(self, passwordData):
        super(ApplyAdvancedl33tFromIndexToIndex, self).transform(passwordData)

    def uniqueTransform(self, xPassword, fromIndex, toIndex):
        """Apply advanced l33t table at X letters in password

        Arguments:
        xPassword -- type of passStruct.Password
        fromIndex -- start index of applying the rule
        toIndex -- last index of applying the rule
        """
        transformedPassword = xPassword.originallyPassword
        for key in self.l33tTable:
            transformedPassword = transformedPassword[: fromIndex] + \
                transformedPassword[fromIndex: toIndex + 1]. \
                replace(key, self.l33tTable[key][random.
                    randint(0, len(self.l33tTable[key]) - 1)]) + \
                transformedPassword[toIndex + 1:]

            # Calculate new fromIndex and toIndex value,
            # password can be longer after transformation
            fromIndex = self.calculateFromIndex(transformedPassword)
            toIndex = self.calculateToIndex(transformedPassword)

        return transformedPassword

    def estimateEntropyChangeAndSaveTransformData(self, xPassword):
        super(
            ApplyAdvancedl33tFromIndexToIndex,
            self).estimateEntropyChangeAndSaveTransformData(xPassword)

    def entropyCondition(self, transformedPassword, originallyPassword):
        if (transformedPassword == originallyPassword):
            return False
        else:
            return True


class CapitalizeFromIndexToIndex(Rule):

    def __init__(self, fromIndex, toIndex):
        super(CapitalizeFromIndexToIndex, self).__init__(fromIndex, toIndex)

    def transform(self, passwordData):
        super(CapitalizeFromIndexToIndex, self).transform(passwordData)

    def uniqueTransform(self, xPassword, fromIndex, toIndex):
        """Captalize X letters in password

        Arguments:
        xPassword -- type of passStruct.Password
        fromIndex -- start index of applying the rule
        toIndex -- last index of applying the rule
        """
        transformedPassword = xPassword.transformedPassword[: fromIndex] + \
            xPassword.transformedPassword[fromIndex: toIndex + 1].upper() + \
            xPassword.transformedPassword[toIndex + 1:]

        return transformedPassword

    def estimateEntropyChangeAndSaveTransformData(self, xPassword):
        super(
            CapitalizeFromIndexToIndex,
            self).estimateEntropyChangeAndSaveTransformData(xPassword)

    def entropyCondition(self, transformedPassword, originallyPassword):
        if (any(c.islower() for c in originallyPassword) and
           transformedPassword.isupper()):
            return True
        else:
            return False


class LowerFromIndexToIndex(Rule):

    def __init__(self, fromIndex, toIndex):
        super(LowerFromIndexToIndex, self).__init__(fromIndex, toIndex)

    def transform(self, passwordData):
        super(LowerFromIndexToIndex, self).transform(passwordData)

    def uniqueTransform(self, xPassword, fromIndex, toIndex):
        """Lower X letters in password

        Arguments:
        xPassword -- type of passStruct.Password
        fromIndex -- start index of applying the rule
        toIndex -- last index of applying the rule
        """
        transformedPassword = xPassword.transformedPassword[: fromIndex] + \
            xPassword.transformedPassword[fromIndex: toIndex + 1].lower() + \
            xPassword.transformedPassword[toIndex + 1:]

        return transformedPassword

    def estimateEntropyChangeAndSaveTransformData(self, xPassword):
        super(LowerFromIndexToIndex,
              self).estimateEntropyChangeAndSaveTransformData(xPassword)

    def entropyCondition(self, transformedPassword, originallyPassword):
        if (any(c.isupper() for c in originallyPassword) and
           transformedPassword.islower()):
            return True
        else:
            return False
