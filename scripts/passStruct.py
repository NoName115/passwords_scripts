import scripts.errorPrinter as errorPrinter
import re
import json


class PassInfo():

    def __init__(self, password=None, entropy=None):
        """
        Arguments:
        password -- (string)
        entropy -- (float/integer)
        """
        self.original_data = [password, entropy]
        self.transformed_data = [password, entropy]
        self.transform_rules = []
        self.error_log = errorPrinter.RuleError()

    def __str__(self):
        return '{0:15} ({1:.2f})'.format(
            self.original_data[0],
            self.original_data[1]
            ) + '\n' + \
            '{0:15} ({1:.2f})'.format(
            self.transformed_data[0],
            self.transformed_data[1]
            ) + '\n' + self.getAppliedTransformation() + '\n'

    def addTransformRule(self, class_name, entropy):
        self.transform_rules.append({class_name: entropy})

    def getAppliedTransformation(self):
        """Return string of applied transformations
        """
        return " -> ".join(
            str(list(trans.keys())[0]) + '(' +
            str(list(trans.values())[0]) + ')'
            for trans in self.transform_rules
            )

    def getOriginalPassword(self):
        return self.original_data[0]

    def getTransformedPassword(self):
        return self.transformed_data[0]

    def getInitialEntropy(self):
        return self.original_data[1]

    def getActualEntropy(self):
        return self.transformed_data[1]

    def getChangedEntropy(self):
        """Return difference between actual entropy and initial entropy
        """
        return self.transformed_data[1] - self.original_data[1]


class PassData(PassInfo):

    def __init__(self, passinfo, original_lib_output, transformed_lib_output):
        self.original_data = passinfo.original_data
        self.transformed_data = passinfo.transformed_data
        self.transform_rules = passinfo.transform_rules
        self.original_lib_output = original_lib_output
        self.transformed_lib_output = transformed_lib_output

    def debugData(self):
        """Return all password data

        Output format:
        Original password   Transformed password : Entropy
        Transform : actualEntropy --> NextTransform
        LibraryName - OriginalPassword_LibraryOutput
        LibraryName - TransformedPassword_LibraryOutput
        """
        if (not self.transform_rules):
            transformations = "No password transform"

        transformations = self.getAppliedTransformation()

        lib_output = ""
        for key in self.original_lib_output:
            lib_output += '{0:8} - {1:20}'.format(
                key,
                self.original_lib_output[key]
                ) + '\n'
            lib_output += '{0:8} - {1:20}'.format(
                key,
                self.transformed_lib_output[key]
                ) + '\n'

        return '{0:1} ({1:.2f}) {2:1} ({3:.2f})'.format(
            self.original_data[0],
            self.original_data[1],
            self.transformed_data[0],
            self.transformed_data[1]
            ) + '\n' + transformations + '\n' + lib_output

    def __str__(self):
        """Return password data

        Return format:
        Password : Entropy
        Transform : actualEntropy (entropyChange) --> NextTransform
        LibraryName - LibraryOutput
        """

        original_PCL_outputs = "    ".join(
            '{0:1}: {1:10}'.format(key, value)
            for key, value in self.original_lib_output.items()
            )

        transformed_PCL_outputs = "    ".join(
            '{0:1}: {1:10}'.format(key, value)
            for key, value in self.transformed_lib_output.items()
            )

        # Check if transformation take effect on password
        error_output = ""
        for trans in self.transform_rules:
            for key, value in trans.items():
                if (value == 0):
                    error_output += (
                        "Transformation  " + key + "  wasn\'t applied" + '\n'
                        )

        return '{0:10} ({1:.2f})'.format(
            self.original_data[0],
            self.original_data[1]
            ) + " " + original_PCL_outputs + '\n' + \
            '{0:10} ({1:.2f})'.format(
                self.transformed_data[0],
                self.transformed_data[1]
                ) + " " + transformed_PCL_outputs + '\n' + error_output

    def getOriginalLibOutput(self):
        return self.original_lib_output

    def getTransformedLibOutput(self):
        return self.transformed_lib_output
