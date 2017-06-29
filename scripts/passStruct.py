import scripts.errorPrinter as errorPrinter


class PassInfo():

    def __init__(self, password=None, entropy=None, orig_passinfo=None):
        """
        Arguments:
        password -- (string)
        entropy -- (float/integer)
        """
        '''
        self.original_data = [password, entropy]
        self.transformed_data = [password, entropy]
        self.transform_rules = []
        self.error_log = errorPrinter.RuleError()
        '''
        self.password = password
        self.entropy = entropy

        if (orig_passinfo):
            self.orig_passinfo = orig_passinfo

    def __str__(self):
        return '{0:15} ({1:.f})'.format(self.password, self.entropy) +
            '\n' + str(self.getAppliedTransformation()) + '\n'
    '''
    def __str__(self):
        return '{0:15} ({1:.2f})'.format(
            self.original_data[0],
            self.original_data[1]
            ) + '\n' + \
            '{0:15} ({1:.2f})'.format(
            self.transformed_data[0],
            self.transformed_data[1]
            ) + '\n' + self.getAppliedTransformation() + '\n'
    '''

    def addTransformRule(self, class_name, entropy):
        if (not hasattr(self, 'transform_rules')):
            self.transform_rules = []

        self.transform_rules.append({class_name: entropy})

    def getAppliedTransformation(self):
        """Return string of applied transformations if exists,
        else return None
        """
        if (hasattr(self, 'transform_rules')):
            return " -> ".join(
                str(list(trans.keys())[0]) + '(' +
                str(list(trans.values())[0]) + ')'
                for trans in self.transform_rules
                )
        else:
            return None

    '''
    def getAppliedTransformationByPassword(self, password):
        """Method return applied transformations if input password
        is same as transformed password, otherwise return '-'
        """
        if (self.transformed_data[0] == password):
            return self.getAppliedTransformation()
        else:
            return '-'
    '''

    def getPassword(self):
        return self.password

    def getEntropy(self):
        return self.entropy

    '''
    def getOriginalPassword(self):
        return self.original_data[0]

    def getTransformedPassword(self):
        return self.transformed_data[0]

    def getInitialEntropy(self):
        return self.original_data[1]

    def getActualEntropy(self):
        return self.transformed_data[1]
    '''

    '''
    def getEntropyByPassword(self, password):
        """Method return initial entropy if input password is same
        as original password, otherwise return actual entropy
        """
        return self.original_data[1] if (password == self.original_data[0]) \
            else self.transformed_data[1]
    '''

    def getChangedEntropy(self):
        """Return difference between entropy of transformed password
        and original password
        """
        if (hasattr(self, 'orig_passinfo')):
            return round(self.entropy - self.orig_passinfo.entropy)
        else:
            return 0

    def isPasswordTransformed(self):
        return hasattr(self, 'transform_rules')


class PassData(PassInfo):

    def __init__(self, passinfo, lib_output, orig_passdata=None):
        self.password = passinfo.password
        self.entropy = passinfo.entropy
        self.lib_output = lib_output

        if (hasattr(passinfo, 'transform_rules')):
            self.transform_rules = passinfo.transform_rules
            self.orig_passdata = orig_passdata

    def debugData(self):
        """Return all password data

        Output format:
        Original password   Transformed password : Entropy
        Transform : actualEntropy --> NextTransform
        LibraryName - OriginalPassword_LibraryOutput
        LibraryName - TransformedPassword_LibraryOutput
        """
        orig_password = ''
        orig_entropy = ''
        orig_lib_output = ''
        trans_password = ''
        trans_entropy = ''
        trans_lib_output = ''
        transformations = ''
        if (not hasattr(self, 'transform_rules')):
            orig_password = self.password
            orig_entropy = self.entropy
            orig_lib_output = '\n'.join(
                key + ' - ' + value for key, value in self.lib_output.items()
            )
        else:
            orig_password = self.orig_passdata.password
            orig_entropy = self.orig_passdata.entropy
            orig_lib_output = '\n'.join(
                key + ' - ' + value
                for key, value in self.orig_passdata.lib_output.items()
            )
            trans_password = self.password
            trans_entropy = self.entropy
            transformations = self.getAppliedTransformation()

        return '{0:1} ({1:.2f}) {2:1} ({3:.2f})'.format(
            orig_password,
            orig_entropy,
            trans_password,
            trans_entropy
            ) + '\n' + transformations + '\n' +
            orig_lib_output + '\n' + trans_lib_output '\n'

    def __str__(self):
        """Return password data

        Return format:
        Password : Entropy
        PCL_Name : PCL_Output     Next_PCL_Name : Next_PCL_Output
        Transformation : actualEntropy (entropyChange) --> NextTransform
        Transformation errors
        """
        pcl_output = "    ".join(
            '{0:1}: {1:10}'.format(key, value)
            for key, value in self.pcl_output.items()
            )

        # Check if transformation take effect on password
        error_output = ''
        transformations = ''
        if (hasattr(self, 'transform_rules')):
            transformations = self.getAppliedTransformation()
            for trans in self.transform_rules:
                for key, value in trans.items():
                    if (value == 0):
                        error_output += (
                            "Transformation  " + key +
                            "  wasn\'t applied" + '\n'
                            )

        return '{0:10} ({1:.2f})'.format(
            self.password,
            self.entropy
        ) + '\n' + pcl_output + '\n' + transformations + '\n' + error_output

    def getLibOutput(self):
        return self.lib_output

    '''
    def getOriginalLibOutput(self):
        return self.original_lib_output

    def getTransformedLibOutput(self):
        return self.transformed_lib_output

    def getLibOutputByPassword(self, password):
        """Method return pcl output for original password
        if input password is same as original password, otherwise
        return pcl output for transformed password
        """
        return self.original_lib_output if (password == self.original_data[0]) \
            else self.transformed_lib_output
    '''
    '''
    def getOkOriginalPassword(self):
        passdic = {}
        for pcl, pcl_output in self.original_lib_output.items():
            if (pcl_output == "OK"):
                passdic.update({ pcl: self.original_data[0] })
            else:
                passdic.update({ pcl: "-" })

        return passdic

    def getOkTransformedPassword(self):
        passdic = {}
        for pcl, pcl_output in self.transformed_lib_output.items():
            if (pcl_output == "OK"):
                passdic.update({ pcl: self.transformed_data[0] })
            else:
                passdic.update({ pcl: "-" })

        return passdic
    '''
