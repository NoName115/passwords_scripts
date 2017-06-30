import scripts.errorPrinter as errorPrinter


class PassInfo():

    def __init__(self, password=None, entropy=None, orig_passinfo=None):
        """
        Arguments:
        password -- (string)
        entropy -- (float/integer)
        orig_passinfo -- class PassInfo
        """
        self.password = password
        self.entropy = entropy

        if (orig_passinfo):
            self.orig_passinfo = orig_passinfo

    def __str__(self):
        return (
            '{0:15} ({1:.f})'.format(self.password, self.entropy) +
            '\n' + str(self.getAppliedTransformation()) + '\n'
        )

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

    def getPassword(self):
        return self.password

    def getEntropy(self):
        return self.entropy

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

    def __init__(self, passinfo, pcl_output, orig_passdata=None):
        self.password = passinfo.password
        self.entropy = passinfo.entropy
        self.pcl_output = pcl_output

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
        orig_pcl_output = ''
        trans_password = ''
        trans_entropy = ''
        trans_pcl_output = ''
        transformations = ''
        if (not hasattr(self, 'transform_rules')):
            orig_password = self.password
            orig_entropy = self.entropy
            orig_pcl_output = '\n'.join(
                key + ' - ' + value for key, value in self.pcl_output.items()
            )
        else:
            orig_password = self.orig_passdata.password
            orig_entropy = self.orig_passdata.entropy
            orig_pcl_output = '\n'.join(
                key + ' - ' + value
                for key, value in self.orig_passdata.pcl_output.items()
            )
            trans_password = self.password
            trans_entropy = self.entropy
            transformations = self.getAppliedTransformation()

        return (
            '{0:1} ({1:.2f}) {2:1} ({3:.2f})'.format(
                orig_password, orig_entropy,
                trans_password, trans_entropy
            ) + '\n' + transformations + '\n' +
            orig_pcl_output + '\n' + trans_pcl_output + '\n'
        )

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
        return self.pcl_output
