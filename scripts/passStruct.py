import scripts.errorPrinter as errorPrinter


class PassInfo():

    def __init__(self, password='', orig_passinfo=None):
        """
        Arguments:
        password -- (string)
        orig_passinfo -- class PassInfo
        """
        self.password = password

        if (orig_passinfo):
            self.orig_pass = orig_passinfo

    def __str__(self):
        return (
            '{0:15} ({1:.1f})'.format(
                self.password,
                self.getEntropyChange()
                ) + '\n' + str(self.getAppliedTransformation()) + '\n'
        )

    def addTransformRule(self, class_name, entropyChange):
        if (not hasattr(self, 'transform_rules')):
            self.transform_rules = []

        self.transform_rules.append({class_name: entropyChange})

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

    def getEntropyChange(self):
        """Return the value of how much the transformations changed entropy
        """
        entropyChange = 0.0
        if (hasattr(self, 'transform_rules')):
            for transformation in self.transform_rules:
                entropyChange += list(transformation.values())[0]

        return entropyChange

    def isPasswordTransformed(self):
        return hasattr(self, 'transform_rules')


class PassData(PassInfo):

    def __init__(self, passinfo, pcl_output, orig_passdata=None):
        self.password = passinfo.password
        self.pcl_output = pcl_output

        if (hasattr(passinfo, 'transform_rules')):
            self.transform_rules = passinfo.transform_rules
            self.orig_pass = orig_passdata

    def debugData(self):
        """Return all password data

        Output format:
        Original password   Transformed password  (entropyChange)
        Transform (entropyChange) --> NextTransform
        LibraryName - OriginalPassword_LibraryOutput
        LibraryName - TransformedPassword_LibraryOutput
        """
        orig_password = ''
        orig_pcl_output = ''
        trans_password = ''
        trans_pcl_output = ''
        transformations = ''
        if (not hasattr(self, 'transform_rules')):
            orig_password = self.password
            orig_pcl_output = '\n'.join(
                key + ' - ' + value for key, value in self.pcl_output.items()
            )
        else:
            orig_password = self.orig_pass.password
            orig_pcl_output = '\n'.join(
                key + ' - ' + value
                for key, value in self.orig_pass.pcl_output.items()
            )
            trans_password = self.password
            transformations = self.getAppliedTransformation()

        return (
            '{0:1}   {1:1}  ({2:.1f})'.format(
                orig_password, trans_password, self.getEntropyChange()
            ) + '\n' + transformations + '\n' +
            orig_pcl_output + '\n' + trans_pcl_output + '\n'
        )

    def __str__(self):
        """Return password data

        Return format:
        Password (entropyChange)
        PCL_Name: PCL_Output    Next_PCL_Name: Next_PCL_Output
        Transform (entropyChange) --> NextTransform
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

        return '{0:10} ({1:.1f})'.format(
            self.password,
            self.getEntropyChange()
        ) + '\n' + pcl_output + '\n' + transformations + '\n' + error_output

    def getPCLOutput(self, pcl):
        return self.pcl_output[pcl][0]

    def getPCLScore(self, pcl):
        pcl_score = self.pcl_output[pcl][1]
        return pcl_score if (pcl_score) else '-'
