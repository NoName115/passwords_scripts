

class PassInfo():

    def __init__(self, password='', orig_passinfo=None):
        """
        Arguments:
        password -- (string)
        orig_passinfo -- class PassInfo
        """
        self.password = password
        self.diff_char = self.differentCharacters(password)
        self.char_classes = self.characterClasses(password)

        if (orig_passinfo):
            self.orig_pass = orig_passinfo

    def __str__(self):
        return (
            '{0:15} ({1:.1f})'.format(
                self.password,
                self.getEntropyChange()
                ) + '\n' + str(self.getAppliedTransformation()) + '\n'
        )

    @staticmethod
    def differentCharacters(password):
        return len(set(password))

    @staticmethod
    def characterClasses(password):
        type_of_classes = []

        # Lowercase character in password
        if (any(c.islower() for c in password)):
            type_of_classes.append('lower letter')

        # Uppercase character in password
        if (any(c.isupper() for c in password)):
            type_of_classes.append('upper letter')

        # Digit character in password
        if (any(c.isdigit() for c in password)):
            type_of_classes.append('number')

        # Other(special) symbols
        if (any(
           (not c.isdigit() and not c.isupper() and not c.islower())
           for c in password)):
            type_of_classes.append('special char')

        return type_of_classes

    def addTransformRule(self, class_name, entropy_change):
        if (not hasattr(self, 'transform_rules')):
            self.transform_rules = []

        self.transform_rules.append({class_name: entropy_change})

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
        entropy_change = 0.0
        if (hasattr(self, 'transform_rules')):
            for transformation in self.transform_rules:
                entropy_change += list(transformation.values())[0]

        return entropy_change

    def isPasswordTransformed(self):
        return hasattr(self, 'transform_rules')


class PassData(PassInfo):

    def __init__(self, passinfo, pcl_output, orig_passdata=None):
        self.password = passinfo.password
        self.pcl_output = pcl_output
        self.diff_char = passinfo.diff_char
        self.char_classes = passinfo.char_classes

        if (hasattr(passinfo, 'transform_rules')):
            self.transform_rules = passinfo.transform_rules
            self.orig_pass = orig_passdata

    def debugData(self):
        """Return all password data

        Output format:
        Original password   Transformed password  (entropy_change)
        Transform (entropy_change) --> NextTransform
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
        Password (entropy_change)
        PCL_Name: PCL_Output    Next_PCL_Name: Next_PCL_Output
        Transform (entropy_change) --> NextTransform
        Transformation errors
        """
        pcl_output = "    ".join(
            '{0:1}: {1:10}, {2:1}'.format(
                key,
                value[0],
                value[1] if (value[1]) else 'None'
            )
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

        return '{0:1} ({1:.1f})'.format(
            self.password,
            self.getEntropyChange()
        ) + '\n' + pcl_output + '\n' + transformations + '\n' + error_output

    def getPCLOutput(self, pcl):
        return self.pcl_output[pcl][0]

    def getPCLScore(self, pcl):
        pcl_score = self.pcl_output[pcl][1]
        return pcl_score if (pcl_score is not None) else None

    def addAttribute(self, attr_dict):
        for attr_name, attr_value in attr_dict.items():
            self.__setattr__(attr_name, attr_value)

    def setPCLScore(self, pcl, score):
        self.pcl_output[pcl] = (self.pcl_output[pcl][0], score)
