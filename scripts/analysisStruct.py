from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassData
from prettytable import PrettyTable

import datetime
import copy


class PassDataGroup():

    def __init__(self):
        """Initialize class for group of passwords
        This group is used for analysis

        Self:
        group_dic -- key is name of pcl, value is list of class Password
        """
        self.group_dic = {}

    def addPassData(self, pcl, passdata):
        """Method add passdata into list by pcl

        Arguments:
        pcl -- string, name of password checking library
        passdata -- class PassData from passStruct.py
        """
        if (pcl not in self.group_dic):
            self.group_dic.update({pcl: []})

        if (passdata is not None):
            self.group_dic[pcl].append(passdata)

    def getPassDataAttribute(self, pcl, attribute):
        """Method return attribute of PassData as String

        Arguments:
        pcl -- string, name of password checking library
        attribute -- string, attribute of class Password
                     every attribute is callable 'getAttributeName'
        """
        return_info = self.group_dic[pcl][0].__getattribute__(attribute)()
        return (
            return_info[pcl] if (type(return_info) is dict) else return_info
        )

    def getDataInTable(self, pcl, header, attributes):
        """Method create and fill 'table' with PassData data from group_dic

        Arguments:
        pcl -- string, name of password checking library
        header -- list, header of every column
        attributes -- list, attributes that are extracted from PassData class
        """
        table = PrettyTable(header)
        for passdata in self.group_dic[pcl]:
            data_list = []
            # Iterate every attribute and get correct data from passdata
            for attr in attributes:
                attrdata = passdata.__getattribute__(attr)()
                if (type(attrdata) is dict):
                    attrdata = attrdata[pcl]
                data_list.append(attrdata)

            table.add_row(data_list)

        return table

    def intersection(self, other):
        """Intersection of two PassDataGroup classes

        Arguments:
        other -- class PassDataGroup

        Return value:
        intersection_group -- return new PassDataGroup class
        """
        intersection_group = PassDataGroup()
        for pcl in self.group_dic:
            for passdata in self.group_dic[pcl]:
                if (passdata in other.group_dic[pcl]):
                    intersection_group.addPassData(pcl, passdata)

        return intersection_group

    def union(self, other):
        """Union of two PassDataGroup classes

        Arguments:
        other -- class PassDataGroup

        Return value:
        union_group -- return new PassDataGroup class
        """
        union_group = copy.copy(self)
        for pcl in self.group_dic:
            if (pcl in other.group_dic):
                for passdata in other.group_dic[pcl]:
                    if (not (passdata in union_group.group_dic[pcl])):
                        union_group.addPassData(pcl, other_passdata)

        return union_group

    # DEBUG
    def printData(self):
        print(self.group_dic)


class Analyzer():

    def __init__(self, passinfo_list, pcl_dic):
        """Initialize 5 default analysis groups

        Arguments:
        passinfo_list -- list of Password classes
        pcl_dic -- dictionary of password checking libraries output

        Self:
        default_analysis -- dictionary of 5 default analysis groups
        allPasswords -- contain every password
        origPass_Ok -- contain passwords which originalPassword
                               pass through pcl
        origPass_NotOk -- contain passwords which originalPassword
                                  did not pass through pcl
        transPass_Ok -- contain passwords which transformedPassword
                                  pass through pcl
        transPass_NotOk -- contain passwords which
                                     transformedPassword
                                     did not pass through pcl
        password_data -- class PassData (input data)
        analysis_dic -- dictionary of analyzes
                       key is name of function in AnalyzerPrinter class
        """
        self.analysis_list = []
        self.default_analysis = {
            'allPasswords': PassDataGroup(),
            'origPass_Ok': PassDataGroup(),
            'origPass_NotOk': PassDataGroup(),
            'transPass_Ok': PassDataGroup(),
            'transPass_NotOk': PassDataGroup()
        }
        self.fillDefaultAnalysisGroups(passinfo_list, pcl_dic)

    def fillDefaultAnalysisGroups(self, passinfo_list, pcl_dic):
        """Method concatenate passinfo_list with pcl_dic
        and create list of PassData class.
        And fill 5 default analysis groups with data

        Arguments:
        passinfo_list -- list of Password classes
        pcl_dic -- dictionary of password checking libraries output
        """
        # Create passdata_list
        passdata_list = []
        for passinfo in passinfo_list:
            passdata_list.append(PassData(
                passinfo,
                pcl_dic[passinfo.original_data[0]],
                pcl_dic[passinfo.transformed_data[0]]
                ))

        # Fill default analysis group with data
        for passdata in passdata_list:
            for pcl in passdata.original_lib_output:
                self.default_analysis['allPasswords'].addPassData(
                    pcl,
                    passdata
                    )

                if (passdata.original_lib_output[pcl] == "OK"):
                    self.default_analysis['origPass_Ok'].addPassData(
                        pcl,
                        passdata
                        )
                else:
                    self.default_analysis['origPass_NotOk'].addPassData(
                        pcl,
                        passdata
                        )

                if (passdata.transformed_lib_output[pcl] == "OK"):
                    self.default_analysis['transPass_Ok'].addPassData(
                        pcl,
                        passdata
                        )
                else:
                    self.default_analysis['transPass_NotOk'].addPassData(
                        pcl,
                        passdata
                        )

    def addAnalysis(self, analysis):
        """Method add inputAnalysis to analysis_list
        """
        self.analysis_list.append(analysis)

    def runAnalyzes(self):
        """Run every analysis in analysis_list
        """
        for analysis in self.analysis_list:
            if (not analysis.analyzer):
                analysis.analyzer = self

            analysis.runAnalysis()

    def printAnalyzesOutput(self):
        """Print output of every analysis from analysis_list
        Short output is printed to stdout
        Long output is written to outputfile
        """
        # Create outputfile name it by current datetime
        now = datetime.datetime.now()
        time = now.strftime("%Y-%m-%d_%H:%M:%S")
        filename = "outputs/analysis_" + time + ".output"

        outputfile = open(filename, 'w')

        # Print analysis output to stdout and outputfile
        for analysis in self.analysis_list:
            print(analysis.getAnalysisOutput())

            # Write data in table with analysisDescription to outputfile
            outputfile.write(
                analysis.getDataInTable()
            )

        # Close output file
        outputfile.close()


class AnalysisTemplate():

    __metaclass__ = ABCMeta

    def __init__(self, analyzer=None, without_pcl_argument=False):
        """Template for new analysis

        Arguments:
        analyzer -- class Analyzer
        """
        self.analyzer = analyzer
        self.without_pcl_argument = without_pcl_argument
        self.data = PassDataGroup()

    def getData(self):
        """Return analysis data
        """
        return self.data

    def addPassData(self, pcl, passdata):
        """Add class PassData to analysis data
        """
        self.data.addPassData(pcl, passdata)

    def addGroup(self, groupData):
        """Add whole group of PassData classes to analysis data
        """
        self.data = groupData

    @abstractmethod
    def getAnalysisDescription(self, pcl):
        """Short analysis description
        This description is written to outputFile
        """
        pass

    @abstractmethod
    def runAnalysis(self):
        pass

    def getAnalysisOutput(self):
        if (self.without_pcl_argument):
            return (str(self.uniqueAnalysisOutput(None)))
        else:
            return '\n'.join(
                str(self.uniqueAnalysisOutput(pcl)) for pcl in self.data.group_dic
                )

    @abstractmethod
    def uniqueAnalysisOutput(self, pcl):
        """Long and detailed analysis output
        """
        pass

    def getDataInTable(self):
        """Return tables of analysis data
        """
        if (self.without_pcl_argument):
            return (
                self.getAnalysisDescription(None) +
                str(self.getUniqueTableOutput(None))
                )
        else:
            return (
                '\n'.join(
                    (
                        self.getAnalysisDescription(pcl) +
                        str(self.getUniqueTableOutput(pcl))
                    )
                    for pcl in self.data.group_dic
                ) + '\n'
            )

    @abstractmethod
    def getUniqueTableOutput(self, pcl):
        """Return one table with analysis data
        """
        pass


class PCLOutputChangedFromOk2NotOK(AnalysisTemplate):

    def __init__(self, analyzer=None, without_pcl_argument=False):
        super(PCLOutputChangedFromOk2NotOK, self).__init__(
            analyzer,
            without_pcl_argument
            )

    def runAnalysis(self):
        """Output of originalPasword is OK but
        transformedPassword was rejected(output is not OK)
        """
        self.addGroup(
            self.analyzer.default_analysis['origPass_Ok'].intersection(
                self.analyzer.default_analysis['transPass_NotOk']
                )
            )

    def getAnalysisDescription(self, pcl):
        return (
            "Original passwords pass through " + pcl +
            " but transformed passwords were rejected\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Original password " +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalPassword'
                ) +
            " pass through " + pcl + "." + '\n' +
            "But transformed password " +
            self.data.getPassDataAttribute(
                pcl,
                'getTransformedPassword'
                ) +
            ", did not pass through " + pcl + "." + '\n' +
            "And the reason of rejection is: " +
            self.data.getPassDataAttribute(
                pcl,
                'geTransformedLibOutput'
                ) +
            '\n'
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                [
                    'Original password', 'Transformed password',
                    'Transformed PCL output'
                ],
                [
                    'getOriginalPassword', 'getTransformedPassword',
                    'getTransformedLibOutput'
                ]
            )
        )


class PCLOutputChangedFromNotOk2Ok(AnalysisTemplate):

    def __init__(self, analyzer=None, without_pcl_argument=False):
        super(PCLOutputChangedFromNotOk2Ok, self).__init__(
            analyzer,
            without_pcl_argument
            )

    def runAnalysis(self):
        """OriginalPassword was rejected by PCL but
        transformedPassword pass through PCL
        """
        self.addGroup(
            self.analyzer.default_analysis['origPass_NotOk'].intersection(
                self.analyzer.default_analysis['transPass_Ok']
                )
            )

    def getAnalysisDescription(self, pcl):
        return (
            "Original passwords were rejected " +
            "but transformed passwords pass through " + pcl + "\n"
            )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Original password " +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalPassword'
                ) +
            " did not pass through " + pcl + ", because \n" +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalLibOutput'
                ) + '\n'
            "But after applying transformations, transformed password " +
            self.data.getPassDataAttribute(
                pcl,
                'getTransformedPassword'
                ) +
            " pass through " + pcl + ".\n"
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                [
                    'Original password', 'Transformed password',
                    'Original PCL output'
                ],
                [
                    'getOriginalPassword', 'getTransformedPassword',
                    'getOriginalLibOutput'
                ]
            )
        )


class PCLOutputChangedFromNotOk2NotOk(AnalysisTemplate):

    def __init__(self, analyzer=None, without_pcl_argument=False):
        super(PCLOutputChangedFromNotOk2NotOk, self).__init__(
            analyzer,
            without_pcl_argument
            )

    def runAnalysis(self):
        """Original and transformed password was rejected but
        reason of rejection is different
        """
        for pcl, passdata_list in (
            self.analyzer.default_analysis['origPass_NotOk'].intersection(
                self.analyzer.default_analysis['transPass_NotOk'])
                ).group_dic.items():
            for passdata in passdata_list:
                if (passdata.original_lib_output[pcl] !=
                   passdata.transformed_lib_output[pcl]):
                    self.addPassData(pcl, passdata)

    def getAnalysisDescription(self, pcl):
        return (
            "Original and transformed passwords were rejected by " + pcl +
            " but reason of rejection is diffrent\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Neither original " +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalPassword'
                ) + ' nor transformed ' +
            self.data.getPassDataAttribute(
                pcl,
                'getTransformedPassword'
                ) + " password, pass through " + pcl + '\n' +
            "But the reason of rejection changed from \n" +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalLibOutput'
                ) + "\nto\n" +
            self.data.getPassDataAttribute(
                pcl,
                'getTransformedLibOutput'
                ) + ".\n"
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                [
                    'Original password', 'Transformed password',
                    'Original PCL output', 'Transformed PCL output'
                ],
                [
                    'getOriginalPassword', 'getTransformedPassword',
                    'getOriginalLibOutput', 'getTransformedLibOutput'
                ]
            )
        )


class LowEntropyOriginalPasswordPassPCL(AnalysisTemplate):

    def __init__(self, analyzer=None, without_pcl_argument=False):
        super(LowEntropyOriginalPasswordPassPCL, self).__init__(
            analyzer,
            without_pcl_argument
            )

    def runAnalysis(self):
        """Original passwords with entropy lower than 36,
        pass through PCL
        """
        for pcl, passdata_list in (
            self.analyzer.default_analysis['origPass_Ok'].group_dic.items()
                ):
            for passdata in passdata_list:
                if (passdata.getInitialEntropy() < 36):
                    self.addPassData(pcl, passdata)

    def getAnalysisDescription(self, pcl):
        return (
            "Original passwords with entropy lower than 36.0, " +
            "pass through " + pcl + "\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Original password " +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalPassword'
                ) + " with low entropy " +
            str(self.data.getPassDataAttribute(
                pcl,
                'getInitialEntropy'
                )) + ",\n" +
            "lower than 36.0, sucesfully pass through " + pcl + ".\n"
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                ['Original password', 'Initial entropy'],
                ['getOriginalPassword', 'getInitialEntropy']
            )
        )


class HighEntropyOriginalPasswordDontPassPCL(AnalysisTemplate):

    def __init__(self, analyzer=None, without_pcl_argument=False):
        super(HighEntropyOriginalPasswordDontPassPCL, self).__init__(
            analyzer,
            without_pcl_argument
            )

    def runAnalysis(self):
        """Original passwords with entropy higher than 60,
        did not pass through PCL
        """
        for pcl, passdata_list in (
            self.analyzer.default_analysis['origPass_NotOk'].group_dic.items()
                ):
            for passdata in passdata_list:
                if (passdata.getInitialEntropy() > 60):
                    self.addPassData(pcl, passdata)

    def getAnalysisDescription(self, pcl):
        return (
            "Original passwords with entropy higher than 60, " +
            "did not pass through " + pcl + "\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Original password " +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalPassword'
                ) + " with high entropy " +
            str(self.data.getPassDataAttribute(
                pcl,
                'getInitialEntropy'
                )) + ",\n" +
            "higher than 60.0, did not pass through " + pcl + ".\n"
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                ['Original password', 'Initial entropy'],
                ['getOriginalPassword', 'getInitialEntropy']
            )
        )


class LowEntropyTransformedPasswordPassPCL(AnalysisTemplate):

    def __init__(self, analyzer=None, without_pcl_argument=False):
        super(LowEntropyTransformedPasswordPassPCL, self).__init__(
            analyzer,
            without_pcl_argument
            )

    def runAnalysis(self):
        """Transformed passwords with entropy lower than 36,
        pass through PCL
        """
        for pcl, passdata_list in (
            self.analyzer.default_analysis['transPass_Ok'].group_dic.items()
                ):
            for passdata in passdata_list:
                if (passdata.getActualEntropy() < 36):
                    self.addPassData(pcl, passdata)

    def getAnalysisDescription(self, pcl):
        return (
            "Transformed passwords with entropy lower than 36, " +
            "pass through " + pcl + "\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Transformed password " +
            self.data.getPassDataAttribute(
                pcl,
                'getTransformedPassword'
                ) + " with low entropy " +
            str(self.data.getPassDataAttribute(
                pcl,
                'getActualEntropy'
                )) + ",\n" +
            "lower than 36.0, sucesfully pass through " + pcl + ".\n"
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                ['Transformed password', 'Entropy'],
                ['getTransformedPassword', 'getActualEntropy']
            )
        )


class HighEntropyTransformedPasswordDontPassPCL(AnalysisTemplate):

    def __init__(self, analyzer=None, without_pcl_argument=False):
        super(HighEntropyTransformedPasswordDontPassPCL, self).__init__(
            analyzer,
            without_pcl_argument
            )

    def runAnalysis(self):
        """Transformed passwords with entropy higher than 60,
        did not pass through PCL
        """
        for pcl, passdata_list in (
            self.analyzer.default_analysis['transPass_NotOk'].group_dic.items()
                ):
            for passdata in passdata_list:
                if (passdata.getActualEntropy() > 60):
                    self.addPassData(pcl, passdata)

    def getAnalysisDescription(self, pcl):
        return (
            "Transformed passwords with entropy higher than 60, " +
            "did not pass through " + pcl + "\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Transformed password " +
            self.data.getPassDataAttribute(
                pcl,
                'getTransformedPassword'
                ) + " with high entropy " +
            str(self.data.getPassDataAttribute(
                pcl,
                'getActualEntropy'
                )) + ",\n" +
            "higher than 60.0, did not pss through " + pcl + ".\n"
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                ['Transformed password', 'Entropy'],
                ['getTransformedPassword', 'getActualEntropy']
            )
        )


class LowEntropyChangePassPCL(AnalysisTemplate):

    def __init__(self, analyzer=None, without_pcl_argument=False):
        super(LowEntropyChangePassPCL, self).__init__(
            analyzer,
            without_pcl_argument
            )

    def runAnalysis(self):
        """Analysis, that focus on entropy-change.
        That is the entropy, which password gets by transformations
        """
        for pcl, passdata_list in (
            self.analyzer.default_analysis['origPass_NotOk'].intersection(
                self.analyzer.default_analysis['transPass_Ok'])
                ).group_dic.items():
            for passdata in passdata_list:
                if (passdata.getChangedEntropy() < 2):
                    self.addPassData(pcl, passdata)

    def getAnalysisDescription(self, pcl):
        return (
            "Transformed password with a low entropy-change, " +
            "pass through " + pcl + "\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Original password " +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalPassword'
                ) + ", transformed password" +
            self.data.getPassDataAttribute(
                pcl,
                'getTransformedPassword'
                ) + " with applied transformations: \n" +
            self.data.getPassDataAttribute(
                pcl,
                'getAppliedTransformation'
                ) + "\nand with a low entropy-change," +
            "entropy value changed from " +
            str(self.data.getPassDataAttribute(
                pcl,
                'getInitialEntropy'
                )) + " to " +
            str(self.data.getPassDataAttribute(
                pcl,
                'getActualEntropy'
                )) + ", pass through " + pcl + ".\n"
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                [
                    'Original password', 'Transformed password',
                    'Transformations', 'Initial entropy', 'Entropy'
                ],
                [
                    'getOriginalPassword', 'getTransformedPassword',
                    'getAppliedTransformation', 'getInitialEntropy',
                    'getActualEntropy'
                ]
            )
        )


class OverallSummary(AnalysisTemplate):

    def __init__(self, analyzer=None, without_pcl_argument=False):
        super(OverallSummary, self).__init__(
            analyzer,
            without_pcl_argument
            )

    def runAnalysis(self):
        """Calculate percentages of transformed passwords
        that pass through PCL, and most common reason for rejection
        """
        self.addGroup(self.analyzer.default_analysis['allPasswords'])

    def getAnalysisDescription(self, pcl):
        return (
            "Percentages of transformed passwords that pass through " + pcl +
            " and most common reason for rejection\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        percent_change = (
            len(
                self.analyzer.default_analysis['transPass_Ok'].group_dic[pcl]
                ) /
            len(self.data.group_dic[pcl]) * 100
            )

        rejection_dic = {}
        for passdata in (
            self.analyzer.default_analysis['transPass_NotOk'].group_dic[pcl]
                ):
            if (passdata.transformed_lib_output[pcl] not in rejection_dic):
                rejection_dic.update({
                    passdata.transformed_lib_output[pcl]: 1
                    })
            else:
                rejection_dic[passdata.transformed_lib_output[pcl]] += 1

        return (
            str(round(percent_change, 2)) +
            "% of transformed passwords pass through " + pcl + ".\n" +
            "Most common reason(" +
            str(
                round(
                    max(rejection_dic.values()) /
                    len(self.data.group_dic[pcl]) * 100,
                    2
                    )
                ) + "%) for rejection is:\n" +
            str(max(rejection_dic, key=rejection_dic.get)) + '\n'
        )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                [
                    'Original password', 'Transformed password',
                    'Original PCL output', 'Transformed PCL output'
                ],
                [
                    'getOriginalPassword', 'getTransformedPassword',
                    'getOriginalLibOutput', 'getTransformedLibOutput'
                ]
            )
        )


class CountOkAndNotOkPasswords(AnalysisTemplate):

    def __init__(self, analyzer=None, without_pcl_argument=False):
        super(CountOkAndNotOkPasswords, self).__init__(
            analyzer,
            without_pcl_argument
            )

    def runAnalysis(self):
        self.addGroup(self.analyzer.default_analysis['allPasswords'])
        self.password_counter = {}

        for pcl, passinfo_list in self.data.group_dic.items():
            self.password_counter.update({ pcl: [0, 0] })
            for passinfo in passinfo_list:
                if (passinfo.getOriginalLibOutput()[pcl] == 'OK'):
                    self.password_counter[pcl][0] += 1
                else:
                    self.password_counter[pcl][1] += 1
                if (passinfo.getTransformedLibOutput()[pcl] == 'OK'):
                    self.password_counter[pcl][0] += 1
                else:
                    self.password_counter[pcl][1] += 1

    def getAnalysisDescription(self, pcl):
        return (
            "Analysis return number of passwords that passed through " + pcl +
            " and number of password that didn\'t\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            str(self.password_counter[pcl][0]) + " passwords pass through " + pcl +
            " & " + str(self.password_counter[pcl][1]) + " passwords didn\'t pass through " + pcl
        )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                [
                    'Original password', 'Transformed password',
                    'Original PCL output', 'Transformed PCL output'
                ],
                [
                    'getOriginalPassword', 'getTransformedPassword',
                    'getOriginalLibOutput', 'getTransformedLibOutput'
                ]
            )
        )


class AllOkPasswords(AnalysisTemplate):

    def __init__(self, analyzer=None, without_pcl_argument=False):
        super(AllOkPasswords, self).__init__(
            analyzer,
            without_pcl_argument
            )

    def runAnalysis(self):
        self.addGroup(
            self.analyzer.default_analysis['transPass_Ok'].union(
                self.analyzer.default_analysis['origPass_Ok']
            )
        )

    def getAnalysisDescription(self, pcl):
        return (
            "Analysis return all OK passwords (original & transformed) for " +
            pcl + " PCL\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "For analysis output, open analysis_file in folder 'outputs'"
        )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                [
                    'Ok Original password', 'Ok Transformed password'
                ],
                [
                    'getOkOriginalPassword', 'getTransformedPassword'
                ]
            )
        )


class AllPCLOutputs(AnalysisTemplate):

    def __init__(self, analyzer=None, without_pcl_argument=True):
        super(AllPCLOutputs, self).__init__(
            analyzer,
            without_pcl_argument
            )

    def runAnalysis(self):
        self.addGroup(self.analyzer.default_analysis['allPasswords'])

    def getAnalysisDescription(self, pcl):
        return (
            "Analysis return table with password and PCLs output\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "For analysis output, open analysis_file in folder 'outputs'"
        )

    def getUniqueTableOutput(self, pcl):
        # TODO
        pass
