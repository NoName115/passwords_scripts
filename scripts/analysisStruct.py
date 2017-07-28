from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassData
from prettytable import PrettyTable

import scripts.errorPrinter as errorPrinter
import scripts.filter as data_filter
import scripts.table as data_table
import datetime
import copy


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
            'all_passwords': [],
            'orig_passwords': [],
            'trans_passwords': []
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
        orig_passdata = None
        for passinfo in passinfo_list:
            if (hasattr(passinfo, 'transform_rules')):
                passdata_list.append(PassData(
                    passinfo=passinfo,
                    pcl_output=pcl_dic[passinfo.password],
                    orig_passdata=orig_passdata
                ))
            else:
                orig_passdata = PassData(
                    passinfo=passinfo,
                    pcl_output=pcl_dic[passinfo.password]
                )
                passdata_list.append(orig_passdata)

        # Fill default analysis group with data
        for passdata in passdata_list:
            self.default_analysis['all_passwords'].append(passdata)
            if (hasattr(passdata, 'transform_rules')):
                self.default_analysis['trans_passwords'].append(passdata)
            else:
                self.default_analysis['orig_passwords'].append(passdata)

    def addAnalysis(self, analysis):
        """Method add inputAnalysis to analysis_list
        """
        self.analysis_list.append(analysis)

    def runAnalyzes(self):
        """Run every analysis in analysis_list
        """
        # Create outputfile name by current datetime
        now = datetime.datetime.now()
        time = now.strftime("%Y-%m-%d_%H:%M:%S")
        self.filename = "outputs/analysis_" + time + ".output"

        for analysis in self.analysis_list:
            analysis.analyzer = self
            analysis.runAnalysis()

    def printToFile(self, text):
        """Print input text to file
        """
        output_file = open(self.filename, 'a')
        output_file.write(text + '\n\n')
        output_file.close()


class AnalysisTemplate():

    __metaclass__ = ABCMeta

    def __init__(self, analyzer=None):
        """Template for new analysis

        Arguments:
        analyzer -- class Analyzer
        """
        self.analyzer = analyzer
        self.data = None
        self.keys = None
        self.filters = []

    def addFilter(self, data_filter):
        self.filters.append(data_filter)

    def cleanFilter(self):
        self.filters = []

    def applyFilter(self):
        for data_filter in self.filters:
            self.data = data_filter.apply_check(self.data)

    def setData(self, data):
        self.data = data
        self.keys = self.data[0].pcl_output.keys()

    def getData(self):
        return self.data

    def getPCLs(self):
        return self.keys

    def printToFile(self, text):
        self.analyzer.printToFile(str(text))

    @abstractmethod
    def runAnalysis(self):
        pass

    @abstractmethod
    def getAnalysisDescription(self):
        """Short analysis description
        """
        pass


class TestNewAnalysis(AnalysisTemplate):

    def runAnalysis(self):
        # Load data
        self.setData(self.analyzer.default_analysis['all_passwords'])

        # Apply filter
        self.addFilter(data_filter.ChangePCLOutputByScore(
            {'CrackLib': 20, 'Zxcvbn': 4, 'Pwscore': 15}
        ))
        self.applyFilter()

        # Get table output
        table_list = []
        table_list.append(data_table.ScoreTable(self.getData()).getTable())
        #table_list.append(data_table.SimplePasswordInfo(self.getData()).getTable())
        #table_list.append(data_table.OrigAndTransPasswordInfo(self.getData()).getTable())
        #table_list.append(data_table.PasswordLength(self.getData(), sortby='Number', reversesort=True).getTable())
        #table_list.append(data_table.TransformedPasswordInfo(self.getData()).getTable())
        table_list.append(data_table.SummaryInfo(self.getData()).getTable())
        #table_list.append(data_table.PasswordWithPCLOutputs(self.getData()).getTable())

        # Print table to outputfile
        for table in table_list:
            self.printToFile(table)
