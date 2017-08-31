from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassData

import scripts.filter as data_filter
import scripts.table as data_table
import datetime
import os.path


class Analyzer():

    def __init__(self, passinfo_list, pcl_dic):
        """Initialize 5 default analysis groups

        Arguments:
        passinfo_list -- list of Password classes
        pcl_dic -- dictionary of password checking libraries output

        Self:
        data_set -- dictionary of 5 default analysis groups
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
        self.data_set = {
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
            self.data_set['all_passwords'].append(passdata)
            if (hasattr(passdata, 'transform_rules')):
                self.data_set['trans_passwords'].append(passdata)
            else:
                self.data_set['orig_passwords'].append(passdata)

    def addAnalysis(self, analysis):
        """Method add inputAnalysis to analysis_list
        """
        self.analysis_list.append(analysis)

    def runAnalyzes(self):
        """Run every analysis in analysis_list
        """
        def getOutputFileName():
            """Generate unique filename by current time & date
            """
            now = datetime.datetime.now()
            time = now.strftime("%Y-%m-%d_%H:%M:%S")

            file_counter = 0
            while (True):
                filename = 'outputs/analysis_' + time + "_" + \
                    str(file_counter) + "_.output"
                if (os.path.exists(filename)):
                    file_counter += 1
                else:
                    break

            return filename

        print("Analyzing...")

        for analysis in self.analysis_list:
            self.filename = getOutputFileName()
            analysis.analyzer = self

            print("Analysis: " + analysis.__class__.__name__)
            analysis.runAnalysis()

        print("Analyzing DONE\n")

    def printToFile(self, text, filename):
        """Print input text to file
        """
        if (not filename):
            filename = self.filename

        output_file = open(filename, 'a')
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

    def clearFilter(self):
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

    def printToFile(self, text, filename=None):
        self.analyzer.printToFile(str(text), filename)

    @abstractmethod
    def runAnalysis(self):
        pass

    @abstractmethod
    def getAnalysisDescription(self):
        """Short analysis description
        """
        pass


class PassfaultScoring(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.PCLOutputDoesNotContainString({
            'Passfault': 'Match'
        }))
        self.addFilter(data_filter.PasswordLengthLower(8))
        self.addFilter(data_filter.HigherScoreThan({
            'Passfault': 10000001
        }))
        self.applyFilter()

        table_1 = data_table.PasswordPCLOutputAndScore(self.getData()).getTable()
        table_2 = data_table.SummaryScoreTableInfo(self.getData()).getTable()
        self.printToFile(table_1, filename='outputs/' + self.__class__.__name__)
        self.printToFile(table_2, filename='outputs/' + self.__class__.__name__)

# TODO
# Podla poctu roznych znakou v hesle
# Pridat to do passInfo
class ZxcvbnPalindrom(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        # Low score palindroms
        self.addFilter(data_filter.PCLOutputContainString({
            'Pwscore': 'The password is a palindrome'
        }))
        self.addFilter(data_filter.LowerScoreThan({
            'Zxcvbn': 3
        }))
        self.applyFilter()

        table = data_table.PasswordPCLOutputAndScore(
            self.getData(),
            sortby='Zxcvbn - score'
            ).getTable()
        self.printToFile(table, filename='outputs/' + self.__class__.__name__)

        # High score palindroms
        self.setData(self.analyzer.data_set['all_passwords'])
        self.clearFilter()
        
        self.addFilter(data_filter.PCLOutputContainString({
            'Pwscore': 'The password is a palindrome'
        }))
        self.addFilter(data_filter.HigherScoreThan({
            'Zxcvbn': 3
        }))
        self.applyFilter()

        table = data_table.PasswordPCLOutputAndScore(
            self.getData(),
            sortby='Zxcvbn - score'
            ).getTable()
        self.printToFile(table, filename='outputs/' + self.__class__.__name__)


class TestAnalysis(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        # TODO
        # PassWDQC: dictionary a Zxcvbn score >= 3

        self.addFilter(data_filter.PCLOutputContainString({
            'PassWDQC': 'dictionary',
            'CrackLib': 'dictionary',
            'Passfault': 'Match',
            'Pwscore': 'dictionary'
        }))
        self.applyFilter()

        table = data_table.PasswordPCLOutputAndScore(self.getData()).getTable()
        self.printToFile(table)
