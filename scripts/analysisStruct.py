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
        # Match passwords & lower score then 10000000
        self.setData(self.analyzer.data_set['all_passwords'])
        self.clearFilter()

        self.addFilter(data_filter.PCLOutputContainString({
            'Passfault': 'Match'
        }))
        self.addFilter(data_filter.ScoreHigher({
            'Passfault': 10000001
        }))
        self.applyFilter()

        table_1 = data_table.ComplexPassword(self.getData()).getTable(
            sortby='Passfault score',
            fields=[
                'Password',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score',
                'Passfault', 'Passfault score',
            ]
        )
        table_2 = data_table.SummaryScore(self.getData()).getTable(
            start=0,
            end=150
        )
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
            )
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
            )


class ZxcvbnPalindrom(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        # Low score palindroms
        self.addFilter(data_filter.PCLOutputContainString({
            'Pwscore': 'The password is a palindrome'
        }))
        self.addFilter(data_filter.ScoreLower({
            'Zxcvbn': 3
        }))
        self.applyFilter()

        table = data_table.ComplexPassword(self.getData()).getTable(
            sortby='Zxcvbn score',
            reversesort=True,
            fields=[
                'Password', 'Diff. char.', 'Char. classes', 'Length',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
                ],
            start=120,
            end=260
        )
        self.printToFile(table, filename='outputs/' + self.__class__.__name__)
        self.printToFile(
            'Number of passwords: ' + str(len(self.getData())),
            filename='outputs/' + self.__class__.__name__
            )

        # High score palindroms
        self.setData(self.analyzer.data_set['all_passwords'])
        self.clearFilter()

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.PCLOutputContainString({
            'Pwscore': 'The password is a palindrome'
        }))
        self.addFilter(data_filter.ScoreHigher({
            'Zxcvbn': 3
        }))
        self.applyFilter()

        table = data_table.ComplexPassword(self.getData()).getTable(
            sortby='Zxcvbn score',
            fields=[
                'Password', 'Diff. char.', 'Char. classes', 'Length',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
                ]
        )
        self.printToFile(table, filename='outputs/' + self.__class__.__name__)
        self.printToFile(
            'Number of passwords: ' + str(len(self.getData())),
            filename='outputs/' + self.__class__.__name__
            )


        # At least diff_char >= 2 & length >= 9
        self.setData(self.analyzer.data_set['all_passwords'])
        self.clearFilter()

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.PCLOutputContainString({
            'Pwscore': 'The password is a palindrome'
        }))
        self.addFilter(data_filter.NumberOfDifferentCharactersHigher(2))
        self.addFilter(data_filter.PasswordLengthHigher(9))
        self.addFilter(data_filter.OriginalPCLOutputIsNotOk(['Zxcvbn']))
        self.applyFilter()

        table = data_table.ComplexPassword(self.getData()).getTable(
            sortby='Zxcvbn score',
            fields=[
                'Password', 'Diff. char.', 'Char. classes', 'Length',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
                ]
        )
        # Most common reason
        table_2 = data_table.OverallSummary(self.getData()).getTable(
            fields=[
                'Zxcvbn reasons of rejection'
            ]
        )

        self.printToFile(table, filename='outputs/' + self.__class__.__name__)
        self.printToFile(
            'Number of passwords: ' + str(len(self.getData())),
            filename='outputs/' + self.__class__.__name__
            )
        self.printToFile(table_2, filename='outputs/' + self.__class__.__name__)


class ZxcvbnDictionary(AnalysisTemplate):

    def runAnalysis(self):
        # Any dictionary word, especially Match in Zxcvbn
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Zxcvbn': 3,
            'Pwscore': 40
        }))
        self.addFilter(data_filter.PCLOutputContainString({
            'CrackLib': 'dictionary word',
            'PassWDQC': 'dictionary',
            'Passfault': 'Match',
            'Pwscore': 'dictionary word'
        }))
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['Zxcvbn']))
        self.applyFilter()

        table_1 = data_table.ComplexPassword(self.getData()).getTable(
            fields=[
                'Password',
                'CrackLib', 'PassWDQC', 'Pwscore', 'Zxcvbn', 'Passfault'
            ],
            start=0,
            end=100
            )
        table_2 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=10
        )
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
            )
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
            )

        # Dictionary word only in CrackLib, PassWDQC & Pwscore
        self.setData(self.analyzer.data_set['all_passwords'])
        self.clearFilter()

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Zxcvbn': 3,
            'Pwscore': 40
        }))
        self.addFilter(data_filter.PCLOutputContainString({
            'CrackLib': 'dictionary word',
            'PassWDQC': 'dictionary',
            'Pwscore': 'dictionary word'
        }))
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['Zxcvbn']))
        self.applyFilter()

        table_1 = data_table.ComplexPassword(self.getData()).getTable(
            sortby='Zxcvbn score',
            fields=[
                'Password',
                'CrackLib', 'PassWDQC', 'Pwscore', 'Zxcvbn', 'Zxcvbn score'
            ],
            start=0,
            end=100
            )
        table_2 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=10
        )
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
            )
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
            )

        # Dictionary word for every PCL
        self.setData(self.analyzer.data_set['all_passwords'])
        self.clearFilter()

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Zxcvbn': 3,
            'Pwscore': 40
        }))
        self.addFilter(data_filter.PCLOutputContainString({
            'CrackLib': 'dictionary word'
        }))
        self.addFilter(data_filter.PCLOutputContainString({
            'PassWDQC': 'dictionary'
        }))
        self.addFilter(data_filter.PCLOutputContainString({
            'Passfault': 'Match'
        }))
        self.addFilter(data_filter.PCLOutputContainString({
            'Pwscore': 'dictionary word'
        }))
        self.applyFilter()

        table_1 = data_table.ComplexPassword(self.getData()).getTable(
            fields=[
                'Password',
                'CrackLib', 'PassWDQC', 'Pwscore', 'Passfault',
                'Zxcvbn', 'Zxcvbn score'
            ],
            start=0,
            end=100
            )

        table_2 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=10
        )

        # Zxcvbn - OK passwords
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['Zxcvbn']))
        self.applyFilter()
        table_3 = data_table.ComplexPassword(self.getData()).getTable(
            fields=[
                'Password',
                'CrackLib', 'PassWDQC', 'Pwscore', 'Zxcvbn', 'Passfault'
            ],
            start=0,
            end=100
            )

        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
            )
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
            )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
            )


class PassfaultKeyboardSequence(AnalysisTemplate):

    def runAnalysis(self):
        # Passfault define passwords with keyboard sequences
        # other libaries accept these passwords
        # Remove Match from passfault
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Pwscore': 40,
            'Zxcvbn': 3
        }))
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['CrackLib']))
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['PassWDQC']))
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['Pwscore']))
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['Zxcvbn']))

        self.addFilter(data_filter.PCLOutputDoesNotContainString({
            'Passfault': 'Match'
        }))
        self.addFilter(data_filter.PCLOutputContainString({
            'Passfault': 'Keyboard'
        }))
        self.applyFilter()

        table = data_table.ComplexPassword(self.getData()).getTable(
            sortby='Passfault score',
            fields=[
                'Password', 'CrackLib', 'PassWDQC',
                'Passfault', 'Passfault score',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
                ]
        )

        self.printToFile(table)

        # Second table, lower score by Passfault pcl, and OK by others pcls
        self.setData(self.analyzer.data_set['all_passwords'])
        self.clearFilter()

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Pwscore': 40,
            'Zxcvbn': 3
        }))
        self.addFilter(data_filter.ScoreLower({
            'Passfault': 2500000
        }))
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['Pwscore']))
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['Zxcvbn']))
        self.addFilter(data_filter.PCLOutputDoesNotContainString({
            'Passfault': 'Match'
        }))
        self.applyFilter()

        table = data_table.ComplexPassword(self.getData()).getTable(
            sortby='Pwscore score',
            fields=[
                'Password', 'CrackLib', 'PassWDQC',
                'Passfault', 'Passfault score',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
                ]
        )
        self.printToFile(table)


class TestAnalysis(AnalysisTemplate):

    def runAnalysis(self):
        pass
