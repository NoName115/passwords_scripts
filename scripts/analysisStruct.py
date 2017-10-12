from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassData

import scripts.filter as data_filter
import scripts.table as data_table
import datetime
import os.path
import copy


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
        self.pcl_dic = pcl_dic
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
                    pcl_output=pcl_dic[passinfo.password].copy(),
                    orig_passdata=orig_passdata
                ))
            else:
                orig_passdata = PassData(
                    passinfo=passinfo,
                    pcl_output=pcl_dic[passinfo.password].copy()
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

            # Update PCL's outputs, coz
            # these outputs could be changed by filters
            self.updatePCLOutputs()

            print("Analysis: " + analysis.__class__.__name__)
            analysis.runAnalysis()

        print("Analyzing DONE\n")

    def updatePCLOutputs(self):
        for passdata in self.data_set['all_passwords']:
            passdata.pcl_output = self.pcl_dic[passdata.password].copy()

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

        self.addFilter(data_filter.PCLOutputRegex({
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
            ],
            start=500,
            end=600
        )
        table_2 = data_table.SummaryScore(self.getData()).getTable(
            fields=[
                'Passfault score', 'Pwscore score', 'Zxcvbn score'
            ],
            start=0,
            end=150
        )
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(
            'Number of passwords: ' + str(len(self.getData())),
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
        self.addFilter(data_filter.PCLOutputRegex({
            'Pwscore': 'The password is a palindrome'
        }))
        self.addFilter(data_filter.ScoreLower({
            'Zxcvbn': 3
        }))
        self.applyFilter()

        table_1 = data_table.ComplexPassword(self.getData()).getTable(
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
        self.printToFile(table_1, filename='outputs/' + self.__class__.__name__)
        self.printToFile(
            'Number of passwords: ' + str(len(self.getData())),
            filename='outputs/' + self.__class__.__name__
        )

        # High score palindroms
        self.setData(self.analyzer.data_set['all_passwords'])
        self.clearFilter()

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.PCLOutputRegex({
            'Pwscore': 'The password is a palindrome'
        }))
        self.addFilter(data_filter.ScoreHigher({
            'Zxcvbn': 3
        }))
        self.applyFilter()

        table_2 = data_table.ComplexPassword(self.getData()).getTable(
            sortby='Zxcvbn score',
            fields=[
                'Password', 'Diff. char.', 'Char. classes', 'Length',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
                ]
        )
        self.printToFile(table_2, filename='outputs/' + self.__class__.__name__)
        self.printToFile(
            'Number of passwords: ' + str(len(self.getData())),
            filename='outputs/' + self.__class__.__name__
        )


        # At least diff_char >= 2 & length >= 9
        self.setData(self.analyzer.data_set['all_passwords'])
        self.clearFilter()

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.PCLOutputRegex({
            'Pwscore': 'The password is a palindrome'
        }))
        self.addFilter(data_filter.NumberOfDifferentCharactersHigher(2))
        self.addFilter(data_filter.PasswordLengthHigher(9))
        #self.addFilter(data_filter.OriginalPCLOutputIsNotOk(['Zxcvbn']))
        self.applyFilter()

        table_3 = data_table.ComplexPassword(self.getData()).getTable(
            sortby='Zxcvbn score',
            fields=[
                'Password', 'Diff. char.', 'Char. classes', 'Length',
                'CrackLib',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
                ]
        )
        # Most common reason
        table_4 = data_table.OverallSummary(self.getData()).getTable(
            fields=[
                'Zxcvbn reasons of rejection'
            ]
        )

        self.printToFile(table_3, filename='outputs/' + self.__class__.__name__)
        self.printToFile(
            'Number of passwords: ' + str(len(self.getData())),
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(table_4, filename='outputs/' + self.__class__.__name__)


class ZxcvbnDictionary(AnalysisTemplate):

    def runAnalysis(self):
        # Any dictionary word, especially Match in Zxcvbn
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Zxcvbn': 3,
            'Pwscore': 40
        }))
        self.addFilter(data_filter.PCLOutputRegex({
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
                'CrackLib', 'PassWDQC', 'Pwscore', 'Passfault', 'Zxcvbn'
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
        self.addFilter(data_filter.PCLOutputRegex({
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

        # PassWDQC - 'Dic. word', CrackLib - 'OK', Pwscore - 'OK'
        self.setData(self.analyzer.data_set['all_passwords'])
        self.clearFilter()

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.PCLOutputRegex({
            'PassWDQC': 'dictionary'
        }))
        #self.addFilter(data_filter.OriginalPCLOutputIsOk(['CrackLib']))
        #self.addFilter(data_filter.OriginalPCLOutputIsOk(['Pwscore']))
        self.applyFilter()

        table_1 = data_table.OverallSummary(self.getData()).getTable(
            fields=[
                'CrackLib accepted', 'CrackLib rejected',
                'CrackLib reasons of rejection',
                'PassWDQC accepted', 'PassWDQC rejected',
                'PassWDQC reasons of rejection',
                'Pwscore accepted', 'Pwscore rejected',
                'Pwscore reasons of rejection'
                ],
            start=0,
            end=7
        )
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )

        # Dictionary word for every PCL
        self.setData(self.analyzer.data_set['all_passwords'])
        self.clearFilter()

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Zxcvbn': 3,
            'Pwscore': 40
        }))
        self.addFilter(data_filter.PCLOutputRegex({
            'CrackLib': 'dictionary word'
        }))
        self.addFilter(data_filter.PCLOutputRegex({
            'PassWDQC': 'dictionary'
        }))
        self.addFilter(data_filter.PCLOutputRegex({
            'Passfault': 'Match'
        }))
        self.addFilter(data_filter.PCLOutputRegex({
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
        self.addFilter(data_filter.PCLOutputRegex({
            'Passfault': 'Keyboard'
        }))
        self.applyFilter()

        table_1 = data_table.ComplexPassword(self.getData()).getTable(
            sortby='Passfault score',
            fields=[
                'Password', 'CrackLib', 'PassWDQC',
                'Passfault', 'Passfault score',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
                ]
        )

        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )

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

        table_2 = data_table.ComplexPassword(self.getData()).getTable(
            sortby='Pwscore score',
            fields=[
                'Password', 'CrackLib', 'PassWDQC',
                'Passfault', 'Passfault score',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
                ]
        )
        table_3 = data_table.OverallSummary(self.getData()).getTable()
        
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
        )


class PassWDQCPasswordPattern(AnalysisTemplate):

    def runAnalysis(self):
        # Passwords contain letter, number & special char.
        # Are longer than 9 characters & have at least 7 diff. characters
        # >80% passwords pass through pcl
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Pwscore': 40,
            'Zxcvbn': 3
        }))
        #self.addFilter(data_filter.NumberOfPasswordCharacterClass(3))
        self.addFilter(data_filter.PasswordContainCharacterClass([
            'lower letter', 'upper letter'
        ]))
        self.addFilter(data_filter.PasswordContainCharacterClass([
            'number'
        ]))
        self.addFilter(data_filter.PasswordContainCharacterClass([
            'special char'
        ]))
        self.addFilter(data_filter.NumberOfDifferentCharactersHigher(7))
        self.addFilter(data_filter.PasswordLengthHigher(9))
        self.applyFilter()

        table_1 = data_table.ComplexPassword(self.getData()).getTable(
            sortby='PassWDQC',
            fields=[
                'Password', 'Diff. char.', 'Char. classes', 'Length',
                'PassWDQC', 'Passfault', 'Pwscore', 'Zxcvbn'
            ]
        )
        table_2 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=15
            #fields=[
            #    'PassWDQC accepted', 'PassWDQC rejected',
            #    'PassWDQC reasons of rejection'
            #    ]
        )

        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
        )


class ZxcvbnPasswordPattern(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Pwscore': 40,
            'Zxcvbn': 3
        }))
        self.addFilter(data_filter.PasswordLengthHigher(10))
        self.addFilter(data_filter.TestFilter())
        self.applyFilter()

        table_1 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=20,
            fields=[
                'CrackLib reasons of rejection',
                'PassWDQC reasons of rejection',
                'Pwscore reasons of rejection',
                'Zxcvbn accepted', 'Zxcvbn rejected',
                'Zxcvbn reasons of rejection'
            ]
        )
        table_2 = data_table.ComplexPassword(self.getData()).getTable(
            fields=[
                'Password', 'Char. classes', 'Length',
                'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
                ]
        )
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
        )


class ZxcvbnPwscorePasswordPattern(AnalysisTemplate):

    def runAnalysis(self):
        def getFirstTable():
            return data_table.ComplexPassword(self.getData()).getTable(
                fields=[
                    'Password', 'Char. classes', 'Length',
                    'Pwscore', 'Pwscore score',
                    'Zxcvbn', 'Zxcvbn score'
                ],
                start=10,
                end=100
            )

        def getSecondTable():
            return data_table.OverallSummary(self.getData()).getTable(
                start=0,
                end=13,
                fields=[
                    'Pwscore accepted', 'Pwscore rejected',
                    'Pwscore reasons of rejection',
                    'Zxcvbn accepted', 'Zxcvbn rejected',
                    'Zxcvbn reasons of rejection'
                ]
            )

        # Passwords have pattern 2NXL2N, length > 8/9/10
        # and contain at least one letter
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Pwscore': 40,
            'Zxcvbn': 3
        }))
        self.addFilter(data_filter.TestFilter())
        self.addFilter(data_filter.PasswordContainCharacterClass([
            'lower letter', 'upper letter'
        ]))
        self.applyFilter()
        self.clearFilter()

        # Get unfiltered data by length
        unfiltered_data = self.getData()

        # Passwords with length >= 10
        self.addFilter(data_filter.PasswordLengthHigher(10))
        self.applyFilter()

        self.printToFile(
            getFirstTable(),
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(
            getSecondTable(),
            filename='outputs/' + self.__class__.__name__
        )

        # Passwords with length >= 9
        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.PasswordLengthHigher(9))
        self.applyFilter()

        self.printToFile(
            getFirstTable(),
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(
            getSecondTable(),
            filename='outputs/' + self.__class__.__name__
        )

        # Passwords with length >= 8
        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.PasswordLengthHigher(8))
        self.applyFilter()

        self.printToFile(
            getFirstTable(),
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(
            getSecondTable(),
            filename='outputs/' + self.__class__.__name__
        )


class PassfaultOneMatch(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.PCLOutputDoesNotContainString({
            'Passfault': ','
        }))
        self.addFilter(data_filter.PCLOutputRegex({
            'Passfault': 'Match'
        }))
        self.addFilter(data_filter.ScoreHigher({
            'Zxcvbn': 3
        }))
        self.applyFilter()

        table = data_table.ComplexPassword(self.getData()).getTable(
            sortby='Zxcvbn score',
            reversesort=True
        )
        self.printToFile(table)


class PassfaultMatchWorstPasswords(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.PCLOutputDoesNotContainString({
            'Passfault': ','
        }))
        self.addFilter(data_filter.PCLOutputRegex({
            'Passfault': 'worst-passwords'
        }))
        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Pwscore': 40,
            'Zxcvbn': 3
        }))
        self.addFilter(data_filter.OriginalPCLOutputIsOk([
            'CrackLib', 'PassWDQC', 'Pwscore', 'Zxcvbn'
        ]))
        self.applyFilter()

        table = data_table.ComplexPassword(self.getData()).getTable()
        self.printToFile(
            table,
            filename='outputs/' + self.__class__.__name__
            )


class ZxcvbnCommonPasswords(AnalysisTemplate):

    def runAnalysis(self):
        # Passwords that only Zxcvbn recognize as 'commonly used password'
        # and are accepteb by other libraries
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.PCLOutputRegex({
            'Zxcvbn': 'commonly used password'
        }))

        self.addFilter(data_filter.PCLOutputDoesNotContainString({
            'CrackLib': 'dictionary word'
        }))
        self.addFilter(data_filter.PCLOutputDoesNotContainString({
            'Pwscore': 'dictionary word'
        }))
        self.addFilter(data_filter.PCLOutputDoesNotContainString({
            'PassWDQC': 'dictionary'
        }))
        self.addFilter(data_filter.PCLOutputDoesNotContainString({
            'Passfault': 'Match'
        }))

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Pwscore': 40
        }))
        self.addFilter(data_filter.OriginalPCLOutputIsOk([
            'CrackLib', 'PassWDQC', 'Pwscore'
        ]))
        self.applyFilter()

        table_1 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=20
        )
        table_2 = data_table.ComplexPassword(self.getData()).getTable()
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
            )
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
            )

        # Passwords are accepted by PassWDQC or Pwscore
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk([
            'PassWDQC', 'Pwscore'
        ]))
        self.applyFilter()

        table_3 = data_table.ComplexPassword(self.getData()).getTable(
            fields=[
                'Password', 'Diff. char.', 'Char. classes', 'Length',
                'CrackLib', 'PassWDQC',
                'Passfault', 'Passfault score',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
            ]
        )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
            )

        # Passwords are accepted by both PCLs PassWDQC and Pwscore
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk([
            'PassWDQC'
        ]))
        self.addFilter(data_filter.OriginalPCLOutputIsOk([
            'Pwscore'
        ]))
        self.applyFilter()

        table_4 = data_table.ComplexPassword(self.getData()).getTable(
            fields=[
                'Password', 'Diff. char.', 'Char. classes', 'Length',
                'CrackLib', 'PassWDQC',
                'Passfault', 'Passfault score',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
            ]
        )
        self.printToFile(
            table_4,
            filename='outputs/' + self.__class__.__name__
            )


class EmailAddresses(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.PasswordRegex('^.+\@.+\..+$'))
        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.applyFilter()

        table_1 = data_table.OverallSummary(self.getData()).getTable()
        table_2 = data_table.ComplexPassword(self.getData()).getTable()
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
        )


class CracklibPwscorePattern(AnalysisTemplate):

    def runAnalysis(self):
        # Password pattern 2NXL2N, X>7, Length > 10
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.PasswordRegex('^\d\d[a-zA-Z]{7,}\d\d$'))
        self.addFilter(data_filter.PasswordLengthHigher(10))
        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Pwscore': 40,
            'Zxcvbn': 3
        }))
        self.applyFilter()

        table_1 = data_table.OverallSummary(self.getData()).getTable()
        table_2 = data_table.ComplexPassword(self.getData()).getTable()
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
        )


class PassWDQCPasswordLength(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Pwscore': 40,
            'Zxcvbn': 3
        }))
        self.applyFilter()

        for pass_length in range(10, 21):
            self.clearFilter()
            self.addFilter(data_filter.PasswordLengthHigher(pass_length))
            self.applyFilter()
            table_1 = data_table.OverallSummary(self.getData()).getTable(
                start=0,
                end=15
            )
            self.printToFile("Password length == " + str(pass_length))
            self.printToFile(table_1)

            if (pass_length in [15, 20]):
                table_2 = data_table.ComplexPassword(self.getData()).getTable(
                    fields=[
                        'Password', 'Length',
                        'CrackLib', 'PassWDQC',
                        'Passfault', 'Passfault score',
                        'Pwscore', 'Pwscore score',
                        'Zxcvbn', 'Zxcvbn score'
                    ]
                )
                self.printToFile(table_2)


class CracklibPwScoreLowPasswordScore(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.PCLOutputRegex({
            'Pwscore': 'Low password score'
        }))
        self.applyFilter()

        table_1 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end= 25,
            fields=[
                'CrackLib accepted', 'CrackLib rejected',
                'CrackLib reasons of rejection',
                #'PassWDQC accepted', 'PassWDQC rejected',
                #'PassWDQC reasons of rejection',
                #'Passfault accepted', 'Passfault rejected',
                #'Passfault reasons of rejection',
                'Pwscore accepted', 'Pwscore rejected',
                'Pwscore reasons of rejection',
                'Zxcvbn accepted', 'Zxcvbn rejected',
                'Zxcvbn reasons of rejection'
            ]
        )
        self.printToFile(table_1)


class CracklibZxcvbnSummary(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.applyFilter()

        table_1 = data_table.OverallSummary(self.getData()).getTable()
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )


class TestAnalysis(AnalysisTemplate):

    def runAnalysis(self):
        pass
