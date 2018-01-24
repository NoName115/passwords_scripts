from scripts.analysisBase import AnalysisTemplate

import scripts.filter as data_filter
import scripts.table as data_table


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
        self.addFilter(data_filter.PasswordRegex('^\d\d.*\d\d$'))
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
            sortby='Zxcvbn score'
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
        self.addFilter(data_filter.PasswordRegex('^\d\d.*\d\d$'))
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
