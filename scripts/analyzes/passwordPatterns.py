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
            sortby='Zxcvbn score',
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


class ZxcvbnPalindrom(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.PCLOutputRegex({
            'Pwscore': 'The password is a palindrome'
        }))
        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.applyFilter()

        unfiltered_data = self.getData()

        table_1 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=30
        )
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )

        self.clearFilter()
        self.addFilter(data_filter.PCLOutputRegex({
            'Zxcvbn': 'OK'
        }))
        self.applyFilter()

        table_2 = data_table.ComplexPassword(self.getData()).getTable(
            sortby='Zxcvbn score',
            reversesort=True,
            fields=[
                'Password', 'Diff. char.', 'Char. classes', 'Length',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
            ]
        )

        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
        )

        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsNotOk([
            'Zxcvbn'
        ]))
        self.applyFilter()

        table_3 = data_table.ComplexPassword(self.getData()).getTable(
            start=200,
            end=400,
            fields=[
                'Password', 'Diff. char.', 'Char. classes', 'Length',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
            ]
        )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
        )

        self.clearFilter()
        self.addFilter(data_filter.PasswordLengthHigher(9))
        self.applyFilter()

        table_4 = data_table.ComplexPassword(self.getData()).getTable(
            fields=[
                'Password', 'Diff. char.', 'Char. classes', 'Length',
                'Pwscore', 'Pwscore score',
                'Zxcvbn', 'Zxcvbn score'
            ]
        )
        self.printToFile(
            table_4,
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(
            'Number of passwords: ' + str(len(self.getData())),
            filename='outputs/' + self.__class__.__name__
        )


class DictionaryWords(AnalysisTemplate):

    def runAnalysis(self):
        # Cracklib, PassWDQC and Pwscore detect dictionary words
        # Passfault - match popular words, but in secure passwords too

        # Dictionary word only in CrackLib, PassWDQC & Pwscore
        self.printToFile(
            'CrackLib, PassWDQC or Pwscore consider passwords as dictionary words' +
            ' and Zxcvbn accept these passwords',
            filename='outputs/' + self.__class__.__name__
        )
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.applyFilter()

        unfiltered_data = self.getData()

        self.clearFilter()
        self.addFilter(data_filter.PCLOutputRegex({
            'CrackLib': 'dictionary word',
            'PassWDQC': 'dictionary',
            'Pwscore': 'dictionary word'
        }))
        self.applyFilter()

        table_1 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=10
        )
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )

        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['Zxcvbn']))
        self.applyFilter()

        table_2 = data_table.ComplexPasswordWithNumberOfUses(self.getData()).getTable(
            sortby='NOUses',
            reversesort=True,
            fields=[
                'NOUses', 'Password',
                'CrackLib', 'PassWDQC', 'Pwscore', 'Zxcvbn', 'Zxcvbn score'
            ],
            start=0,
            end=50
        )
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(
            'Number of passwords: ' + str(len(self.getData())),
            filename='outputs/' + self.__class__.__name__
        )

        # Dictionary word - PassWDQC & Pwscore
        self.printToFile(
            'PassWDQC or Pwscore consider passwords as dictionary words' +
            ' and CrackLib accept these passwords',
            filename='outputs/' + self.__class__.__name__
        )
        self.setData(unfiltered_data)
        self.clearFilter()

        self.addFilter(data_filter.PCLOutputRegex({
            'PassWDQC': 'dictionary',
            'Pwscore': 'dictionary word'
        }))
        self.applyFilter()

        table_3 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=10
        )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
        )

        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['CrackLib']))
        self.applyFilter()

        table_4 = data_table.ComplexPasswordWithNumberOfUses(self.getData()).getTable(
            sortby='NOUses',
            reversesort=True,
            fields=[
                'NOUses', 'Password',
                'CrackLib', 'PassWDQC', 'Pwscore', 'Zxcvbn'
            ],
            start=0,
            end=40
        )
        self.printToFile(
            table_4,
            filename='outputs/' + self.__class__.__name__
        )

        # Dictionary word - CrackLib & Pwscore
        self.printToFile(
            'CrackLib or Pwscore consider passwords as dictionary words' +
            ' and PassWDQC accept these passwords',
            filename='outputs/' + self.__class__.__name__
        )
        self.setData(unfiltered_data)
        self.clearFilter()

        self.addFilter(data_filter.PCLOutputRegex({
            'CrackLib': 'dictionary word',
            'Pwscore': 'dictionary word'
        }))
        self.applyFilter()

        table_5 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=10
        )
        self.printToFile(
            table_5,
            filename='outputs/' + self.__class__.__name__
        )

        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['PassWDQC']))
        self.applyFilter()

        table_6 = data_table.ComplexPasswordWithNumberOfUses(self.getData()).getTable(
            sortby='NOUses',
            reversesort=True,
            fields=[
                'NOUses', 'Password',
                'CrackLib', 'PassWDQC', 'Pwscore', 'Zxcvbn'
            ],
            start=0,
            end=40
        )
        self.printToFile(
            table_6,
            filename='outputs/' + self.__class__.__name__
        )

        # Dictionary word - CrackLib & PassWDQC
        self.printToFile(
            'CrackLib or PassWDQC consider passwords as dictionary words' +
            ' and Pwscore accept these passwords',
            filename='outputs/' + self.__class__.__name__
        )
        self.setData(unfiltered_data)
        self.clearFilter()

        self.addFilter(data_filter.PCLOutputRegex({
            'CrackLib': 'dictionary word',
            'PassWDQC': 'dictionary',
        }))
        self.applyFilter()

        table_7 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=10
        )
        self.printToFile(
            table_7,
            filename='outputs/' + self.__class__.__name__
        )

        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['Pwscore']))
        self.applyFilter()

        table_8 = data_table.ComplexPasswordWithNumberOfUses(self.getData()).getTable(
            sortby='NOUses',
            reversesort=True,
            fields=[
                'NOUses', 'Password',
                'CrackLib', 'PassWDQC', 'Pwscore', 'Zxcvbn'
            ],
            start=0,
            end=40
        )
        self.printToFile(
            table_8,
            filename='outputs/' + self.__class__.__name__
        )


class PassfaultKeyboardSequence(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Pwscore': 40,
            'Zxcvbn': 3
        }))
        self.addFilter(data_filter.PCLOutputRegex({
            'Passfault': 'Keyboard'
        }))
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.applyFilter()

        table_1 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=20
        )
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )

        unfiltered_data = self.getData()

        for pcl in ['CrackLib', 'PassWDQC', 'Pwscore', 'Zxcvbn']:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()

            table = data_table.ComplexPasswordWithNumberOfUses(
                self.getData()
            ).getTable(
                start=0,
                end=100
            )
            self.printToFile(
                'PCL: ' + pcl + ' Number of passwords: ' + str(len(self.getData())),
                filename='outputs/' + self.__class__.__name__
            )
            self.printToFile(
                table,
                filename='outputs/' + self.__class__.__name__
            )


class Dictionary123Pattern(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.PasswordRegex('[a-zA-Z]+123$'))
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.applyFilter()

        # Overall summary
        table = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=30
        )
        self.printToFile(
            table,
            filename='outputs/' + self.__class__.__name__
        )

        unfiltered_data = self.getData()

        # Password longer than 8 characters
        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.PasswordLengthHigher(8))
        self.applyFilter()

        table = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=30
        )
        self.printToFile(
            table,
            filename='outputs/' + self.__class__.__name__
        )


        # Ok passwords for PCL from list
        pcl_list = ['CrackLib', 'Pwscore', 'Zxcvbn']
        for pcl in pcl_list:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()
            table_1 = data_table.ComplexPasswordWithNumberOfUses(self.getData()).getTable(
                start=0,
                end=200,
                fields=[
                    'NOUses', 'Password',
                    'CrackLib', 'PassWDQC', 'Passfault',
                    'Pwscore', 'Pwscore score', 'Zxcvbn', 'Zxcvbn score'
                ]
            )
            self.printToFile(
                'PCL: ' + pcl + ' Number of passwords: ' + str(len(self.getData())),
                filename='outputs/' + self.__class__.__name__
            )
            self.printToFile(
                table_1,
                filename='outputs/' + self.__class__.__name__
            )

        # Not Ok passwords for CrackLib
        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsNotOk(['CrackLib']))
        self.applyFilter()

        table_2 = data_table.ComplexPasswordWithNumberOfUses(self.getData()).getTable()
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
        )
