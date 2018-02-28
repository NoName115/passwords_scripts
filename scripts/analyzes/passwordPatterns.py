from scripts.analysisBase import AnalysisTemplate

import scripts.filter as data_filter
import scripts.table as data_table


class PassWDQCPasswordPattern(AnalysisTemplate):

    def runAnalysis(self):
        # Passwords contain letter, number & special char.
        # Are longer than 9 characters & have at least 7 diff. characters
        # ~60% for almost every pcl
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.PasswordContainCharacterClass([
            'lower letter', 'upper letter'
        ]))
        self.addFilter(data_filter.PasswordContainCharacterClass([
            'number'
        ]))
        self.addFilter(data_filter.PasswordContainCharacterClass([
            'special char'
        ]))
        self.addFilter(data_filter.PasswordLengthHigher(9))
        self.addFilter(data_filter.NumberOfDifferentCharactersHigher(7))
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.applyFilter()

        table_1 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=15
        )

        table_2 = data_table.ComplexPasswordWithNumberOfUses(self.getData()).getTable(
            fields=[
                'NOUses', 'Password', 'Diff. char.', 'Char. classes', 'Length',
                'PassWDQC', 'Passfault', 'Pwscore', 'ZxcvbnC', 'ZxcvbnPython'
            ],
            start=0,
            end=200
        )

        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
        )


class ZxcvbnPythonPwscore2DigitsPattern(AnalysisTemplate):

    def runAnalysis(self):
        # Passwords have pattern 2NXL2N, length > 8/9/10
        # and contain at least one letter
        # >10 length - >80% ZxcvbnPython, ~70% Pwscore
        # >9 length  - ~70% ZxcvbnPython, ~50% Pwscore
        # >8 length  - ~50% ZxcvbnPython, >30% Pwscore
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.PasswordRegex('^\d\d.*\d\d$'))
        self.addFilter(data_filter.PasswordContainCharacterClass([
            'lower letter', 'upper letter'
        ]))
        self.applyFilter()
        self.clearFilter()

        # Get unfiltered data by length
        unfiltered_data = self.getData()

        for pass_length in [10, 9, 8]:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.PasswordLengthHigher(pass_length))
            self.applyFilter()

            table_1 = data_table.OverallSummary(self.getData()).getTable(
                start=0,
                end=13,
                fields=[
                    'Pwscore accepted', 'Pwscore rejected',
                    'Pwscore reasons of rejection',
                    'ZxcvbnC accepted', 'ZxcvbnC rejected',
                    'ZxcvbnC reasons of rejection',
                    'ZxcvbnPython accepted', 'ZxcvbnPython rejected',
                    'ZxcvbnPython reasons of rejection'
                ]
            )

            table_2 = data_table.ComplexPassword(self.getData()).getTable(
                fields=[
                    'Password', 'Char. classes', 'Length',
                    'Pwscore', 'Pwscore score',
                    'ZxcvbnPython', 'ZxcvbnPython score'
                ],
                start=10,
                end=100
            )

            self.printToFile(
                "Minimum password length: " + str(pass_length),
                filename='outputs/' + self.__class__.__name__
            )
            self.printToFile(
                table_1,
                filename='outputs/' + self.__class__.__name__
            )
            self.printToFile(
                table_2,
                filename='outputs/' + self.__class__.__name__
            )


class PalindromPasswords(AnalysisTemplate):

    def runAnalysis(self):
        # Palindrom passwords recognized by Pwscore
        # ~1% accepted by ZxcvbnPython, but still it's 1%!!
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.PCLOutputRegex({
            'Pwscore': 'The password is a palindrome'
        }))
        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.applyFilter()

        unfiltered_data = self.getData()

        table_1 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=30
        )
        # Complex table
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )

        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk([
            'CrackLib', 'PassWDQC', 'Passfault',
            'Pwscore', 'ZxcvbnC', 'ZxcvbnPython'
        ]))
        #self.addFilter(data_filter.PCLOutputRegex({'ZxcvbnPython': 'OK'}))
        self.applyFilter()

        table_2 = data_table.ComplexPasswordWithNumberOfUses(self.getData()).getTable(
            fields=[
                'NOUses', 'Password', 'Diff. char.', 'Char. classes', 'Length',
                'CrackLib', 'PassWDQC',
                'Passfault', 'Passfault score',
                'Pwscore', 'Pwscore score',
                'ZxcvbnC', 'ZxcvbnC score',
                'ZxcvbnPython', 'ZxcvbnPython score'
            ]
        )
        # OK palindrom passwords table
        self.printToFile(
            'Accepted passwords (' + str(len(self.getData())) + '):\n' + table_2,
            filename='outputs/' + self.__class__.__name__
        )

        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsNotOk([
            'CrackLib', 'PassWDQC', 'Passfault',
            'Pwscore', 'ZxcvbnC', 'ZxcvbnPython'
        ]))
        self.applyFilter()

        table_3 = data_table.ComplexPasswordWithNumberOfUses(self.getData()).getTable(
            start=200,
            end=400,
            fields=[
                'NOUses', 'Password', 'Diff. char.', 'Char. classes', 'Length',
                'CrackLib', 'PassWDQC',
                'Passfault', 'Passfault score',
                'Pwscore', 'Pwscore score',
                'ZxcvbnC', 'ZxcvbnC score',
                'ZxcvbnPython', 'ZxcvbnPython score'
            ]
        )
        # N'OK palindrom passwords table
        self.printToFile(
            'Rejected passwords (' + str(len(self.getData())) + '):\n' + table_3,
            filename='outputs/' + self.__class__.__name__
        )


class DictionaryWords(AnalysisTemplate):

    def runAnalysis(self):
        # Cracklib, PassWDQC and Pwscore detect dictionary words
        # Passfault - match popular words, but in secure passwords too

        # Dictionary word only in CrackLib, PassWDQC & Pwscore
        self.printToFile(
            'CrackLib, PassWDQC or Pwscore consider passwords as dictionary words' +
            ' and ZxcvbnPython accept these passwords',
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
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['ZxcvbnPython']))
        self.applyFilter()

        table_2 = data_table.ComplexPasswordWithNumberOfUses(self.getData()).getTable(
            sortby='NOUses',
            reversesort=True,
            fields=[
                'NOUses', 'Password',
                'CrackLib', 'PassWDQC', 'Pwscore', 'ZxcvbnPython', 'ZxcvbnPython score'
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
        '''
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
                'CrackLib', 'PassWDQC', 'Pwscore', 'ZxcvbnPython'
            ],
            start=0,
            end=40
        )
        self.printToFile(
            table_4,
            filename='outputs/' + self.__class__.__name__
        )
        '''

        # Dictionary word - CrackLib & Pwscore
        # Not problem, but PassWDQC library can be improved with this analyse
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
                'CrackLib', 'PassWDQC', 'Pwscore', 'ZxcvbnPython'
            ],
            start=0,
            end=40
        )
        self.printToFile(
            table_6,
            filename='outputs/' + self.__class__.__name__
        )

        # Dictionary word - CrackLib & PassWDQC
        '''
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
                'CrackLib', 'PassWDQC', 'Pwscore', 'ZxcvbnPython'
            ],
            start=0,
            end=40
        )
        self.printToFile(
            table_8,
            filename='outputs/' + self.__class__.__name__
        )
        '''


class PassfaultKeyboardSequence(AnalysisTemplate):

    def runAnalysis(self):
        # Keyboard sequence detected by Passfault,
        # but not only 'keyboard sequence' is the reason of rejection
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Pwscore': 40,
            'ZxcvbnC': 33,
            'ZxcvbnPython': 3
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

        for pcl in ['CrackLib', 'PassWDQC', 'Pwscore', 'ZxcvbnPython']:
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
        # Passwords with pattern '[a-zA-Z]123'
        # ~25% accepted by CrackLib, ~6% ZxcvbnPython
        # with password length >=8
        # ~40% accepted by CrackLib, ~10% ZxcvbnPython
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
            end=15
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
            end=15
        )
        self.printToFile(
            table,
            filename='outputs/' + self.__class__.__name__
        )


        # Ok passwords for PCL from list
        pcl_list = ['CrackLib', 'Pwscore', 'ZxcvbnPython']
        for pcl in pcl_list:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()
            table_1 = data_table.ComplexPasswordWithNumberOfUses(self.getData()).getTable(
                start=0,
                end=100,
                fields=[
                    'NOUses', 'Password',
                    'CrackLib', 'PassWDQC', 'Passfault',
                    'Pwscore', 'Pwscore score', 'ZxcvbnPython', 'ZxcvbnPython score'
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
