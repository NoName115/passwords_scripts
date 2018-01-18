from scripts.analysisBase import AnalysisTemplate

import scripts.filter as data_filter
import scripts.table as data_table


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


class LibrariesSummary(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.applyFilter()

        table_1 = data_table.OverallSummary(self.getData()).getTable(
            #start=0,
            #end=30
        )
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )


class LibrariesTopOkPasswords(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.applyFilter()
        unfiltered_data = self.getData()

        folder_path = 'outputs/' + self.__class__.__name__
        self.createFolder(folder_path)
        folder_path += "/"

        for pcl in ['CrackLib', 'PassWDQC', 'Passfault', 'Pwscore', 'Zxcvbn']:
            self.clearFilter()
            self.setData(unfiltered_data)
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()
            self.printToFile(
                'PCL: ' + pcl,
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )
            self.printToFile(
                data_table.ComplexPasswordWithNumberOfUses(self.getData()).getTable(
                    #start=0,
                    #end=200,
                    #fields=['NOUses', 'Password'] + [pcl, pcl + ' score']
                ),
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )
            self.printToFile(
                data_table.OverallSummary(self.getData()).getTable(
                    start=0,
                    end=20,
                ),
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )


class AllRejectedOneAccepted(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.applyFilter()
        unfiltered_data = self.getData()

        folder_path = 'outputs/' + self.__class__.__name__
        self.createFolder(folder_path)
        folder_path += "/"

        for pcl in ['CrackLib', 'PassWDQC', 'Passfault', 'Pwscore', 'Zxcvbn']:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.AllRejectedOneAccepted(pcl))
            self.applyFilter()

            table = data_table.ComplexPasswordWithNumberOfUses(
                self.getData()
            ).getTable(
                #start=0,
                #end=200
            )
            self.printToFile(
                'PCL: ' + pcl +
                    '. Number of passwords: ' + str(len(self.getData())),
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )
            self.printToFile(
                table,
                filename=folder_path + pcl + "_" + self.__class__.__name__
                )


class AllAccepted(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])
        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        for pcl in ['CrackLib', 'PassWDQC', 'Passfault', 'Pwscore', 'Zxcvbn']:
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))

        self.applyFilter()

        table = data_table.ComplexPasswordWithNumberOfUses(
            self.getData()
        ).getTable(
            #start=0,
            #end=500,
        )
        self.printToFile(
            "Number of password: " + str(len(self.getData())),
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(
            table,
            filename='outputs/' + self.__class__.__name__
        )


class LibrariesCrackLibTopRejection(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.PCLOutputRegex({
            'CrackLib': 'dictionary word'
        }))
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
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

        pcl_list = ['PassWDQC', 'Passfault', 'Pwscore', 'Zxcvbn']
        for pcl in pcl_list:
            self.clearFilter()
            self.setData(unfiltered_data)
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()
            table_2 = data_table.ComplexPasswordWithNumberOfUses(
                self.getData()
            ).getTable(
                start=0,
                end=200,
            )
            self.printToFile(
                "PCL: " + pcl +
                "\nNumber of passwords: " + str(len(self.getData())),
                filename="outputs/" + self.__class__.__name__
            )
            self.printToFile(
                table_2,
                filename='outputs/' + self.__class__.__name__
            )
        
        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(pcl_list))
        self.applyFilter()
        table_3 = data_table.ComplexPasswordWithNumberOfUses(
            self.getData()
        ).getTable(
            start=0,
            end=200
        )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
        )


class LibrariesPassWDQCTopRejection(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.addFilter(data_filter.PCLOutputRegex({
            'PassWDQC': 'not enough different characters or classes'
        }))
        self.applyFilter()

        unfiltered_data = self.getData()

        table = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=30,
        )
        self.printToFile(
            table,
            filename='outputs/' + self.__class__.__name__
        )

        pcl_list = ['CrackLib', 'Passfault', 'Pwscore', 'Zxcvbn']
        for pcl in pcl_list:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()

            table_2 = data_table.ComplexPasswordWithNumberOfUses(
                self.getData()
            ).getTable(
                start=0,
                end=200,
            )
            self.printToFile(
                "PCL: " + pcl +
                    "\nNumber of passwords: " + str(len(self.getData())),
                filename="outputs/" + self.__class__.__name__
            )
            self.printToFile(
                table_2,
                filename='outputs/' + self.__class__.__name__
            )

        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(pcl_list))
        self.applyFilter()
        table_3 = data_table.ComplexPasswordWithNumberOfUses(
            self.getData()
        ).getTable(
            start=0,
            end=200
        )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
        )


class LibrariesPassfaulTopRejection(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.addFilter(data_filter.PCLOutputRegex({
            'Passfault': 'worst-passwords'
        }))
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

        pcl_list = ['CrackLib', 'PassWDQC', 'Pwscore', 'Zxcvbn']
        for pcl in pcl_list:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()
            table_2 = data_table.ComplexPasswordWithNumberOfUses(
                self.getData()
            ).getTable(
                start=0,
                end=200,
            )
            self.printToFile(
                "PCL: " + pcl +
                    "\nNumber of passwords: " + str(len(self.getData())),
                filename="outputs/" + self.__class__.__name__
            )
            self.printToFile(
                table_2,
                filename="outputs/" + self.__class__.__name__
            )

        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(pcl_list))
        self.applyFilter()
        table_3 = data_table.ComplexPasswordWithNumberOfUses(
            self.getData()
        ).getTable(
            start=0,
            end=200
        )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
        )


class LibrariesPwscoreTopRejection(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.addFilter(data_filter.PCLOutputRegex({
            'Pwscore': 'shorter than 8'
        }))
        self.applyFilter()

        unfiltered_data = self.getData()

        table = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=30,
        )
        self.printToFile(
            table,
            filename='outputs/' + self.__class__.__name__
        )

        pcl_list = ['CrackLib', 'PassWDQC', 'Passfault', 'Zxcvbn']
        for pcl in pcl_list:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()
            table_1 = data_table.ComplexPasswordWithNumberOfUses(
                self.getData()
            ).getTable(
                start=0,
                end=200
            )
            self.printToFile(
                "PCL: " + pcl +
                "\nNumber of passwords: " + str(len(self.getData())),
                filename="outputs/" + self.__class__.__name__
            )
            self.printToFile(
                table_1,
                filename="outputs/" + self.__class__.__name__
            )

        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(pcl_list))
        self.applyFilter()
        table_3 = data_table.ComplexPasswordWithNumberOfUses(
            self.getData()
        ).getTable(
            start=0,
            end=200
        )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
        )


class LibrariesZxcvbnTopRejection(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.addFilter(data_filter.PCLOutputRegex({
            'Zxcvbn': 'top.*100.*password'
        }))
        self.applyFilter()

        unfiltered_data = self.getData()

        table = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=30
        )
        self.printToFile(
            table,
            filename='outputs/' + self.__class__.__name__
        )

        pcl_list = ['CrackLib', 'PassWDQC', 'Passfault', 'Pwscore']
        for pcl in pcl_list:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()
            table_1 = data_table.ComplexPasswordWithNumberOfUses(
                self.getData()
            ).getTable(
                start=0,
                end=200
            )
            self.printToFile(
                "PCL: " + pcl +
                "\nNumber of passwords: " + str(len(self.getData())),
                filename="outputs/" + self.__class__.__name__
            )
            self.printToFile(
                table_1,
                filename="outputs/" + self.__class__.__name__
            )

        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(pcl_list))
        self.applyFilter()
        table_3 = data_table.ComplexPasswordWithNumberOfUses(
            self.getData()
        ).getTable(
            start=0,
            end=200
        )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
        )


class AllAcceptedOneRejected(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['trans_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        '''
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        '''
        self.applyFilter()

        unfiltered_data = self.getData()

        folder_path = "outputs/" + self.__class__.__name__
        self.createFolder(folder_path)
        folder_path += "/"

        pcl_list = ['CrackLib', 'PassWDQC', 'Passfault', 'Pwscore', 'Zxcvbn']
        for pcl in pcl_list:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.OriginalPCLOutputIsNotOk([pcl]))
            for pcl_2 in pcl_list:
                if (pcl != pcl_2):
                    self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl_2]))

            self.applyFilter()
            table = data_table.ComplexTransformedPassword(
                self.getData()
            ).getTable(
                #start=0,
                #end=200
            )
            self.printToFile(
                'PCL: ' + pcl +
                    '. Number of passwords: ' + str(len(self.getData())),
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )
            self.printToFile(
                table,
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )


class LibrariesSummaryTransformedPass(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['trans_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.applyFilter()

        unfiltered_data = self.getData()

        folder_path = "outputs/" + self.__class__.__name__
        self.createFolder(folder_path)
        folder_path += "/"

        table_1 = data_table.OverallSummary(self.getData()).getTable()
        self.printToFile(
            table_1,
            filename=folder_path + "summary_" + self.__class__.__name__
        )

        pcl_list = ['CrackLib', 'PassWDQC', 'Passfault', 'Zxcvbn']
        for pcl in pcl_list:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.TransformedPCLOutputIsNotOk([pcl]))
            self.applyFilter()
            table_2 = data_table.ComplexPassword(
                self.getData()
            ).getTable(
                #start=0,
                #end=200,
            )
            self.printToFile(
                'PCL: ' + pcl +
                    '. Number of passwords: ' + str(len(self.getData())),
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )
            self.printToFile(
                table_2,
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )

class TestAnalysis(AnalysisTemplate):

    def runAnalysis(self):
        pass
