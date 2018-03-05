from scripts.analysisBase import AnalysisTemplate

import scripts.filter as data_filter
import scripts.table as data_table
import math


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
                'ZxcvbnPython', 'ZxcvbnPython score',
                'Passfault', 'Passfault score',
            ],
            start=500,
            end=600
        )
        table_2 = data_table.SummaryScore(self.getData()).getTable(
            fields=[
                'Passfault score', 'Pwscore score', 'ZxcvbnPython score'
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


class PassfaultOneMatch(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.PCLOutputDoesNotContainString({
            'Passfault': ','
        }))
        self.addFilter(data_filter.PCLOutputRegex({
            'Passfault': 'Match'
        }))
        self.addFilter(data_filter.ChangePCLOutputByScore({
            'Pwscore': 40,
            'ZxcvbnPython': 3
        }))
        self.applyFilter()

        table_1 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=30
        )
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )

        table_2 = data_table.ComplexPassword(self.getData()).getTable(
            sortby='ZxcvbnPython score',
            reversesort=True
        )
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
        )


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
            'ZxcvbnPython': 3
        }))
        self.applyFilter()

        table_1 = data_table.OverallSummary(self.getData()).getTable()
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )

        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(['CrackLib']))
        self.applyFilter()

        table_2 = data_table.ComplexPassword(self.getData()).getTable()
        self.printToFile(
            table_2,
            filename='outputs/' + self.__class__.__name__
        )


class TestAnalysis(AnalysisTemplate):

    def runAnalysis(self):
        pass
