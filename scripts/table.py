from abc import ABCMeta, abstractmethod
from prettytable import PrettyTable

import scripts.errorPrinter as errorPrinter


class TableTemplate():

    __metaclass__ = ABCMeta

    def __init__(self, data, sortby=None, reversesort=False):
        self.table = PrettyTable()
        self.data = data
        self.pcl_list = sorted(list(self.data[0].pcl_output.keys())) \
            if (self.data) else []

        # Table header
        self.setHeader()

        # Table content
        if (self.table):
            self.setContent()

            # Table sorting
            self.table.reversesort = reversesort
            if (sortby):
                try:
                    self.table.sortby = sortby
                except Exception:
                    errorPrinter.printWarning(
                        self.__class__.__name__,
                        "Can\'t sort table, column \'" + sortby +
                        "\' does not exist"
                    )
        else:
            errorPrinter.printWarning(
                self.__class__.__name__,
                'No data to be printed into table'
            )

    def getTable(self):
        return self.table if (self.table) \
            else "No data for \'" + self.__class__.__name__ + "\' table."

    def setHeader(self):
        if (self.data):
            self.table.field_names = self.getHeader()
        else:
            self.table = None

    @abstractmethod
    def getHeader(self):
        pass

    @abstractmethod
    def setContent(self):
        pass


class SimplePasswordInfo(TableTemplate):

    def getHeader(self):
        return ['Password', 'Entropy change'] + self.pcl_list

    def setContent(self):
        for passdata in self.data:
            row = [passdata.password, passdata.getEntropyChange()]
            for pcl in self.pcl_list:
                row.append(passdata.getPCLOutput(pcl))

            self.table.add_row(row)


class PasswordPCLOutputAndScore(TableTemplate):

    def getHeader(self):
        header = ['Password']

        for pcl in self.pcl_list:
            header.append(pcl)
            if (self.data[0].getPCLScore(pcl) is not None):
                header.append(pcl + ' - score')

        return header

    def setContent(self):
        for passdata in self.data:
            row = [passdata.password]
            for pcl in self.pcl_list:
                row.append(passdata.getPCLOutput(pcl))
                pcl_score = passdata.getPCLScore(pcl)
                if (pcl_score is not None):
                    row.append(pcl_score)

            self.table.add_row(row)


class OrigAndTransPasswordInfo(TableTemplate):

    def getHeader(self):
        header = ['Original password', 'Transformed password']
        for pcl in self.pcl_list:
            header += [pcl + ' - orig.password', pcl + ' - trans.password']

        return header

    def setContent(self):
        for passdata in self.data:
            if (hasattr(passdata, 'transform_rules')):
                row = [passdata.orig_pass.password, passdata.password]
                for pcl in self.pcl_list:
                    row.append(passdata.orig_pass.getPCLOutput(pcl))
                    row.append(passdata.getPCLOutput(pcl))
                self.table.add_row(row)


class PasswordLength(TableTemplate):

    def getHeader(self):
        return ['Length', 'Number', '[%]']

    def setContent(self):
        length_dic = {}
        for passdata in self.data:
            length = len(passdata.password)
            if (length not in length_dic):
                length_dic.update({length: 1})
            else:
                length_dic[length] += 1

        for length, count in length_dic.items():
            self.table.add_row([
                length, count, round(count / len(self.data) * 100, 2)
            ])


class TransformedPasswordInfo(TableTemplate):

    def getHeader(self):
        return [
            'Password', 'Transformation', 'Entropy change'
            ] + self.pcl_list

    def setContent(self):
        for passdata in self.data:
            if (hasattr(passdata, 'transform_rules')):
                row = [
                    passdata.password, passdata.getAppliedTransformation(),
                    passdata.getEntropyChange()
                ]
                for pcl in self.pcl_list:
                    row.append(passdata.getPCLOutput(pcl))

                self.table.add_row(row)


class OverallSummary(TableTemplate):

    def getHeader(self):
        header = []
        for pcl in self.pcl_list:
            header += [
                pcl + ' accepted', pcl + ' rejected',
                pcl + ' reasons of rejection'
                ]

        return header

    def setContent(self):
        row = []
        for pcl in self.pcl_list:
            rejection_dic = {}
            count_ok_pass = 0
            count_not_ok_pass = 0
            for passdata in self.data:
                reason = passdata.getPCLOutput(pcl)
                if (reason != "OK"):
                    count_not_ok_pass += 1
                else:
                    count_ok_pass += 1
                if (reason not in rejection_dic):
                    rejection_dic.update({reason: 1})
                else:
                    rejection_dic[reason] += 1

            # Calculate % for every reason of rejection
            sorted_rejection_dic = sorted(
                rejection_dic.items(),
                key=lambda value: value[1],
                reverse=True
                )
            reasons_of_rejection = '\n'.join(
                reason_value[0] + " - " +
                str(round(reason_value[1] / len(self.data) * 100, 2)) + '%'
                for reason_value in sorted_rejection_dic
            )

            row += [
                str(count_ok_pass) + ' (' +
                    str(round(count_ok_pass / len(self.data) * 100, 2)) + '%)',
                str(count_not_ok_pass) + ' (' +
                    str(round(count_not_ok_pass / len(self.data) * 100, 2)) + '%)',
                reasons_of_rejection
            ]

        self.table.add_row(row)


class PasswordWithPCLOutputs(TableTemplate):

    def getHeader(self):
        return ['Password', 'PCL list', 'PCL outputs']

    def setContent(self):
        for passdata in self.data:
            row = [
                passdata.password,
                '  '.join(pcl for pcl in self.pcl_list),
                ' | '.join(passdata.getPCLOutput(pcl) for pcl in self.pcl_list)
                ]

            self.table.add_row(row)


class ScoreTable(TableTemplate):

    def getHeader(self):
        return ['Password'] + self.pcl_list

    def setContent(self):
        for passdata in self.data:
            row = [passdata.password]
            for pcl in self.pcl_list:
                row.append(passdata.getPCLScore(pcl))

            self.table.add_row(row)


class SummaryScoreTableInfo(TableTemplate):

    def getHeader(self):
        header = []
        for pcl in self.pcl_list:
            header += [pcl + ' score']

        return header

    def setContent(self):
        row = []
        for pcl in self.pcl_list:
            score_dic = {}
            for passdata in self.data:
                pcl_score = passdata.getPCLScore(pcl)
                if (pcl_score not in score_dic):
                    score_dic.update({pcl_score: 1})
                else:
                    score_dic[pcl_score] += 1

            # Calculate % for every score
            sorted_score_dic = sorted(
                score_dic.items(),
                key=lambda value: value[1],
                reverse=True
                )
            scores = '\n'.join(
                str(score_value[0]) + " - " + str(score_value[1]) + " (" +
                str(round(score_value[1] / len(self.data) * 100, 2)) + ')%'
                for score_value in sorted_score_dic
            )

            # Calculate average score
            average = round(sum(
                scr * cnt if (scr) else cnt for scr, cnt in sorted_score_dic
                ) / sum(cnt for _, cnt in sorted_score_dic), 2)

            row.append(str(average) + " - average score\n\n" + scores)

        self.table.add_row(row)
