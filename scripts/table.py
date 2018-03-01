from abc import ABCMeta, abstractmethod
from prettytable import PrettyTable

import scripts.errorPrinter as errorPrinter


class TableTemplate():

    __metaclass__ = ABCMeta

    def __init__(self, data):
        # Initialize table & data
        self.table = PrettyTable()
        self.data = data
        self.pcl_list = sorted(list(self.data[0].pcl_output.keys())) \
            if (self.data) else []

        if (self.data):
            # Set table header & content
            self.table.field_names = self.getHeader()
            self.setContent()

    def getTable(
        self, sortby=None, reversesort=False,
        start=None, end=None, fields=[]
        ):
        try:
            # Check data
            if (not self.data):
                raise Exception(
                    "No data to be printed into table"
                )

            # Check start & end index
            if (type(start) == type(end)):
                if (start is None):
                    return self.table.get_string(
                        sortby=sortby,
                        reversesort=reversesort,
                        fields=fields
                    )
                elif (start >= 0 and end >= 0):
                    return self.table.get_string(
                        sortby=sortby,
                        reversesort=reversesort,
                        start=start,
                        end=end,
                        fields=fields
                    )
                else:
                    raise Exception(
                        "Argument 'start' or 'end' is lower than 0"
                    )
            else:
                raise Exception(
                    "Arguments 'start' & 'end' have different datatypes"
                    )
        except Exception as error:
            errorPrinter.printWarning(
                self.__class__.__name__,
                str(error)
            )
            return "No data for \'" + self.__class__.__name__ + "\' table."

    def getTableObject(self):
        return self.table

    @abstractmethod
    def getHeader(self):
        pass

    @abstractmethod
    def setContent(self):
        pass


class ComplexPassword(TableTemplate):

    def getHeader(self):
        header = ['Password', 'Diff. char.', 'Char. classes', 'Length']
        for pcl in self.pcl_list:
            header += [pcl, pcl + ' score']

        return header

    def setContent(self):
        for passdata in self.data:
            row = [
                passdata.password,
                passdata.diff_char,
                ', '.join(passdata.char_classes),
                len(passdata.password)
            ]
            for pcl in self.pcl_list:
                row += [
                    passdata.getPCLOutput(pcl),
                    passdata.getPCLScore(pcl)
                ]

            self.table.add_row(row)


class ComplexTransformedPassword(TableTemplate):

    def getHeader(self):
        header = [
            'Original password', 'O. length',
            'Transformed password', 'T. length',
            'Entropy change', 'Transformation',
            'Diff. char.', 'Char. classes'
            ]
        for pcl in self.pcl_list:
            header += [
                pcl + ' Orig. pass.', pcl + ' O. score',
                pcl + ' Trans. pass.', pcl + ' T. score'
            ]

        return header

    def setContent(self):
        for passdata in self.data:
            if (not hasattr(passdata, 'orig_pass')):
                continue

            row = [
                passdata.orig_pass.password, len(passdata.orig_pass.password),
                passdata.password, len(passdata.password),
                passdata.getEntropyChange(),
                passdata.getAppliedTransformation(),
                passdata.diff_char, ', '.join(passdata.char_classes)
            ]
            for pcl in self.pcl_list:
                row += [
                    passdata.orig_pass.getPCLOutput(pcl),
                    passdata.orig_pass.getPCLScore(pcl),
                    passdata.getPCLOutput(pcl),
                    passdata.getPCLScore(pcl)
                ]

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
        pcl_rows = []
        first_row = []

        # Calculate and sort data
        for pcl, index in zip(self.pcl_list, range(0, len(self.pcl_list))):
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

            pcl_rows.append([
                reason_value[0] + " - " +
                str(round(reason_value[1] / len(self.data) * 100, 2)) + '%'
                for reason_value in sorted_rejection_dic
                ])

            # Add data to first row
            first_row += [
                str(count_ok_pass) + ' (' +
                    str(round(count_ok_pass / len(self.data) * 100, 2)) + '%)',
                str(count_not_ok_pass) + ' (' +
                    str(round(count_not_ok_pass / len(self.data) * 100, 2)) + '%)',
                pcl_rows[index][0]
            ]

        # Write first row
        self.table.add_row(first_row)

        # Add data to table
        for i in range(1, max(len(row) for row in pcl_rows)):
            row = []
            for pcl_row in pcl_rows:
                # 2 blank columns for 'pcl_accepted' and 'pcl_rejected' column
                row += ['', '']
                row.append(pcl_row[i] if (i < len(pcl_row)) else '')

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


class SummaryScore(TableTemplate):

    def getHeader(self):
        header = []
        for pcl in self.pcl_list:
            header += [pcl + ' score']

        return header

    def setContent(self):
        pcl_rows = []
        first_row = []  # average row
        second_row = [] # min/max row

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

            pcl_rows.append([
                str(score_value[0]) + " - " + str(score_value[1]) + " (" +
                str(round(score_value[1] / len(self.data) * 100, 2)) + ')%'
                for score_value in sorted_score_dic
            ])

            # Calculate average score
            average = round(sum(
                scr * cnt if (scr) else cnt for scr, cnt in sorted_score_dic
                ) / sum(cnt for _, cnt in sorted_score_dic), 2)

            first_row.append(str(average) + " - average score")
            second_row.append(
                'min score - ' + str(min(score_dic.keys())) +
                '\nmax score - ' + str(max(score_dic.keys())) + '\n'
            )

        # Write data to table
        self.table.add_row(first_row)
        self.table.add_row(second_row)

        for i in range(0, max(len(row) for row in pcl_rows)):
            row = []
            for pcl_row in pcl_rows:
                row.append(pcl_row[i] if (i < len(pcl_row)) else '')

            self.table.add_row(row)


class DiffChar(TableTemplate):
    
    def getHeader(self):
        header = ['Diff. char.', 'Total num. of pass.']
        for pcl in self.pcl_list:
            header += [pcl + ' OK', pcl + ' Diff. char. / All']

        return header

    def setContent(self):
        complet_dict = {}

        for passdata in self.data:
            for pcl in self.pcl_list:
                if (passdata.diff_char not in complet_dict):
                    complet_dict.update({passdata.diff_char: {}})

                if (pcl not in complet_dict[passdata.diff_char]):
                    complet_dict[passdata.diff_char].update({pcl: [0, 0]})

                if (passdata.getPCLOutput(pcl) == "OK"):
                    complet_dict[passdata.diff_char][pcl][0] += 1
                else:
                    complet_dict[passdata.diff_char][pcl][1] += 1

        for diff_char, pcl_dict in complet_dict.items():
            row = [diff_char, sum(list(pcl_dict.values())[0])]
            for pcl in self.pcl_list:
                row.append(pcl_dict[pcl][0])
                row.append(
                    str(
                        round(pcl_dict[pcl][0] / sum(pcl_dict[pcl]) * 100, 2)
                        ) + '%  /  ' +
                    str(
                        round(pcl_dict[pcl][0] / len(self.data) * 100, 2)
                        ) + '%'
                )

            self.table.add_row(row)


class PasswordLength(TableTemplate):

    def getHeader(self):
        header = ['Length', 'Total num. of pass.', '[%]']
        for pcl in self.pcl_list:
            header += [pcl + ' OK', pcl + ' Length / All']

        return header

    def setContent(self):
        complet_dict = {}

        for passdata in self.data:
            for pcl in self.pcl_list:
                if (len(passdata.password) not in complet_dict):
                    complet_dict.update({len(passdata.password): {}})
                
                if (pcl not in complet_dict[len(passdata.password)]):
                    complet_dict[len(passdata.password)].update({pcl: [0, 0]})
                
                if (passdata.getPCLOutput(pcl) == "OK"):
                    complet_dict[len(passdata.password)][pcl][0] += 1
                else:
                    complet_dict[len(passdata.password)][pcl][1] += 1

        for length, pcl_dict in complet_dict.items():
            number_of_pass = sum(list(pcl_dict.values())[0])
            row = [
                length,
                number_of_pass,
                str(round(number_of_pass / len(self.data) * 100, 2))
                ]
            for pcl in self.pcl_list:
                row += [
                    pcl_dict[pcl][0],
                    str(
                        round(pcl_dict[pcl][0] / sum(pcl_dict[pcl]) * 100, 2)
                        ) + '%  /  ' +
                    str(
                        round(pcl_dict[pcl][0] / len(self.data) * 100, 2)
                        ) + '%'
                ]
            self.table.add_row(row)


class ComplexPasswordWithNumberOfUses(TableTemplate):

    def getHeader(self):
        header = ['NOUses', 'Password', 'Diff. char.', 'Char. classes', 'Length']
        for pcl in self.pcl_list:
            header += [pcl, pcl + ' score']

        return header

    def setContent(self):
        for passdata in self.data:
            row = [
                passdata.numberOfUses,
                passdata.password,
                passdata.diff_char,
                ', '.join(passdata.char_classes),
                len(passdata.password)
            ]
            for pcl in self.pcl_list:
                row += [
                    passdata.getPCLOutput(pcl),
                    passdata.getPCLScore(pcl)
                ]

            self.table.add_row(row)
