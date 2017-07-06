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

        # Table header and content
        self.setHeader()
        self.setContent()

        # Table sorting
        self.table.reversesort = reversesort
        if (sortby):
            self.table.sortby = sortby

    def getTable(self):
        return self.table if (self.table) \
            else "No data for \'" + self.__class__.__name__ + "\' table."

    def setHeader(self):
        if (self.data):
            self.table.field_names = self.getHeader()
        else:
            self.table = None
            errorPrinter.printWarning(
                self.__class__.__name__,
                'No data to be printed'
            )

    @abstractmethod
    def getHeader(self):
        pass

    @abstractmethod
    def setContent(self):
        pass


class SimplePasswordInfo(TableTemplate):

    def getHeader(self):
        return ['Password', 'Entropy'] + self.pcl_list

    def setContent(self):
        for passdata in self.data:
            row = [passdata.password, passdata.entropy]
            for pcl in self.pcl_list:
                row.append(passdata.pcl_output[pcl])

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
                    row.append(passdata.orig_pass.pcl_output[pcl])
                    row.append(passdata.pcl_output[pcl])
                self.table.add_row(row)


class PasswordLength(TableTemplate):

    def getHeader(self):
        return ['Length', 'Number', '[%]']

    def setContent(self):
        length_dic = {}
        for passdata in self.data:
            length = len(passdata.password)
            if (not length in length_dic):
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
            'Password', 'Transformation', 'Initial entropy', 'Actual entropy'
            ] + self.pcl_list

    def setContent(self):
        for passdata in self.data:
            if (hasattr(passdata, 'transform_rules')):
                row = [
                    passdata.password, passdata.getAppliedTransformation(),
                    passdata.getInitialEntropy(), passdata.entropy
                ]
                for pcl in self.pcl_list:
                    row.append(passdata.pcl_output[pcl])

                self.table.add_row(row)


class SummaryInfo(TableTemplate):

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
            countOkPass = 0
            countNotOkPass = 0
            for passdata in self.data:
                reason = passdata.pcl_output[pcl]
                if (reason != "OK"):
                    countNotOkPass += 1
                else:
                    countOkPass += 1
                if (not reason in rejection_dic):
                    rejection_dic.update({ reason : 1 })
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
                str(countOkPass) + ' (' +
                    str(round(countOkPass / len(self.data) * 100, 2)) + ')%',
                str(countNotOkPass) + ' (' +
                    str(round(countNotOkPass / len(self.data) * 100, 2)) + ')%',
                reasons_of_rejection
            ]

        self.table.add_row(row)


class PasswordsWithPCLOutputs(TableTemplate):

    def getHeader(self):
        return ['Password', 'PCL list', 'PCL outputs']

    def setContent(self):
        for passdata in self.data:
            row = [
                passdata.password,
                '  '.join(pcl for pcl in self.pcl_list),
                '  |  '.join(passdata.pcl_output[pcl] for pcl in self.pcl_list)
                ]

            self.table.add_row(row)
