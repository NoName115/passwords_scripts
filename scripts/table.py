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

    def __init__(self, data, sortby=None, reversesort=False):
        super(SimplePasswordInfo, self).__init__(
            data, sortby, reversesort
            )

    def getHeader(self):
        return ['Password', 'Entropy'] + self.pcl_list

    def setContent(self):
        for passdata in self.data:
            row = [passdata.password, passdata.entropy]
            for pcl in self.pcl_list:
                row.append(passdata.pcl_output[pcl])

            self.table.add_row(row)


class OrigAndTransPasswordInfo(TableTemplate):

    def __init__(self, data, sortby=None, reversesort=False):
        super(OrigAndTransPasswordInfo, self).__init__(
            data, sortby, reversesort
            )

    def getHeader(self):
        header = ['Original password', 'Transformed password']
        for pcl in self.pcl_list:
            header += [pcl + ' - orig.password', pcl + ' - trans.password']

        return header

    def setContent(self):
        for passdata in self.data:
            if (hasattr(passdata, 'transform_rules')):
                row = [passdata.orig_passdata.password, passdata.password]
                for pcl in self.pcl_list:
                    row.append(passdata.orig_passdata.pcl_output[pcl])
                    row.append(passdata.pcl_output[pcl])
                self.table.add_row(row)


class PasswordLength(TableTemplate):

    def __init__(self, data, sortby=None, reversesort=False):
        super(PasswordLength, self).__init__(
            data, sortby, reversesort
            )

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
