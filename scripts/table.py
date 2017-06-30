from abc import ABCMeta, abstractmethod
from prettytable import PrettyTable


class TableTemplate():

    __metaclass__ = ABCMeta

    def __init__(self, data):
        self.table = PrettyTable()
        self.data = data
        self.setHeader()
        self.setContent()

    def getTable(self):
        return self.table

    @abstractmethod
    def setHeader(self):
        pass

    @abstractmethod
    def setContent(self):
        pass


class SimpleTable(TableTemplate):

    def __init__(self, data):
        super(SimpleTable, self).__init__(data)

    def setHeader(self):
        self.table.field_names = ['Password'] + \
            list(self.data[0].pcl_output.keys())

    def setContent(self):
        for passdata in self.data:
            row = [passdata.password]
            for name in self.table.field_names[1:]:
                row.append(passdata.pcl_output[name])

            self.table.add_row(row)
