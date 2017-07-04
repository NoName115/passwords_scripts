from abc import ABCMeta, abstractmethod
from prettytable import PrettyTable

import scripts.errorPrinter as errorPrinter


class TableTemplate():

    __metaclass__ = ABCMeta

    def __init__(self, data):
        self.table = PrettyTable()
        self.data = data
        self.setHeader()
        self.setContent()

    def getTable(self):
        return self.table if (self.table) \
            else "No data for \'" + self.__class__.__name__ + "\' table."

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
        if (self.data):
            self.table.field_names = ['Password', 'Entropy'] + \
                list(self.data[0].pcl_output.keys())
        else:
            self.table = None
            errorPrinter.printWarning(
                self.__class__.__name__,
                'No data to be printed'
                )

    def setContent(self):
        for passdata in self.data:
            row = [passdata.password, passdata.entropy]
            for name in self.table.field_names[2:]:
                row.append(passdata.pcl_output[name])

            self.table.add_row(row)


class OrigAndTransPasswordInfo(TableTemplate):

    def __init__(self, data):
        super(OrigAndTransPasswordInfo, self).__init__(data)

    def setHeader(self):
        if (self.data):
            self.table.field_names = [
                'Original password', 'Transformed password'
                ]
            for pcl in self.data[0].pcl_output.keys():
                self.table.field_names.append([
                    pcl + " orig. password", pcl + " trans. password"
                ])
        else:
            self.table = None
            errorPrinter.printWarning(
                self.__class__.__name__,
                'No data to be printed'
                )

    def setContent(self):
        for passdata in self.data:
            pass
            # TODO
            # Nemozes dat informaciu do spravneho stlpca lebo meno
            # je PCL + 'daco'
            # Mozno pridat zoznam KEYS niekde do analyzy kde z toho bude
            # zoznam ktory sa zoradi podla abecedy aby to bolo vsade rovnako
