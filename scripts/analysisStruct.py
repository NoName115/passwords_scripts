from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassData
from prettytable import PrettyTable

import scripts.errorPrinter as errorPrinter
import scripts.filter as data_filter
import scripts.table as data_table
import datetime
import copy

'''
class PassDataGroup():

    def __init__(self):
        """Initialize class for group of passwords
        This group is used for analysis

        Self:
        group_dic -- key is name of pcl, value is list of class Password
        """
        self.group_dic = {}

    def addPassData(self, pcl, passdata):
        """Method add passdata into list by pcl

        Arguments:
        pcl -- string, name of password checking library
        passdata -- class PassData from passStruct.py
        """
        if (pcl not in self.group_dic):
            self.group_dic.update({pcl: []})

        if (passdata is not None):
            self.group_dic[pcl].append(passdata)

    def getPassDataAttribute(self, pcl, attribute):
        """Method return attribute of PassData as String

        Arguments:
        pcl -- string, name of password checking library
        attribute -- string, attribute of class Password
                     every attribute is callable 'getAttributeName'
        """
        return_info = self.group_dic[pcl][0].__getattribute__(attribute)()
        return (
            return_info[pcl] if (type(return_info) is dict) else return_info
        )

    def getDataInTable(self, pcl, header, attributes):
        """Method create and fill 'table' with PassData data from group_dic

        Arguments:
        pcl -- string, name of password checking library
        header -- list, header of every column
        attributes -- list, attributes that are extracted from PassData class
        """
        table = PrettyTable(header)
        for passdata in self.group_dic[pcl]:
            data_list = []
            # Iterate every attribute and get correct data from passdata
            for attr in attributes:
                attrdata = passdata.__getattribute__(attr)()
                if (type(attrdata) is dict):
                    attrdata = attrdata[pcl]
                data_list.append(attrdata)

            table.add_row(data_list)

        return table

    def intersection(self, other):
        """Intersection of two PassDataGroup classes

        Arguments:
        other -- class PassDataGroup

        Return value:
        intersection_group -- return new PassDataGroup class
        """
        intersection_group = PassDataGroup()
        for pcl in self.group_dic:
            for passdata in self.group_dic[pcl]:
                if (passdata in other.group_dic[pcl]):
                    intersection_group.addPassData(pcl, passdata)

        return intersection_group

    def union(self, other):
        """Union of two PassDataGroup classes

        Arguments:
        other -- class PassDataGroup

        Return value:
        union_group -- return new PassDataGroup class
        """
        union_group = copy.copy(self)
        for pcl in self.group_dic:
            if (pcl in other.group_dic):
                for passdata in other.group_dic[pcl]:
                    if (not (passdata in union_group.group_dic[pcl])):
                        union_group.addPassData(pcl, passdata)

        return union_group

    # DEBUG
    def printData(self):
        print(self.group_dic)
'''


class Analyzer():

    def __init__(self, passinfo_list, pcl_dic):
        """Initialize 5 default analysis groups

        Arguments:
        passinfo_list -- list of Password classes
        pcl_dic -- dictionary of password checking libraries output

        Self:
        default_analysis -- dictionary of 5 default analysis groups
        allPasswords -- contain every password
        origPass_Ok -- contain passwords which originalPassword
                               pass through pcl
        origPass_NotOk -- contain passwords which originalPassword
                                  did not pass through pcl
        transPass_Ok -- contain passwords which transformedPassword
                                  pass through pcl
        transPass_NotOk -- contain passwords which
                                     transformedPassword
                                     did not pass through pcl
        password_data -- class PassData (input data)
        analysis_dic -- dictionary of analyzes
                       key is name of function in AnalyzerPrinter class
        """
        self.analysis_list = []
        self.default_analysis = {
            'all_passwords': [],
            'orig_passwords': [],
            'trans_passwords': []
        }
        self.fillDefaultAnalysisGroups(passinfo_list, pcl_dic)

    def fillDefaultAnalysisGroups(self, passinfo_list, pcl_dic):
        """Method concatenate passinfo_list with pcl_dic
        and create list of PassData class.
        And fill 5 default analysis groups with data

        Arguments:
        passinfo_list -- list of Password classes
        pcl_dic -- dictionary of password checking libraries output
        """
        # Create passdata_list
        passdata_list = []
        orig_passdata = None
        for passinfo in passinfo_list:
            if (hasattr(passinfo, 'transform_rules')):
                passdata_list.append(PassData(
                    passinfo=passinfo,
                    pcl_output=pcl_dic[passinfo.password],
                    orig_passdata=orig_passdata
                ))
            else:
                orig_passdata = PassData(
                    passinfo=passinfo,
                    pcl_output=pcl_dic[passinfo.password]
                )
                passdata_list.append(orig_passdata)

        # Fill default analysis group with data
        for passdata in passdata_list:
            self.default_analysis['all_passwords'].append(passdata)
            if (hasattr(passdata, 'transform_rules')):
                self.default_analysis['trans_passwords'].append(passdata)
            else:
                self.default_analysis['orig_passwords'].append(passdata)

    def addAnalysis(self, analysis):
        """Method add inputAnalysis to analysis_list
        """
        self.analysis_list.append(analysis)

    def runAnalyzes(self):
        """Run every analysis in analysis_list
        """
        # Create outputfile name by current datetime
        now = datetime.datetime.now()
        time = now.strftime("%Y-%m-%d_%H:%M:%S")
        self.filename = "outputs/analysis_" + time + ".output"

        for analysis in self.analysis_list:
            analysis.analyzer = self
            analysis.runAnalysis()

    def printToFile(self, text):
        """Print input text to file
        """
        output_file = open(self.filename, 'a')
        output_file.write(text + '\n\n')
        output_file.close()


class AnalysisTemplate():

    __metaclass__ = ABCMeta

    def __init__(self, analyzer=None):
        """Template for new analysis

        Arguments:
        analyzer -- class Analyzer
        """
        self.analyzer = analyzer
        self.data = None
        self.keys = None
        self.filters = []

    def addFilter(self, data_filter):
        self.filters.append(data_filter)

    def cleanFilter(self):
        self.filters = []

    def applyFilter(self):
        for data_filter in self.filters:
            self.data = data_filter.apply_check(self.data)

    def setData(self, data):
        self.data = data
        self.keys = self.data[0].pcl_output.keys()

    def getData(self):
        return self.data

    def getPCLs(self):
        return self.keys

    def printToFile(self, text):
        self.analyzer.printToFile(str(text))

    @abstractmethod
    def runAnalysis(self):
        pass

    @abstractmethod
    def getAnalysisDescription(self):
        """Short analysis description
        """
        pass


class TestNewAnalysis(AnalysisTemplate):

    def runAnalysis(self):
        # Load data
        self.setData(self.analyzer.default_analysis['trans_passwords'])

        # Apply filter
        self.addFilter(data_filter.PCLOutputIsOk(['CrackLib']))
        self.addFilter(data_filter.PCLOutputIsNotOk(['PassWDQC']))
        self.applyFilter()

        # Get table output
        table = data_table.TransformedPasswordInfo(self.getData()).getTable()
        table_2 = data_table.SummaryInfo(self.getData()).getTable()

        # Print table to outputfile
        self.printToFile(table_2)
        self.printToFile(table)
