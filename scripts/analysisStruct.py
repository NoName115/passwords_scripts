from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassData
from prettytable import PrettyTable

import datetime


class PassDataGroup():

    def __init__(self):
        """Initialize class for group of passwords
        This group is used for analysis

        Self:
        groupDic -- key is name of pcl, value is list of class Password
        """
        self.groupDic = {}

    def addPassData(self, pcl, passData):
        """Method add passData into list by pcl

        Arguments:
        pcl -- string, name of password checking library
        passData -- class PassData from passStruct.py
        """
        if (pcl not in self.groupDic):
            self.groupDic.update({pcl: []})

        if (passData is not None):
            self.groupDic[pcl].append(passData)

    def getPassDataAttribute(self, pcl, attribute):
        """Method return attribute of PassData as String

        Arguments:
        pcl -- string, name of password checking library
        attribute -- string, attribute of class Password
                     every attribute is callable 'getAttributeName'
        """
        returnInfo = self.groupDic[pcl][0].__getattribute__(attribute)()
        return (
            returnInfo[pcl] if (type(returnInfo) is dict) else returnInfo
        )

    def getDataInTable(self, pcl, header, attributes):
        """Method create and fill 'table' with PassData data from groupDic

        Arguments:
        pcl -- string, name of password checking library
        header -- list, header of every column
        attributes -- list, attributes that are extracted from PassData class
        """
        table = PrettyTable(header)
        for passData in self.groupDic[pcl]:
            dataList = []
            # Iterate every attribute and get correct data from passData
            for attr in attributes:
                attrData = passData.__getattribute__(attr)()
                if (type(attrData) is dict):
                    attrData = attrData[pcl]
                dataList.append(attrData)

            table.add_row(dataList)

        return table

    def intersection(self, other):
        """Intersection of two PassDataGroup classes

        Arguments:
        other -- class PassDataGroup

        Return value:
        intersectionGroup -- return new PassDataGroup class
        """
        intersectionGroup = PassDataGroup()
        for pcl in self.groupDic:
            for passData in self.groupDic[pcl]:
                if (passData in other.groupDic[pcl]):
                    intersectionGroup.addPassData(pcl, passData)

        return intersectionGroup

    # DEBUG
    def printData(self):
        print(self.groupDic)


class Analyzer():

    def __init__(self, passInfoList, pclDic):
        """Initialize 5 default analysis groups

        Arguments:
        passInfoList -- list of Password classes
        pclDic -- dictionary of password checking libraries output

        Self:
        defaultAnalysis -- dictionary of 5 default analysis groups
        AllPasswords -- contain every password
        origPass_Ok -- contain passwords which originalPassword
                               pass through pcl
        origPass_NotOk -- contain passwords which originalPassword
                                  did not pass through pcl
        transPass_Ok -- contain passwords which transformedPassword
                                  pass through pcl
        transPass_NotOk -- contain passwords which
                                     transformedPassword
                                     did not pass through pcl
        passwordData -- class PassData (input data)
        analysisDic -- dictionary of analyzes
                       key is name of function in AnalyzerPrinter class
        """
        self.analysisList = []
        self.defaultAnalysis = {
            'AllPasswords': PassDataGroup(),
            'origPass_Ok': PassDataGroup(),
            'origPass_NotOk': PassDataGroup(),
            'transPass_Ok': PassDataGroup(),
            'transPass_NotOk': PassDataGroup()
        }
        self.fillDefaultAnalysisGroups(passInfoList, pclDic)

    def fillDefaultAnalysisGroups(self, passInfoList, pclDic):
        """Method concatenate passInfoList with pclDic
        and create list of PassData class.
        And fill 5 default analysis groups with data

        Arguments:
        passInfoList -- list of Password classes
        pclDic -- dictionary of password checking libraries output
        """
        # Create passDataList
        passDataList = []
        for passInfo in passInfoList:
            passDataList.append(PassData(
                passInfo,
                pclDic[passInfo.originalData[0]],
                pclDic[passInfo.transformedData[0]]
                ))

        # Fill default analysis group with data
        for passData in passDataList:
            for pcl in passData.originalLibOutput:
                self.defaultAnalysis['AllPasswords'].addPassData(
                    pcl,
                    passData
                    )

                if (passData.originalLibOutput[pcl] == "OK"):
                    self.defaultAnalysis['origPass_Ok'].addPassData(
                        pcl,
                        passData
                        )
                else:
                    self.defaultAnalysis['origPass_NotOk'].addPassData(
                        pcl,
                        passData
                        )

                if (passData.transformedLibOutput[pcl] == "OK"):
                    self.defaultAnalysis['transPass_Ok'].addPassData(
                        pcl,
                        passData
                        )
                else:
                    self.defaultAnalysis['transPass_NotOk'].addPassData(
                        pcl,
                        passData
                        )

    def addAnalysis(self, analysis):
        """Method add inputAnalysis to analysisList
        """
        self.analysisList.append(analysis)

    def runAnalyzes(self):
        """Run every analysis in analysisList
        """
        for analysis in self.analysisList:
            analysis.runAnalysis()

    def printAnalyzesOutput(self):
        """Print output of every analysis from analysisList
        Short output is printed to stdout
        Long output is written to outputFile
        """
        # Create outputfile name it by current datetime
        now = datetime.datetime.now()
        time = now.strftime("%Y-%m-%d_%H:%M:%S")
        filename = "outputs/analysis_" + time + ".output"

        outputFile = open(filename, 'w')

        # Print analysis output to stdout and outputFile
        for analysis in self.analysisList:
            print(analysis.getAnalysisOutput())

            # Write data in table with analysisDescription to outputFile
            outputFile.write(
                analysis.getDataInTable()
            )

        # Close output file
        outputFile.close()


class AnalysisTemplate():

    __metaclass__ = ABCMeta

    def __init__(self, analyzer):
        """Template for new analysis

        Arguments:
        analyzer -- class Analyzer
        """
        self.analyzer = analyzer
        self.data = PassDataGroup()

    def getData(self):
        """Return analysis data
        """
        return self.data

    def addPassData(self, pcl, passData):
        """Add class PassData to analysis data
        """
        self.data.addPassData(pcl, passData)

    def addGroup(self, groupData):
        """Add whole group of PassData classes to analysis data
        """
        self.data = groupData

    @abstractmethod
    def getAnalysisDescription(self, pcl):
        """Short analysis description
        This description is written to outputFile
        """
        pass

    @abstractmethod
    def runAnalysis(self):
        pass

    def getAnalysisOutput(self):
        return '\n'.join(
            str(self.uniqueAnalysisOutput(pcl)) for pcl in self.data.groupDic
            )

    @abstractmethod
    def uniqueAnalysisOutput(self, pcl):
        """Long and detailed analysis output
        """
        pass

    def getDataInTable(self):
        """Return tables of analysis data
        """
        return (
            '\n'.join(
                (
                    self.getAnalysisDescription(pcl) +
                    str(self.getUniqueTableOutput(pcl))
                )
                for pcl in self.data.groupDic
            ) + '\n'
        )

    @abstractmethod
    def getUniqueTableOutput(self, pcl):
        """Return one table with analysis data
        """
        pass


class PCLOutputChanged_Ok2NotOK(AnalysisTemplate):

    def __init__(self, analyzer):
        super(PCLOutputChanged_Ok2NotOK, self).__init__(analyzer)

    def runAnalysis(self):
        """Output of originalPasword is OK but
        transformedPassword was rejected(output is not OK)
        """
        self.addGroup(
            self.analyzer.defaultAnalysis['origPass_Ok'].intersection(
                self.analyzer.defaultAnalysis['transPass_NotOk']
                )
            )

    def getAnalysisDescription(self, pcl):
        return (
            "Original passwords pass through " + pcl +
            " but transformed passwords were rejected\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Original password " +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalPassword'
                ) +
            " pass through " + pcl + "." + '\n' +
            "But transformed password " +
            self.data.getPassDataAttribute(
                pcl,
                'getTransformedPassword'
                ) +
            ", did not pass through " + pcl + "." + '\n' +
            "And the reason of rejection is: " +
            self.data.getPassDataAttribute(
                pcl,
                'geTransformedLibOutput'
                ) +
            '\n'
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                [
                    'Original password', 'Transformed password',
                    'Transformed PCL output'
                ],
                [
                    'getOriginalPassword', 'getTransformedPassword',
                    'getTransformedLibOutput'
                ]
            )
        )


class PCLOutputChanged_NotOk2Ok(AnalysisTemplate):

    def __init__(self, analyzer):
        super(PCLOutputChanged_NotOk2Ok, self).__init__(analyzer)

    def runAnalysis(self):
        """OriginalPassword was rejected by PCL but
        transformedPassword pass through PCL
        """
        self.addGroup(
            self.analyzer.defaultAnalysis['origPass_NotOk'].intersection(
                self.analyzer.defaultAnalysis['transPass_Ok']
                )
            )

    def getAnalysisDescription(self, pcl):
        return (
            "Original passwords were rejected " +
            "but transformed passwords pass through " + pcl + "\n"
            )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Original password " +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalPassword'
                ) +
            " did not pass through " + pcl + ", because \n" +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalLibOutput'
                ) + '\n'
            "But after applying transformations, transformed password " +
            self.data.getPassDataAttribute(
                pcl,
                'getTransformedPassword'
                ) +
            " pass through " + pcl + ".\n"
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                [
                    'Original password', 'Transformed password',
                    'Original PCL output'
                ],
                [
                    'getOriginalPassword', 'getTransformedPassword',
                    'getOriginalLibOutput'
                ]
            )
        )


class PCLOutputChanged_NotOk2NotOk(AnalysisTemplate):

    def __init__(self, analyzer):
        super(PCLOutputChanged_NotOk2NotOk, self).__init__(analyzer)

    def runAnalysis(self):
        """Original and transformed password was rejected but
        reason of rejection is different
        """
        for pcl, passDataList in (
            self.analyzer.defaultAnalysis['origPass_NotOk'].intersection(
                self.analyzer.defaultAnalysis['transPass_NotOk'])
                ).groupDic.items():
            for passData in passDataList:
                if (passData.originalLibOutput[pcl] !=
                   passData.transformedLibOutput[pcl]):
                    self.addPassData(pcl, passData)

    def getAnalysisDescription(self, pcl):
        return (
            "Original and transformed passwords were rejected by " + pcl +
            " but reason of rejection is diffrent\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Neither original " +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalPassword'
                ) + ' nor transformed ' +
            self.data.getPassDataAttribute(
                pcl,
                'getTransformedPassword'
                ) + " password, pass through " + pcl + '\n' +
            "But the reason of rejection changed from \n" +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalLibOutput'
                ) + "\nto\n" +
            self.data.getPassDataAttribute(
                pcl,
                'getTransformedLibOutput'
                ) + ".\n"
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                [
                    'Original password', 'Transformed password',
                    'Original PCL output', 'Transformed PCL output'
                ],
                [
                    'getOriginalPassword', 'getTransformedPassword',
                    'getOriginalLibOutput', 'getTransformedLibOutput'
                ]
            )
        )


class lowEntropyOriginalPasswordPassPCL(AnalysisTemplate):

    def __init__(self, analyzer):
        super(lowEntropyOriginalPasswordPassPCL, self).__init__(analyzer)

    def runAnalysis(self):
        """Original passwords with entropy lower than 36,
        pass through PCL
        """
        for pcl, passDataList in (
            self.analyzer.defaultAnalysis['origPass_Ok'].groupDic.items()
                ):
            for passData in passDataList:
                if (passData.getInitialEntropy() < 36):
                    self.addPassData(pcl, passData)

    def getAnalysisDescription(self, pcl):
        return (
            "Original passwords with entropy lower than 36.0, " +
            "pass through " + pcl + "\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Original password " +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalPassword'
                ) + " with low entropy " +
            str(self.data.getPassDataAttribute(
                pcl,
                'getInitialEntropy'
                )) + ",\n" +
            "lower than 36.0, sucesfully pass through " + pcl + ".\n"
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                ['Original password', 'Initial entropy'],
                ['getOriginalPassword', 'getInitialEntropy']
            )
        )


class highEntropyOriginalPasswordDontPassPCL(AnalysisTemplate):

    def __init__(self, analyzer):
        super(highEntropyOriginalPasswordDontPassPCL, self).__init__(analyzer)

    def runAnalysis(self):
        """Original passwords with entropy higher than 60,
        did not pass through PCL
        """
        for pcl, passDataList in (
            self.analyzer.defaultAnalysis['origPass_NotOk'].groupDic.items()
                ):
            for passData in passDataList:
                if (passData.getInitialEntropy() > 60):
                    self.addPassData(pcl, passData)

    def getAnalysisDescription(self, pcl):
        return (
            "Original passwords with entropy higher than 60, " +
            "did not pass through " + pcl + "\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Original password " +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalPassword'
                ) + " with high entropy " +
            str(self.data.getPassDataAttribute(
                pcl,
                'getInitialEntropy'
                )) + ",\n" +
            "higher than 60.0, did not pass through " + pcl + ".\n"
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                ['Original password', 'Initial entropy'],
                ['getOriginalPassword', 'getInitialEntropy']
            )
        )


class lowEntropyTransformedPasswordPassPCL(AnalysisTemplate):

    def __init__(self, analyzer):
        super(lowEntropyTransformedPasswordPassPCL, self).__init__(analyzer)

    def runAnalysis(self):
        """Transformed passwords with entropy lower than 36,
        pass through PCL
        """
        for pcl, passDataList in (
            self.analyzer.defaultAnalysis['transPass_Ok'].groupDic.items()
                ):
            for passData in passDataList:
                if (passData.getActualEntropy() < 36):
                    self.addPassData(pcl, passData)

    def getAnalysisDescription(self, pcl):
        return (
            "Transformed passwords with entropy lower than 36, " +
            "pass through " + pcl + "\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Transformed password " +
            self.data.getPassDataAttribute(
                pcl,
                'getTransformedPassword'
                ) + " with low entropy " +
            str(self.data.getPassDataAttribute(
                pcl,
                'getActualEntropy'
                )) + ",\n" +
            "lower than 36.0, sucesfully pass through " + pcl + ".\n"
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                ['Transformed password', 'Entropy'],
                ['getTransformedPassword', 'getActualEntropy']
            )
        )


class highEntropyTransformedPasswordDontPassPCL(AnalysisTemplate):

    def __init__(self, analyzer):
        super(highEntropyTransformedPasswordDontPassPCL, self).__init__(
            analyzer
            )

    def runAnalysis(self):
        """Transformed passwords with entropy higher than 60,
        did not pass through PCL
        """
        for pcl, passDataList in (
            self.analyzer.defaultAnalysis['transPass_NotOk'].groupDic.items()
                ):
            for passData in passDataList:
                if (passData.getActualEntropy() > 60):
                    self.addPassData(pcl, passData)

    def getAnalysisDescription(self, pcl):
        return (
            "Transformed passwords with entropy higher than 60, " +
            "did not pass through " + pcl + "\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Transformed password " +
            self.data.getPassDataAttribute(
                pcl,
                'getTransformedPassword'
                ) + " with high entropy " +
            str(self.data.getPassDataAttribute(
                pcl,
                'getActualEntropy'
                )) + ",\n" +
            "higher than 60.0, did not pss through " + pcl + ".\n"
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                ['Transformed password', 'Entropy'],
                ['getTransformedPassword', 'getActualEntropy']
            )
        )


class lowEntropyChangePassPCL(AnalysisTemplate):

    def __init__(self, analyzer):
        super(lowEntropyChangePassPCL, self).__init__(analyzer)

    def runAnalysis(self):
        """Analysis, that focus on entropy-change.
        That is the entropy, which password gets by transformations
        """
        for pcl, passDataList in (
            self.analyzer.defaultAnalysis['origPass_NotOk'].intersection(
                self.analyzer.defaultAnalysis['transPass_Ok'])
                ).groupDic.items():
            for passData in passDataList:
                if (passData.getChangedEntropy() < 2):
                    self.addPassData(pcl, passData)

    def getAnalysisDescription(self, pcl):
        return (
            "Transformed password with a low entropy-change, " +
            "pass through " + pcl + "\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        return (
            "Original password " +
            self.data.getPassDataAttribute(
                pcl,
                'getOriginalPassword'
                ) + ", transformed password" +
            self.data.getPassDataAttribute(
                pcl,
                'getTransformedPassword'
                ) + " with applied transformations: \n" +
            self.data.getPassDataAttribute(
                pcl,
                'getAppliedTransformation'
                ) + "\nand with a low entropy-change," +
            "entropy value changed from " +
            str(self.data.getPassDataAttribute(
                pcl,
                'getInitialEntropy'
                )) + " to " +
            str(self.data.getPassDataAttribute(
                pcl,
                'getActualEntropy'
                )) + ", pass through " + pcl + ".\n"
            )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                [
                    'Original password', 'Transformed password',
                    'Transformations', 'Initial entropy', 'Entropy'
                ],
                [
                    'getOriginalPassword', 'getTransformedPassword',
                    'getAppliedTransformation', 'getInitialEntropy',
                    'getActualEntropy'
                ]
            )
        )


class overallSummary(AnalysisTemplate):

    def __init__(self, analyzer):
        super(overallSummary, self).__init__(analyzer)

    def runAnalysis(self):
        """Calculate percentages of transformed passwords
        that pass through PCL, and most common reason for rejection
        """
        self.addGroup(self.analyzer.defaultAnalysis['AllPasswords'])

    def getAnalysisDescription(self, pcl):
        return (
            "Percentages of transformed passwords that pass through " + pcl +
            " and most common reason for rejection\n"
        )

    def uniqueAnalysisOutput(self, pcl):
        percentChange = (
            len(
                self.analyzer.defaultAnalysis['transPass_Ok'].groupDic[pcl]
                ) /
            len(self.data.groupDic[pcl]) * 100
            )

        rejectionDic = {}
        for passData in (
            self.analyzer.defaultAnalysis['transPass_NotOk'].groupDic[pcl]
                ):
            if (passData.transformedLibOutput[pcl] not in rejectionDic):
                rejectionDic.update({
                    passData.transformedLibOutput[pcl]: 1
                    })
            else:
                rejectionDic[passData.transformedLibOutput[pcl]] += 1

        return (
            str(round(percentChange, 2)) +
            "% of transformed passwords pass through " + pcl + ".\n" +
            "Most common reason(" +
            str(
                round(
                    max(rejectionDic.values()) /
                    len(self.data.groupDic[pcl]) * 100,
                    2
                    )
                ) + "%) for rejection is:\n" +
            str(max(rejectionDic, key=rejectionDic.get)) + '\n'
        )

    def getUniqueTableOutput(self, pcl):
        return (
            self.data.getDataInTable(
                pcl,
                [
                    'Original password', 'Transformed password',
                    'Original PCL output', 'Transformed PCL output'
                ],
                [
                    'getOriginalPassword', 'getTransformedPassword',
                    'getOriginalLibOutput', 'getTransformedLibOutput'
                ]
            )
        )
