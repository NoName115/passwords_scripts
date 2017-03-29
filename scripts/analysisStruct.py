from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassData

import datetime


class PassInfoGroup():

    def __init__(self):
        """Initialize class for group of passwords
        This group is used for analysis

        Self:
        groupDic -- key is name of pcl, value is list of class Password
        """
        self.groupDic = {}

    def addPassInfo(self, pcl, passInfo):
        """Method add passInfo into list by pcl

        Arguments:
        pcl -- string, name of password checking library
        passInfo -- class Password in passStruct.py
        """
        if (pcl not in self.groupDic):
            self.groupDic.update({pcl: []})

        if (passInfo is not None):
            self.groupDic[pcl].append(passInfo)

    def getPassInfoAttribute(self, pcl, shortOutput, attribute, isCallable):
        """Method return attribute of Password as String

        Arguments:
        pcl -- string, name of password checking library
        shortOutput -- boolean, True if only one element is needed
                       (return element at index 0)
        attribute -- string, attribute of class Password
        isCallable -- boolean, True if attribute is callable
        """
        returnInfo = self.groupDic[pcl][0].__getattribute__(attribute)() \
            if (isCallable) \
            else self.groupDic[pcl][0].__getattribute__(attribute)

        if (shortOutput):
            return (
                returnInfo[pcl] if (type(returnInfo) is dict) else returnInfo
                )
        else:
            if (type(returnInfo) is dict):
                return "  ".join(
                    (
                        passInfo.__getattribute__(attribute)()[pcl]
                        if (isCallable)
                        else passInfo.__getattribute__(attribute)[pcl]
                    )
                    for passInfo in self.groupDic[pcl]
                    )
            else:
                if (isCallable):
                    return "  ".join(
                        str(passInfo.__getattribute__(attribute)())
                        for passInfo in self.groupDic[pcl]
                        )
                else:
                    return "  ".join(
                        str(passInfo.__getattribute__(attribute))
                        for passInfo in self.groupDic[pcl]
                        )

    def intersection(self, other):
        """Intersection of two PassInfoGroup classes

        Arguments:
        other -- class PassInfoGroup

        Return value:
        intersectionGroup -- return new PassInfoGroup class
        """
        intersectionGroup = PassInfoGroup()
        for pcl in self.groupDic:
            for passInfo in self.groupDic[pcl]:
                if (passInfo in other.groupDic[pcl]):
                    intersectionGroup.addPassInfo(pcl, passInfo)

        return intersectionGroup

    def printData(self):
        print(self.groupDic)


class Analyzer():

    def __init__(self, passInfoList, pclDic):
        """Initialize 5 default analysis groups

        Arguments:
        passInfoList -- list of Password class
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
            'AllPasswords': PassInfoGroup(),
            'origPass_Ok': PassInfoGroup(),
            'origPass_NotOk': PassInfoGroup(),
            'transPass_Ok': PassInfoGroup(),
            'transPass_NotOk': PassInfoGroup()
        }
        self.fillDefaultAnalysisGroups(passInfoList, pclDic)

    def fillDefaultAnalysisGroups(self, passInfoList, pclDic):
        """Method concatenate passInfoList with pclDic
        and create list of PassData class.
        And fill 5 default analysis groups with data

        Arguments:
        passInfoList -- list of Password class
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
                self.defaultAnalysis['AllPasswords'].addPassInfo(
                    pcl,
                    passData
                    )

                if (passData.originalLibOutput[pcl] == "OK"):
                    self.defaultAnalysis['origPass_Ok'].addPassInfo(
                        pcl,
                        passData
                        )
                else:
                    self.defaultAnalysis['origPass_NotOk'].addPassInfo(
                        pcl,
                        passData
                        )

                if (passData.transformedLibOutput[pcl] == "OK"):
                    self.defaultAnalysis['transPass_Ok'].addPassInfo(
                        pcl,
                        passData
                        )
                else:
                    self.defaultAnalysis['transPass_NotOk'].addPassInfo(
                        pcl,
                        passData
                        )

    def addAnalysis(self, analysis):
        self.analysisList.append(analysis)

    def runAnalysis(self):
        for analysis in self.analysisList:
            analysis.runAnalysis()

    def printAnalysisOutput(self):
        for analysis in self.analysisList:
            print(analysis.getAnalysisOutput())


class AnalysisTemplate():

    __metaclass__ = ABCMeta

    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.data = PassInfoGroup()

    def getData(self):
        return self.data

    def addPassInfo(self, pcl, passInfo):
        self.data.addPassInfo(pcl, passInfo)

    def addGroup(self, groupData):
        self.data = groupData

    @abstractmethod
    def runAnalysis(self):
        pass

    @abstractmethod
    def getAnalysisOutput(self):
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

    def getAnalysisOutput(self):
        output = ""
        for pcl in self.data.groupDic:
            output += (
                "Original password " +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getOriginalPassword',
                    True
                    ) +
                " pass through " + pcl + "." + '\n' +
                "But transformed password " +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getTransformedPassword',
                    True
                    ) +
                ", did not pass through " + pcl + "." + '\n' +
                "And the reason of rejection is: " +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'transformedLibOutput',
                    False
                    ) +
                '\n'
                )
        return output


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

    def getAnalysisOutput(self):
        output = ""
        for pcl in self.data.groupDic:
            output += (
                "Original password " +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getOriginalPassword',
                    True
                    ) +
                " did not pass throught " + pcl + ", because \n" +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'originalLibOutput',
                    False
                    ) + '\n'
                "But after applying transformations, transformed password " +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getTransformedPassword',
                    True
                    ) +
                " pass throught " + pcl + ".\n"
                )
        return output


class PCLOutputChanged_NotOk2NotOk(AnalysisTemplate):

    def __init__(self, analyzer):
        super(PCLOutputChanged_NotOk2NotOk, self).__init__(analyzer)

    def runAnalysis(self):
        """Original and transformed password was rejected but
        reason of rejection is different
        """
        for pcl, passInfoList in (
            self.analyzer.defaultAnalysis['origPass_NotOk'].intersection(
                self.analyzer.defaultAnalysis['transPass_NotOk'])
                ).groupDic.items():
            for passInfo in passInfoList:
                if (passInfo.originalLibOutput[pcl] !=
                   passInfo.transformedLibOutput[pcl]):
                    self.addPassInfo(pcl, passInfo)

    def getAnalysisOutput(self):
        output = ""
        for pcl in self.data.groupDic:
            output += (
                "Neither original " +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getOriginalPassword',
                    True
                    ) + ' nor transformed ' +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getTransformedPassword',
                    True
                    ) + " password, pass through " + pcl + '\n' +
                "But the reason of rejection changed from \n" +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'originalLibOutput',
                    False
                    ) + "\nto\n" +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'transformedLibOutput',
                    False
                    ) + ".\n"
                )
        return output


class lowEntropyOriginalPasswordPassPCL(AnalysisTemplate):

    def __init__(self, analyzer):
        super(lowEntropyOriginalPasswordPassPCL, self).__init__(analyzer)

    def runAnalysis(self):
        """Original passwords with entropy lower than 36,
        pass through PCHL
        """
        for pcl, passInfoList in (
            self.analyzer.defaultAnalysis['origPass_Ok'].groupDic.items()
                ):
            for passInfo in passInfoList:
                if (passInfo.getInitialEntropy() < 36):
                    self.addPassInfo(pcl, passInfo)

    def getAnalysisOutput(self):
        output = ""
        for pcl in self.data.groupDic:
            output += (
                "Original password " +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getOriginalPassword',
                    True
                    ) + " with low entropy " +
                str(self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getInitialEntropy',
                    True
                    )) + ",\n" +
                "lower than 36.0, sucesfully pass through " + pcl + ".\n"
                )
        return output


class highEntropyOriginalPasswordDontPassPCL(AnalysisTemplate):

    def __init__(self, analyzer):
        super(highEntropyOriginalPasswordDontPassPCL, self).__init__(analyzer)

    def runAnalysis(self):
        """Original passwords with entropy higher than 60,
        did not pass throught PCL
        """
        for pcl, passInfoList in (
            self.analyzer.defaultAnalysis['origPass_NotOk'].groupDic.items()
                ):
            for passInfo in passInfoList:
                if (passInfo.getInitialEntropy() > 60):
                    self.addPassInfo(pcl, passInfo)

    def getAnalysisOutput(self):
        output = ""
        for pcl in self.data.groupDic:
            output += (
                "Original password " +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getOriginalPassword',
                    True
                    ) + " with high entropy " +
                str(self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getInitialEntropy',
                    True
                    )) + ",\n" +
                "higher than 60.0, did not pass throught " + pcl + ".\n"
                )
        return output


class lowEntropyTransformedPasswordPassPCL(AnalysisTemplate):

    def __init__(self, analyzer):
        super(lowEntropyTransformedPasswordPassPCL, self).__init__(analyzer)

    def runAnalysis(self):
        """Transformed passwords with entropy lower than 36,
        pass through PCHL
        """
        for pcl, passInfoList in (
            self.analyzer.defaultAnalysis['transPass_Ok'].groupDic.items()
                ):
            for passInfo in passInfoList:
                if (passInfo.getActualEntropy() < 36):
                    self.addPassInfo(pcl, passInfo)

    def getAnalysisOutput(self):
        output = ""
        for pcl in self.data.groupDic:
            output += (
                "Transformed password " +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getTransformedPassword',
                    True
                    ) + " with low entropy " +
                str(self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getActualEntropy',
                    True
                    )) + ",\n" +
                "lower than 36.0, sucesfully pass through " + pcl + ".\n"
                )
        return output


class highEntropyTransformedPasswordDontPassPCL(AnalysisTemplate):

    def __init__(self, analyzer):
        super(highEntropyTransformedPasswordDontPassPCL, self).__init__(
            analyzer
            )

    def runAnalysis(self):
        """Transformed passwords with entropy higher than 60,
        did not pass through PCHL
        """
        for pcl, passInfoList in (
            self.analyzer.defaultAnalysis['transPass_NotOk'].groupDic.items()
                ):
            for passInfo in passInfoList:
                if (passInfo.getActualEntropy() > 60):
                    self.addPassInfo(pcl, passInfo)

    def getAnalysisOutput(self):
        output = ""
        for pcl in self.data.groupDic:
            output += (
                "Transformed password " +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getTransformedPassword',
                    True
                    ) + " with high entropy " +
                str(self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getActualEntropy',
                    True
                    )) + ",\n" +
                "higher than 60.0, did not pss through " + pcl + ".\n"
                )
        return output


class lowEntropyChangePassPCL(AnalysisTemplate):

    def __init__(self, analyzer):
        super(lowEntropyChangePassPCL, self).__init__(analyzer)

    def runAnalysis(self):
        """Analysis, that focus on entropy-change.
        That is the entropy, which password gets by transformations
        """
        for pcl, passInfoList in (
            self.analyzer.defaultAnalysis['origPass_NotOk'].intersection(
                self.analyzer.defaultAnalysis['transPass_Ok'])
                ).groupDic.items():
            for passInfo in passInfoList:
                if (passInfo.getChangedEntropy() < 2):
                    self.addPassInfo(pcl, passInfo)

    def getAnalysisOutput(self):
        output = ""
        for pcl in self.data.groupDic:
            output += (
                "Original password " +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getOriginalPassword',
                    True
                    ) + ", transformed password" +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getTransformedPassword',
                    True
                    ) + " with applied transformations: \n" +
                self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getAppliedTransformation',
                    True
                    ) + "\nand with a low entropy-change," +
                "entropy value changed from " +
                str(self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getInitialEntropy',
                    True
                    )) + " to " +
                str(self.data.getPassInfoAttribute(
                    pcl,
                    True,
                    'getActualEntropy',
                    True
                    )) + ", pass through " + pcl + ".\n"
                )
        return output


class overallSummary(AnalysisTemplate):

    def __init__(self, analyzer):
        super(overallSummary, self).__init__(analyzer)

    def runAnalysis(self):
        """Calculate percentages of transformed passwords
        that pass through PCHL, and most common reason for rejection
        """
        self.addGroup(self.analyzer.defaultAnalysis['AllPasswords'])

    def getAnalysisOutput(self):
        output = ""
        for pcl in self.data.groupDic:
            percentChange = (
                len(
                    self.analyzer.defaultAnalysis['transPass_Ok'].groupDic[pcl]
                    ) /
                len(self.data.groupDic[pcl]) * 100
                )

            rejectionDic = {}
            for passInfo in (
                self.analyzer.defaultAnalysis['transPass_NotOk'].groupDic[pcl]
                    ):
                if (passInfo.transformedLibOutput[pcl] not in rejectionDic):
                    rejectionDic.update({
                        passInfo.transformedLibOutput[pcl]: 1
                        })
                else:
                    rejectionDic[passInfo.transformedLibOutput[pcl]] += 1

            output += (
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
        return output


'''
class AnalyzerPrinter():

    def __init__(self, analysisData):
        self.analysisData = analysisData

    def printMainAnalysis(self):
        # Create outputFile name by current time and date
        now = datetime.datetime.now()
        time = now.strftime("%Y-%m-%d_%H:%M:%S")
        filename = "outputs/analysis_" + time + ".output"

        # Open file to store analysis output
        outputFile = open(filename, "w")

        # Print main information to file
        outputFile.write(
            "\nTransformations applied:" + '\n'
            )
        outputFile.write(
            self.analysisData.passwordData.getTransformRules() + '\n'
            )

        # Print analysis output to stdout and outputFile
        if (self.analysisData.analysisDic):
            for analysisFuncName, analysisPassData in (
                    self.analysisData.analysisDic.items()):
                if (hasattr(self, analysisFuncName)):
                    for PCHL in analysisPassData.groupDic:
                        print(
                            self.__getattribute__(analysisFuncName)(
                                analysisPassData,
                                PCHL,
                                True
                                )
                            )
                        outputFile.write(
                            self.__getattribute__(analysisFuncName)(
                                analysisPassData,
                                PCHL,
                                False
                                ) + '\n'
                            )

        # Close output file
        outputFile.close()

'''
