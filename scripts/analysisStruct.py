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
    def printAnalysisOutput(self):
        pass


class pclOutputChanged_Ok2NotOK(AnalysisTemplate):

    def __init__(self, analyzer):
        super(pclOutputChanged_Ok2NotOK, self).__init__(analyzer)

    def runAnalysis(self):
        self.addGroup(
            self.analyzer.defaultAnalysis['origPass_Ok'].intersection(
                self.analyzer.defaultAnalysis['transPass_NotOk']
                )
            )

    def printAnalysisOutput(self):
        for pcl in self.data.groupDic:
            print(
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

'''
def PCHLOutputChanged_Ok2NotOk(self, groupInfo, PCHL, shortOutput):
        return (
            "Original password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalPassword',
                False
                ) +
            " pass through " + PCHL + "." + '\n'
            "But transformed password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedPassword',
                False
                ) +
            ", did not pass through " + PCHL + "." + '\n' +
            "And the reason of rejection is: " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedLibOutput',
                False
                ) +
            '\n'
            )
'''

'''
    def addPasswordToAnalysisOutput(self, analysisName, PCHL, passInfo):
        """Method add passInfo into PassInfoGroup in analysisDic
        by analysisName and PCHL.

        Arguments:
        analysisName -- string, name of analysis
        PCHL -- string, name of password checking library
        passInfo -- class Password
        """
        if (analysisName not in self.analysisDic):
            self.analysisDic.update({analysisName: PassInfoGroup()})

        self.analysisDic[analysisName].addPassInfo(PCHL, passInfo)

    def addGroupToAnalysisOutput(self, analysisName, groupInfo):
        """Add whole groupInfo into analysisDic by analysisName

        Arguments:
        analysisName -- string, name of analysis
        groupInfo -- class PassInfoGroup
        """
        self.analysisDic.update({analysisName: groupInfo})

    def mainAnalysis(self):
        """Run analyzes
        """
        self.PCHLOutputChanged()
        self.lowAndHighEntropyAnalysis()
        self.lowEntropyChangePassPCHL()
        self.overallSummary()

    def PCHLOutputChanged(self):
        """Three analysis, that focus on outputs of
        password checking library for original and transformed password
        """

        # PCHLOutputChanged_Ok2NotOk -- analysis name
        # output of originalPasword is OK but
        # transformedPassword was rejected, output is not OK
        self.addGroupToAnalysisOutput(
            'PCHLOutputChanged_Ok2NotOk',
            self.defaultAnalysis['origPass_Ok'].intersection(
                self.defaultAnalysis['transPass_NotOk']
                )
            )

        # PCHLOutputChanged_NotOk2Ok -- analysis name
        # originalPassword was rejected by PCHL but
        # transformedPassword pass through PCHL
        self.addGroupToAnalysisOutput(
            'PCHLOutputChanged_NotOk2Ok',
            self.defaultAnalysis['origPass_NotOk'].intersection(
                self.defaultAnalysis['transPass_Ok']
                )
            )

        # PCHLOutputChanged_NotOk2NotOk -- analysis name
        # original and transformed password was rejected but
        # reason of rejection is different
        for PCHL, passInfoList in (
            self.defaultAnalysis['origPass_NotOk'].intersection(
                self.defaultAnalysis['transPass_NotOk'])
                ).groupDic.items():
            for passInfo in passInfoList:
                if (passInfo.originalLibOutput[PCHL] !=
                   passInfo.transformedLibOutput[PCHL]):
                    self.addPasswordToAnalysisOutput(
                        'PCHLOutputChanged_NotOk2NotOk',
                        PCHL,
                        passInfo
                        )

    def lowAndHighEntropyAnalysis(self):
        """Four analysis, that focus on entropy of original
        and transformed password
        """

        for PCHL, passInfoList in (
                self.defaultAnalysis['origPass_Ok'].groupDic.items()):
            for passInfo in passInfoList:
                # lowEntropyOriginalPasswordPassPCHL -- analysis name
                # originalPasswords with entropy lower then 36,
                # pass through PCHL
                if (passInfo.calculateInitialEntropy() < 36):
                    self.addPasswordToAnalysisOutput(
                        'lowEntropyOriginalPasswordPassPCHL',
                        PCHL,
                        passInfo
                        )

        for PCHL, passInfoList in (
                self.defaultAnalysis['origPass_NotOk'].groupDic.items()):
            for passInfo in passInfoList:
                # highEntropyOriginalPasswordDontPassPCHL -- analysis name
                # originalPasswords with entropy higher then 60,
                # did not pass through PCHL
                if (passInfo.calculateInitialEntropy() > 60):
                    self.addPasswordToAnalysisOutput(
                        'highEntropyOriginalPasswordDontPassPCHL',
                        PCHL,
                        passInfo
                        )

        for PCHL, passInfoList in (
                self.defaultAnalysis['transPass_Ok'].groupDic.items()):
            for passInfo in passInfoList:
                # lowEntropyTransformedPasswordPassPCHL -- analysis name
                # transformedPasswords with entropy lower then 36,
                # pass through PCHL
                if (passInfo.entropy < 36):
                    self.addPasswordToAnalysisOutput(
                        'lowEntropyTransformedPasswordPassPCHL',
                        PCHL,
                        passInfo
                        )

        for PCHL, passInfoList in (
                self.defaultAnalysis['transPass_NotOk'].groupDic.items()):
            for passInfo in passInfoList:
                # highEntropyTransformedPasswordDontPassPCHL -- analysis name
                # transformedPasswords with entropy higher then 60,
                # did not pass through PCHL
                if (passInfo.entropy > 60):
                    self.addPasswordToAnalysisOutput(
                        'highEntropyTransformedPasswordDontPassPCHL',
                        PCHL,
                        passInfo
                        )

    def lowEntropyChangePassPCHL(self):
        """Analysis, that focus on entropy-change.
        That is the entropy, which password gets by transformations
        """
        for PCHL, passInfoList in (
            self.defaultAnalysis['origPass_NotOk'].intersection(
                self.defaultAnalysis['transPass_Ok'])
                ).groupDic.items():
            for passInfo in passInfoList:
                if (passInfo.calculateChangedEntropy() < 2):
                    self.addPasswordToAnalysisOutput(
                        'withLowEntropyChangePassPCHL',
                        PCHL,
                        passInfo
                        )

    def overallSummary(self):
        """Calculate percentages of transformedPassword that pass through PCHL
        And most common reason for rejection
        """
        self.addGroupToAnalysisOutput(
            'overallSummary',
            self.defaultAnalysis['AllPasswords']
            )


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

    def PCHLOutputChanged_Ok2NotOk(self, groupInfo, PCHL, shortOutput):
        return (
            "Original password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalPassword',
                False
                ) +
            " pass through " + PCHL + "." + '\n'
            "But transformed password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedPassword',
                False
                ) +
            ", did not pass through " + PCHL + "." + '\n' +
            "And the reason of rejection is: " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedLibOutput',
                False
                ) +
            '\n'
            )

    def PCHLOutputChanged_NotOk2Ok(self, groupInfo, PCHL, shortOutput):
        return (
            "Original password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalPassword',
                False
                ) +
            " did not pass throught " + PCHL + ", because \n" +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalLibOutput',
                False
                ) + '\n'
            "But after applying transformations, trasformed password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedPassword',
                False
                ) +
            " pass throught " + PCHL + ".\n"
            )

    def PCHLOutputChanged_NotOk2NotOk(self, groupInfo, PCHL, shortOutput):
        return (
            "Neither original " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalPassword',
                False
                ) + " nor transformed " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedPassword',
                False
                ) + " password, pass throught " + PCHL + '\n' +
            "But the reason of rejection changed from \n" +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalLibOutput',
                False
                ) + "\nto\n" +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedLibOutput',
                False
                ) + ".\n"
            )

    def lowEntropyTransformedPasswordPassPCHL(self, groupInfo,
                                              PCHL, shortOutput):
        return (
            "Transformed password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedPassword',
                False
                ) + " with low entropy " +
            str(groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'entropy',
                False
                )) + ",\n" +
            "lower then 36.0, sucesfully pass through " + PCHL + ".\n"
            )

    def lowEntropyOriginalPasswordPassPCHL(self, groupInfo,
                                           PCHL, shortOutput):
        return (
            "Original password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalPassword',
                False
                ) + " with low entropy " +
            str(groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'calculateInitialEntropy',
                True
                )) + ",\n" +
            "lower than 36.0, sucesfully pass through " + PCHL + ".\n"
            )

    def highEntropyTransformedPasswordDontPassPCHL(self, groupInfo,
                                                   PCHL, shortOutput):
        return (
            "Transformed password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedPassword',
                False
                ) + " with high entropy " +
            str(groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'entropy',
                False
                )) + ",\n" +
            "higher than 60.0, did not pass throught " + PCHL + ".\n"
            )

    def highEntropyOriginalPasswordDontPassPCHL(self, groupInfo,
                                                PCHL, shortOutput):
        return (
            "Original password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalPassword',
                False
                ) + " with high entropy " +
            str(groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'calculateInitialEntropy',
                True
                )) + ",\n" +
            "higher than 60.0, did not pass throught " + PCHL + ".\n"
            )

    def withLowEntropyChangePassPCHL(self, groupInfo, PCHL, shortOutput):
        return (
            "Original password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'originalPassword',
                False
                ) + ", " +
            "transformed password " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedPassword',
                False
                ) + " with applied transformations: \n" +
            groupInfo.groupDic[PCHL][0].getAppliedTransformation() +
            "\nand with a low entropy-change, entropy value changed" +
            " from " +
            str(groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'calculateInitialEntropy',
                True
                )) + " to " +
            str(groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'entropy',
                False
                )) + ", pass through " + PCHL + ".\n"
            )

    def overallSummary(self, groupInfo, PCHL, shortOutput):
        percentChange = (
            len(
                self.analysisData.defaultAnalysis['transPass_Ok'].
                groupDic[PCHL]
                ) /
            len(groupInfo.groupDic[PCHL]) * 100
            )

        rejectionDic = {}
        for passInfo in (
                self.analysisData.defaultAnalysis['transPass_NotOk'].
                groupDic[PCHL]
                ):
            if (passInfo.transformedLibOutput[PCHL] not in rejectionDic):
                rejectionDic.update({passInfo.transformedLibOutput[PCHL]: 1})
            else:
                rejectionDic[passInfo.transformedLibOutput[PCHL]] += 1

        return (
            str(round(percentChange, 2)) +
            "% of transformed passwords pass through " + PCHL + ".\n" +
            "Most common reason(" +
            str(
                round(
                    (max(
                        rejectionDic.values()
                        ) / len(groupInfo.groupDic[PCHL])) * 100,
                    2
                    )
                ) +
            "%) for rejection is:\n" +
            str(max(rejectionDic, key=rejectionDic.get)) + '\n'
            )
'''
