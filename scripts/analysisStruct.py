import datetime


class PassInfoGroup():

    def __init__(self):
        """Initialize class for group of passwords
        This group is used for analysis

        Self:
        groupDic -- key is name of PCHL, value is list of class Password
        """
        self.groupDic = {}

    def addPassInfo(self, PCHL, passInfo):
        """Method add passInfo into list by PCHL

        Arguments:
        PCHL -- string, name of password checking library
        passInfo -- class Password in passStruct.py
        """
        if (PCHL not in self.groupDic):
            self.groupDic.update({PCHL: []})

        if (passInfo is not None):
            self.groupDic[PCHL].append(passInfo)

    def getPassInfoAttribute(self, PCHL, shortOutput, attribute, isCallable):
        """Method return attribute of Password as String

        Arguments:
        PCHL -- string, name of password checking library
        shortOutput -- boolean, True if only one element is needed
                       (return element at index 0)
        attribute -- string, attribute of class Password
        isCallable -- boolean, True if attribute is callable
        """
        returnInfo = self.groupDic[PCHL][0].__getattribute__(attribute)() \
            if (isCallable) \
            else self.groupDic[PCHL][0].__getattribute__(attribute)

        if (shortOutput):
            return (
                returnInfo[PCHL] if (type(returnInfo) is dict) else returnInfo
                )
        else:
            if (type(returnInfo) is dict):
                return "  ".join(
                    (
                        passInfo.__getattribute__(attribute)()[PCHL]
                        if (isCallable)
                        else passInfo.__getattribute__(attribute)[PCHL]
                    )
                    for passInfo in self.groupDic[PCHL]
                    )
            else:
                if (isCallable):
                    return "  ".join(
                        str(passInfo.__getattribute__(attribute)())
                        for passInfo in self.groupDic[PCHL]
                        )
                else:
                    return "  ".join(
                        str(passInfo.__getattribute__(attribute))
                        for passInfo in self.groupDic[PCHL]
                        )

    def intersection(self, other):
        """Intersection of two PassInfoGroup classes

        Arguments:
        other -- class PassInfoGroup

        Return value:
        intersectionGroup -- return new PassInfoGroup class
        """
        intersectionGroup = PassInfoGroup()
        for PCHL in self.groupDic:
            for passInfo in self.groupDic[PCHL]:
                if (passInfo in other.groupDic[PCHL]):
                    intersectionGroup.addPassInfo(PCHL, passInfo)

        return intersectionGroup


class Analyzer():

    def __init__(self, passwordData):
        """Initialize 5 default analysis groups

        Arguments:
        passwordData -- class PassData in passStruct.py

        Self:
        defaultAnalysis -- dictionary of 5 default analysis groups
        AllPasswords -- contain every password
        origPass_Ok -- contain passwords which originalPassword
                               pass through PCHL
        origPass_NotOk -- contain passwords which originalPassword
                                  did not pass through PCHL
        transPass_Ok -- contain passwords which transformedPassword
                                  pass through PCHL
        transPass_NotOk -- contain passwords which
                                     transformedPassword
                                     did not pass through PCHL
        analysisFunctionNames -- list of every analysis
                                 names of function in class AnalyzerPrinter
        passwordData -- class PassData (input data)
        analysisDic -- dictionary of analyzes
                       key is element from analysisFunctionNames
        """
        self.defaultAnalysis = {
            'AllPasswords': PassInfoGroup(),
            'origPass_Ok': PassInfoGroup(),
            'origPass_NotOk': PassInfoGroup(),
            'transPass_Ok': PassInfoGroup(),
            'transPass_NotOk': PassInfoGroup()
        }
        self.analysisFunctionNames = [
            'PCHLOutputChanged_Ok2NotOk',
            'PCHLOutputChanged_NotOk2Ok',
            'PCHLOutputChanged_NotOk2NotOk',
            'lowEntropyOriginalPasswordPassPCHL',
            'lowEntropyTransformedPasswordPassPCHL',
            'highEntropyOriginalPasswordDontPassPCHL',
            'highEntropyTransformedPasswordDontPassPCHL',
            'withLowEntropyChangePassPCHL',
            'overallSummary'
        ]
        self.defaultGroupAnalysis(passwordData)

        self.passwordData = passwordData
        self.analysisDic = {}

    def defaultGroupAnalysis(self, passwordData):
        """Method fill 5 default analysis groups with data

        Arguments:
        passwordData -- class PassData (input data)
        """
        for passInfo in passwordData:
            for PCHL in passInfo.originalLibOutput:
                self.defaultAnalysis['AllPasswords'].addPassInfo(
                    PCHL,
                    passInfo
                    )

                if (passInfo.originalLibOutput[PCHL] == "OK"):
                    self.defaultAnalysis['origPass_Ok'].addPassInfo(
                        PCHL,
                        passInfo
                        )
                else:
                    self.defaultAnalysis['origPass_NotOk'].addPassInfo(
                        PCHL,
                        passInfo
                        )

                if (passInfo.transformedLibOutput[PCHL] == "OK"):
                    self.defaultAnalysis['transPass_Ok'].addPassInfo(
                        PCHL,
                        passInfo
                        )
                else:
                    self.defaultAnalysis['transPass_NotOk'].addPassInfo(
                        PCHL,
                        passInfo
                        )

    def addPasswordToAnalysisOutput(self, analysisName, PCHL, passInfo):
        """Method add passInfo into PassInfoGroup in analysisDic
        by analysisName and PCHL.

        Arguments:
        analysisName -- string, name of analysis
                        (element from analysisFunctionNames)
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
                        (element from analysisFunctionNames)
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
            self.analysisFunctionNames[0],
            self.defaultAnalysis['origPass_Ok'].intersection(
                self.defaultAnalysis['transPass_NotOk']
                )
            )

        # PCHLOutputChanged_NotOk2Ok -- analysis name
        # originalPassword was rejected by PCHL but
        # transformedPassword pass through PCHL
        self.addGroupToAnalysisOutput(
            self.analysisFunctionNames[1],
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
                        self.analysisFunctionNames[2],
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
                        self.analysisFunctionNames[3],
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
                        self.analysisFunctionNames[5],
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
                        self.analysisFunctionNames[4],
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
                        self.analysisFunctionNames[6],
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
                        self.analysisFunctionNames[7],
                        PCHL,
                        passInfo
                        )

    def overallSummary(self):
        """Calculate percentages of transformedPassword that pass through PCHL
        And most common reason for rejection
        """
        self.addGroupToAnalysisOutput(
            self.analysisFunctionNames[8],
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

        # Print analysis output to StdOut and outputFile
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
                ) + " or transformed " +
            groupInfo.getPassInfoAttribute(
                PCHL,
                shortOutput,
                'transformedPassword',
                False
                ) + " password, did not pass throught " + PCHL + '\n' +
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
            "Transformed password " +
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
