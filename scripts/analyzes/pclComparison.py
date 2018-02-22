from scripts.analysisBase import AnalysisTemplate

import scripts.filter as data_filter
import scripts.table as data_table


class LibrariesSummary(AnalysisTemplate):

    def runAnalysis(self):
        #self.setData(self.analyzer.data_set['all_passwords'])
        self.setData(self.analyzer.data_set['trans_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.applyFilter()

        table_1 = data_table.OverallSummary(self.getData()).getTable(
            #start=0,
            #end=30
        )
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )


class LibrariesTopOkPasswords(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.applyFilter()
        unfiltered_data = self.getData()

        folder_path = 'outputs/' + self.__class__.__name__
        self.createFolder(folder_path)
        folder_path += "/"

        for pcl in ['CrackLib', 'PassWDQC', 'Passfault', 'Pwscore', 'ZxcvbnPython', 'ZxcvbnC']:
            self.clearFilter()
            self.setData(unfiltered_data)
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()
            self.printToFile(
                'PCL: ' + pcl,
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )
            self.printToFile(
                data_table.ComplexPasswordWithNumberOfUses(self.getData()).getTable(
                    #start=0,
                    #end=200,
                    #fields=['NOUses', 'Password'] + [pcl, pcl + ' score']
                ),
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )
            self.printToFile(
                data_table.OverallSummary(self.getData()).getTable(
                    start=0,
                    end=20,
                ),
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )


class AllRejectedOneAccepted(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.applyFilter()
        unfiltered_data = self.getData()

        folder_path = 'outputs/' + self.__class__.__name__
        self.createFolder(folder_path)
        folder_path += "/"

        for pcl in ['CrackLib', 'PassWDQC', 'Passfault', 'Pwscore', 'ZxcvbnPython', 'ZxcvbnC']:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.AllRejectedOneAccepted(pcl))
            self.applyFilter()

            table = data_table.ComplexPasswordWithNumberOfUses(
                self.getData()
            ).getTable(
                #start=0,
                #end=200
            )
            self.printToFile(
                'PCL: ' + pcl +
                    '. Number of passwords: ' + str(len(self.getData())),
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )
            self.printToFile(
                table,
                filename=folder_path + pcl + "_" + self.__class__.__name__
                )


class AllAccepted(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])
        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        for pcl in ['CrackLib', 'PassWDQC', 'Passfault', 'Pwscore', 'ZxcvbnPython', 'ZxcvbnC']:
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))

        self.applyFilter()

        table = data_table.ComplexPasswordWithNumberOfUses(
            self.getData()
        ).getTable(
            #start=0,
            #end=500,
        )
        self.printToFile(
            "Number of password: " + str(len(self.getData())),
            filename='outputs/' + self.__class__.__name__
        )
        self.printToFile(
            table,
            filename='outputs/' + self.__class__.__name__
        )


class LibrariesCrackLibTopRejection(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.PCLOutputRegex({
            'CrackLib': 'dictionary word'
        }))
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.applyFilter()

        unfiltered_data = self.getData()

        table_1 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=30
        )
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )

        pcl_list = ['PassWDQC', 'Passfault', 'Pwscore', 'ZxcvbnPython']
        for pcl in pcl_list:
            self.clearFilter()
            self.setData(unfiltered_data)
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()
            table_2 = data_table.ComplexPasswordWithNumberOfUses(
                self.getData()
            ).getTable(
                start=0,
                end=200,
            )
            self.printToFile(
                "PCL: " + pcl +
                "\nNumber of passwords: " + str(len(self.getData())),
                filename="outputs/" + self.__class__.__name__
            )
            self.printToFile(
                table_2,
                filename='outputs/' + self.__class__.__name__
            )
        
        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(pcl_list))
        self.applyFilter()
        table_3 = data_table.ComplexPasswordWithNumberOfUses(
            self.getData()
        ).getTable(
            start=0,
            end=200
        )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
        )


class LibrariesPassWDQCTopRejection(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.addFilter(data_filter.PCLOutputRegex({
            'PassWDQC': 'not enough different characters or classes'
        }))
        self.applyFilter()

        unfiltered_data = self.getData()

        table = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=30,
        )
        self.printToFile(
            table,
            filename='outputs/' + self.__class__.__name__
        )

        pcl_list = ['CrackLib', 'Passfault', 'Pwscore', 'ZxcvbnPython']
        for pcl in pcl_list:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()

            table_2 = data_table.ComplexPasswordWithNumberOfUses(
                self.getData()
            ).getTable(
                start=0,
                end=200,
            )
            self.printToFile(
                "PCL: " + pcl +
                    "\nNumber of passwords: " + str(len(self.getData())),
                filename="outputs/" + self.__class__.__name__
            )
            self.printToFile(
                table_2,
                filename='outputs/' + self.__class__.__name__
            )

        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(pcl_list))
        self.applyFilter()
        table_3 = data_table.ComplexPasswordWithNumberOfUses(
            self.getData()
        ).getTable(
            start=0,
            end=200
        )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
        )


class LibrariesPassfaulTopRejection(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.addFilter(data_filter.PCLOutputRegex({
            'Passfault': 'worst-passwords'
        }))
        self.applyFilter()

        unfiltered_data = self.getData()

        table_1 = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=30
        )
        self.printToFile(
            table_1,
            filename='outputs/' + self.__class__.__name__
        )

        pcl_list = ['CrackLib', 'PassWDQC', 'Pwscore', 'ZxcvbnPython']
        for pcl in pcl_list:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()
            table_2 = data_table.ComplexPasswordWithNumberOfUses(
                self.getData()
            ).getTable(
                start=0,
                end=200,
            )
            self.printToFile(
                "PCL: " + pcl +
                    "\nNumber of passwords: " + str(len(self.getData())),
                filename="outputs/" + self.__class__.__name__
            )
            self.printToFile(
                table_2,
                filename="outputs/" + self.__class__.__name__
            )

        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(pcl_list))
        self.applyFilter()
        table_3 = data_table.ComplexPasswordWithNumberOfUses(
            self.getData()
        ).getTable(
            start=0,
            end=200
        )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
        )


class LibrariesPwscoreTopRejection(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.addFilter(data_filter.PCLOutputRegex({
            'Pwscore': 'shorter than 8'
        }))
        self.applyFilter()

        unfiltered_data = self.getData()

        table = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=30,
        )
        self.printToFile(
            table,
            filename='outputs/' + self.__class__.__name__
        )

        pcl_list = ['CrackLib', 'PassWDQC', 'Passfault', 'ZxcvbnPython']
        for pcl in pcl_list:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()
            table_1 = data_table.ComplexPasswordWithNumberOfUses(
                self.getData()
            ).getTable(
                start=0,
                end=200
            )
            self.printToFile(
                "PCL: " + pcl +
                "\nNumber of passwords: " + str(len(self.getData())),
                filename="outputs/" + self.__class__.__name__
            )
            self.printToFile(
                table_1,
                filename="outputs/" + self.__class__.__name__
            )

        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(pcl_list))
        self.applyFilter()
        table_3 = data_table.ComplexPasswordWithNumberOfUses(
            self.getData()
        ).getTable(
            start=0,
            end=200
        )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
        )


class LibrariesZxcvbnPythonTopRejection(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        self.addFilter(data_filter.PCLOutputRegex({
            'ZxcvbnPython': 'top.*100.*password'
        }))
        self.applyFilter()

        unfiltered_data = self.getData()

        table = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=30
        )
        self.printToFile(
            table,
            filename='outputs/' + self.__class__.__name__
        )

        pcl_list = ['CrackLib', 'PassWDQC', 'Passfault', 'Pwscore']
        for pcl in pcl_list:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl]))
            self.applyFilter()
            table_1 = data_table.ComplexPasswordWithNumberOfUses(
                self.getData()
            ).getTable(
                start=0,
                end=200
            )
            self.printToFile(
                "PCL: " + pcl +
                "\nNumber of passwords: " + str(len(self.getData())),
                filename="outputs/" + self.__class__.__name__
            )
            self.printToFile(
                table_1,
                filename="outputs/" + self.__class__.__name__
            )

        self.setData(unfiltered_data)
        self.clearFilter()
        self.addFilter(data_filter.OriginalPCLOutputIsOk(pcl_list))
        self.applyFilter()
        table_3 = data_table.ComplexPasswordWithNumberOfUses(
            self.getData()
        ).getTable(
            start=0,
            end=200
        )
        self.printToFile(
            table_3,
            filename='outputs/' + self.__class__.__name__
        )


class AllAcceptedOneRejected(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['trans_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        '''
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        '''
        self.applyFilter()

        unfiltered_data = self.getData()

        folder_path = "outputs/" + self.__class__.__name__
        self.createFolder(folder_path)
        folder_path += "/"

        pcl_list = ['CrackLib', 'PassWDQC', 'Passfault', 'Pwscore', 'ZxcvbnPython', 'ZxcvbnC']
        for pcl in pcl_list:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.OriginalPCLOutputIsNotOk([pcl]))
            for pcl_2 in pcl_list:
                if (pcl != pcl_2):
                    self.addFilter(data_filter.OriginalPCLOutputIsOk([pcl_2]))

            self.applyFilter()
            table = data_table.ComplexTransformedPassword(
                self.getData()
            ).getTable(
                #start=0,
                #end=200
            )
            self.printToFile(
                'PCL: ' + pcl +
                    '. Number of passwords: ' + str(len(self.getData())),
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )
            self.printToFile(
                table,
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )


class LibrariesSummaryTransformedPass(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['trans_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.applyFilter()

        unfiltered_data = self.getData()

        folder_path = "outputs/" + self.__class__.__name__
        self.createFolder(folder_path)
        folder_path += "/"

        table_1 = data_table.OverallSummary(self.getData()).getTable()
        self.printToFile(
            table_1,
            filename=folder_path + "summary_" + self.__class__.__name__
        )

        pcl_list = ['CrackLib', 'PassWDQC', 'Passfault', 'ZxcvbnPython', 'ZxcvbnC']
        for pcl in pcl_list:
            self.setData(unfiltered_data)
            self.clearFilter()
            self.addFilter(data_filter.TransformedPCLOutputIsNotOk([pcl]))
            self.applyFilter()
            table_2 = data_table.ComplexPassword(
                self.getData()
            ).getTable(
                #start=0,
                #end=200,
            )
            self.printToFile(
                'PCL: ' + pcl +
                    '. Number of passwords: ' + str(len(self.getData())),
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )
            self.printToFile(
                table_2,
                filename=folder_path + pcl + "_" + self.__class__.__name__
            )


class ZxcvbnImplementacionComparison(AnalysisTemplate):

    def runAnalysis(self):
        #self.setData(self.analyzer.data_set['all_passwords'])
        self.setData(self.analyzer.data_set['trans_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore({
            'ZxcvbnPython': 3,
            'ZxcvbnC': 37
        }))
        '''
        self.addFilter(data_filter.AddNumberOfUsesToPassData(
            'inputs/rockyou-withcount/data.txt'
        ))
        '''
        self.applyFilter()

        '''
        table = data_table.ComplexPasswordWithNumberOfUses(self.getData()).getTable(
            start=0,
            end=5000
        )
        '''
        table = data_table.OverallSummary(self.getData()).getTable(
            start=0,
            end=40,
            fields=[
                'ZxcvbnC accepted', 'ZxcvbnC rejected',
                'ZxcvbnC reasons of rejection',
                'ZxcvbnPython accepted', 'ZxcvbnPython rejected',
                'ZxcvbnPython reasons of rejection'
            ]
        )
        self.printToFile(table)
