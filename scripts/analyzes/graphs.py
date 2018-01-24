from scripts.analysisBase import AnalysisTemplate
from matplotlib.transforms import Bbox

import scripts.filter as data_filter
import scripts.table as data_table
import matplotlib.pyplot as plt
import numpy as np
import math


class ScoreHistogram(AnalysisTemplate):

    def runAnalysis(self):
        self.setData(self.analyzer.data_set['all_passwords'])

        self.addFilter(data_filter.ChangePCLOutputByScore())
        self.applyFilter()

        # Calculate passwords score by PCL
        pass_score = {
            'CrackLib': {},
            'PassWDQC': {},
            'Passfault': {},
            'Pwscore': {},
            'Zxcvbn': {},
        }
        pcl_to_remove = set()
        for passdata in self.getData():
            for pcl in pass_score.keys():
                try:
                    pcl_score = passdata.getPCLScore(pcl)
                except KeyError:
                    pcl_to_remove.add(pcl)
                    continue

                # Set score as 0 or 1 if output is N'OK or OK
                if (pcl_score == None):
                    pcl_score = 0 if (passdata.getPCLOutput(pcl) != "OK") else 1

                # Calculate score value for Passfault library
                if (pcl == 'Passfault'):
                    pcl_score = round(math.log(pcl_score, 2))
                
                # Initialize or increment pcl counter
                if (pcl_score not in pass_score[pcl]):
                    pass_score[pcl].update({
                        pcl_score: 0
                    })
                else:
                    pass_score[pcl][pcl_score] += 1

            # Remove pcl from pass_score
            for pcl in pcl_to_remove:
                pass_score.pop(pcl, None)

        # the x locations for the groups
        N = max([len(value) for pcl, value in pass_score.items()])
        ind = np.arange(N)
        color = ['r', 'b', 'g', 'y', 'c']
        pcl_shorcut = {
            'CrackLib': 'CL',
            'PassWDQC': 'PW',
            'Passfault': 'PF',
            'Pwscore': 'PS',
            'Zxcvbn': 'ZX',
        }
        # the width of the bars
        width = 0.5

        fig, ax = plt.subplots()

        rects_list = []
        for i, pcl in enumerate(pass_score):
            rects_list.append(
                ax.bar(
                    np.arange(len(pass_score[pcl].keys())) * 2.5 + i * width,
                    pass_score[pcl].values(),
                    width,
                    color=color[i],
                    label=pcl
                )
            )

        ax.set_xticks(ind * 2.5 + width * 2)
        ax.set_xticklabels(range(0, N))

        def autolabel(rects):
            """
            Attach a text label above each bar displaying its height
            """
            label = rects.get_label()
            for rect in rects:
                height = rect.get_height()
                ax.text(
                    rect.get_x() + rect.get_width() / 2.,
                    1.05 * height,
                    '{0:d} ({1:1})'.format(
                        int(height),
                        pcl_shorcut[label]
                    ),
                    ha='center',
                    va='bottom',
                    rotation=90,
                    fontsize=7
                )

        ax.legend()
        for rects in rects_list:
            autolabel(rects)

        ax.set_xlabel('Password score')
        ax.set_ylabel('Passwords')

        fig.set_size_inches(30, 9)
        fig.savefig(
            fname='outputs/' + self.__class__.__name__ + '.pdf',
            orientation='landscape',
        )
        #plt.show()
