from abc import ABCMeta, abstractmethod
from prettytable import PrettyTable


class FilterTemplate():
    
    __metaclass__ = ABCMeta

    def __init__(self, variable=None):
        if (variable):
            self.variable = variable

    @abstractmethod
    def apply(self, data):
        pass

class LowEntropyFilter(FilterTemplate):

    def apply(self, data):
        low_entropy_data = list(filter(
            lambda passdata: passdata.entropy <= self.variable,
            data
            ))

        return low_entropy_data


class HighEntropyFilter(FilterTemplate):

    def apply(self, data):
        high_entropy_data = list(filter(
            lambda passdata: passdata.entropy >= self.variable,
            data
            ))

        return high_entropy_data


class PCLOutputChangedFromOk2NotOk(FilterTemplate):

    def apply(self, data):
        filtered_data = []
        for passdata in data:
            if (hasattr(passdata, 'transform_rules')):
                # Check only one PCL or check it for all PCLs
                pcl_list = [self.variable] if (hasattr(self, 'variable')) \
                    else passdata.pcl_output.keys()

                for pcl in pcl_list:
                    if (passdata.orig_passdata.pcl_output[pcl] == "OK" and
                       passdata.pcl_output[pcl] != "OK"):
                        filtered_data.append(passdata)
                        break

        return filtered_data


class PCLOutputChangedFromNotOk2Ok(FilterTemplate):

    def apply(self, data):
        filtered_data = []
        for passdata in data:
            if (hasattr(passdata, 'transform_rules')):
                # Check only one PCL or check it for all PCLs
                pcl_list = [self.variable] if (hasattr(self, 'variable')) \
                    else passdata.pcl_output.keys()

                for pcl in pcl_list:
                    if (passdata.orig_passdata.pcl_output[pcl] != "OK" and
                       passdata.pcl_output[pcl] == "OK"):
                        filtered_data.append(passdata)
                        break

        return filtered_data


class PCLOutputsAreNotAllSame(FilterTemplate):

    def apply(self, data):
        filtered_data = []
        
        if (not self.data):
            return filtered_data
        
        pcl_list = data[0].pcl_output.keys()
        for passdata in data:
            counterOk = 0
            counterNotOk = 0
            for pcl in pcl_list:
                if (passdata.pcl_output[pcl] == "OK"):
                    counterOk += 1
                else:
                    counterNotOk += 1
            if (counterOk != len(pcl_list) and counterNotOk != len(pcl_list)):
                filtered_data.append(passdata)

        return filtered_data
