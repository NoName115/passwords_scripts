from abc import ABCMeta, abstractmethod
from prettytable import PrettyTable


class FilterTemplate():
    
    __metaclass__ = ABCMeta

    @abstractmethod
    def apply(self, data):
        pass

class LowEntropyFilter(FilterTemplate):

    def apply(self, data):
        low_entropy_data = list(filter(
            lambda passdata: passdata.entropy < 36,
            data
            ))

        return low_entropy_data
