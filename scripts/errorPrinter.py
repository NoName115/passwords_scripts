from sys import exit


"""Dictionary that store main errors

Especcialy, wrong type of input data
"""
main_error = {}


def addMainError(class_name, error_text):
    """Store main_error message

    Arguments:
    class_name -- name of the class in which error occured
    error_text -- details about error
    """
    main_error.update({class_name: error_text})


class RuleError():

    def __init__(self, error_log=None):
        """Iniatialize class for storing errors

        Self:
        error_log -- dictionary of errors ({class_name : errorDetails})
        """
        self.error_log = error_log if (error_log) else {}

    def addError(self, class_name, error_text):
        """Store error message

        Arguments:
        class_name -- name of the class in which error occured
        error_text -- details about error
        """
        self.error_log.update({class_name: error_text})

    def getLog(self):
        return self.error_log


def printError(class_name, error_text):
    """Print error message and terminate program

    Arguments:
    class_name -- name of the class that called this method
    error_text -- details about error
    """
    print('Error: ' + class_name + ' - ' + str(error_text))
    exit(-1)


def printWarning(class_name, error_text):
    """Print warning message

    Arguments:
    class_name -- name of the class that called this method
    error_text -- details about error
    """
    print('Warning: ' + class_name + ' - ' + str(error_text))
