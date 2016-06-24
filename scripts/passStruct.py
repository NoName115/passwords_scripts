import random,re, errorPrinter

from math import log

#Class Password
class Password():

    #Arguments: password(String), entropy(number, >= 0), libraryOutput(String)
    def __init__(self, password=None, entropy=None):
        self.password = password
        self.entropy = entropy
        self.actualEntropy = entropy
        self.libReasonOutput = {}
        self.libCheck = False
        self.transformRules = []

    #Output format: Password : Entropy
    #               LibraryName - LibraryOutput
    def __str__(self):
        transformOutput = ''
        previousEntropy = self.entropy
        for element in self.transformRules:
            transformOutput += '{0:15} : {1:.2f} ({2:.2f})'.format(element[0], element[1], float(element[1]) - previousEntropy) + ' --> '
            previousEntropy = float(element[1])

        if (len(self.transformRules) == 0):
            transformOutput = "No password transform"

        libOutput = ''
        for key in self.libReasonOutput:
            libOutput += '{0:8} - {1:20}'.format(key, self.libReasonOutput[key]) + '\n'

        return '{0:15} : {1:.2f}'.format(self.password, self.entropy) + '\n' + transformOutput + '\n' + libOutput

    #Method add library output to dictionary
    #Arguments: libraryName(String), libOutput(String)
    def addLibOutput(self, libraryName, libOutput):
        self.libReasonOutput.update({libraryName : libOutput})


#Class create list of passwords
class PassData():

    #Initialize list(list of objects of type Password)
    def __init__(self):
        self.passwordList = []

    #Add new password to list
    #Arguments: password(string), entropy(number >= 0)
    #entropy is optional argument
    def add(self, *args):
        if (len(args) == 1):
            self.passwordList.append(Password(args[0], self.generateEntropy(args[0])))
        elif (len(args) == 2):
            try:
                self.passwordList.append(Password(args[0], round(args[1], 2)))
            except ValueError:
                errorPrinter.printWarning("Adding password to passwordData", '\'{0:1}\' is not a number'.format(args[1]))
        else:
            errorPrinter.printWarning("Adding password to passwordData", "Wrong number of arguments, Correct: password(String), entropy(Number) - optional argument")

    #Print all passwords from list
    #Output format: Password : Entropy >> LibraryOutput
    def printData(self):
        if (len(self.passwordList) == 0):
            errorPrinter.printWarning("printData", "PasswordData is empty... Nothing to write")
            return

        for x in self.passwordList:
            print x

    def __iter__(self):
        for x in self.passwordList:
            yield x

    #Method return float number(entropy)
    #Entropy calculated by basic formula
    # n: password length
    # c: password cardinality: the size of the symbol space
    #    (26 for lowercase letters only, 62 for a mix of lower+upper+numbers)
    # entropy = n * log(c)  # log - base 2
    def generateEntropy(self, inputPassword):
        if (any(c.isupper() for c in inputPassword) or any(c.isdigit() for c in inputPassword)):
            return round(len(inputPassword) * log(62, 2), 2)
        else:
            return round(len(inputPassword) * log(26, 2), 2)
