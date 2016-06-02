import random
import re

from math import log

#Class Password
class Password():

    #Arguments: password(String), entropy(number, >= 0), libraryOutput(String)
    def __init__(self, password=None, entropy=None, libReasonOutput=None):
        self.password = password
        self.entropy = entropy
        self.libReasonOutput = libReasonOutput
        self.libCheck = False

    #Output format: Password : Entropy >> LibraryOutput
    def __str__(self):
        return '{0:12} : {1:.2f}  >>  {2:1}'.format(self.password, self.entropy, self.libReasonOutput)



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
            self.passwordList.append(Password(args[0], self.generateEntropy(args[0]), None))
        elif (len(args) == 2):
            if (isinstance(args[1], int) or args[1].isdigit()):
                self.passwordList.append(Password(args[0], args[1], None))
            else:
                print("Wrong second argument - Password not added to list")
        else:
            print("Wrong number of arguments - Correct: password(String), entropy(Number) - optional argument")

    #Print all passwords from list
    #Output format: Password : Entropy >> LibraryOutput
    def printAll(self):
        for x in self.passwordList:
            print x

    #Method return float number(entropy)
    #Entropy calculated by basic formula
    # n: password length
    # c: password cardinality: the size of the symbol space
    #    (26 for lowercase letters only, 62 for a mix of lower+upper+numbers)
    # entropy = n * log(c)  # log - base 2
    def generateEntropy(self, inputPassword):
        if (any(c.isupper() for c in inputPassword) or any(c.isdigit() for c in inputPassword)):
            return len(inputPassword) * log(62, 2)
        else:
            return len(inputPassword) * log(26, 2)

    '''
    #####################################################################
    ######################## Password Rules #############################
    #####################################################################

    #Simple/Advande l33t table
    #Arguments: table(class l33tTable)
    def Applyl33t(self, table):
        if (self.password is None) or (self.entropy is None):
            return

        if table is None:
            print("Wrong input: table is empty")

        password = self.password

        for i in range(len(table)):
            password = password.replace(table[i][0], table[i][random.randint(1, len(table[i]) - 1)])
            self.password = password


    #Capitalize one letter from password at certain index
    #Arguments: Index(number)
    def CapitalizeLetterAtIndex(self, indx):
        if (self.password is None) or (self.entropy is None) or (indx is None):
            return

        if (len(self.password) - 1 < indx) or (indx < 0):
            return

        if (isinstance(indx, int)) or (indx.isdigit()):
            self.password = self.password[:indx] + self.password[indx].upper() + self.password[indx + 1:]

    #Delete letter at index from password
    #Arguments: Index(number)
    def DeleteLetter(self, indx):
        passwo = self.password
        passwo = re.sub(passwo[indx], '', passwo)

        self.password = passwo

    def PrintAscii(self, asciiCode):
        print(chr(asciiCode))
    '''


#Class for loading l33tTables
class l33tTable:

    #Initialize table and load Data from file
    #Arguments: fileName(String)
    def __init__(self, fileName):
        with open(fileName, 'r') as l33tInput:
            self.table = []

            for line in l33tInput:
                line = line.strip("\n")
                line = line.split(" ")

                self.table.append(line)