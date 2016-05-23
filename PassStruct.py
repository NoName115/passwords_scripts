import random
import re

#Password structure
class PassData:

    #Initialize structure(object) for password
    #Password parameters
    #   password(String), entropy(number, >= 0), outputFromLibaryCheck(String)
    def __init__(self, password=None, entropy=None, libCheckOutput=None):
        if (password is not None) and (entropy is not None):

            self.password = password
            if (isinstance(entropy, int)) or (entropy.isdigit()):
                self.entropy = entropy
            else:
                self.SetNoneValues()
                print("Wrong input: entropy is not a number")
        else:
            self.SetNoneValues()
            print("Wrong input: password or entropy is empty")

    #PassData --> String
    def __str__(self):
        return '{0:12} : {1:4d} >> {2:1}'.format(self.password, self.entropy, self.libCheckOutput)

    #Set None value to Password parameters 
    def SetNoneValues(self):
        self.password = None
        self.entropy = None
        self.libCheckOutput = None


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

    #Capitalize all letters in password
    #Arguments: None
    def CapitalizeAllLetters(self):
        if (self.password is None) or (self.entropy is None):
            return

        self.password = self.password.upper()

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


