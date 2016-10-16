from termcolor import colored


class Tager(object):

    def __init__(self):
        pass

    def tagPasswords(self, passwordData):
        for xPassword in passwordData:

            # Password length
            if (len(xPassword.password) <= 8):
                self.addTag(xPassword, "Password_Length", 2)
            else:
                self.addTag(xPassword, "Password_Length", 4)

            # Contain number
            if (any(c.isdigit() for c in xPassword.password)):
                self.addTag(xPassword, "Numbers", 2)

            # Contain letters
            if (any(c.isalpha() for c in xPassword.password)):
                self.addTag(xPassword, "Letters", 2)

            # Contain uppercase letter
            if (any(c.isupper() for c in xPassword.password)):
                self.addTag(xPassword, "Letter_Uppercase", 2)

            # Contain lowercase letter
            if (any(c.islower() for c in xPassword.password)):
                self.addTag(xPassword, "Letter_Lowercase", 2)

            # Contain symbols
            for c in xPassword.password:
                if ((c.isalpha() == False) and (c.isdigit() == False)):
                    self.addTag(xPassword, "Symbols", 2)
                    continue

        passwordData.isTagged = True

    def addTag(self, xPassword, tag, value):
        xPassword.tags.append([tag, value])

    # DEBUG method
    def printTags(self, passwordData):
        for xPassword in passwordData:
            print (xPassword.tags)


class Analyzer(object):

    def __init__(self):
        pass

    def simpleAnalyze(self, passwordData):
        if (passwordData.isTagged is False):
            Tager().tagPasswords(passwordData)

        interStrongPasswords = []
        interWeakPasswords = []

        for xPassword in passwordData:
            # Calculate password rating
            passwordRating = 0
            for tag in xPassword.tags:
                passwordRating += tag[1]

            # Interesting weak password
            if (passwordRating <= 11):
                self.addInterestPassword(xPassword, interWeakPasswords, True)
            else:
                self.addInterestPassword(
                    xPassword,
                    interStrongPasswords,
                    False)

        # Print analyze output
        # Print strong passwords with not OK libCheck output
        print (colored("Strong passwords: ", "yellow"))

        for strongPassword in interStrongPasswords:
            print (strongPassword.password)

            for key in strongPassword.libReasonOutput:
                if (strongPassword.libReasonOutput[key] != "OK"):
                    print ('{0:8} - {1:2}'.format(
                        key,
                        strongPassword.libReasonOutput[key].decode('UTF-8')
                        ) + '\n')

        # Print weak passwords with OK libCheck output
        print (colored("Weak passwords: ", "yellow"))

        for weakPassword in interWeakPasswords:
            print (weakPassword.password)

            for key in weakPassword.libReasonOutput:
                if (weakPassword.libReasonOutput[key] == "OK"):
                    print ('{0:8} - {1:2}'.format(
                        key,
                        weakPassword.libReasonOutput[key].decode('UTF-8')
                        ) + '\n')

    def addInterestPassword(self, xPassword, listToAdd, isOK):
        for key, value in xPassword.libReasonOutput.items():
            if ((value == "OK") == isOK):
                listToAdd.append(xPassword)
                break
