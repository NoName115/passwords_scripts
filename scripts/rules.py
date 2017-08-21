from abc import ABCMeta, abstractmethod
from scripts.passStruct import PassInfo, PassData
from random import randint


class Transformation():

    def __init__(self):
        self.transformation_list = []

    def add(self, transformation):
        self.transformation_list.append(transformation)

    def apply(self, password_list):
        print("Transformation...")
        passinfo_list = []
        used_transformations = []

        for password in password_list:
            if (type(password) is not PassData):
                orig_passinfo = PassInfo(
                    password=password
                    )
                passinfo_list.append(orig_passinfo)

                if (self.transformation_list):
                    trans_passinfo = PassInfo(
                        password=password,
                        orig_passinfo=orig_passinfo
                        )
                    passinfo_list.append(trans_passinfo)
            else:
                if (hasattr(password, 'transform_rules')):
                    trans_passinfo = password
                else:
                    passinfo_list.append(password)
                    continue

            for trans in self.transformation_list:
                if (trans not in used_transformations):
                    print("Applying " + trans.__class__.__name__)
                    used_transformations.append(trans)

                trans.transform(trans_passinfo)

        print("Transformation DONE\n")

        return passinfo_list


class Rule():

    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, input_from_index, input_to_index):
        self.input_from_index = input_from_index
        self.input_to_index = input_to_index

    def transform(self, passinfo):
        """Main method for password transformation

        Method catch errors, calculate indexes,
        call uniqueTransform method
        """
        try:
            from_index = self.calculateFromIndex(
                passinfo.password
                )
            to_index = self.calculateToIndex(
                passinfo.password
                )

            if (from_index > to_index):
                passinfo.error_log.addError(
                    self.__class__.__name__,
                    "Wrong value of input data. " + '\n' +
                    "'from_index' must be same or lower than 'to_index'"
                    )
                return

            # transformOutput obtain transformed_password and entropy_change
            transform_output = self.uniqueTransform(
                passinfo, from_index, to_index
                )

            passinfo.password = transform_output[0]
            passinfo.addTransformRule(
                self.__class__.__name__,
                transform_output[1]
                )

        except TypeError:
            passinfo.error_log.addError(
                self.__class__.__name__,
                "Argument 'from_index' or 'to_index' is not a number. " +
                '\n ' + "Input format: " +
                "rules.rule_name(from_index, to_index).transform(passwordData)"
                )

    @abstractmethod
    def uniqueTransform(self, passinfo, from_index, to_index):
        """
        Return:
        transformed_password -- string
        entropy_change -- float number
        """
        pass

    def calculateFromIndex(self, input_password):
        return self.input_from_index if self.input_from_index != -1 \
               else (len(input_password) - 1)

    def calculateToIndex(self, input_password):
        return self.input_to_index if self.input_to_index != -1 \
               else (len(input_password) - 1)


class ApplySimplel33tFromIndexToIndex(Rule):

    def __init__(self, from_index, to_index):
        super(ApplySimplel33tFromIndexToIndex,
              self).__init__(from_index, to_index)
        self.l33t_table = {
                'a': ['4', '@'],
                'b': ['8'],
                'e': ['3'],
                'g': ['6', '9', '&'],
                'h': ['#'],
                'i': ['1', '!', '|'],
                'l': ['1', '|'],
                'o': ['0'],
                's': ['5', '$'],
                't': ['7'],
                'z': ['2'],
        }

    def uniqueTransform(self, passinfo, from_index, to_index):
        """Apply simple l33t table at X letters in password

        Arguments:
        passinfo -- type of passStruct.Password
        from_index -- start index of applying the rule
        to_index -- last index of applying the rule
        """
        transformed_password = list(
            passinfo.password[from_index: to_index + 1]
            )
        for char, index in zip(
            transformed_password,
            range(0, len(transformed_password))
        ):
            if (char in self.l33t_table):
                transformed_password[index] = self.l33t_table[char][
                    randint(0, len(self.l33t_table[char]) - 1)
                    ]

        transformed_password = passinfo.password[: from_index] + \
            ''.join(transformed_password) + passinfo.password[to_index + 1:]

        # Check if transformation changed the password
        entropy_change = 0.0
        if (passinfo.password != transformed_password):
            entropy_change = 1.0

        return [transformed_password, entropy_change]


class ApplySimplel33tTable(ApplySimplel33tFromIndexToIndex):

    def __init__(self):
        super(ApplySimplel33tTable, self).__init__(0, -1)


class ApplyAdvancedl33tFromIndexToIndex(Rule):

    def __init__(self, from_index, to_index):
        super(ApplyAdvancedl33tFromIndexToIndex,
              self).__init__(from_index, to_index)
        self.l33t_table = {
                'a': ['4', '/-\\', '@', '^'],
                'b': ['8', ']3', '13'],
                'c': ['(', '{', '[[', '<'],
                'd': [')', '|)'],
                'e': ['3', 'ii'],
                'f': ['|=', 'ph'],
                'g': ['6', '9', '&'],
                'h': ['#', '|-|', ')-(', '/-/', '|~|'],
                'i': ['1', '!', '|'],
                'j': ['_|', 'u|'],
                'k': ['|<', '|{'],
                'l': ['|', '1', '|_'],
                'm': ['/\\/\\', '|\\/|', '[\\/]'],
                'n': ['/\\/', '|\\|', '~'],
                'o': ['0', '()'],
                'p': ['|D', '|*', '|>'],
                'q': ['(,)', '0,', 'O,', 'O\\'],
                'r': ['|2', '|?', '|-'],
                's': ['5', '$'],
                't': ['7', '+', '7`', "']['"],
                'u': ['|_|', '\\_\\', '/_/', '(_)'],
                'v': ['\\/'],
                'w': ['\\/\\/', '|/\\|', 'VV', '///', '\\^/'],
                'x': ['><'],
                'y': ["'/", '%', '`/', 'j'],
                'z': ['2', '7_']
        }

    def uniqueTransform(self, passinfo, from_index, to_index):
        """Apply advanced l33t table at X letters in password

        Arguments:
        passinfo -- type of passStruct.Password
        from_index -- start index of applying the rule
        to_index -- last index of applying the rule
        """
        transformed_password = list(
            passinfo.password[from_index: to_index + 1]
            )
        for char, index in zip(
            transformed_password,
            range(0, len(transformed_password))
        ):
            if (char in self.l33t_table):
                transformed_password[index] = self.l33t_table[char][
                    randint(0, len(self.l33t_table[char]) - 1)
                    ]

        transformed_password = passinfo.password[: from_index] + \
            ''.join(transformed_password) + passinfo.password[to_index + 1:]

        # Check if transformation changed the password
        entropy_change = 0.0
        if (passinfo.password != transformed_password):
            entropy_change = 2.0

        return [transformed_password, entropy_change]


class ApplyAdvancedl33tTable(ApplyAdvancedl33tFromIndexToIndex):

    def __init__(self):
        super(ApplyAdvancedl33tTable, self).__init__(0, -1)


class CapitalizeFromIndexToIndex(Rule):

    def __init__(self, from_index, to_index):
        super(CapitalizeFromIndexToIndex, self).__init__(from_index, to_index)

    def uniqueTransform(self, passinfo, from_index, to_index):
        """Captalize X letters in password

        Arguments:
        passinfo -- type of passStruct.Password
        from_index -- start index of applying the rule
        to_index -- last index of applying the rule
        """
        transformed_password = passinfo.password[: from_index] + \
            passinfo.password[from_index: to_index + 1].upper() + \
            passinfo.password[to_index + 1:]

        # Check if transformation changed the password
        entropy_change = 0.0
        if (passinfo.password != transformed_password):
            entropy_change = 1.0

        return [transformed_password, entropy_change]


class CapitalizeAllLetters(CapitalizeFromIndexToIndex):

    def __init__(self):
        super(CapitalizeAllLetters, self).__init__(0, -1)


class CapitalizeFirstLetter(CapitalizeFromIndexToIndex):

    def __init__(self):
        super(CapitalizeFirstLetter, self).__init__(0, 0)


class CapitalizeLastLetter(CapitalizeFromIndexToIndex):

    def __init__(self):
        super(CapitalizeLastLetter, self).__init__(-1, -1)


class LowerFromIndexToIndex(Rule):

    def __init__(self, from_index, to_index):
        super(LowerFromIndexToIndex, self).__init__(from_index, to_index)

    def uniqueTransform(self, passinfo, from_index, to_index):
        """Lower X letters in password

        Arguments:
        passinfo -- type of passStruct.Password
        from_index -- start index of applying the rule
        to_index -- last index of applying the rule
        """
        transformed_password = passinfo.password[: from_index] + \
            passinfo.password[from_index: to_index + 1].lower() + \
            passinfo.password[to_index + 1:]

        # Check if transformation changed the password
        entropy_change = 0.0
        if (passinfo.password != transformed_password):
            entropy_change = 1.0

        return [transformed_password, entropy_change]


class LowerAllLetters(LowerFromIndexToIndex):

    def __init__(self):
        super(LowerAllLetters, self).__init__(0, -1)


class LowerFirstLetter(LowerFromIndexToIndex):

    def __init__(self):
        super(LowerFirstLetter, self).__init__(0, 0)


class LowerLastLetter(LowerFromIndexToIndex):

    def __init__(self):
        super(LowerLastLetter, self).__init__(-1, -1)


class AddStringAsPostfixOrPrefix(Rule):

    def __init__(self, string_to_add, entropy_change):
        super(AddStringAsPostfixOrPrefix, self).__init__(0, 0)
        self.string_to_add = string_to_add
        self.entropy_change = entropy_change

    def uniqueTransform(self, passinfo, from_index, to_index):
        transformed_password = passinfo.password

        postfix_or_prefix = self.string_to_add
        if (type(self.string_to_add) is list):
            postfix_or_prefix = self.string_to_add[randint(
                0,
                len(self.string_to_add) - 1
                )]

        # If == 1, add string as prefix, else as postfix
        if (randint(0, 1)):
            transformed_password = postfix_or_prefix + transformed_password
        else:
            transformed_password += postfix_or_prefix

        return [transformed_password, self.entropy_change]


class AddOneAsPostfixOrPrefix(AddStringAsPostfixOrPrefix):

    def __init__(self):
        super(AddOneAsPostfixOrPrefix, self).__init__('1', 1)


class AddExclamationMarkAsPostfixOrPrefix(AddStringAsPostfixOrPrefix):

    def __init__(self):
        super(AddExclamationMarkAsPostfixOrPrefix, self).__init__('!', 1)


class AddRandomTitleNameAsPostfixOrPrefix(AddStringAsPostfixOrPrefix):

    def __init__(self):
        super(AddRandomTitleNameAsPostfixOrPrefix, self).__init__(
            ['Mc', 'Mac', 'Dr', 'Ms', 'Mr', 'Mrs'],
            1
            )


class AddTwoRandomDigitsAsPrefix(Rule):

    def __init__(self):
        super(AddTwoRandomDigitsAsPrefix, self).__init__(0, 0)

    def uniqueTransform(self, passinfo, from_index, to_index):
        digits = str(randint(0, 9)) + str(randint(0, 9))
        transformed_password = digits + passinfo.password
        
        # Postfix or prefix a random digit with zero
        if (digits[1] == '0'):
            entropy_change = 3.5
        # Postfix or prefix a short(<3) sequence of digits
        elif ((int(digits[1]) - int(digits[0])) == 1):
            # Postfix or prefix a sequence of number starting from 1
            if (digits[0] == '1'):
                entropy_change = 1
            else:
                entropy_change = 3.5
        # Postfix or prefix a short(<3) repetion of digit
        elif (digits[0] == digits[1]):
            entropy_change = 3.5
        else:
            entropy_change = 6.5

        return [transformed_password, entropy_change]


class ChangeFirstLetterToRandomLetter(Rule):

    def __init__(self):
        super(ChangeFirstLetterToRandomLetter, self).__init__(0, 0)

    def uniqueTransform(self, passinfo, from_index, to_index):
        transformed_password = passinfo.password
        entropy_change = 0

        for c, i in zip(
            transformed_password,
            range(0, len(transformed_password))
        ):
            if (c.islower() or c.isupper()):
                transformed_password = transformed_password[0: i] + \
                    chr(randint(97, 122)) + transformed_password[i + 1:]
                entropy_change = 4.5
                break

        return [transformed_password, entropy_change]


class ChangeRandomLetterToRandomLetter(Rule):

    def __init__(self):
        super(ChangeRandomLetterToRandomLetter, self).__init__(0, 0)

    def uniqueTransform(self, passinfo, from_index, to_index):
        transformed_password = passinfo.password
        entropy_change = 0
        character_index_list = []

        for c, i in zip(
            transformed_password,
            range(0, len(transformed_password))
        ):
            if (c.islower() or c.isupper()):
                character_index_list.append(i)

        if (character_index_list):
            random_index = character_index_list[randint(
                0,
                len(character_index_list) - 1
                )]
            transformed_password = transformed_password[0: random_index] + \
                chr(randint(97, 122)) + transformed_password[random_index + 1:]

            # If random letter is first letter, it is different transformation
            if (random_index == 0):
                entropy_change = 4.5
            else:
                entropy_change = 7.5

        return [transformed_password, entropy_change]
