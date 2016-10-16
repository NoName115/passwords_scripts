"""Configuration file

File obtain:
ruleEntropyValue -- value of entropy that is added when rule is applied
simpleL33tTable -- dictionary of simple l33t table rules
advancedL33tTable -- dictionary of advanced l33t table rules
"""

ruleEntropyValue = {
        'ApplySimplel33tFromIndexToIndex': 1,
        'ApplyAdvancedl33tFromIndexToIndex': 2,
        'CapitalizeFromIndexToIndex': 1,
        'LowerFromIndexToIndex': 1,
}

simpleL33tTable = {
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

advancedL33tTable = {
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
        'z': ['2', '7_'],
}
