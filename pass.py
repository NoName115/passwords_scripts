import random

import PassStruct


#Load Table
Table = PassStruct.l33tTable("Simple_l33t")

#Read input file
with open("Test_Input.txt", "r") as fileInput:
    lines = []
    for line in fileInput:
        lines.append(PassStruct.PassData(line.rstrip('\n'), random.randint(1, 200), None))

#Apply rules
for i in range(len(lines)):
    #lines[i].PrintAscii(97)

    #lines[i].DeleteLetter(0)
    #lines[i].CapitalizeLetterAtIndex(5)

    lines[i].Applyl33t(Table.table)
    #lines[i].CapitalizeAllLetters()

    #Print password
   # print(lines[i].password, ": ", lines[i].entropy);
    print(lines[i].password);

#------------------------------------
f = open("passStruct.output", "w")
for i in range(len(lines)):
    f.write(lines[i].password + ": " + str(lines[i].entropy) + "\n")
f.close()

