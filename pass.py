import sys
import random, subprocess

import PassStruct


#Load l33tTable
Table = PassStruct.l33tTable("Simple_l33t")
'''
#Load passwords from file and set entropy(random)
#with open("Test_Input.txt", "r") as fileInput:
#    passwords = []
#    for line in fileInput:
#        passwords.append(PassStruct.PassData(line.rstrip('\n'), random.randint(1, 200), None))

#Get input(passwords) from STDIN
passwordList = []

for line in sys.stdin:
    passwordList.append(PassStruct.PassData(line.rstrip('\n'), random.randint(1, 50), None))


#Apply rules for passwordList
for i in range(len(passwordList)):

    passwordList[i].Applyl33t(Table.table)
    passwordList[i].CapitalizeAllLetters()
'''

#Call cracklib-check
for i in range(len(passwordList)):
	#cracklib-check		pwqcheck -1
	#["pwqcheck", "-1"]

    p = subprocess.Popen(["cracklib-check"], stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    output = p.communicate(input = passwordList[i].password)[0].rstrip('\n')

    doc = output.split(": ")
    libOutput = ""

    if (len(doc) > 1):
    	libOutput = doc[1]
    else:
    	libOutput = doc[0]

    passwordList[i].libCheckOutput = libOutput

    print passwordList[i]
