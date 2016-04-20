#passStruct.output	- heslo + entropy
#craclib.output		- heslo + vysledok cracklib-check

import PassStruct

with open("passStruct.output", "r") as inputFile:
	lines = []
	for line in inputFile:
		zat = line.strip("\n")
		zat = zat.split(": ")
		lines.append(PassStruct.PassData(zat[0], zat[1], None))


with open("cracklib.output", "r") as inputFile:
	for line in inputFile:
		zat = line.strip("\n")
		zat = zat.split(": ")

		index = -1;
		for i in range(len(lines)):
			if (lines[i].password == zat[0]):
				index = i;
				break;

		if (index != -1):
			lines[index].cracklibCheck = zat[1]

for i in range(len(lines)):
	print(lines[i].password + ": " + lines[i].entropy + " : " + lines[i].cracklibCheck)