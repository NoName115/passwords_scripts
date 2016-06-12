from sys import exit
from termcolor import colored

#Print error message and terminate program
def printError(className, errorText):
	print colored("Error: ", "red"), '{0:13} - {1:30}'.format(className, errorText)
	exit(0)

#Print warning message, program is not teminated
def printWarning(className, errorText):
	print colored("Warning: ", "yellow"), '{0:13} - {1:30}'.format(className, errorText)
