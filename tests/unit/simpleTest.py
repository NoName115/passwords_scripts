import unittest

from scripts.passStruct import PassData
import scripts.rules as rules
import scripts.loadData as loadData

class SimpleTestEntropy(unittest.TestCase):

	def testCheckStartEntropy(self):
		self.passwordData = loadData.LoadFromFile("tests/unit/simpleInput").loadData()

		for password, x in zip(self.passwordData, [10, 25, 8, 8, 8, 5, 1, 9]):
			self.assertEqual(password.entropy, x)

	def testCheckChangedEntropy(self):
		self.passwordData = loadData.LoadFromFile("tests/unit/simpleInput").loadData()

		self.assertIsNone(rules.CapitalizeAllLetters().transform(self.passwordData))

		for password, x in zip(self.passwordData, [11, 26, 8, 9, 8, 5, 1, 10]):
			self.assertEqual(password.actualEntropy, x)

if __name__ == '__main__':
	unittest.main(exit=False)