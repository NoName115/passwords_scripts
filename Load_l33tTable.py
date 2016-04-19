

class l33tTable:

    def __init__(self, fileName):
        print(fileName)

        with open(fileName, 'r') as l33tInput:
            self.table = []

            for line in l33tInput:
                line = line.strip("\n")
                line = line.split(" ")

                self.table.append(line)





