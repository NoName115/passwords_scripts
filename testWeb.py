import scripts.rules as rules
import scripts.libCheck as libCheck
import scripts.loadData as loadData

passwordList = loadData.LoadFromStdin().loadData()

rules.DeleteLetter(2).transform(passwordList)

passwordList.printLibCheckData()

