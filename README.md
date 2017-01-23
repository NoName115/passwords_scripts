## Implement your own password checking library

In file *libCheck.py* you can add your own password checking library.
Create new class with your *checking_library_name*.
Output of your *checking_library_name* must be in format:

\_password\_ (spaces or tabs) \_checking_library_output\_

or

\_password\_ \_delimiter\_ \_checking_library_output\_

```python
class checking_library_name(Library):
  def __init__(self):
    super(checking_library_name, self).__init__()
    
  def checkResult(self, passwordData):
    """
    passwordData -- input data of type PassData
    delimiter -- optional argument, if is necessary to split library output
    *args -- arguments for run/call library
    """
    super(checking_library_name, self).checkResult(passwordData, delimiter, *args)
```



## Run simple analysis

Run *exampleAnalysis.py* to get a basic analysis of implemented password checking libraries.
You can edit analysis options by following commands:

#### Options to load input data:

```python
passwordData = loadData.LoadFromFile("file_path").loadData()
passwordData = loadData.LoadFromJson("file_path").loadData()
passwordData = loadData.LoadFromStdin().loadData()
```

#### Different rules to transform passwordData

```python
rules.CapitalizeAllLetters().transform(passwordData)
rules.CapitalizeFirstLetter().transform(passwordData)
rules.CapitalizeLastLetter().transform(passwordData)
rules.LowerAllLetters().transform(passwordData)
rules.LowerFirstLetter().transform(passwordData)
rules.LowerLastLetter().transform(passwordData)
rules.ApplySimplel33tTable().transform(passwordData)
rules.ApplyAdvancedl33tTable().transform(passwordData)
```

#### Implemented password checking libraries
```python
libCheck.CrackLib().checkResult(passwordList)
libCheck.PassWDQC().checkResult(passwordList)
```

#### Store password data
```python
passwordList.storeDataToJson("file_path")
```

#### Run analyzer
```python
analyzer.Analyzer().mainAnalysis(passwordList)
```
