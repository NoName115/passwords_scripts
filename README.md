## Implement your own password checking library

In file *libCheck.py* you can add your own password checking library.
Create new class with your *checking_library_name*.

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
passwordData = loadData.LoadFromStdin().loadData()
```

#### Different rules to transform passwordData
```python
rules.ApplySimplel33t().transform(passwordData)
rules.ApplyAdvancedl33t().transform(passwordData)
rules.CapitalizeAllLetters().transform(passwordData)
rules.LowerAllLetters().transform(passwordData)
rules.CapitalizeLetterAtIndex("index").transform(passwordData)
rules.DeleteLetterAtIndex("index").transform(passwordData)
```

#### Implemented password checking libraries
```python
libCheck.CrackLib().checkResult(passwordList)
libCheck.PassWDQC().checkResult(passwordList)
```

#### Run analyzer
```python
analyzer.Analyzer().simpleAnalyze(passwordList)
```
