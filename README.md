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
passwordData = loadData.LoadFromFile("file_path").transformToPassData()
passwordData = loadData.LoadFromJson("file_path").transformToPassData()
passwordData = loadData.LoadFromStdin().transformToPassData()
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
libCheck.CrackLib().checkResult(passwordData)
libCheck.PassWDQC().checkResult(passwordData)
```

#### Store password data
```python
passwordData.storeDataToJson("file_path")
```

#### Run analyzer
```python
analyzer = analysisStruct.Analyzer(passwordData)
analyzer.mainAnalysis()
```

#### Get analysis output
Simple output is printed to stdout. Whole analysis output is in *outputs/analysis_date_time.output* file
```python
analysisStruct.AnalyzerPrinter(analyzer).printMainAnalysis()
```
