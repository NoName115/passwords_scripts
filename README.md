[![Code Climate](https://codeclimate.com/github/redhat-qe-security/pcl-analyzer/badges/gpa.svg)](https://codeclimate.com/github/redhat-qe-security/pcl-analyzer)


## Implement your own password checking library

In file *libCheck.py* you can add your own password checking library.
Create new class with your *password_checking_library_name*.
Output of your *password_checking_library_name* must be in format:

\_password\_ (spaces or tabs) \_checking_library_output\_

or

\_password\_ \_delimiter\_ \_checking_library_output\_

```python
class password_checking_library_name(Library):
  def __init__(self):
    super(password_checking_library_name, self).__init__()

  def checkResult(self, passInfo, pclDic):
    """
    passInfo -- type Password from passStruct.py
    pclDic -- dictionary
    delimiter -- optional argument, if is necessary to split library output
    *args -- arguments for run/call library
    """
    super(password_checking_library_name, self).checkResult(passInfo, pclDic, delimiter, *args)
```



## Run analysis

Run *exampleAnalysis.py* to get a basic analysis of implemented password checking libraries.
You can edit analysis options by following commands:

### Options to load input data:

```python
passwordList = dataLoader.LoadFromStdin().load()
passwordList = dataLoader.LoadFromFile("file_path").load()
passwordList = dataLoader.LoadFromJson("file_path").load()
```

### Apply different rules to transform passwordData
##### Create transformation class
```python
transformation = rules.Transformation()
```
##### Add rules
```python
transformation.add(rules.CapitalizeAllLetters())
transformation.add(rules.CapitalizeFirstLetter())
transformation.add(rules.CapitalizeLastLetter())
transformation.add(rules.LowerAllLetters())
transformation.add(rules.LowerFirstLetter())
transformation.add(rules.LowerLastLetter())
transformation.add(rules.ApplySimplel33tTable())
transformation.add(rules.ApplyAdvancedl33tTable())
```
##### Applying transformations to passwords
```python
passInfoList = list(map(
  lambda password: transformation.apply(password),
	passwordList
	))
```

### Check passwords with implemented password checking libraries
##### Create password checking libraries class
```python
pcl = PassCheckLib()
```
##### Add password checking library
```python
pcl.add(libCheck.CrackLib())
pcl.add(libCheck.PassWDQC())
```
##### Check passwords with password checking libraries
```python
pclData = pcl.check(passInfoList)
```

### Store data to Json
```python
dataLoader.StoreDataToJson().store(passInfoList, pclData)
```

### Create main analyzer
Simple output is printed to stdout. Whole analysis output is written to *outputs/analysis_date_time.output* file
```python
analyzer = Analyzer(passInfoList, pclData)
```
### Run list of analyzes and extract their output
##### Add analysis
```python
analyzer.addAnalysis(PCLOutputChanged_Ok2NotOK())
analyzer.addAnalysis(PCLOutputChanged_NotOk2Ok())
analyzer.addAnalysis(PCLOutputChanged_NotOk2NotOk())
analyzer.addAnalysis(lowEntropyOriginalPasswordPassPCL())
analyzer.addAnalysis(highEntropyOriginalPasswordDontPassPCL())
analyzer.addAnalysis(lowEntropyTransformedPasswordPassPCL())
analyzer.addAnalysis(highEntropyTransformedPasswordDontPassPCL())
analyzer.addAnalysis(lowEntropyChangePassPCL())
analyzer.addAnalysis(overallSummary())
```
##### Run list of analyzes
```python
anlyzer.runAnalyzes()
```
##### Extract their output
```python
analyzer.printAnalysisOutput()
```

### Run one analysis
##### Choose one analysis
```python
simpleAnalysis = PCLOutputChanged_Ok2NotOK(analyzer)
```
##### Run it
```python
simpleAnalysis.runAnalysis()
```
##### Get output
```python
print(simpleAnalysis.getAnalysisOutput())
```
