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
passwordList = dataLoader.LoadFromStdin().load()
passwordList = dataLoader.LoadFromFile("file_path").load()
passwordList = dataLoader.LoadFromJson("file_path").load()
```

#### Apply different rules to transform passwordData
##### Create transformation class
```python
transformation = Transformation()
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

#### Check passwords with implemented password checking libraries
##### Create password checking libraries class
```python
pcl = PassCheckLib()
```
##### Add password checking libraries
```python
pcl.add(libCheck.CrackLib())
pcl.add(libCheck.PassWDQC())
```
##### Check passwords with password checking libraries
```python
pclData = pcl.check(passInfoList)
```

#### Store data to Json
```python
dataLoader.StoreDataToJson().store(passInfoList, pclData)
```

### Analyzer
Simple output is printed to stdout. Whole analysis output written to *outputs/analysis_date_time.output* file
#### Create main analyzer
```python
analyzer = Analyzer(passInfoList, pclData)
```
#### Run list of analyzes and extract their output
##### Add analysis
```python
analyzer.addAnalysis(PCLOutputChanged_Ok2NotOK(analyzer))
analyzer.addAnalysis(PCLOutputChanged_NotOk2Ok(analyzer))
analyzer.addAnalysis(PCLOutputChanged_NotOk2NotOk(analyzer))
analyzer.addAnalysis(lowEntropyOriginalPasswordPassPCL(analyzer))
analyzer.addAnalysis(highEntropyOriginalPasswordDontPassPCL(analyzer))
analyzer.addAnalysis(lowEntropyTransformedPasswordPassPCL(analyzer))
analyzer.addAnalysis(highEntropyTransformedPasswordDontPassPCL(analyzer))
analyzer.addAnalysis(lowEntropyChangePassPCL(analyzer))
analyzer.addAnalysis(overallSummary(analyzer))
```
##### Run list of analyzes
```python
anlyzer.runAnalyzes()
```
##### Extract their output
```python
analyzer.printAnalysisOutput()
```

#### Run one analysis
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
