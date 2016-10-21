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
passwordData = loadData.LoadFromStdin().loadData()
```

#### Different rules to transform passwordData

You can apply any rule at any range of characters in password.

To apply rule only at one character write same index to both arguments.
```python
rules.__ruleName__(2, 2).transform(passwordList)
```

To apply rule at every character in password, set first argument to 0 and second to -1.
```python
rules.__ruleName__(0, -1).transform(passwordList)
```

To apply rule at range of characters in password.
For example to apply rule from second to fifth character:
```python
rules.__ruleName__(2, 5).transform(passwordList)
```

```python
rules.ApplySimplel33tFromIndexToIndex("fromIndex", "toIndex").transform(passwordList)
rules.ApplyAdvancedl33tFromIndexToIndex("fromIndex", "toIndex").transform(passwordList)
rules.CapitalizeFromIndexToIndex("fromIndex", "toIndex").transform(passwordList)
rules.LowerFromIndexToIndex("fromIndex", "toIndex").transform(passwordList)
```

#### Implemented password checking libraries
```python
libCheck.CrackLib().checkResult(passwordList)
libCheck.PassWDQC().checkResult(passwordList)
```

#### Run analyzer
```python
analyzer.Analyzer().mainAnalysis(passwordList)
```
