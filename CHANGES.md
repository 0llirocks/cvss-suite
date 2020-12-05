# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [1.2.3] - 2020-12-05

### Fixes
* CVSS v2 now returns the correct severity values based on NVD recommendation
* CVSS v2 now supports vectors which are enclosed in parenthesis e.g. (AV:N/AC:L/Au:N/C:P/I:P/A:P)

## [1.2.2] - 2020-07-19

### Fixes
Fixed an error that resulted in incorrect environmental score if modified attributes were not defined.

## [1.2.1] - 2020-05-10

### Improvements
* Added CvssSuite module to every class (thanks to @fwininger)
* Removed override for integer and float (thanks to @fwininger)
* Added rubocop to development environment (thanks to @fwininger)

### Notes
Adding CvssSuite module everywhere means it’s no longer possible to access a class without it. Since this only affects the undocumented and ‚internal‘ classes this should not affect you. If you’re using them, stop it.

Still works:

```ruby
cvss = CvssSuite.new('string')
```

Won’t work anymore (without any code change):

```ruby
cvss = Cvss31.new('string')
```

This would need to be CvssSuite::Cvss31.new('string') to work. Or you could include the whole namespace.

## [1.2.0] - 2019-07-02

### Notes
Because version 2.0 of this gem will include breaking changes, please make sure to include this gem in your gemfile as shown below to not automatically update to version 2.0.

```ruby
gem 'cvss-suite', '~> 1.2'
```

### Improvements
* Added Severity
* Added CVSS 3.1
* CVSS 3.0 vectors now return 3.0 instead of 3 as version

### Changes in CVSS 3.1 [Source] (https://www.first.org/cvss/v3.1/user-guide)
* The Temporal Score for all vulnerabilities which have a Base Score of 2.5, 5.0 or 10.0, Exploit Code Maturity (E) of High (H), Remediation Level (RL) of Unavailable (U) and Report Confidence (RC) of Unknown (U) is 0.1 lower in CVSS v3.1 than for 3.0.
* Some combinations of metrics have Environmental Scores that differ when scored with CVSS v3.1 rather than v3.0. This is due to a combination of the redefinition of Roundup and the change to the ModifiedImpact sub-formula. Less than 7% of metric combinations are 0.1 higher in CVSS v3.1 than v3.0, and less than 1% are 0.1 lower. No Environmental Scores differ by more than 0.1.
* Other implementations of the CVSS formulas may see different scoring changes between CVSS v3.0 and v3.1 if they previously generated different CVSS v3.0 scores due to the problems that the CVSS v3.1 formula changes are intended to fix.

## [1.1.2] - 2018-12-28

### Fixes
Replaced Fixnum by Integer to improve compatibility with newer versions of Ruby.

### Improvements
Added example for CVSS v3 to README.

## [1.1.1] - 2018-10-18

### Fixes
Corrects behaviour when using "CVSS:3.0/" as vector. Bugfix for #3.

## [1.1.0] - 2018-10-17

### Notes
This update might break some of your code, please check the following changes carefully.

### Fixes
* New CvssSuiteErrors are introduced to improve exception handling.
* Initialization of CvssSuite with an invalid vector does not throw an exception anymore. It will return an InvalidCvss
instead, which returns false for valid? and throws an exception for all other methods. See the updated README for
examples.

### Improvements
Finally the webpage is officially linked in the gem.

## [1.0.8] - 2016-09-30
### Fixes
Fixes a bug with rounding Fixnums in CVSS3.

## [1.0.7] - 2016-06-23
### Improvements
Removes gems: Rake & badgerbadgerbadger. Improved documentation, webpage (github) is coming very soon!

## [1.0.6] - 2016-04-15
### Fixes
While production we spotted a problem with calculating the temporal score in CVSS3. This version fixes this issue.

## [1.0.5] - 2016-04-15
### Fixes
Due to troubleshooting issues I forgot to rename a variable, this version fixes this issue.
Versions 1.0.1 to 1.0.4 are broken due to this error, do **NOT** use these versions. Use ≥ 1.0.5 instead.

## [1.0.2] - 2016-04-15
### Troubleshooting
Tried to fix an error. It turned out to be a local problem. Due to this I increased the version by 2. It's 1.0.2 now.

## [1.0.0] - 2016-04-15
### Initial release
First release of this gem.