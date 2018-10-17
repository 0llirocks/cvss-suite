# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

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
Fixed a bug with rounding Fixnums in CVSS3.

## [1.0.7] - 2016-06-23
### Improvements
Removed gems: Rake & badgerbadgerbadger. Improved documentation, webpage (github) is coming very soon!

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