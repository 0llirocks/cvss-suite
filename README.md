# CvssSuite for Ruby

[![Gem Version](http://img.shields.io/gem/v/cvss-suite.svg)](https://rubygems.org/gems/cvss-suite)
[![Ruby Version](https://img.shields.io/badge/Ruby-2.x-brightgreen.svg)](https://rubygems.org/gems/cvss-suite)
[![Cvss Support](https://img.shields.io/badge/CVSS-v2-brightgreen.svg)](https://www.first.org/cvss/v2/guide)
[![Cvss Support](https://img.shields.io/badge/CVSS-v3.0-brightgreen.svg)](https://www.first.org/cvss/v3.0/user-guide)
[![Cvss Support](https://img.shields.io/badge/CVSS-v3.1-brightgreen.svg)](https://www.first.org/cvss/v3.1/user-guide)
![RSpec](https://github.com/siemens/cvss-suite/workflows/RSpec/badge.svg)

This Ruby gem helps you to process the vector of the [**Common Vulnerability Scoring System**](https://www.first.org/cvss/specification-document).
Besides calculating the Base, Temporal and Environmental Score, you are able to extract the selected option.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'cvss-suite'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install cvss-suite
    
## Version 1.x

If your still using CvssSuite 1.x please refer to the [specific branch](https://github.com/siemens/cvss-suite/tree/1.x) for documentation and changelog.

## Usage

```ruby
require 'cvss_suite'

cvss3 = CvssSuite.new('CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H')

vector = cvss3.vector       # 'CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H'
version = cvss3.version     # 3.0
valid = cvss3.valid?        # true
severity = cvss3.severity   # 'High'

cvss31 = CvssSuite.new('CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U')

vector = cvss31.vector     # 'CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U'
version = cvss31.version   # 3.1
valid = cvss31.valid?      # true
severity = cvss31.severity # 'Medium'

cvss = CvssSuite.new('AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M')

vector = cvss.vector       # 'AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M'
version = cvss.version     # 2
valid = cvss.valid?        # true
severity = cvss.severity   # 'Low'

# Scores
base_score = cvss.base_score                        # 4.9
temporal_score = cvss.temporal_score                # 3.6
environmental_score = cvss.environmental_score      # 3.2
overall_score = cvss.overall_score                  # 3.2

# Available options
access_vector = cvss.base.access_vector.name                # 'Access Vector'
remediation_level = cvss.temporal.remediation_level.name    # 'Remediation Level'

access_vector.values.each do |value|
    value[:name]           # 'Local', 'Adjacent Network', 'Network'
    value[:abbreviation]   # 'L', 'A', 'N'
    value[:selected]       # false, true, false
end

# Selected options
cvss.base.access_vector.selected_value[:name]          # Adjacent Network
cvss.temporal.remediation_level.selected_value[:name]  # Temporary Fix

# Exceptions

cvss = CvssSuite.new('random_string')  # invalid vector
valid = cvss.valid?     # false
version = cvss.version  # will throw CvssSuite::Errors::InvalidVector: Vector is not valid!
cvss.base_score         # will throw CvssSuite::Errors::InvalidVector: Vector is not valid!

cvss = CvssSuite.new(1337)  # invalid vector
valid = cvss.valid?     # false
version = cvss.version  # will throw CvssSuite::Errors::InvalidVector: Vector is not valid!
cvss.base_score         # will throw CvssSuite::Errors::InvalidVector: Vector is not valid!

CvssSuite.new()         # will throw a ArgumentError

cvss = CvssSuite.new('AV:N/AC:P/C:P/AV:U/RL:OF/RC:C')   # invalid vector, authentication is missing
version = cvss.version  # 2
valid = cvss.valid?     # false
cvss.base_score         # will throw CvssSuite::Errors::InvalidVector: Vector is not valid!
```

## Notable Features

Properties (Access Vector, Remediation Level, etc) do have a position attribute, with this they can be ordered the same way they appear in the vector.

## Known Issues

Currently it is not possible to leave an attribute blank instead of ND/X. If you don't have a value for an attribute, please use ND/X instead.

Because the documentation isn't clear on how to calculate the score if Modified Scope (CVSS 3.0 Environmental) is not defined, Modified Scope has to have a valid value (S/U).

There is a possibility of implementations generating different scores (+/- 0,1) due to small floating-point inaccuracies. This can happen due to differences in floating point arithmetic between different languages and hardware platforms.

## Changelog

[Click here to see all changes.](https://github.com/siemens/cvss-suite/blob/master/CHANGES.md)

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/siemens/cvss-suite. This project is intended to be a safe, welcoming space for collaboration.

## References
[CvssSuite for .NET](https://github.com/oliverhamboerger/CvssSuite)
