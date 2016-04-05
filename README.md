# CvssSuite

[![Gem Version](http://img.shields.io/gem/v/cvss-suite.svg)](https://rubygems.org/gems/cvss-suite)
[![Ruby Version](https://img.shields.io/badge/Ruby-2.x-brightgreen.svg)](https://rubygems.org/gems/cvss-suite)
[![Cvss Support](https://img.shields.io/badge/CVSS-v2-brightgreen.svg)](https://www.first.org/cvss/cvss-v2-guide.pdf)
[![Cvss Support](https://img.shields.io/badge/CVSS-v3.0-brightgreen.svg)](https://www.first.org/cvss/cvss-v3-guide.pdf)

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

## Usage

```ruby
require 'cvss_suite'

cvss = CvssSuite.new('AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M')

vector = cvss.vector    # 'AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M'
version = cvss.version  # 2

# Scores
base_score = cvss.base_score                        # 4.9
temporal_score = cvss.temporal_score                # 3.6
environmental_score = cvss.environmental_score      # 3.2
overall_score = cvss.overall_score                  # 3.2

# Available options
access_vector = cvss.base.access_vector.name                # 'Access Vector'
remediation_level = cvss.temporal.remediation_level.name    # 'Remediation Level'

access_vector.choices.each do |choice|
    choice[:name]           # 'Local', 'Adjacent Network', 'Network'
    choice[:abbreviation]   # 'L', 'A', 'N'
    choice[:selected]       # false, true, false
end

# Selected options
cvss.base.access_vector.selected_choice[:name]          # Adjacent Network
cvss.temporal.remediation_level.selected_choice[:name]  # Temporary Fix

# Exceptions

CvssSuite.new('random_string')  # will throw a RuntimeError: Vector is not valid!
CvssSuite.new()                 # will throw a ArgumentError

cvss = CvssSuite.new('AV:N/AC:P/C:P/AV:U/RL:OF/RC:C')   # invalid vector, authentication is missing

version = cvss.version  # 2

cvss.base_score         # will throw a RuntimeError: Vector is not valid!
```

## Notable Features

Properties (Access Vector, Remediation Level, etc) do have a position attribute, with this they can be ordered the same way they appear in the vector.

## Known Issues

Currently it is not possible to leave a attribute blank instead of ND/X. If you don't have a value for a attribute, please use ND/X instead.

Because the documentation isn't clear on how to calculate the score if Modified Scope (CVSS 3.0 Environmental) is not defined, Modified Scope has to have a valid value (S/U).

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/cvss_suite. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](contributor-covenant.org) code of conduct.

