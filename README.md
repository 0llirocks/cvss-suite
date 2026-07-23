# CvssSuite for Ruby

[![Gem Version](http://img.shields.io/gem/v/cvss-suite.svg)](https://rubygems.org/gems/cvss-suite)
[![Ruby Version](https://img.shields.io/badge/Ruby-3.3+-brightgreen.svg)](https://rubygems.org/gems/cvss-suite)
[![Cvss Support](https://img.shields.io/badge/CVSS-v2-brightgreen.svg)](https://www.first.org/cvss/v2/guide)
[![Cvss Support](https://img.shields.io/badge/CVSS-v3.0-brightgreen.svg)](https://www.first.org/cvss/v3.0/user-guide)
[![Cvss Support](https://img.shields.io/badge/CVSS-v3.1-brightgreen.svg)](https://www.first.org/cvss/v3.1/user-guide)
[![Cvss Support](https://img.shields.io/badge/CVSS-v4.0-brightgreen.svg)](https://www.first.org/cvss/v4.0/user-guide)
[![RSpec](https://github.com/0llirocks/cvss-suite/workflows/RSpec/badge.svg)](https://github.com/0llirocks/cvss-suite/actions)

This Ruby gem helps you to process the vector of the [**Common Vulnerability Scoring System**](https://www.first.org/cvss/specification-document).
Besides calculating the Base, Temporal and Environmental Score, you are able to extract the selected option.

> [!IMPORTANT]
> This project could need some new maintainer(s). I am having less time and motivation to support this gem. Support for v4 was only possible with the help of the community and I am sure I will not implement any v4.x or v5.x support by myself. Since this gem is used in some projects I will not step down without any kind of support. If you are interested in CVSS and ruby, feel free to work on upcoming issues and let me ([@Ollirocks](https://github.com/0llirocks)) know if you are willing to become a maintainer. As of today there are only a very few issues each year but each new version of CVSS results in quite a lot of work. I am fine with staying the owner of this project until someone is willing to take over completely. I will not vanish from GitHub once and or all :smile: The same applies to the ruby gems account, I am willing to push new versions to rubygems.org until someone trustworthy is found to take over.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'cvss-suite'
```

Since the naming of this gem is not following the naming convention you can also add the following line to automatically require the gem:

```ruby
gem 'cvss-suite', require: 'cvss_suite'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install cvss-suite

## Upgrading to 5.x

### Three module methods are now private

`CvssSuite.version`, `CvssSuite.prepare_vector` and `CvssSuite.prepare_cvss2_vector` were public,
but only because `CvssSuite.new` needed them. They read module-level state that `CvssSuite.new`
writes, so their return value depended on whichever vector was parsed last, anywhere in the
process. Calling them directly was never meaningful and is now a `NoMethodError`.

To get the CVSS version of a vector, ask the vector:

```ruby
# Before (raises NoMethodError as of 5.x)
CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
CvssSuite.version   # 3.1, but only until anything else parses a vector

# After
CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').version   # 3.1
```

Note that `CvssSuite.version` was never the gem version. That is `CvssSuite::VERSION`, which is
unchanged. The two names being one letter-case apart is part of why the method is gone.

There is no replacement for `prepare_vector` and `prepare_cvss2_vector`. They strip the
`CVSS:x.x/` prefix (or the surrounding parentheses of a CVSS 2 vector) before the vector is handed
to the parser, and that is now an implementation detail of `CvssSuite.new`.

### Nothing else changed

`CvssSuite.new` behaves exactly as it did in 4.x for every input, valid or not, and still never
raises. `CvssSuite.parse` is new and additive; see [Parsing a vector](#parsing-a-vector) for when to
reach for which.

## Version 3.x

If you are still using CvssSuite 3.x please refer to the [specific branch](https://github.com/0llirocks/cvss-suite/tree/3.x) for documentation and changelog.

## Version 2.x

If you are still using CvssSuite 2.x please refer to the [specific branch](https://github.com/0llirocks/cvss-suite/tree/2.x) for documentation and changelog.
    
## Version 1.x

If you are still using CvssSuite 1.x please refer to the [specific branch](https://github.com/0llirocks/cvss-suite/tree/1.x) for documentation and changelog.

## Usage

```ruby
require 'cvss_suite'

cvss4 = CvssSuite.new('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')

vector = cvss4.vector       # 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
version = cvss4.version     # 4.0
valid = cvss4.valid?        # true
severity = cvss4.severity   # 'Critical'

cvss31 = CvssSuite.new('CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U')

vector = cvss31.vector     # 'CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U'
version = cvss31.version   # 3.1
valid = cvss31.valid?      # true
severity = cvss31.severity # 'Medium'

cvss3 = CvssSuite.new('CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H')

vector = cvss3.vector       # 'CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H'
version = cvss3.version     # 3.0
valid = cvss3.valid?        # true
severity = cvss3.severity   # 'High'

cvss = CvssSuite.new('AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M')

vector = cvss.vector       # 'AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M'
version = cvss.version     # 2
valid = cvss.valid?        # true
severity = cvss.severity   # 'Low'

# Scores
score = cvss4.overall_score                         # 9.3, cvss4 only has overall score
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

## Parsing a vector

Both entry points return the same object for a valid vector. They differ in what they do with input
they cannot parse, so pick the failure mode you want.

**`CvssSuite.parse` raises**, at the parse, for every kind of bad input:

```ruby
CvssSuite.parse('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').base_score
# => 9.8
CvssSuite.parse('CVSS:3.0/')
# => raises CvssSuite::Errors::InvalidVector: Vector is not valid!
```

**`CvssSuite.new` never raises.** It hands back an object whose `valid?` is `false` and defers the
error to whatever eventually reads a score. What that object is depends on whether the vector's
prefix was recognised:

| `CvssSuite.new(...)` | returns | `valid?` | `version` | `base_score` |
| --- | --- | --- | --- | --- |
| `'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'` | `Cvss31` | `true` | `3.1` | `9.8` |
| `'CVSS:3.0/'` | `Cvss3` | `false` | `3.0` | raises `Errors::InvalidVector` |
| `'AV:N/AC:L'` | `Cvss2` | `false` | `2` | raises `Errors::InvalidVector` |
| `'random_string'` | `InvalidCvss` | `false` | raises `Errors::InvalidVector` | raises `Errors::InvalidVector` |
| `1337` | `InvalidCvss` | `false` | raises `Errors::InvalidVector` | raises `Errors::InvalidVector` |

Note the second and third rows: a vector that carries a recognised prefix but an unusable body still
comes back as a real version class, and `version` still answers. Only `valid?` and the scores tell
you it is broken.

**Use `CvssSuite.new`** when an invalid vector is an expected input you intend to branch on:

```ruby
cvss = CvssSuite.new(untrusted_input)
return render_error unless cvss.valid?
```

**Use `CvssSuite.parse`** when an invalid vector is a bug. The object `CvssSuite.new` returns stays
quiet until something asks it for a number, so a caller who forgets `valid?` sees the exception far
from the input that caused it, or never, if that read sits behind a conditional.

Neither method accepts a missing argument; `CvssSuite.new` and `CvssSuite.parse` both raise
`ArgumentError` when called with none.

## Known Issues

There is a possibility of implementations generating different scores (+/- 0,1) due to small floating-point inaccuracies. This can happen due to differences in floating point arithmetic between different languages and hardware platforms.

On an invalid CVSS 3.x vector whose prefix was recognised, `base_score` raises
`CvssSuite::Errors::InvalidVector` as documented, but `temporal_score` and `environmental_score`
raise `TypeError` instead. Check `valid?`, or use `CvssSuite.parse`, rather than relying on the
error class.

## Changelog

[Click here to see all changes.](https://github.com/0llirocks/cvss-suite/blob/master/CHANGES.md)

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/0llirocks/cvss-suite. This project is intended to be a safe, welcoming space for collaboration.

## References
[CvssSuite for .NET](https://cvsssuite.0lli.rocks)
