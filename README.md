# CvssSuite for Ruby

Score a CVSS vector string, and read back every metric in it.

CvssSuite turns a vector string into scores and severity, and lets you ask which option each metric
selected. It handles four CVSS versions behind one interface, so code that ingests advisories from
more than one era does not need a branch per specification version.

The parsed vector stays addressable, which is what you need to render a vector back to a user, drive
an input form, or explain a score rather than just report it.

> [!IMPORTANT]
> This project could need some new maintainer(s). I am having less time and motivation to support this gem. Support for v4 was only possible with the help of the community and I am sure I will not implement any v4.x or v5.x support by myself. Since this gem is used in some projects I will not step down without any kind of support. If you are interested in CVSS and ruby, feel free to work on upcoming issues and let me ([@Ollirocks](https://github.com/0llirocks)) know if you are willing to become a maintainer. As of today there are only a very few issues each year but each new version of CVSS results in quite a lot of work. I am fine with staying the owner of this project until someone is willing to take over completely. I will not vanish from GitHub once and or all :smile: The same applies to the ruby gems account, I am willing to push new versions to rubygems.org until someone trustworthy is found to take over.

## Example

```ruby
require 'cvss_suite'

cvss = CvssSuite.parse('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')

cvss.version                                    # => 4.0
cvss.overall_score                              # => 9.3
cvss.severity                                   # => 'Critical'
cvss.base.attack_vector.name                    # => 'Attack Vector'
cvss.base.attack_vector.selected_value[:name]   # => 'Network'
```

`CvssSuite.new` is the non-raising counterpart, unchanged since 4.x: it returns an object whose
`valid?` reports the problem instead. CVSS 2 and 3.x also expose `base_score`, `temporal_score` and
`environmental_score`. See [Usage](https://github.com/0llirocks/cvss-suite/blob/master/docs/usage.md)
for both.

## What you get

- **Four specification versions, one API.** CVSS [2](https://www.first.org/cvss/v2/guide),
  [3.0](https://www.first.org/cvss/v3.0/user-guide), [3.1](https://www.first.org/cvss/v3.1/user-guide)
  and [4.0](https://www.first.org/cvss/v4.0/user-guide), including 4.0 macro-vector scoring.
  `CvssSuite.parse` picks the version off the vector string.
- **Metrics stay readable.** Every metric exposes its name, its permitted options, and which option
  the vector selected.
- **One runtime dependency.** `bigdecimal`, to keep arithmetic off binary floats.
- **Over 80,000 examples** in the test suite, run against the oldest supported Ruby, current
  stable, and head.
- **Ruby 3.3+**, MIT licensed.

## Install

Add the gem to your Gemfile. The gem is named `cvss-suite` but loads as `cvss_suite`, so tell
Bundler which file to load:

```ruby
gem 'cvss-suite', require: 'cvss_suite'
```

Then:

```console
$ bundle install
```

Or without Bundler:

```console
$ gem install cvss-suite
```

## Documentation

- **[Usage](https://github.com/0llirocks/cvss-suite/blob/master/docs/usage.md)** covers every score,
  reading and enumerating metrics, and how invalid vectors behave.
- **[Upgrading to 5.x](https://github.com/0llirocks/cvss-suite/blob/master/docs/upgrading-to-5.md)**
  lists the breaking changes and the migration for each.
- **[API reference](https://www.rubydoc.info/gems/cvss-suite)** on RubyDoc.

Using an older major? Documentation and changelog live on the
[3.x](https://github.com/0llirocks/cvss-suite/tree/3.x),
[2.x](https://github.com/0llirocks/cvss-suite/tree/2.x) and
[1.x](https://github.com/0llirocks/cvss-suite/tree/1.x) branches.

## Known issues

Other implementations can produce scores differing by +/- 0.1, because floating-point arithmetic
differs between languages and hardware platforms.

## Changelog

Changes through 4.x are in
[CHANGES.md](https://github.com/0llirocks/cvss-suite/blob/master/CHANGES.md). From 5.0.0 onwards,
see the [Releases page](https://github.com/0llirocks/cvss-suite/releases).

## Contributing

Bug reports and pull requests are welcome at
[github.com/0llirocks/cvss-suite](https://github.com/0llirocks/cvss-suite). This project is intended
to be a safe, welcoming space for collaboration.

## References

[CvssSuite for .NET](https://cvsssuite.0lli.rocks)
