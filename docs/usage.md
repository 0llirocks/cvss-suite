# Usage

Every score, every metric, and what invalid vectors do.

## Parsing a vector

`CvssSuite.parse` and `CvssSuite.new` return the same object for a valid vector. They differ on
input they cannot parse; pick the failure mode you want.

**`CvssSuite.parse` raises immediately** on any bad input:

```ruby
CvssSuite.parse('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').base_score
# => 9.8
CvssSuite.parse('CVSS:3.0/')
# => raises CvssSuite::Errors::InvalidVector: Vector is not valid!
```

**`CvssSuite.new` never raises.** It hands back an object whose `valid?` is `false` and defers the
error to whatever eventually reads a score. What that object is depends on whether the vector's
prefix was recognized:

| `CvssSuite.new(...)` | returns | `valid?` | `version` | `base_score` |
| --- | --- | --- | --- | --- |
| `'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'` | `Cvss31` | `true` | `3.1` | `9.8` |
| `'CVSS:3.0/'` | `Cvss3` | `false` | `3.0` | raises `Errors::InvalidVector` |
| `'AV:N/AC:L'` | `Cvss2` | `false` | `2` | raises `Errors::InvalidVector` |
| `'random_string'` | `InvalidCvss` | `false` | raises `Errors::InvalidVector` | raises `Errors::InvalidVector` |
| `1337` | `InvalidCvss` | `false` | raises `Errors::InvalidVector` | raises `Errors::InvalidVector` |

Note rows two and three: a recognized prefix with an unusable body still comes back as a real
version class.

Use `CvssSuite.new` when an invalid vector is an expected input you intend to branch on:

```ruby
cvss = CvssSuite.new(untrusted_input)
return render_error unless cvss.valid?
```

Use `CvssSuite.parse` when an invalid vector is a bug. The object `CvssSuite.new` returns stays
quiet until something asks it for a number, so a caller who forgets `valid?` meets the exception far
from the input that caused it. Or never, if that read sits behind a conditional.

Both raise `ArgumentError` when called with no argument.

CVSS 2 vectors are accepted with or without surrounding parentheses. Otherwise the string must begin
with the vector: anything before the `CVSS:x.x/` prefix, or before a CVSS 2 vector's first metric,
makes it unparseable.

## Scores

CVSS 2, 3.0 and 3.1 expose the three sub-scores plus an overall score:

```ruby
cvss = CvssSuite.parse('AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M')

cvss.base_score            # => 4.9
cvss.temporal_score        # => 3.6
cvss.environmental_score   # => 3.2
cvss.overall_score         # => 3.2
```

`overall_score` is the most specific score the vector provides:

- the environmental score, if environmental metrics were given
- otherwise the temporal score, if temporal metrics were given
- otherwise the base score

CVSS 4.0 defines a single score. `overall_score` is that score, and `base_score` is exposed
alongside it so a 4.0 vector can be compared against the base score that NVD and GHSA publish:

```ruby
cvss = CvssSuite.parse('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')

cvss.overall_score   # => 9.3
cvss.base_score      # => 9.3
```

## Severity

`severity` maps a score onto the qualitative rating from the specification. The two rating scales
differ, and so does the score each one reads:

| | scale | reads |
| --- | --- | --- |
| CVSS 3.0, 3.1, 4.0 | None, Low, Medium, High, Critical | `overall_score` |
| CVSS 2 | Low, Medium, High | `base_score` |

CVSS 2 predates the Critical band and rates on the base score, so a CVSS 2 vector can report a severity
that looks inconsistent with its own `overall_score`:

```ruby
cvss = CvssSuite.parse('AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M')

cvss.base_score      # => 4.9
cvss.overall_score   # => 3.2
cvss.severity        # => 'Medium', rated on the 4.9 base score
```

## Reading metrics

A parsed vector exposes its metric groups. Every version has `base`. CVSS 2 and 3.x add `temporal`
and `environmental`. CVSS 4.0 has `threat`, `environmental`, `environmental_security` and
`supplemental`. Each metric answers its human-readable name, all permitted options, and the option
this vector selected.

```ruby
cvss = CvssSuite.parse('AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M')

access_vector = cvss.base.access_vector

access_vector.name                     # => 'Access Vector'
access_vector.selected_value[:name]    # => 'Adjacent Network'

access_vector.values
# => [{ name: 'Network',          abbreviation: 'N', weight: 1.0,   selected: false },
#     { name: 'Adjacent Network', abbreviation: 'A', weight: 0.646, selected: true  },
#     { name: 'Local',            abbreviation: 'L', weight: 0.395, selected: false }]

cvss.temporal.remediation_level.name                   # => 'Remediation Level'
cvss.temporal.remediation_level.selected_value[:name]  # => 'Temporary Fix'
```

On CVSS 2 and 3.x, `weight` is the numeric coefficient the specification assigns to that option. The
score is computed from it; it is exposed so you can show your working. CVSS 4.0 options carry no
`weight`, because 4.0 scores through a macro-vector lookup rather than per-option coefficients.

The original vector string is available too:

```ruby
CvssSuite.parse('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').vector
# => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
```

One asymmetry: a CVSS 2 vector given in parentheses comes back without them.
`CvssSuite.parse('(AV:N/AC:L/Au:N/C:N/I:N/A:C)').vector` returns
`'AV:N/AC:L/Au:N/C:N/I:N/A:C'`.

To enumerate every metric in a group rather than naming one, use `properties`:

```ruby
cvss.base.properties.map(&:abbreviation)
# => ['AV', 'AC', 'Au', 'C', 'I', 'A']
```

## Metrics without a vector

`CvssSuite.metrics` returns the schema for a CVSS version without parsing anything, which is what
you want when building an input form or validating against the specification rather than against a
particular vector:

```ruby
schema = CvssSuite.metrics(3.1)

schema.map { |group| group[:group] }
# => ['Base', 'Temporal', 'Environmental']

schema.first[:metrics].first
# => { name: 'Attack Vector',
#      abbreviation: 'AV',
#      options: [{ name: 'Network',  abbreviation: 'N', default: false },
#                { name: 'Adjacent', abbreviation: 'A', default: false },
#                { name: 'Local',    abbreviation: 'L', default: false },
#                { name: 'Physical', abbreviation: 'P', default: false }] }
```

Optional metrics flag their Not Defined option as the default, so a form can preselect it:

```ruby
temporal = CvssSuite.metrics(3.1).find { |group| group[:group] == 'Temporal' }
temporal[:metrics].first[:name]                                          # => 'Exploit Code Maturity'
temporal[:metrics].first[:options].select { |o| o[:default] }.map { |o| o[:abbreviation] }
# => ['X']
```

It accepts `2`, `3.0`, `3.1` and `4.0`, the string equivalents of each, and the value a parsed
vector reports from `version`. Anything else raises `CvssSuite::Errors::UnsupportedVersion`, which
descends from `ArgumentError`.

## Exceptions

Reading a score or a version off an invalid vector raises `CvssSuite::Errors::InvalidVector`:

```ruby
cvss = CvssSuite.new('random_string')

cvss.valid?       # => false
cvss.version      # => raises CvssSuite::Errors::InvalidVector: Vector is not valid!
cvss.base_score   # => raises CvssSuite::Errors::InvalidVector: Vector is not valid!
```

A vector whose prefix was recognized but whose body is unusable still answers `version`, and only
reports the problem through `valid?` and the scores:

```ruby
cvss = CvssSuite.new('AV:N/AC:P/C:P/AV:U/RL:OF/RC:C')   # authentication is missing

cvss.version      # => 2
cvss.valid?       # => false
cvss.base_score   # => raises CvssSuite::Errors::InvalidVector: Vector is not valid!
```

Every score reader behaves the same way. On CVSS 2 and 3.x that is `base_score`, `temporal_score`,
`environmental_score`, `overall_score` and `severity`. CVSS 4.0 folds threat and environmental
metrics into its single score, so it defines only `base_score`, `overall_score` and `severity`;
calling `temporal_score` or `environmental_score` on a 4.0 vector raises `NoMethodError` whether or
not the vector is valid.

The metric groups themselves are not guarded. `cvss.base`, `cvss.temporal` and `cvss.environmental`
hand back live objects on an invalid vector, and their `score` will compute from it. Read scores
through the methods above rather than through the metric groups.

Every error class lives under `CvssSuite::Errors`. `InvalidVector` descends from `RuntimeError`, so
a bare `rescue => e` catches it.
