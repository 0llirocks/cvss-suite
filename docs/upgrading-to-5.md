# Upgrading to 5.x

Most callers need no change. `CvssSuite.new` and every score for a valid vector behave as they did
in 4.x. What follows is the exceptions.

## Ruby 3.3 is the minimum

5.x requires Ruby 3.3 or newer. 4.1.4 ran on Ruby 2.6 and newer.

## Invalid vectors no longer score

In 4.x, only `base_score` checked that the vector was valid before computing. `temporal_score` and
`environmental_score` did not, so a vector that `valid?` had already rejected could still hand back
a plausible-looking number:

```ruby
cvss = CvssSuite.new('AV:A/AC:H/Au:M/C:C/I:C/A:C/ZZ:Q')   # ZZ is not a CVSS 2 metric

cvss.valid?               # => false, in both 4.x and 5.x
cvss.environmental_score  # 4.x: 6.2
                          # 5.x: raises CvssSuite::Errors::InvalidVector
```

`overall_score` on the `InvalidCvss` returned for unrecognized input used to raise `NoMethodError`
rather than `InvalidVector`. It now raises `InvalidVector` like every other reader.

If you were rescuing `TypeError` or `NoMethodError` around these calls, rescue
`CvssSuite::Errors::InvalidVector` instead. If you were checking `valid?` first, nothing changes.

## Three module methods are now private

`CvssSuite.version`, `CvssSuite.prepare_vector` and `CvssSuite.prepare_cvss2_vector` were public,
but only because `CvssSuite.new` needed them. They read module-level state that `CvssSuite.new`
writes, so their return value depended on whichever vector was parsed last, anywhere in the
process. Calling them directly could not be relied on, and now raises `NoMethodError`.

To get the CVSS version of a vector, ask the vector:

```ruby
# Before (raises NoMethodError as of 5.x)
CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
CvssSuite.version   # 3.1, but only until anything else parses a vector

# After
CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').version   # => 3.1
```

`CvssSuite.version` was never the gem version; that is `CvssSuite::VERSION`, unchanged.

There is no replacement for `prepare_vector` and `prepare_cvss2_vector`. They strip the `CVSS:x.x/`
prefix, or the surrounding parentheses of a CVSS 2 vector, before the vector reaches the parser, and
that is now an implementation detail of `CvssSuite.new`.

## `CvssSuite.parse` is new

`CvssSuite.parse` raises `CvssSuite::Errors::InvalidVector` on input it cannot parse, where
`CvssSuite.new` returns an object that reports the problem only through `valid?` and the scores.
This is additive; `CvssSuite.new` is unchanged. See
[Parsing a vector](usage.md#parsing-a-vector).

```ruby
# 4.x, still works
cvss = CvssSuite.new(untrusted_input)
return render_error unless cvss.valid?

# 5.x, when a bad vector is a bug rather than an input
cvss = CvssSuite.parse(vector_from_our_own_database)
```

## What did not change

Scores for valid vectors are unchanged across all four CVSS versions. `CvssSuite.new` still never
raises, and still returns the same object for the same input. Metric names, permitted options and
selected options are unchanged.
