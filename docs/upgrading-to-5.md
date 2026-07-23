# Upgrading to 5.x

## Ruby 3.3 is the minimum

5.x requires Ruby 3.3 or newer. 4.x supported older releases.

## Three module methods are now private

`CvssSuite.version`, `CvssSuite.prepare_vector` and `CvssSuite.prepare_cvss2_vector` were public,
but only because `CvssSuite.new` needed them. They read module-level state that `CvssSuite.new`
writes, so their return value depended on whichever vector was parsed last, anywhere in the
process. Calling them directly was never meaningful, and now raises `NoMethodError`.

To get the CVSS version of a vector, ask the vector:

```ruby
# Before (raises NoMethodError as of 5.x)
CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
CvssSuite.version   # 3.1, but only until anything else parses a vector

# After
CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').version   # => 3.1
```

`CvssSuite.version` was never the gem version. That is `CvssSuite::VERSION`, which is unchanged. The
two names being one letter-case apart is part of why the method is gone.

There is no replacement for `prepare_vector` and `prepare_cvss2_vector`. They strip the `CVSS:x.x/`
prefix, or the surrounding parentheses of a CVSS 2 vector, before the vector reaches the parser, and
that is now an implementation detail of `CvssSuite.new`.

## New: `CvssSuite.parse`

`CvssSuite.parse` raises `CvssSuite::Errors::InvalidVector` on input it cannot parse, where
`CvssSuite.new` returns an object that reports the problem only through `valid?` and the scores.
This is additive; `CvssSuite.new` is unchanged and is still the right call when an invalid vector is
an expected input you branch on. See [Parsing a vector](usage.md#parsing-a-vector).

```ruby
# 4.x, still works
cvss = CvssSuite.new(untrusted_input)
return render_error unless cvss.valid?

# 5.x, when a bad vector is a bug rather than an input
cvss = CvssSuite.parse(vector_from_our_own_database)
```

## Nothing else changed

`CvssSuite.new` behaves exactly as it did in 4.x for every input, valid or not, and still never
raises. Scores, severities, metric names and selected options are unchanged.
