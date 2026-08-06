# frozen_string_literal: true

# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative 'spec_helper'

describe CvssSuite::Error do
  # Provoked the way the gem raises them, so the rescue under test is the one a
  # caller would actually write, not a hand-constructed instance.
  {
    CvssSuite::Errors::InvalidVector => -> { CvssSuite.parse('Not a valid vector!') },
    CvssSuite::Errors::UnsupportedVersion => -> { CvssSuite.metrics('9.9') },
    CvssSuite::Errors::InvalidParentClass => -> { CvssSuite::Cvss.new('AV:N') }
  }.each do |klass, raiser|
    it "catches #{klass} in one rescue" do
      # Asserting the concrete class as well as the marker. Matching the marker
      # alone would pass if every entry point raised the same class, which is
      # the thing this example exists to rule out.
      expect { raiser.call }.to raise_error(klass) { |error| expect(error).to be_a(described_class) }
    end
  end

  # f7e9866 (2018) moved these off a shared base class deliberately, so callers
  # rescuing RuntimeError or ArgumentError kept catching them. A module grants
  # the shared rescue without taking that back, and these pin the second half.
  it 'leaves InvalidVector a RuntimeError' do
    expect(CvssSuite::Errors::InvalidVector.ancestors).to include(RuntimeError)
  end

  it 'leaves the argument errors ArgumentErrors' do
    expect(CvssSuite::Errors::UnsupportedVersion.ancestors).to include(ArgumentError)
    expect(CvssSuite::Errors::InvalidParentClass.ancestors).to include(ArgumentError)
  end

  it 'is a module, so nothing can raise it in place of a real error' do
    expect { raise described_class }.to raise_error(TypeError)
  end

  it 'replaces the CvssError that never had subclasses' do
    # Naming the constant in the message, so deleting the Errors namespace
    # wholesale could not satisfy this by accident.
    expect { CvssSuite::Errors::CvssError }.to raise_error(NameError, /CvssError/)
  end
end

describe CvssSuite::Errors::InvalidVector do
  # The message was a bare 'Vector is not valid!', which tells a caller nothing
  # when .parse raises it three frames from wherever the vector came from.
  {
    '.parse' => -> { CvssSuite.parse('CVSS:3.1/AV:N') },
    'a score reader' => -> { CvssSuite.new('CVSS:3.1/AV:N').base_score }
  }.each do |label, raiser|
    it "names the rejected vector, raised from #{label}" do
      expect { raiser.call }.to raise_error(described_class, %r{Vector is not valid: "CVSS:3\.1/AV:N"})
    end
  end

  # .new takes anything; the sentinel it hands back used to forget what it was
  # given, so every one of these reported an empty string.
  {
    1337 => '1337',
    nil => 'nil',
    :symbol => ':symbol'
  }.each do |input, described|
    it "reports #{input.inspect} as #{described}, not as an empty string" do
      expect { CvssSuite.new(input).base_score }
        .to raise_error(described_class, "Vector is not valid: #{described}")
    end
  end

  # Both the cheapest input to echo and the most expensive: escaping inflates
  # what 200 trimmed characters become, so testing only 'A' would report a bound
  # six times tighter than the real one.
  { 'A' => 300, "\x00" => 1300 }.each do |char, bound|
    it "trims a pathological vector of #{char.inspect} rather than repeating it into a log" do
      message = begin
        CvssSuite.parse("CVSS:3.1/#{char * 10_000}")
      rescue described_class => e
        e.message
      end

      expect(message.length).to be < bound
      # The ellipsis sits inside the quotes because the input is trimmed before
      # inspect, not after: escaping is never cut mid-sequence and the closing
      # quote always survives.
      expect(message).to end_with('..."')
    end
  end

  # Derived from the gem's own schema, taking each metric's longest option, so
  # the bound is re-measured rather than restated. Assuming one character per
  # option undercounts by four: CVSS 4.0's Provider Urgency reads 'U:Clear'.
  it 'repeats the longest real vector back in full' do
    longest = "CVSS:4.0/#{CvssSuite.metrics(4.0).flat_map { |group| group[:metrics] }
      .map { |metric| "#{metric[:abbreviation]}:#{metric[:options].map { |o| o[:abbreviation] }.max_by(&:length)}" }
      .join('/')}"

    expect(longest.length).to eq(178)
    expect(CvssSuite.new(longest)).to be_valid

    # Corrupted to an unknown option rather than lengthened, so the vector under
    # test stays exactly as long as the longest one the gem accepts.
    rejected = longest.sub('AV:N', 'AV:Q')
    expect { CvssSuite.parse(rejected) }.to raise_error(described_class, /#{Regexp.escape(rejected)}/)
  end

  it 'reports what it was given, not what a later mutation made of it' do
    vector = +'garbage'
    sentinel = CvssSuite.new(vector)
    vector << '-mutated-afterwards'

    expect { sentinel.base_score }.to raise_error(described_class, 'Vector is not valid: "garbage"')
  end
end

# CvssSuite.new accepts any object, so #inspect here is arbitrary caller code
# running on something the gem never validated. Whatever it does has to end in
# the error that describes the vector, not in the error it caused while being
# asked to describe one.
describe 'describing a hostile vector' do
  {
    'raises' => -> { raise(NoMethodError, 'boom from inspect') },
    'recurses until the stack goes' => -> { inspect },
    'answers with a collection that duck-types as a String' => -> { ['Y' * 1_000_000] }
  }.each do |label, inspect_body|
    it "still raises InvalidVector when #inspect #{label}" do
      hostile = Class.new { define_method(:inspect, &inspect_body) }.new

      expect { CvssSuite.parse(hostile) }
        .to raise_error(CvssSuite::Errors::InvalidVector) { |error| expect(error.message.length).to be < 300 }
    end
  end
end
