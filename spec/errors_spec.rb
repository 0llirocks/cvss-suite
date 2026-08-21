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
