# frozen_string_literal: true

# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative 'spec_helper'

describe CvssSuite do
  it 'has a version number' do
    expect(CvssSuite::VERSION).not_to be nil
  end

  it 'is invalid' do
    expect { described_class.new('Not a valid vector!').version }
      .to raise_error(CvssSuite::Errors::InvalidVector, 'Vector is not valid!')
  end

  it 'is invalid' do
    expect { described_class.new('Not a valid vector!').version }
      .to raise_error(RuntimeError)
  end

  it 'is invalid' do
    expect(described_class.new('Not a valid vector!').valid?).to be false
  end

  it 'is invalid' do
    expect(described_class.new(1337).valid?).to be false
  end

  it 'is invalid' do
    expect(described_class.new('CVSS:3.0/').valid?).to be false
  end

  describe '.metrics' do
    it 'returns the schema without constructing a vector' do
      expect(described_class.metrics(3.1)).to be_an(Array)
    end

    it 'exposes the metric groups for each version in vector order' do
      expect(described_class.metrics(2).map { |group| group[:group] })
        .to eq(%w[Base Temporal Environmental])
      expect(described_class.metrics(3.0).map { |group| group[:group] })
        .to eq(%w[Base Temporal Environmental])
      expect(described_class.metrics(3.1).map { |group| group[:group] })
        .to eq(%w[Base Temporal Environmental])
      expect(described_class.metrics(4.0).map { |group| group[:group] })
        .to eq(['Base', 'Threat', 'Environmental', 'Environmental Security Requirements', 'Supplemental'])
    end

    it 'lists base metric abbreviations in vector order' do
      base_abbreviations = lambda do |version|
        described_class.metrics(version).first[:metrics].map { |metric| metric[:abbreviation] }
      end
      expect(base_abbreviations.call(2)).to eq(%w[AV AC Au C I A])
      expect(base_abbreviations.call(3.1)).to eq(%w[AV AC PR UI S C I A])
      expect(base_abbreviations.call(4.0)).to eq(%w[AV AC AT PR UI VC VI VA SC SI SA])
    end

    it 'describes each option with a name, abbreviation, and default flag' do
      attack_vector = described_class.metrics(3.1).first[:metrics].first
      expect(attack_vector[:name]).to eq('Attack Vector')
      expect(attack_vector[:abbreviation]).to eq('AV')
      expect(attack_vector[:options]).to eq(
        [
          { name: 'Network', abbreviation: 'N', default: false },
          { name: 'Adjacent', abbreviation: 'A', default: false },
          { name: 'Local', abbreviation: 'L', default: false },
          { name: 'Physical', abbreviation: 'P', default: false }
        ]
      )
    end

    it 'flags the Not Defined option as the default for optional metrics' do
      exploit_code_maturity = described_class.metrics(3.1).find { |group| group[:group] == 'Temporal' }[:metrics].first
      defaults = exploit_code_maturity[:options].select { |option| option[:default] }
      expect(defaults.map { |option| option[:abbreviation] }).to eq(['X'])
    end

    it 'accepts the canonical version and its string equivalents' do
      expect(described_class.metrics(2)).to eq(described_class.metrics('2'))
      expect(described_class.metrics(2)).to eq(described_class.metrics('2.0'))
      expect(described_class.metrics(3.1)).to eq(described_class.metrics('3.1'))
      expect(described_class.metrics(4.0)).to eq(described_class.metrics('4.0'))
    end

    it 'accepts the version reported by a real vector instance, including v2' do
      {
        'AV:N/AC:L/Au:N/C:N/I:N/A:C' => 2,
        'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' => 3.0,
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' => 3.1,
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H' => 4.0
      }.each do |vector, version|
        expect(described_class.new(vector).version).to eq(version)
        expect { described_class.metrics(described_class.new(vector).version) }.not_to raise_error
      end
    end

    it 'raises an ArgumentError-compatible error for an unsupported version' do
      expect { described_class.metrics('9.9') }.to raise_error(CvssSuite::Errors::UnsupportedVersion)
      expect { described_class.metrics(9.9) }.to raise_error(ArgumentError)
    end

    it 'returns equal data on repeated calls' do
      expect(described_class.metrics(3.1)).to eq(described_class.metrics(3.1))
    end

    it 'returns frozen strings a caller cannot corrupt' do
      schema = described_class.metrics(3.1)

      expect(schema.first[:group]).to be_frozen
      expect(schema.first[:metrics].first[:options].first[:name]).to be_frozen
    end
  end

  describe '.parse' do
    {
      'AV:N/AC:L/Au:N/C:N/I:N/A:C' => CvssSuite::Cvss2,
      'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' => CvssSuite::Cvss3,
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' => CvssSuite::Cvss31,
      'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H' => CvssSuite::Cvss40
    }.each do |vector, klass|
      it "'#{vector}' is expected to return a #{klass}" do
        expect(described_class.parse(vector)).to be_a(klass)
      end
    end

    it 'returns a vector that scores' do
      expect(described_class.parse('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').base_score).to eq(9.8)
    end

    ['Not a valid vector!', 'CVSS:3.0/', 1337].each do |input|
      it "raises for #{input.inspect} instead of returning a sentinel" do
        expect { described_class.parse(input) }
          .to raise_error(CvssSuite::Errors::InvalidVector, 'Vector is not valid!')
      end
    end

    it 'leaves .new lenient so existing callers keep their sentinel' do
      expect(described_class.new('Not a valid vector!')).to be_a(CvssSuite::InvalidCvss)
    end
  end

  describe 'an invalid vector' do
    # Every score reader should report the same problem the same way. base_score
    # guarded from the start; temporal_score and environmental_score reached the
    # arithmetic first and either died there or, worse, returned a score for a
    # vector valid? had already rejected.
    all_readers = %i[base_score temporal_score environmental_score overall_score severity]
    # CVSS 4.0 folds threat and environmental metrics into the one score, so it
    # defines no temporal_score or environmental_score to guard.
    cvss40_readers = %i[base_score overall_score severity]

    [
      ['no recognised prefix', 'random_string', all_readers],
      ['not a string', 1337, all_readers],
      ['CVSS 3.1, prefix only', 'CVSS:3.1/AV:N', all_readers],
      ['CVSS 3.0, prefix only', 'CVSS:3.0/', all_readers],
      ['CVSS 2, missing authentication', 'AV:N/AC:P/C:P/AV:U/RL:OF/RC:C', all_readers],
      ['CVSS 2, unknown metric', 'AV:A/AC:H/Au:M/C:C/I:C/A:C/ZZ:Q', all_readers],
      ['CVSS 4.0, prefix only', 'CVSS:4.0/AV:N', cvss40_readers]
    ].each do |label, vector, readers|
      readers.each do |reader|
        it "raises InvalidVector from ##{reader} (#{label})" do
          expect { described_class.new(vector).public_send(reader) }
            .to raise_error(CvssSuite::Errors::InvalidVector, 'Vector is not valid!')
        end
      end
    end

    it 'does not expose temporal or environmental scores on CVSS 4.0 at all' do
      cvss = described_class.new('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H')

      expect(cvss).to be_valid
      expect(cvss).not_to respond_to(:temporal_score)
      expect(cvss).not_to respond_to(:environmental_score)
    end
  end

  describe 'public API surface' do
    # These were public only because .new needed them; they are parsing internals
    # that depend on module state and are meaningless to call directly.
    %i[version prepare_vector prepare_cvss2_vector].each do |internal|
      it "no longer exposes .#{internal}" do
        expect(described_class).not_to respond_to(internal)
        expect { described_class.public_send(internal) }.to raise_error(NoMethodError)
      end
    end
  end
end
