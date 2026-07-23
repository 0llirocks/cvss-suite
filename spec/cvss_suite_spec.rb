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
end
