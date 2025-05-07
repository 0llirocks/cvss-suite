# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative 'spec_helper'
require 'csv'

describe CvssSuite::Cvss do
  context 'when initialized without subclass' do
    subject { described_class.new('AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L') }

    it 'raises InvalidParentClass error' do
      expect { subject }.to raise_error(CvssSuite::Errors::InvalidParentClass)
    end

    it 'raises InvalidParentClass error' do
      expect { subject }.to raise_error(ArgumentError)
    end
  end

  describe 'calculations' do
    CSV.foreach(File.join(__dir__, 'cvss_scores.csv'), headers: true) do |row|
      context "with CVSS vector #{row['Vector']}" do
        subject { CvssSuite.new(row['Vector']) }

        let(:version) { row['Version'].to_i == 2 ? 2 : row['Version'].to_f }
        let(:base_score) { row['BaseScore'].to_f }
        let(:temporal_score) { row['TemporalScore'] ? row['TemporalScore'].to_f : base_score }
        let(:environmental_score) { row['EnvironmentalScore'] ? row['EnvironmentalScore'].to_f : temporal_score }

        its(:version) { is_expected.to eql(version) }
        if row['Version'].to_i < 4
          its(:base_score) { is_expected.to eql(base_score) }
          its(:temporal_score) { is_expected.to eql(temporal_score) }
          its(:environmental_score) { is_expected.to eql(environmental_score) }
          it 'has the correct impact subscore' do
            expect(subject.base.impact_subscore).to be_within(0.01).of(row['ImpactSubscore'].to_f)
          end
          it 'has the correct exploitability subscore' do
            expect(subject.base.exploitability_subscore).to be_within(0.01).of(row['ExploitabilitySubscore'].to_f)
          end
        else
          its(:overall_score) { is_expected.to eql(base_score) }
        end
      end
    end
  end
end
