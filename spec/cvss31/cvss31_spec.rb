# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../spec_helper'

describe CvssSuite::Cvss31 do
  let(:valid_cvss31) { CvssSuite.new('CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L') }
  let(:valid_reordered_cvss31) { CvssSuite.new('CVSS:3.1/A:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/AV:L') }
  let(:valid_cvss31_base_score10) { CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:O/RC:C') }
  let(:valid_cvss31_temporal_score10) { CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C') }
  let(:valid_cvss31_temporal_round_up) { CvssSuite.new('CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U') }
  let(:valid_cvss31_temporal) { CvssSuite.new('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N/E:P/RL:T/RC:C') }
  let(:valid_incomplete_cvss31_temporal) { CvssSuite.new('CVSS:3.1/RC:C/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N/RL:T/AV:N') }
  let(:valid_reordered_cvss31_temporal) { CvssSuite.new('CVSS:3.1/RC:C/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N/E:P/RL:T/AV:N') }
  let(:valid_cvss31_environmental) do
    CvssSuite.new('CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H') # rubocop:disable Layout/LineLength
  end
  let(:valid_reordered_cvss31_environmental) do
    CvssSuite.new('CVSS:3.1/MA:H/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/AV:L') # rubocop:disable Layout/LineLength
  end
  let(:valid_cvss31_temporal_environmental) do
    CvssSuite.new('CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:P/RL:W/RC:R/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:C/MC:N/MI:L/MA:H') # rubocop:disable Layout/LineLength
  end
  let(:valid_cvss31_temporal_environmental_partly_not_defined) do
    CvssSuite.new('CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H/E:X/RL:T/RC:C/CR:M/IR:L/AR:H/MAV:P/MAC:L/MPR:L/MUI:X/MS:U/MC:N/MI:X/MA:H') # rubocop:disable Layout/LineLength
  end
  let(:valid_cvss31_temporal_environmental_not_defined) do
    CvssSuite.new('CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H/E:X/RL:T/RC:C/CR:M/IR:L/AR:H/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X') # rubocop:disable Layout/LineLength
  end
  let(:valid_cvss31_temporal_environmental_modified_confidentiality_low) do
    CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:H') # rubocop:disable Layout/LineLength
  end
  let(:valid_cvss31_temporal_environmental_modified_confidentiality_high) do
    CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H') # rubocop:disable Layout/LineLength
  end
  let(:invalid_cvss31_with_version) { CvssSuite.new('CVSS:3.1/AV:L/AC:') }
  let(:invalid_cvss31_not_defined) { CvssSuite.new('CVSS:3.1/AV:X/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:H') }
  let(:invalid_cvss31_missing_metric) { CvssSuite.new('CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L') }
  let(:invalid_cvss31_multiple_metrics) { CvssSuite.new('CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L/A:L') }
  let(:invalid_cvss31_additional_fields) do
    CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P/RL:U/RC:C/Extra/')
  end
  let(:invalid_cvss31_additional_fields_missing_temporal) do
    CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/Extra/')
  end
  let(:invalid_cvss31_extra_slash) { CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N//I:N/A:H/E:P/RL:U/RC:C/') }
  let(:invalid_cvss31_wrong_value) { CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:R/RL:U/RC:C') }
  let(:invalid_cvss31_empty_value) { CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:/RL:U/RC:C') }

  describe 'valid cvss31' do
    subject { valid_cvss31 }

    it_behaves_like 'a valid cvss vector', 3.1, 4.2, 3.37, 0.76, 4.2, 4.2, 4.2, 'Medium'
  end

  describe 'valid reordered cvss31' do
    subject { valid_reordered_cvss31 }

    it_behaves_like 'a valid cvss vector', 3.1, 4.2, 3.37, 0.76, 4.2, 4.2, 4.2, 'Medium'
  end

  describe 'valid cvss31 with base_score 10' do
    subject { valid_cvss31_base_score10 }

    it_behaves_like 'a valid cvss vector', 3.1, 10.0, 6.05, 3.89, 8.7, 8.7, 8.7, 'High'
  end

  describe 'valid cvss31 with temporal_score 10' do
    subject { valid_cvss31_temporal_score10 }

    it_behaves_like 'a valid cvss vector', 3.1, 10.0, 6.05, 3.89, 10.0, 10.0, 10.0, 'Critical'
  end

  describe 'valid cvss31 with temporal_round_up' do
    subject { valid_cvss31_temporal_round_up }

    it_behaves_like 'a valid cvss vector', 3.1, 5.0, 4.70, 0.28, 4.6, 4.6, 4.6, 'Medium'
  end

  describe 'valid cvss31 with temporal' do
    subject { valid_cvss31_temporal }

    it_behaves_like 'a valid cvss vector', 3.1, 4.0, 1.44, 2.22, 3.7, 3.7, 3.7, 'Low'
  end

  describe 'valid incomplete cvss31 with temporal' do
    subject { valid_incomplete_cvss31_temporal }

    it_behaves_like 'a valid cvss vector', 3.1, 4.0, 1.44, 2.22, 3.9, 3.9, 3.9, 'Low'
  end

  describe 'valid reordered cvss31 with temporal' do
    subject { valid_reordered_cvss31_temporal }

    it_behaves_like 'a valid cvss vector', 3.1, 4.0, 1.44, 2.22, 3.7, 3.7, 3.7, 'Low'
  end

  describe 'valid cvss31 with environmental' do
    subject { valid_cvss31_environmental }

    it_behaves_like 'a valid cvss vector', 3.1, 5.0, 3.73, 0.84, 5.0, 7.3, 7.3, 'High'
  end

  describe 'valid reordered cvss31 with environmental' do
    subject { valid_reordered_cvss31_environmental }

    it_behaves_like 'a valid cvss vector', 3.1, 5.0, 3.73, 0.84, 5.0, 7.3, 7.3, 'High'
  end

  describe 'valid cvss31 with temporal and environmental' do
    subject { valid_cvss31_temporal_environmental }

    it_behaves_like 'a valid cvss vector', 3.1, 5.0, 3.73, 0.84, 4.4, 7.4, 7.4, 'High'
  end

  describe 'valid cvss31 with temporal and environmental and partly not defined' do
    subject { valid_cvss31_temporal_environmental_partly_not_defined }

    it_behaves_like 'a valid cvss vector', 3.1, 5.7, 4.72, 0.54, 5.5, 6.0, 6.0, 'Medium'
  end

  describe 'valid cvss31 with temporal and environmental and not defined' do
    subject { valid_cvss31_temporal_environmental_not_defined }

    it_behaves_like 'a valid cvss vector', 3.1, 5.7, 4.72, 0.54, 5.5, 6.9, 6.9, 'Medium'
  end

  describe 'valid cvss31 with temporal and environmental and modified confidentiality low' do
    subject { valid_cvss31_temporal_environmental_modified_confidentiality_low }

    it_behaves_like 'a valid cvss vector', 3.1, 10.0, 6.05, 3.89, 8.1, 5.6, 5.6, 'Medium'
  end

  describe 'valid cvss31 with temporal and environmental and modified confidentiality high' do
    subject { valid_cvss31_temporal_environmental_modified_confidentiality_high }

    it_behaves_like 'a valid cvss vector', 3.1, 10.0, 6.05, 3.89, 8.1, 5.6, 5.6, 'Medium'
  end

  describe 'invalid cvss31' do
    subject { invalid_cvss31_with_version }

    it_behaves_like 'a invalid cvss vector with version', 3.1
  end

  describe 'invalid cvss31 with not defined' do
    subject { invalid_cvss31_not_defined }

    it_behaves_like 'a invalid cvss vector with version', 3.1
  end

  describe 'invalid cvss31 with missing base metric' do
    subject { invalid_cvss31_missing_metric }

    it_behaves_like 'a invalid cvss vector with version', 3.1
  end

  describe 'invalid cvss31 with multiple base metrics' do
    subject { invalid_cvss31_multiple_metrics }

    it_behaves_like 'a invalid cvss vector with version', 3.1
  end

  describe 'invalid cvss31 with additional fields' do
    subject { invalid_cvss31_additional_fields }

    it_behaves_like 'a invalid cvss vector with version', 3.1
  end

  describe 'invalid cvss31 with additional fields missing temporal' do
    subject { invalid_cvss31_additional_fields_missing_temporal }

    it_behaves_like 'a invalid cvss vector with version', 3.1
  end

  describe 'invalid cvss31 with extra slash' do
    subject { invalid_cvss31_extra_slash }

    it_behaves_like 'a invalid cvss vector with version', 3.1
  end

  describe 'invalid cvss31 with wrong value for Exploit Code Maturity (E)' do
    subject { invalid_cvss31_wrong_value }

    it_behaves_like 'a invalid cvss vector with version', 3.1
  end

  describe 'invalid cvss31 with wrong value for Exploit Code Maturity (E)' do
    subject { invalid_cvss31_empty_value }

    it_behaves_like 'a invalid cvss vector with version', 3.1
  end

  describe 'correct vector' do
    [
      ['CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L', 'CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L'],
      ['CVSS:3.1/A:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/AV:L', 'CVSS:3.1/A:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/AV:L'],
      [
        'CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H/E:X/RL:T/RC:C/CR:M/IR:L/AR:H/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X', # rubocop:disable Layout/LineLength
        'CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H/E:X/RL:T/RC:C/CR:M/IR:L/AR:H/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X' # rubocop:disable Layout/LineLength
      ]
    ].each do |vector|
      it "'#{vector[0]}' is expected to return '#{vector[1]}'" do
        expect(CvssSuite.new(vector[0]).vector).to eq(vector[1])
      end
    end
  end
end
