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
  # Base-only vectors with Scope: Changed (issue #58)
  let(:valid_cvss31_base_only_scope_changed_1) { CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H') }
  let(:valid_cvss31_base_only_scope_changed_2) { CvssSuite.new('CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H') }
  let(:valid_cvss31_base_only_scope_changed_3) { CvssSuite.new('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H') }
  let(:valid_cvss31_base_only_scope_changed_4) { CvssSuite.new('CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H') }
  let(:valid_cvss31_base_only_scope_changed_5) { CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H') }
  # Base-only with Scope: Unchanged (sanity check — should also return base_score)
  let(:valid_cvss31_base_only_scope_unchanged) { CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H') }
  # Temporal-only with Scope: Changed (issue #58)
  let(:valid_cvss31_temporal_only_scope_changed_1) { CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H/E:H/RL:T/RC:C') }
  let(:valid_cvss31_temporal_only_scope_changed_2) { CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H/E:P/RL:O/RC:R') }
  # Environmental-only with Scope: Changed (issue #58)
  let(:valid_cvss31_env_only_scope_changed) do
    CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H') # rubocop:disable Layout/LineLength
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

  # Issue #58: overall_score should equal base_score for base-only vectors with Scope: Changed
  describe 'base-only vectors with Scope: Changed (issue #58)' do
    it 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H overall_score equals base_score (9.6)' do
      cvss = valid_cvss31_base_only_scope_changed_1
      expect(cvss.overall_score).to eql(cvss.base_score)
      expect(cvss.base_score).to eql(9.6)
    end

    it 'CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H overall_score equals base_score (7.6)' do
      cvss = valid_cvss31_base_only_scope_changed_2
      expect(cvss.overall_score).to eql(cvss.base_score)
      expect(cvss.base_score).to eql(7.6)
    end

    it 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H overall_score equals base_score (9.0)' do
      cvss = valid_cvss31_base_only_scope_changed_3
      expect(cvss.overall_score).to eql(cvss.base_score)
      expect(cvss.base_score).to eql(9.0)
    end

    it 'CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H overall_score equals base_score (8.8)' do
      cvss = valid_cvss31_base_only_scope_changed_4
      expect(cvss.overall_score).to eql(cvss.base_score)
      expect(cvss.base_score).to eql(8.8)
    end

    it 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H overall_score equals base_score (9.0)' do
      cvss = valid_cvss31_base_only_scope_changed_5
      expect(cvss.overall_score).to eql(cvss.base_score)
      expect(cvss.base_score).to eql(9.0)
    end
  end

  # Issue #58: overall_score should equal base_score for base-only S:U vectors too
  describe 'base-only vector with Scope: Unchanged (issue #58 sanity check)' do
    it 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H overall_score equals base_score (8.8)' do
      cvss = valid_cvss31_base_only_scope_unchanged
      expect(cvss.overall_score).to eql(cvss.base_score)
      expect(cvss.base_score).to eql(8.8)
    end
  end

  # Issue #58: overall_score should equal temporal_score when only temporal metrics are provided
  describe 'temporal-only vectors with Scope: Changed (issue #58)' do
    it 'CVSS:3.1/.../E:H/RL:T/RC:C overall_score equals temporal_score (9.3)' do
      cvss = valid_cvss31_temporal_only_scope_changed_1
      expect(cvss.overall_score).to eql(cvss.temporal_score)
      expect(cvss.temporal_score).to eql(9.3)
    end

    it 'CVSS:3.1/.../E:P/RL:O/RC:R overall_score equals temporal_score (8.3)' do
      cvss = valid_cvss31_temporal_only_scope_changed_2
      expect(cvss.overall_score).to eql(cvss.temporal_score)
      expect(cvss.temporal_score).to eql(8.3)
    end
  end

  # Issue #58: overall_score should equal environmental_score when only env metrics are provided
  describe 'environmental-only vector with Scope: Changed (issue #58)' do
    it 'overall_score equals environmental_score (7.3)' do
      cvss = valid_cvss31_env_only_scope_changed
      expect(cvss.overall_score).to eql(cvss.environmental_score)
      expect(cvss.environmental_score).to eql(7.3)
    end
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
