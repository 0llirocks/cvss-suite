# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../spec_helper'

describe CvssSuite::Cvss2 do
  let(:valid_cvss2) { CvssSuite.new('AV:N/AC:L/Au:N/C:P/I:P/A:P') }
  let(:valid_cvss2_issue49) { CvssSuite.new('AV:L/AC:L/Au:N/C:C/I:C/A:C') }
  let(:valid_cvss2_maxed_out_environmental) do
    CvssSuite.new('AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H')
  end
  let(:valid_cvss2_parenthesis) { CvssSuite.new('(AV:N/AC:L/Au:N/C:P/I:P/A:P)') }
  let(:valid_cvss2_temporal) { CvssSuite.new('AV:N/AC:L/Au:N/C:P/I:P/A:P/E:U/RL:OF/RC:C') }
  let(:valid_cvss2_temporal_parenthesis) { CvssSuite.new('(AV:N/AC:L/Au:N/C:P/I:P/A:P/E:U/RL:OF/RC:C)') }
  let(:valid_cvss2_temporal_rounding) { CvssSuite.new('AV:N/AC:L/Au:N/C:C/I:P/A:P/E:H/RL:U/RC:UR') }
  let(:valid_cvss2_environmental) { CvssSuite.new('AV:A/AC:M/Au:S/C:P/I:P/A:P/CDP:L/TD:M/CR:M/IR:M/AR:M') }
  let(:valid_cvss2_environmental_parenthesis) do
    CvssSuite.new('(AV:A/AC:M/Au:S/C:P/I:P/A:P/CDP:L/TD:M/CR:M/IR:M/AR:M)')
  end
  let(:valid_cvss2_environmental_rounding) { CvssSuite.new('AV:N/AC:L/Au:N/C:C/I:P/A:P/E:H/RL:U/RC:UR') }
  let(:valid_cvss2_temporal_environmental) do
    CvssSuite.new('AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M')
  end
  let(:valid_cvss2_temporal_environmental_parenthesis) do
    CvssSuite.new('(AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M)')
  end
  let(:invalid_cvss2) { CvssSuite.new('AV:N/AC:P/C:P/AV:U/RL:OF/RC:C') }
  let(:invalid_cvss2_parenthesis_closed) { CvssSuite.new('(AV:N/AC:L/Au:N/C:P/I:P/A:P') }
  let(:invalid_cvss2_parenthesis) { CvssSuite.new('(AV:N/AC:L/Au:N()/C:P/I:P/A:P') }
  let(:invalid_cvss2_missing_metric) { CvssSuite.new('AV:N/Au:N/C:P/I:P/A:P/E:U/RL:OF/RC:C') }
  let(:invalid_cvss2_multiple_metrics) { CvssSuite.new('AV:N/AV:N/AC:L/Au:N/C:P/I:P/A:P/E:U/RL:OF/RC:C') }
  let(:invalid_cvss2_additional_fields) do
    CvssSuite.new('AV:N/AC:L/Au:N/C:P/I:P/A:P/E:U/RL:OF/RC:C/Extra/')
  end
  let(:invalid_cvss2_additional_fields_missing_temporal) do
    CvssSuite.new('AV:N/AC:L/Au:N/C:P/I:P/A:P/RL:OF/RC:C/Extra/')
  end
  let(:invalid_cvss2_extra_slash) { CvssSuite.new('AV:N//AC:L/Au:N/C:P/I:P/A:P/E:U/RL:OF/RC:C') }
  let(:invalid_cvss2_wrong_value) { CvssSuite.new('AV:N/AC:L/Au:N/C:P/I:P/A:P/E:R/RL:OF/RC:C') }
  let(:invalid_cvss2_empty_value) { CvssSuite.new('AV:N/AC:L/Au:N/C:P/I:P/A:P/E:/RL:OF/RC:C') }

  describe 'valid cvss2' do
    subject { valid_cvss2 }

    it_behaves_like 'a valid cvss vector', 2, 7.5, 6.44, 10.00, 7.5, 7.5, 7.5, 'High'
  end

  describe 'valid cvss2 for issue 49' do
    subject { valid_cvss2_issue49 }

    it_behaves_like 'a valid cvss vector', 2, 7.2, 10.00, 3.95, 7.2, 7.2, 7.2, 'High'
  end

  describe 'valid cvss2 that maxes out the environmental score' do
    subject { valid_cvss2_maxed_out_environmental }

    it_behaves_like 'a valid cvss vector', 2, 10.0, 10.00, 10.00, 10.0, 10.0, 10.0, 'High'
  end

  describe 'valid cvss2 enclosed with parenthesis' do
    subject { valid_cvss2_parenthesis }

    it_behaves_like 'a valid cvss vector', 2, 7.5, 6.44, 10.00, 7.5, 7.5, 7.5, 'High'
  end

  describe 'valid cvss2 with temporal' do
    subject { valid_cvss2_temporal }

    it_behaves_like 'a valid cvss vector', 2, 7.5, 6.44, 10.00, 5.5, 5.5, 5.5, 'High'
  end

  describe 'valid cvss2 with temporal enclosed with parenthesis' do
    subject { valid_cvss2_temporal_parenthesis }

    it_behaves_like 'a valid cvss vector', 2, 7.5, 6.44, 10.00, 5.5, 5.5, 5.5, 'High'
  end

  describe 'valid cvss2 with temporal that causes floating point errors' do
    subject { valid_cvss2_temporal_rounding }

    # base_score = 9, temporal_score = 0.95. Product should be 8.55
    it_behaves_like 'a valid cvss vector', 2, 9.0, 8.55, 10.00, 8.6, 8.6, 8.6, 'High'
  end

  describe 'valid cvss2 with environmental' do
    subject { valid_cvss2_environmental }

    it_behaves_like 'a valid cvss vector', 2, 4.9, 6.44, 4.41, 4.9, 4.1, 4.1, 'Medium'
  end

  describe 'valid cvss2 with environmental enclosed with parenthesis' do
    subject { valid_cvss2_environmental_parenthesis }

    it_behaves_like 'a valid cvss vector', 2, 4.9, 6.44, 4.41, 4.9, 4.1, 4.1, 'Medium'
  end

  describe 'valid cvss2 with environmental that causes floating point errors' do
    subject { valid_cvss2_environmental_rounding }

    # base_score = 9, temporal_score = 0.95. Product should be 8.55
    it_behaves_like 'a valid cvss vector', 2, 9.0, 8.55, 10.00, 8.6, 8.6, 8.6, 'High'
  end

  describe 'valid cvss2 with temporal and environmental' do
    subject { valid_cvss2_temporal_environmental }

    it_behaves_like 'a valid cvss vector', 2, 4.9, 6.44, 4.41, 3.6, 3.2, 3.2, 'Medium'
  end

  describe 'valid cvss2 with temporal and environmental enclosed with parenthesis' do
    subject { valid_cvss2_temporal_environmental_parenthesis }

    it_behaves_like 'a valid cvss vector', 2, 4.9, 6.44, 4.41, 3.6, 3.2, 3.2, 'Medium'
  end

  describe 'invalid cvss2' do
    subject { invalid_cvss2 }

    it_behaves_like 'a invalid cvss vector with version', 2
  end

  describe 'invalid cvss2 with missing closing parenthesis' do
    subject { invalid_cvss2_parenthesis_closed }

    it_behaves_like 'a invalid cvss vector with version', 2
  end

  describe 'invalid cvss2 with incorrect parenthesis' do
    subject { invalid_cvss2_parenthesis }

    it_behaves_like 'a invalid cvss vector with version', 2
  end

  describe 'invalid cvss2 with missing base metric' do
    subject { invalid_cvss2_missing_metric }

    it_behaves_like 'a invalid cvss vector with version', 2
  end

  describe 'invalid cvss2 with multiple base metrics' do
    subject { invalid_cvss2_multiple_metrics }

    it_behaves_like 'a invalid cvss vector with version', 2
  end

  describe 'invalid cvss2 with additional fields' do
    subject { invalid_cvss2_additional_fields }

    it_behaves_like 'a invalid cvss vector with version', 2
  end

  describe 'invalid cvss2 with additional fields missing temporal' do
    subject { invalid_cvss2_additional_fields_missing_temporal }

    it_behaves_like 'a invalid cvss vector with version', 2
  end

  describe 'invalid cvss2 with extra slash' do
    subject { invalid_cvss2_extra_slash }

    it_behaves_like 'a invalid cvss vector with version', 2
  end

  describe 'invalid cvss2 with wrong value for Exploit Code Maturity (E)' do
    subject { invalid_cvss2_wrong_value }

    it_behaves_like 'a invalid cvss vector with version', 2
  end

  describe 'invalid cvss2 with empty value for Exploit Code Maturity (E)' do
    subject { invalid_cvss2_empty_value }

    it_behaves_like 'a invalid cvss vector with version', 2
  end

  # Severity tests https://nvd.nist.gov/vuln-metrics/cvss
  # v2 Severity High: 7.0 - 10.0
  describe 'valid cvss2_severity_high' do
    [
      'AV:A/AC:M/Au:S/C:C/I:C/A:P', # 7.04
      'AV:N/AC:M/Au:N/C:C/I:C/A:C', # 9.33
      'AV:N/AC:L/Au:N/C:C/I:C/A:C'  # 9.99
    ].each do |vector|
      it "'#{vector}' severity is expected to eql \"High\"" do
        cv2 = CvssSuite.new(vector)
        expect(cv2.severity).to eq('High')
      end
    end
  end

  # v2 Severity Med: 4.0 - 6.9
  describe 'valid cvss2_severity_med' do
    [
      'AV:N/AC:H/Au:N/C:N/I:P/A:P', # 4.03
      'AV:N/AC:L/Au:M/C:P/I:P/A:P', # 5.78
      'AV:L/AC:M/Au:N/C:C/I:C/A:C' # 6.88
    ].each do |vector|
      it "'#{vector}' severity is expected to eql \"Medium\"" do
        cv2 = CvssSuite.new(vector)
        expect(cv2.severity).to eq('Medium')
      end
    end
  end

  # v2 Severity Low: 0.0 - 3.9
  describe 'valid cvss2_severity_low' do
    [
      'AV:L/AC:H/Au:M/C:N/I:N/A:N', # 0.0
      'AV:L/AC:L/Au:M/C:P/I:N/A:N' # 1.44
    ].each do |vector|
      it "'#{vector}' severity is expected to eql \"Low\"" do
        cv2 = CvssSuite.new(vector)
        expect(cv2.severity).to eq('Low')
      end
    end
  end

  describe 'correct vector' do
    [
      ['AV:N/AC:L/Au:N/C:P/I:P/A:P', 'AV:N/AC:L/Au:N/C:P/I:P/A:P'],
      ['(AV:N/AC:L/Au:N/C:P/I:P/A:P)', 'AV:N/AC:L/Au:N/C:P/I:P/A:P']
    ].each do |vector|
      it "'#{vector[0]}' is expected to return '#{vector[1]}'" do
        expect(CvssSuite.new(vector[0]).vector).to eq(vector[1])
      end
    end
  end
end
