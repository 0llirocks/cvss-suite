# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) 2016-2022 Siemens AG
# Copyright (c) 2022-2023 0llirocks
#
# Authors:
#   0llirocks <http://0lli.rocks>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../spec_helper'

describe CvssSuite::Cvss2 do
  let(:valid_cvss2) { CvssSuite.new('AV:N/AC:L/Au:N/C:P/I:P/A:P') }
  let(:valid_cvss2_parenthesis) { CvssSuite.new('(AV:N/AC:L/Au:N/C:P/I:P/A:P)') }
  let(:valid_cvss2_temporal) { CvssSuite.new('AV:N/AC:L/Au:N/C:P/I:P/A:P/E:U/RL:OF/RC:C') }
  let(:valid_cvss2_temporal_parenthesis) { CvssSuite.new('(AV:N/AC:L/Au:N/C:P/I:P/A:P/E:U/RL:OF/RC:C)') }
  let(:valid_cvss2_environmental) { CvssSuite.new('AV:A/AC:M/Au:S/C:P/I:P/A:P/CDP:L/TD:M/CR:M/IR:M/AR:M') }
  let(:valid_cvss2_environmental_parenthesis) do
    CvssSuite.new('(AV:A/AC:M/Au:S/C:P/I:P/A:P/CDP:L/TD:M/CR:M/IR:M/AR:M)')
  end
  let(:valid_cvss2_temporal_environmental) do
    CvssSuite.new('AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M')
  end
  let(:valid_cvss2_temporal_environmental_parenthesis) do
    CvssSuite.new('(AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M)')
  end
  let(:invalid_cvss2) { CvssSuite.new('AV:N/AC:P/C:P/AV:U/RL:OF/RC:C') }
  let(:invalid_cvss2_parenthesis_closed) { CvssSuite.new('(AV:N/AC:L/Au:N/C:P/I:P/A:P') }
  let(:invalid_cvss2_parenthesis) { CvssSuite.new('(AV:N/AC:L/Au:N()/C:P/I:P/A:P') }

  describe 'valid cvss2' do
    subject { valid_cvss2 }

    it_behaves_like 'a valid cvss vector', 2, 7.5, 7.5, 7.5, 7.5, 'High'
  end

  describe 'valid cvss2 enclosed with parenthesis' do
    subject { valid_cvss2_parenthesis }

    it_behaves_like 'a valid cvss vector', 2, 7.5, 7.5, 7.5, 7.5, 'High'
  end

  describe 'valid cvss2 with temporal' do
    subject { valid_cvss2_temporal }

    it_behaves_like 'a valid cvss vector', 2, 7.5, 5.5, 5.5, 5.5, 'Medium'
  end

  describe 'valid cvss2 with temporal enclosed with parenthesis' do
    subject { valid_cvss2_temporal_parenthesis }

    it_behaves_like 'a valid cvss vector', 2, 7.5, 5.5, 5.5, 5.5, 'Medium'
  end

  describe 'valid cvss2 with environmental' do
    subject { valid_cvss2_environmental }

    it_behaves_like 'a valid cvss vector', 2, 4.9, 4.9, 4.1, 4.1, 'Medium'
  end

  describe 'valid cvss2 with environmental enclosed with parenthesis' do
    subject { valid_cvss2_environmental_parenthesis }

    it_behaves_like 'a valid cvss vector', 2, 4.9, 4.9, 4.1, 4.1, 'Medium'
  end

  describe 'valid cvss2 with temporal and environmental' do
    subject { valid_cvss2_temporal_environmental }

    it_behaves_like 'a valid cvss vector', 2, 4.9, 3.6, 3.2, 3.2, 'Low'
  end

  describe 'valid cvss2 with temporal and environmental enclosed with parenthesis' do
    subject { valid_cvss2_temporal_environmental_parenthesis }

    it_behaves_like 'a valid cvss vector', 2, 4.9, 3.6, 3.2, 3.2, 'Low'
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
