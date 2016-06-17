# © Siemens AG, 2016

require_relative '../spec_helper'

describe Cvss3 do

  let(:valid_cvss3) { CvssSuite.new('CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L') }
  let(:valid_cvss3_temporal) { CvssSuite.new('CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N/E:P/RL:T/RC:C') }
  let(:valid_cvss3_environmental) { CvssSuite.new('CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H') }
  let(:valid_cvss3_temporal_environmental) { CvssSuite.new('CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:P/RL:W/RC:R/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:C/MC:N/MI:L/MA:H') }
  let(:invalid_cvss3_with_version) { CvssSuite.new('CVSS:3.0/AV:L/AC:') }

  describe 'valid cvss3' do
    subject { valid_cvss3 }

    it_should_behave_like 'a valid cvss vector', 3, 4.2, 4.2, 4.2, 4.2
  end

  describe 'valid cvss3 with temporal' do
    subject { valid_cvss3_temporal }

    it_should_behave_like 'a valid cvss vector', 3, 4.0, 3.7, 3.7, 3.7
  end

  describe 'valid cvss3 with environmental' do
    subject { valid_cvss3_environmental }

    it_should_behave_like 'a valid cvss vector', 3, 5.0, 5.0, 7.3, 7.3
  end

  describe 'valid cvss3 with temporal and environmental' do
    subject { valid_cvss3_temporal_environmental }

    it_should_behave_like 'a valid cvss vector', 3, 5.0, 4.4, 7.3, 7.3
  end

  describe 'invalid cvss3' do
    subject { invalid_cvss3_with_version }

    it_should_behave_like 'a invalid cvss vector with version', 3
  end
end