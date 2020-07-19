# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) Siemens AG, 2016
#
# Authors:
#   Oliver Hambörger <oliver.hamboerger@siemens.com>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../spec_helper'

describe CvssSuite::Cvss3 do
  let(:valid_cvss3) { CvssSuite.new('CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L') }
  let(:valid_cvss3_base_score10) { CvssSuite.new('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:O/RC:C') }
  let(:valid_cvss3_temporal_score10) { CvssSuite.new('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C') }
  let(:valid_cvss3_temporal_round_up) { CvssSuite.new('CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U') }
  let(:valid_cvss3_temporal) { CvssSuite.new('CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N/E:P/RL:T/RC:C') }
  let(:valid_cvss3_environmental) do
    CvssSuite.new('CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H') # rubocop:disable Layout/LineLength
  end
  let(:valid_cvss3_temporal_environmental) do
    CvssSuite.new('CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:P/RL:W/RC:R/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:C/MC:N/MI:L/MA:H') # rubocop:disable Layout/LineLength
  end
  let(:valid_cvss3_temporal_environmental_partly_not_defined) do
    CvssSuite.new('CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H/E:X/RL:T/RC:C/CR:M/IR:L/AR:H/MAV:P/MAC:L/MPR:L/MUI:X/MS:U/MC:N/MI:X/MA:H') # rubocop:disable Layout/LineLength
  end
  let(:valid_cvss3_temporal_environmental_not_defined) do
    CvssSuite.new('CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H/E:X/RL:T/RC:C/CR:M/IR:L/AR:H/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X') # rubocop:disable Layout/LineLength
  end
  let(:valid_cvss3_temporal_environmental_modified_confidentiality_low) do
    CvssSuite.new('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:H') # rubocop:disable Layout/LineLength
  end
  let(:valid_cvss3_temporal_environmental_modified_confidentiality_high) do
    CvssSuite.new('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H') # rubocop:disable Layout/LineLength
  end
  let(:invalid_cvss3_with_version) { CvssSuite.new('CVSS:3.0/AV:L/AC:') }
  let(:invalid_cvss3_not_defined) { CvssSuite.new('CVSS:3.0/AV:X/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:H') }

  describe 'valid cvss3' do
    subject { valid_cvss3 }

    it_should_behave_like 'a valid cvss vector', 3.0, 4.2, 4.2, 4.2, 4.2, 'Medium'
  end

  describe 'valid cvss3 with base_score 10' do
    subject { valid_cvss3_base_score10 }

    it_should_behave_like 'a valid cvss vector', 3.0, 10.0, 8.7, 8.7, 8.7, 'High'
  end

  describe 'valid cvss3 with temporal_score 10' do
    subject { valid_cvss3_temporal_score10 }

    it_should_behave_like 'a valid cvss vector', 3.0, 10.0, 10.0, 10.0, 10.0, 'Critical'
  end

  describe 'valid cvss3 with temporal_round_up' do
    subject { valid_cvss3_temporal_round_up }

    it_should_behave_like 'a valid cvss vector', 3.0, 5.0, 4.7, 4.7, 4.7, 'Medium'
  end

  describe 'valid cvss3 with temporal' do
    subject { valid_cvss3_temporal }

    it_should_behave_like 'a valid cvss vector', 3.0, 4.0, 3.7, 3.7, 3.7, 'Low'
  end

  describe 'valid cvss3 with environmental' do
    subject { valid_cvss3_environmental }

    it_should_behave_like 'a valid cvss vector', 3.0, 5.0, 5.0, 7.3, 7.3, 'High'
  end

  describe 'valid cvss3 with temporal and environmental' do
    subject { valid_cvss3_temporal_environmental }

    it_should_behave_like 'a valid cvss vector', 3.0, 5.0, 4.4, 7.3, 7.3, 'High'
  end

  describe 'valid cvss3 with temporal and environmental and partly not defined' do
    subject { valid_cvss3_temporal_environmental_partly_not_defined }

    it_behaves_like 'a valid cvss vector', 3.0, 5.7, 5.5, 6.0, 6.0, 'Medium'
  end

  describe 'valid cvss3 with temporal and environmental and not defined' do
    subject { valid_cvss3_temporal_environmental_not_defined }

    it_behaves_like 'a valid cvss vector', 3.0, 5.7, 5.5, 6.9, 6.9, 'Medium'
  end

  describe 'valid cvss3 with temporal and environmental and modified confidentiality low' do
    subject { valid_cvss3_temporal_environmental_modified_confidentiality_low }

    it_should_behave_like 'a valid cvss vector', 3.0, 10.0, 8.1, 5.6, 5.6, 'Medium'
  end

  describe 'valid cvss3 with temporal and environmental and modified confidentiality high' do
    subject { valid_cvss3_temporal_environmental_modified_confidentiality_high }

    it_should_behave_like 'a valid cvss vector', 3.0, 10.0, 8.1, 5.5, 5.5, 'Medium'
  end

  describe 'invalid cvss3' do
    subject { invalid_cvss3_with_version }

    it_should_behave_like 'a invalid cvss vector with version', 3.0
  end

  describe 'invalid cvss3 with not defined' do
    subject { invalid_cvss3_not_defined }

    it_behaves_like 'a invalid cvss vector with version', 3.0
  end
end
