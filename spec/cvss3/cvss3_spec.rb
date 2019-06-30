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

describe Cvss3 do

  let(:valid_cvss3) { CvssSuite.new('CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L') }
  let(:valid_cvss3_base_score10) { CvssSuite.new('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:O/RC:C') }
  let(:valid_cvss3_temporal_score10) { CvssSuite.new('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C') }
  let(:valid_cvss3_temporal_round_up) { CvssSuite.new('CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U') }
  let(:valid_cvss3_temporal) { CvssSuite.new('CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N/E:P/RL:T/RC:C') }
  let(:valid_cvss3_environmental) { CvssSuite.new('CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H') }
  let(:valid_cvss3_temporal_environmental) { CvssSuite.new('CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:P/RL:W/RC:R/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:C/MC:N/MI:L/MA:H') }
  let(:invalid_cvss3_with_version) { CvssSuite.new('CVSS:3.0/AV:L/AC:') }

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

  describe 'invalid cvss3' do
    subject { invalid_cvss3_with_version }

    it_should_behave_like 'a invalid cvss vector with version', 3.0
  end
end