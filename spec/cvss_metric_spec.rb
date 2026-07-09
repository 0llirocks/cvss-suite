# frozen_string_literal: true

# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative 'spec_helper'

describe CvssSuite::CvssMetric, '#explicitly_provided?' do
  context 'with a CVSS 3.1 base-only vector' do
    let(:cvss) { CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H') }

    it 'base metric is explicitly provided' do
      expect(cvss.base.explicitly_provided?).to be true
    end

    it 'temporal metric is not explicitly provided' do
      expect(cvss.temporal.explicitly_provided?).to be false
    end

    it 'environmental metric is not explicitly provided' do
      expect(cvss.environmental.explicitly_provided?).to be false
    end
  end

  context 'with a CVSS 3.1 vector including temporal metrics' do
    let(:cvss) { CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H/E:H/RL:T/RC:C') }

    it 'temporal metric is explicitly provided' do
      expect(cvss.temporal.explicitly_provided?).to be true
    end

    it 'environmental metric is not explicitly provided' do
      expect(cvss.environmental.explicitly_provided?).to be false
    end
  end

  context 'with a CVSS 3.1 vector including environmental metrics' do
    let(:cvss) do
      CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H') # rubocop:disable Layout/LineLength
    end

    it 'temporal metric is not explicitly provided' do
      expect(cvss.temporal.explicitly_provided?).to be false
    end

    it 'environmental metric is explicitly provided' do
      expect(cvss.environmental.explicitly_provided?).to be true
    end
  end

  context 'with a CVSS 3.1 vector including temporal and environmental metrics' do
    let(:cvss) do
      CvssSuite.new('CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:P/RL:W/RC:R/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:C/MC:N/MI:L/MA:H') # rubocop:disable Layout/LineLength
    end

    it 'temporal metric is explicitly provided' do
      expect(cvss.temporal.explicitly_provided?).to be true
    end

    it 'environmental metric is explicitly provided' do
      expect(cvss.environmental.explicitly_provided?).to be true
    end
  end

  context 'with a CVSS 3.1 vector with all environmental modifiers set to X' do
    let(:cvss) do
      CvssSuite.new('CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H/E:X/RL:T/RC:C/CR:M/IR:L/AR:H/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X') # rubocop:disable Layout/LineLength
    end

    it 'temporal metric is explicitly provided (RL:T, RC:C are non-default)' do
      expect(cvss.temporal.explicitly_provided?).to be true
    end

    it 'environmental metric is explicitly provided (CR:M, IR:L, AR:H are non-default)' do
      expect(cvss.environmental.explicitly_provided?).to be true
    end
  end

  context 'with a CVSS 2 base-only vector' do
    let(:cvss) { CvssSuite.new('AV:N/AC:L/Au:N/C:P/I:P/A:P') }

    it 'base metric is explicitly provided' do
      expect(cvss.base.explicitly_provided?).to be true
    end

    it 'temporal metric is not explicitly provided' do
      expect(cvss.temporal.explicitly_provided?).to be false
    end

    it 'environmental metric is not explicitly provided' do
      expect(cvss.environmental.explicitly_provided?).to be false
    end
  end

  context 'with a CVSS 3.0 base-only vector' do
    let(:cvss) { CvssSuite.new('CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H') }

    it 'temporal metric is not explicitly provided' do
      expect(cvss.temporal.explicitly_provided?).to be false
    end

    it 'environmental metric is not explicitly provided' do
      expect(cvss.environmental.explicitly_provided?).to be false
    end
  end
end
