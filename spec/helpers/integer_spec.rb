# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) Siemens AG, 2016
#
# Authors:
#   Adam David <adamrdavid@gmail.com>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../spec_helper'

describe Integer do
  let(:integer) { 2 }

  describe '#round_up' do
    subject { integer.round_up(places) }

    context 'by 0 places' do
      let(:places) { 0 }

      it { is_expected.to eq 2.0 }
    end

    context 'by 1 place' do
      let(:places) { 1 }

      it { is_expected.to eq 2.0 }
    end
  end
end
