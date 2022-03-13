# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) 2016-2022 Siemens AG
# Copyright (c) 2022 0llirocks
#
# Authors:
#   Adam David <adamrdavid@gmail.com>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative 'spec_helper'

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
end
