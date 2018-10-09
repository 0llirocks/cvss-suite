# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) Siemens AG, 2016
#
# Authors:
#   Oliver Hambörger <oliver.hamboerger@siemens.com>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative 'spec_helper'

describe CvssSuite do
  it 'has a version number' do
    expect(CvssSuite::VERSION).not_to be nil
  end

  it 'is invalid' do
    expect { CvssSuite.new('Not a valid vector!') }
      .to raise_error(CvssSuite::Errors::InvalidVector, 'Vector is not valid!')
  end

  it 'is invalid' do
    expect { CvssSuite.new('Not a valid vector!') }
        .to raise_error(RuntimeError)
  end
end
