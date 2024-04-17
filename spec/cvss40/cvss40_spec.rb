# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require 'debug'
require_relative '../spec_helper'

describe CvssSuite::Cvss40 do
  let(:valid_cvss40) { CvssSuite.new('CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N') }

  describe 'valid cvss40' do
    subject { valid_cvss40 }
   
    it_behaves_like 'a valid cvss vector', 4.0, 6.6, 6.6, 6.6, 6.6, 'Medium'
  end
end
