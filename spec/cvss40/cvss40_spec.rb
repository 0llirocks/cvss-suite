# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require 'debug'
require_relative '../spec_helper'

describe CvssSuite::Cvss40 do
  let(:valid_cvss40) { CvssSuite.new('CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N') }
  let(:valid_cvss40_unreported_threat) { CvssSuite.new('CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:P/VC:L/VI:L/VA:H/SC:L/SI:H/SA:N') } # 1.6, Low

  # describe 'valid cvss40 base' do
  #   subject { valid_cvss40 }
   
  #   it_behaves_like 'a valid 4.0 cvss vector', 4.0, 6.6, 6.6, 6.6, 6.6, 6.6, 'Medium'
  # end
 
  describe 'valid cvss40 threat' do
    subject { valid_cvss40_unreported_threat }
   
    it_behaves_like 'a valid 4.0 cvss vector', 4.0, 5.8, 'Low'
  end
end
