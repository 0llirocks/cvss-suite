# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require 'debug'
require_relative '../spec_helper'

describe CvssSuite::Cvss40 do
  let(:valid_cvss40_unreported_threat) { CvssSuite.new('CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:P/VC:L/VI:L/VA:H/SC:L/SI:H/SA:N/E:U') } # 1.6, Low
  let(:valid_cvss40_base) { CvssSuite.new('CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:H/SA:L')} # 7.2, high
 
  describe 'valid cvss40 threat' do
    subject { valid_cvss40_unreported_threat }
   
    it_behaves_like 'a valid 4.0 cvss vector', 4.0, 1.6, 'Low'
  end

  describe 'valid cvss40 base' do
    subject { valid_cvss40_base }
   
    it_behaves_like 'a valid 4.0 cvss vector', 4.0, 7.2, 'High'
  end
end
