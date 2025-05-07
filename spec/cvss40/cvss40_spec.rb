# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../spec_helper'

describe CvssSuite::Cvss40 do
  [
    {
      name: 'full-impact',
      cvss_string: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',
      expected_score: 10.0,
      expected_severity: 'Critical'
    },
    {
      name: 'no-impact',
      cvss_string: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
      expected_score: 0.0,
      expected_severity: 'None'
    },
    {
      name: 'full-system-no-subsequent',
      cvss_string: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
      expected_score: 9.3,
      expected_severity: 'Critical'
    },
    {
      name: 'no-system-full-subsequent',
      cvss_string: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H',
      expected_score: 7.9,
      expected_severity: 'High'
    },
    {
      name: 'with-threat-intelligence',
      cvss_string: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U',
      expected_score: 9.1,
      expected_severity: 'Critical'
    },
    {
      name: 'with-exposure',
      cvss_string: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVI:L/MSA:S',
      expected_score: 9.8,
      expected_severity: 'Critical'
    },
    {
      name: 'slightly-vulnerable',
      cvss_string: 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
      expected_score: 1.0,
      expected_severity: 'Low'
    },
    {
      name: 'floating-point-rounding: CVE-2024-11193',
      cvss_string: 'CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H',
      expected_score: 5.0,
      expected_severity: 'Medium'
    },
    {
      name: 'floating-point-rounding: CVE-2025-27498',
      cvss_string: 'CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N',
      expected_score: 5.7,
      expected_severity: 'Medium'
    },
    {
      name: 'clement-b',
      cvss_string: 'CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L',
      expected_score: 5.2,
      expected_severity: 'Medium'
    },
    {
      name: 'clement-bte',
      cvss_string: 'CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L/E:P/CR:H/IR:M/AR:H/MAV:A/MAT:P/MPR:N/MVI:H/MVA:N/MSI:H/MSA:N/S:N/V:C/U:Amber', # rubocop:disable Layout/LineLength
      expected_score: 4.7,
      expected_severity: 'Medium'
    },
    {
      name: 'reg-deptheq3eq6',
      cvss_string: 'CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:H/SI:H/SA:H/CR:L/IR:L/AR:L',
      expected_score: 5.8,
      expected_severity: 'Medium'
    }
  ].each do |a|
    describe "CVSS string #{a[:name]} correctly evaluates" do
      subject { CvssSuite.new(a[:cvss_string]) }

      it_behaves_like 'a valid 4.0 cvss vector', 4.0, a[:expected_score], a[:expected_severity]
    end
  end

  [
    {
      name: 'missing metric',
      cvss_string: 'CVSS:4.0/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'
    },
    {
      name: 'incorrect metric value',
      cvss_string: 'CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N'
    },
    {
      name: 'duplicate metric value',
      cvss_string: 'CVSS:4.0/AV:A/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N'
    }
  ].each do |a|
    describe "CVSS string #{a[:name]} is incorrect" do
      subject { CvssSuite.new(a[:cvss_string]) }

      it_behaves_like 'a invalid cvss vector with version', 4.0
    end
  end
end
