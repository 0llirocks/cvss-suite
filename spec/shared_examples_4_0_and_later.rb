# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

shared_examples 'a valid 4.0 cvss vector' do |version, overall_score, severity|
  it { is_expected.to be_valid }
  its(:valid?) { is_expected.to be(true) }
  its(:version) { is_expected.to eql(version) }
  its(:overall_score) { is_expected.to eql(overall_score) }
  its(:severity) { is_expected.to eql(severity) }
end
