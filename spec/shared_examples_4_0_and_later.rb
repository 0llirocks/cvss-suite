# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) 2016-2022 Siemens AG
# Copyright (c) 2022 0llirocks
#
# Authors:
#   0llirocks <http://0lli.rocks>
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

# shared_examples 'a invalid cvss vector with version' do |version|
#   its(:version) { is_expected.to eql(version) }
#   it { is_expected.not_to be_valid }
#   its(:valid?) { is_expected.to be(false) }
# end

# shared_examples 'a invalid cvss vector' do
#   it { is_expected.to raise_error(RuntimeError, 'Vector is not valid!') }
# end
