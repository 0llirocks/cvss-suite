# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) Siemens AG, 2016
#
# Authors:
#   Oliver Hambörger <oliver.hamboerger@siemens.com>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

shared_examples 'a valid cvss vector' do |version, base_score, temporal_score, environmental_score, overall_score|
  it { should be_valid }
  its(:valid?) { should eql(true) }
  its(:version) { should eql(version) }
  its(:base_score) { should eql(base_score) }
  its(:temporal_score) { should eql(temporal_score) }
  its(:environmental_score) { should eql(environmental_score) }
  its(:overall_score) { should eql(overall_score) }
end

shared_examples 'a invalid cvss vector with version' do |version|
  its(:version) { should eql(version) }
  it { should_not be_valid }
  its(:valid?) { should eql(false) }
end

shared_examples 'a invalid cvss vector' do
  it { should raise_error(RuntimeError, 'Vector is not valid!') }
end