# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

shared_examples 'a valid cvss vector' do |version, base_score, impact_subscore, exploitability_subscore, # rubocop:disable Metrics/ParameterLists
                                          temporal_score, environmental_score, overall_score, severity|
  it { is_expected.to be_valid }
  its(:valid?) { is_expected.to be(true) }
  its(:version) { is_expected.to eql(version) }
  its(:base_score) { is_expected.to eql(base_score) }
  its(:temporal_score) { is_expected.to eql(temporal_score) }
  its(:environmental_score) { is_expected.to eql(environmental_score) }
  its(:overall_score) { is_expected.to eql(overall_score) }
  its(:severity) { is_expected.to eql(severity) }
  it 'exposes the impact sub-score' do
    expect(subject.base.impact_subscore).to be_within(0.01).of(impact_subscore)
  end
  it 'exposes the exploitability sub-score' do
    expect(subject.base.exploitability_subscore).to be_within(0.01).of(exploitability_subscore)
  end
end

shared_examples 'a invalid cvss vector with version' do |version|
  its(:version) { is_expected.to eql(version) }
  it { is_expected.not_to be_valid }
  its(:valid?) { is_expected.to be(false) }
end

shared_examples 'a invalid cvss vector' do
  it { is_expected.to raise_error(RuntimeError, 'Vector is not valid!') }
end
