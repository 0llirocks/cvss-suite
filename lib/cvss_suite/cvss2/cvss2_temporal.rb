# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'

module CvssSuite
  ##
  # This class represents a CVSS Temporal metric in version 2.
  class Cvss2Temporal < CvssMetric
    ##
    # Property of this metric
    attr_reader :exploitability, :remediation_level, :report_confidence

    ##
    # Returns score of this metric
    def score
      return 1 unless valid?

      @exploitability.score * @remediation_level.score * @report_confidence.score
    end

    private

    def init_properties
      @properties.push(@exploitability =
                         CvssProperty.new(name: 'Exploitability', abbreviation: 'E', position: [6],
                                          values: [{ name: 'Not Defined', abbreviation: 'ND', weight: 1 },
                                                   { name: 'Unproven', abbreviation: 'U', weight: 0.85 },
                                                   { name: 'Proof-of-Concept', abbreviation: 'POC', weight: 0.9 },
                                                   { name: 'Functional', abbreviation: 'F', weight: 0.95 },
                                                   { name: 'High', abbreviation: 'H', weight: 1 }]))
      @properties.push(@remediation_level =
                         CvssProperty.new(name: 'Remediation Level', abbreviation: 'RL', position: [7],
                                          values: [{ name: 'Not Defined', abbreviation: 'ND', weight: 1 },
                                                   { name: 'Official Fix', abbreviation: 'OF', weight: 0.87 },
                                                   { name: 'Temporary Fix', abbreviation: 'TF', weight: 0.9 },
                                                   { name: 'Workaround', abbreviation: 'W', weight: 0.95 },
                                                   { name: 'Unavailable', abbreviation: 'U', weight: 1 }]))

      @properties.push(@report_confidence =
                         CvssProperty.new(name: 'Report Confidence', abbreviation: 'RC', position: [8],
                                          values: [{ name: 'Not Defined', abbreviation: 'ND', weight: 1 },
                                                   { name: 'Unconfirmed', abbreviation: 'UC', weight: 0.9 },
                                                   { name: 'Uncorroborated', abbreviation: 'UR', weight: 0.95 },
                                                   { name: 'Confirmed', abbreviation: 'C', weight: 1 }]))
    end
  end
end
