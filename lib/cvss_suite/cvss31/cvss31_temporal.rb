# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'

module CvssSuite
  ##
  # This class represents a CVSS Temporal metric in version 3.1.
  class Cvss31Temporal < CvssMetric
    ##
    # Property of this metric
    attr_reader :exploit_code_maturity, :remediation_level, :report_confidence

    ##
    # Returns score of this metric
    def score
      return 1.0 unless valid?

      @exploit_code_maturity.score * @remediation_level.score * @report_confidence.score
    end

    private

    def init_properties
      @properties.push(@exploit_code_maturity =
                         CvssProperty.new(name: 'Exploit Code Maturity', abbreviation: 'E',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', weight: 1.0 },
                                                   { name: 'Unproven', abbreviation: 'U', weight: 0.91 },
                                                   { name: 'Proof-of-Concept', abbreviation: 'P', weight: 0.94 },
                                                   { name: 'Functional', abbreviation: 'F', weight: 0.97 },
                                                   { name: 'High', abbreviation: 'H', weight: 1.0 }]))
      @properties.push(@remediation_level =
                         CvssProperty.new(name: 'Remediation Level', abbreviation: 'RL',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', weight: 1.0 },
                                                   { name: 'Official Fix', abbreviation: 'O', weight: 0.95 },
                                                   { name: 'Temporary Fix', abbreviation: 'T', weight: 0.96 },
                                                   { name: 'Workaround', abbreviation: 'W', weight: 0.97 },
                                                   { name: 'Unavailable', abbreviation: 'U', weight: 1.0 }]))

      @properties.push(@report_confidence =
                         CvssProperty.new(name: 'Report Confidence', abbreviation: 'RC',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', weight: 1.0 },
                                                   { name: 'Unknown', abbreviation: 'U', weight: 0.92 },
                                                   { name: 'Reasonable', abbreviation: 'R', weight: 0.96 },
                                                   { name: 'Confirmed', abbreviation: 'C', weight: 1.0 }]))
    end
  end
end
