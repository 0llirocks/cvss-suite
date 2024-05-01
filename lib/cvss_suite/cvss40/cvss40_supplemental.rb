# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'

module CvssSuite
  ##
  # This class represents a CVSS Temporal metric in version 3.1.
  class Cvss40Supplemental < CvssMetric
    ##
    # Property of this metric
    attr_reader :safety, :automatable, :recovery, :value_density,
                :vulnerability_response_effort, :provider_urgency

    ##
    # Returns score of this metric
    def score
      return 1.0 unless valid?

      @exploit_code_maturity.score * @remediation_level.score * @report_confidence.score
    end

    private

    def init_properties
      @properties.push(@safety =
                         CvssProperty.new(name: 'Safety', abbreviation: 'S',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', weight: 1.0 },
                                                   { name: 'Negligible', abbreviation: 'N', weight: 0.91 },
                                                   { name: 'Present', abbreviation: 'P', weight: 0.94 }]))
      @properties.push(@automatable =
                         CvssProperty.new(name: 'Automatable', abbreviation: 'AU',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', weight: 1.0 },
                                                   { name: 'No', abbreviation: 'N', weight: 0.95 },
                                                   { name: 'Yes', abbreviation: 'Y', weight: 0.96 }]))

      @properties.push(@recovery =
                         CvssProperty.new(name: 'Recovery', abbreviation: 'R',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', weight: 1.0 },
                                                   { name: 'Automatic', abbreviation: 'A', weight: 0.92 },
                                                   { name: 'User', abbreviation: 'U', weight: 0.96 },
                                                   { name: 'Irrecoverable', abbreviation: 'I', weight: 1.0 }]))
      @properties.push(@value_density =
                         CvssProperty.new(name: 'Value Density', abbreviation: 'V',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', weight: 1.0 },
                                                   { name: 'Diffuse', abbreviation: 'D', weight: 0.91 },
                                                   { name: 'Concentrated', abbreviation: 'C', weight: 0.94 }]))
      @properties.push(@vulnerability_response_effort =
                         CvssProperty.new(name: 'Vulnerability Response Effort', abbreviation: 'RE',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', weight: 1.0 },
                                                   { name: 'Low', abbreviation: 'L', weight: 0.91 },
                                                   { name: 'Moderate', abbreviation: 'M', weight: 0.91 },
                                                   { name: 'High', abbreviation: 'H', weight: 0.94 }]))
      @properties.push(@provider_urgency =
                         CvssProperty.new(name: 'Provider Urgency', abbreviation: 'U',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', weight: 1.0 },
                                                   { name: 'Clear', abbreviation: 'Clear', weight: 0.91 },
                                                   { name: 'Green', abbreviation: 'Green', weight: 0.91 },
                                                   { name: 'Amber', abbreviation: 'Amber', weight: 0.91 },
                                                   { name: 'Red', abbreviation: 'Red', weight: 0.94 }]))
    end
  end
end
