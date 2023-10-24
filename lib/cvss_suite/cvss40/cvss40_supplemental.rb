# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) 2019-2022 Siemens AG
# Copyright (c) 2022-2023 0llirocks
#
# Authors:
#   0llirocks <http://0lli.rocks>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'

module CvssSuite
  ##
  # This class represents a CVSS Temporal metric in version 4.0.
  class Cvss40Supplemental < CvssMetric
    ##
    # Property of this metric
    attr_reader :safety, :automatable, :recovery, :value_density, :vulnerability_response_effort, :provider_urgency

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
                                          values: [{ name: 'Not Defined', abbreviation: 'X', default: true },
                                                   { name: 'Present', abbreviation: 'P', default: false },
                                                   { name: 'Negligible', abbreviation: 'N', default: false }]))
      @properties.push(@automatable =
                         CvssProperty.new(name: 'Automatable', abbreviation: 'AU',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', default: true },
                                                   { name: 'No', abbreviation: 'N', default: false },
                                                   { name: 'Yes', abbreviation: 'Y', default: false }]))
      @properties.push(@recovery =
                         CvssProperty.new(name: 'Recovery', abbreviation: 'AU',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', default: true },
                                                   { name: 'Automatic', abbreviation: 'A', default: false },
                                                   { name: 'User', abbreviation: 'U', default: false },
                                                   { name: 'Irrecoverable', abbreviation: 'I', default: false }]))
      @properties.push(@value_density =
                         CvssProperty.new(name: 'Value Density', abbreviation: 'V',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', default: true },
                                                   { name: 'Diffuse', abbreviation: 'D',
                                                     default: false },
                                                   { name: 'Concentrated', abbreviation: 'C',
                                                     default: false }]))
      @properties.push(@vulnerability_response_effort =
                         CvssProperty.new(name: 'Vulnerability Response Effort', abbreviation: 'RE',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', default: true },
                                                   { name: 'Low', abbreviation: 'L',
                                                     default: false },
                                                   { name: 'Moderate', abbreviation: 'M',
                                                     default: false },
                                                   { name: 'High', abbreviation: 'H',
                                                     default: false }]))
      @properties.push(@provider_urgency =
                         CvssProperty.new(name: 'Provider Urgency', abbreviation: 'U',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', default: true },
                                                   { name: 'Clear', abbreviation: 'Clear', default: false },
                                                   { name: 'Green', abbreviation: 'Green', default: false },
                                                   { name: 'Amber', abbreviation: 'Amber', default: false },
                                                   { name: 'Red', abbreviation: 'Red', default: false }]))
    end
  end
end
