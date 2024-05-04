# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'

module CvssSuite
  ##
  # This class represents a CVSS Base metric in version 2.
  class Cvss2Base < CvssMetric
    ##
    # Property of this metric
    attr_reader :access_vector, :access_complexity, :authentication,
                :confidentiality_impact, :integrity_impact, :availability_impact

    ##
    # Returns the base score of the CVSS vector. The calculation is based on formula version 2.10 .
    # See CVSS documentation for further information https://www.first.org/cvss/v2/guide#i3.2.1 .
    #
    # Takes +Security+ +Requirement+ +Impacts+ for calculating environmental score.
    def score(sr_cr_score = 1, sr_ir_score = 1, sr_ar_score = 1)
      impact = calc_impact(sr_cr_score, sr_ir_score, sr_ar_score)

      exploitability = calc_exploitability

      additional_impact = (impact.zero? ? 0 : 1.176)

      ((0.6 * impact) + (0.4 * exploitability) - 1.5) * additional_impact
    end

    private

    def init_properties
      @properties.push(@access_vector =
                         CvssProperty.new(name: 'Access Vector', abbreviation: 'AV', position: [0],
                                          values: [{ name: 'Network', abbreviation: 'N', weight: 1.0 },
                                                   { name: 'Adjacent Network', abbreviation: 'A', weight: 0.646 },
                                                   { name: 'Local', abbreviation: 'L', weight: 0.395 }]))
      @properties.push(@access_complexity =
                         CvssProperty.new(name: 'Access Complexity', abbreviation: 'AC', position: [1],
                                          values: [{ name: 'Low', abbreviation: 'L', weight: 0.71 },
                                                   { name: 'Medium', abbreviation: 'M', weight: 0.61 },
                                                   { name: 'High', abbreviation: 'H', weight: 0.35 }]))
      @properties.push(@authentication =
                         CvssProperty.new(name: 'Authentication', abbreviation: 'Au', position: [2],
                                          values: [{ name: 'None', abbreviation: 'N', weight: 0.704 },
                                                   { name: 'Single', abbreviation: 'S', weight: 0.56 },
                                                   { name: 'Multiple', abbreviation: 'M', weight: 0.45 }]))
      @properties.push(@confidentiality_impact =
                         CvssProperty.new(name: 'Confidentiality Impact', abbreviation: 'C', position: [3],
                                          values: [{ name: 'None', abbreviation: 'N', weight: 0.0 },
                                                   { name: 'Partial', abbreviation: 'P', weight: 0.275 },
                                                   { name: 'Complete', abbreviation: 'C', weight: 0.66 }]))
      @properties.push(@integrity_impact =
                         CvssProperty.new(name: 'Integrity Impact', abbreviation: 'I', position: [4],
                                          values: [{ name: 'None', abbreviation: 'N', weight: 0.0 },
                                                   { name: 'Partial', abbreviation: 'P', weight: 0.275 },
                                                   { name: 'Complete', abbreviation: 'C', weight: 0.66 }]))
      @properties.push(@availability_impact =
                         CvssProperty.new(name: 'Availability Impact', abbreviation: 'A', position: [5],
                                          values: [{ name: 'None', abbreviation: 'N', weight: 0.0 },
                                                   { name: 'Partial', abbreviation: 'P', weight: 0.275 },
                                                   { name: 'Complete', abbreviation: 'C', weight: 0.66 }]))
    end

    def calc_impact(sr_cr_score, sr_ir_score, sr_ar_score)
      confidentiality_score = 1 - @confidentiality_impact.score * sr_cr_score
      integrity_score = 1 - @integrity_impact.score * sr_ir_score
      availability_score = 1 - @availability_impact.score * sr_ar_score

      [10, 10.41 * (1 - confidentiality_score * integrity_score * availability_score)].min
    end

    def calc_exploitability
      20 * @access_vector.score * @access_complexity.score * @authentication.score
    end
  end
end
