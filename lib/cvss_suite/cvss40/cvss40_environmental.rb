# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'

module CvssSuite
  ##
  # This class represents a CVSS Threat metric in version 4.0.
  class Cvss40Environmental < CvssMetric
    ##
    # Property of this metric
    attr_reader :modified_attack_vector, :modified_attack_complexity, :modified_attack_requirements,
                :modified_privileges_required, :modified_user_interaction, :modified_vulnerable_system_confidentiality,
                :modified_vulnerable_system_integrity, :modified_vulnerable_system_availability,
                :modified_subsequent_system_confidentiality, :modified_subsequent_system_integrity,
                :modified_subsequent_system_availability

    ##
    # Returns score of this metric
    def score
      Cvss40CalcHelper.new(@properties.map { |p| [p.abbreviation, p.selected_value[:abbreviation]] }.to_h).score
    end

    private

    def init_properties
      @properties.push(@modified_attack_vector =
                         CvssProperty.new(name: 'Modified Attack Vector', abbreviation: 'MAV',
                                          values: [{ name: 'Network', abbreviation: 'N' },
                                                   { name: 'Adjacent', abbreviation: 'A' },
                                                   { name: 'Local', abbreviation: 'L' },
                                                   { name: 'Physical', abbreviation: 'P' },
                                                   { name: 'Not Defined', abbreviation: 'X' }]))
      @properties.push(@modified_attack_complexity =
                         CvssProperty.new(name: 'Modified Attack Complexity', abbreviation: 'MAC',
                                          values: [{ name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' },
                                                   { name: 'Not Defined', abbreviation: 'X' }]))
      @properties.push(@modified_attack_requirements =
                         CvssProperty.new(name: 'Modified Attack Requirements', abbreviation: 'MAT',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Present', abbreviation: 'P' },
                                                   { name: 'Not Defined', abbreviation: 'X' }]))
      @properties.push(@modified_privileges_required =
                         CvssProperty.new(name: 'Modified Privileges Required', abbreviation: 'MPR',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' },
                                                   { name: 'Not Defined', abbreviation: 'X' }]))
      @properties.push(@modified_user_interaction =
                         CvssProperty.new(name: 'Modified User Interaction', abbreviation: 'MUI',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Passive', abbreviation: 'P' },
                                                   { name: 'Active', abbreviation: 'A' },
                                                   { name: 'Not Defined', abbreviation: 'X' }]))
      @properties.push(@vulnerable_system_confidentiality =
                         CvssProperty.new(name: 'Modified Vulnerable System Confidentiality Impact',
                                          abbreviation: 'MVC',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' },
                                                   { name: 'Not Defined', abbreviation: 'X' }]))
      @properties.push(@modified_vulnerable_system_integrity =
                         CvssProperty.new(name: 'Modified Vulnerable System Integrity Impact',
                                          abbreviation: 'MVI',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' },
                                                   { name: 'Not Defined', abbreviation: 'X' }]))
      @properties.push(@modified_vulnerable_system_availability =
                         CvssProperty.new(name: 'Modified Vulnerable System Availability Impact',
                                          abbreviation: 'MVA',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' },
                                                   { name: 'Not Defined', abbreviation: 'X' }]))
      @properties.push(@modified_subsequent_system_confidentiality =
                         CvssProperty.new(name: 'Modified Subsequent System Confidentiality Impact',
                                          abbreviation: 'MSC',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' },
                                                   { name: 'Not Defined', abbreviation: 'X' }]))
      @properties.push(@modified_subsequent_system_integrity =
                         CvssProperty.new(name: 'Modified Subsequent System Integrity Impact',
                                          abbreviation: 'MSI',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Safety', abbreviation: 'S' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' },
                                                   { name: 'Not Defined', abbreviation: 'X' }]))
      @properties.push(@modified_subsequent_system_availability =
                         CvssProperty.new(name: 'Modified Subsequent System Availability Impact',
                                          abbreviation: 'MSA',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Safety', abbreviation: 'S' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' },
                                                   { name: 'Not Defined', abbreviation: 'X' }]))
    end
  end
end
