# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'
require_relative 'cvss40_calc_helper'

module CvssSuite
  ##
  # This class represents a CVSS Base metric in version 4.0.
  class Cvss40Base < CvssMetric
    ##
    # Property of this metric

    attr_reader :attack_vector, :attack_complexity, :attack_requirements, :privileges_required, :user_interaction,
                :vulnerable_system_confidentiality, :vulnerable_system_integrity, :vulnerable_system_availability,
                :subsequent_system_confidentiality, :subsequent_system_integrity, :subsequent_system_availability

    ##
    # Returns score of this metric
    def score
      Cvss40CalcHelper.new(@properties.map { |p| [p.abbreviation, p.selected_value[:abbreviation]] }.to_h).score
    end

    private

    def init_properties
      @properties.push(@attack_vector =
                         CvssProperty.new(name: 'Attack Vector', abbreviation: 'AV',
                                          values: [{ name: 'Network', abbreviation: 'N' },
                                                   { name: 'Adjacent', abbreviation: 'A' },
                                                   { name: 'Local', abbreviation: 'L' },
                                                   { name: 'Physical', abbreviation: 'P' }]))
      @properties.push(@attack_complexity =
                         CvssProperty.new(name: 'Attack Complexity', abbreviation: 'AC',
                                          values: [{ name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' }]))
      @properties.push(@attack_requirements =
                         CvssProperty.new(name: 'Attack Requirements', abbreviation: 'AT',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Present', abbreviation: 'P' }]))
      @properties.push(@privileges_required =
                         CvssProperty.new(name: 'Privileges Required', abbreviation: 'PR',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' }]))
      @properties.push(@user_interaction =
                         CvssProperty.new(name: 'User Interaction', abbreviation: 'UI',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Passive', abbreviation: 'P' },
                                                   { name: 'Active', abbreviation: 'A' }]))
      @properties.push(@vulnerable_system_confidentiality =
                         CvssProperty.new(name: 'Vulnerable System Confidentiality Impact', abbreviation: 'VC',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' }]))
      @properties.push(@vulnerable_system_integrity =
                         CvssProperty.new(name: 'Vulnerable System Integrity Impact', abbreviation: 'VI',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' }]))
      @properties.push(@vulnerable_system_availability =
                         CvssProperty.new(name: 'Vulnerable System Availability Impact', abbreviation: 'VA',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' }]))
      @properties.push(@subsequent_system_confidentiality =
                         CvssProperty.new(name: 'Subsequent System Confidentiality Impact', abbreviation: 'SC',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' }]))
      @properties.push(@subsequent_system_integrity =
                         CvssProperty.new(name: 'Subsequent System Integrity Impact', abbreviation: 'SI',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' }]))
      @properties.push(@subsequent_system_availability =
                         CvssProperty.new(name: 'Subsequent System Availability Impact', abbreviation: 'SA',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' }]))
    end
  end
end
