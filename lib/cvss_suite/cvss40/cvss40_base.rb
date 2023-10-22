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
  # This class represents a CVSS Base metric in version 4.0.
  class Cvss40Base < CvssMetric
    ##
    # Property of this metric

    attr_reader :attack_vector, :attack_complexity, :attack_requirements, :privileges_required, :user_interaction,
                :vulnerable_confidentiality, :vulnerable_integrity, :vulnerable_availability, 
                :subsequent_confidentiality, :subsequent_integrity, :subsequent_availability

    ##
    # Returns score of this metric
    def score
      privilege_score = Cvss3Helper.privileges_required_score(@privileges_required, @scope)

      exploitability = 8.22 * @attack_vector.score * @attack_complexity.score *
                       privilege_score * @user_interaction.score

      isc_base = 1 - ((1 - @confidentiality.score) * (1 - @integrity.score) * (1 - @availability.score))

      impact_sub_score = if @scope.selected_value[:name] == 'Changed'
                           7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02)**15
                         else
                           6.42 * isc_base
                         end

      return 0 if impact_sub_score <= 0

      if @scope.selected_value[:name] == 'Changed'
        [10, 1.08 * (impact_sub_score + exploitability)].min
      else
        [10, impact_sub_score + exploitability].min
      end
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
      @properties.push(@vulnerable_confidentiality =
                         CvssProperty.new(name: 'Vulnerable Confidentiality', abbreviation: 'VC',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' }]))
      @properties.push(@vulnerable_integrity =
                         CvssProperty.new(name: 'Vulnerable Integrity', abbreviation: 'VI',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' }]))
      @properties.push(@vulnerable_availability =
                         CvssProperty.new(name: 'Vulnerable Availability', abbreviation: 'VA',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' }]))
      @properties.push(@subsequent_confidentiality =
                         CvssProperty.new(name: 'Subsequent Confidentiality', abbreviation: 'SC',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' }]))
      @properties.push(@subsequent_integrity =
                         CvssProperty.new(name: 'Subsequent Integrity', abbreviation: 'SI',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' }]))
      @properties.push(@subsequent_availability =
                         CvssProperty.new(name: 'Subsequent Availability', abbreviation: 'SA',
                                          values: [{ name: 'None', abbreviation: 'N' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'High', abbreviation: 'H' }]))
    end
  end
end
