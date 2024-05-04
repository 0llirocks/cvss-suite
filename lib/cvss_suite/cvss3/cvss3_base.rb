# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'
require_relative '../helpers/cvss3_helper'

module CvssSuite
  ##
  # This class represents a CVSS Base metric in version 3.
  class Cvss3Base < CvssMetric
    ##
    # Property of this metric
    attr_reader :attack_vector, :attack_complexity, :privileges_required, :user_interaction,
                :scope, :confidentiality, :integrity, :availability

    ##
    # Returns score of this metric
    def score
      privilege_score = Cvss3Helper.privileges_required_score @privileges_required, @scope

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
                                          values: [{ name: 'Network', abbreviation: 'N', weight: 0.85 },
                                                   { name: 'Adjacent', abbreviation: 'A', weight: 0.62 },
                                                   { name: 'Local', abbreviation: 'L', weight: 0.55 },
                                                   { name: 'Physical', abbreviation: 'P', weight: 0.2 }]))
      @properties.push(@attack_complexity =
                         CvssProperty.new(name: 'Attack Complexity', abbreviation: 'AC',
                                          values: [{ name: 'Low', abbreviation: 'L', weight: 0.77 },
                                                   { name: 'High', abbreviation: 'H', weight: 0.44 }]))
      @properties.push(@privileges_required =
                         CvssProperty.new(name: 'Privileges Required', abbreviation: 'PR',
                                          values: [{ name: 'None', abbreviation: 'N', weight: 0.85 },
                                                   { name: 'Low', abbreviation: 'L', weight: 0.62 },
                                                   { name: 'High', abbreviation: 'H', weight: 0.27 }]))
      @properties.push(@user_interaction =
                         CvssProperty.new(name: 'User Interaction', abbreviation: 'UI',
                                          values: [{ name: 'None', abbreviation: 'N', weight: 0.85 },
                                                   { name: 'Required', abbreviation: 'R', weight: 0.62 }]))
      @properties.push(@scope =
                         CvssProperty.new(name: 'Scope', abbreviation: 'S',
                                          values: [{ name: 'Unchanged', abbreviation: 'U' },
                                                   { name: 'Changed', abbreviation: 'C' }]))
      @properties.push(@confidentiality =
                         CvssProperty.new(name: 'Confidentiality', abbreviation: 'C',
                                          values: [{ name: 'None', abbreviation: 'N', weight: 0.0 },
                                                   { name: 'Low', abbreviation: 'L', weight: 0.22 },
                                                   { name: 'High', abbreviation: 'H', weight: 0.56 }]))
      @properties.push(@integrity =
                         CvssProperty.new(name: 'Integrity', abbreviation: 'I',
                                          values: [{ name: 'None', abbreviation: 'N', weight: 0.0 },
                                                   { name: 'Low', abbreviation: 'L', weight: 0.22 },
                                                   { name: 'High', abbreviation: 'H', weight: 0.56 }]))
      @properties.push(@availability =
                         CvssProperty.new(name: 'Availability', abbreviation: 'A',
                                          values: [{ name: 'None', abbreviation: 'N', weight: 0.0 },
                                                   { name: 'Low', abbreviation: 'L', weight: 0.22 },
                                                   { name: 'High', abbreviation: 'H', weight: 0.56 }]))
    end
  end
end
