# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'
require_relative '../helpers/cvss3_helper'

module CvssSuite
  ##
  # This class represents a CVSS Environmental metric in version 3.
  class Cvss3Environmental < CvssMetric
    ##
    # Property of this metric
    attr_reader :confidentiality_requirement, :integrity_requirement, :availability_requirement,
                :modified_attack_vector, :modified_attack_complexity, :modified_privileges_required,
                :modified_user_interaction, :modified_scope, :modified_confidentiality,
                :modified_integrity, :modified_availability

    ##
    # Returns score of this metric

    def score(base, temporal)
      @base = base

      merged_modified_privileges_required = @modified_privileges_required
      if @modified_privileges_required.selected_value[:name] == 'Not Defined'
        merged_modified_privileges_required = @base.privileges_required
      end

      merged_modified_scope = @modified_scope
      if @modified_scope.selected_value[:name] == 'Not Defined'
        merged_modified_scope = @base.scope
      end

      privilege_score = Cvss3Helper.privileges_required_score(merged_modified_privileges_required, merged_modified_scope)

      modified_exploitability_sub_score = modified_exploitability_sub(privilege_score)

      modified_impact_sub_score = modified_impact_sub(isc_modified)

      return 0 if modified_impact_sub_score <= 0

      calculate_score modified_impact_sub_score, modified_exploitability_sub_score, temporal.score
    end

    private

    def init_properties
      @properties.push(@confidentiality_requirement =
                         CvssProperty.new(name: 'Confidentiality Requirement', abbreviation: 'CR',
                                          values: [{ name: 'Low', abbreviation: 'L', weight: 0.5 },
                                                   { name: 'Medium', abbreviation: 'M', weight: 1.0 },
                                                   { name: 'High', abbreviation: 'H', weight: 1.5 },
                                                   { name: 'Not Defined', abbreviation: 'X', weight: 1 }]))
      @properties.push(@integrity_requirement =
                         CvssProperty.new(name: 'Integrity Requirement', abbreviation: 'IR',
                                          values: [{ name: 'Low', abbreviation: 'L', weight: 0.5 },
                                                   { name: 'Medium', abbreviation: 'M', weight: 1.0 },
                                                   { name: 'High', abbreviation: 'H', weight: 1.5 },
                                                   { name: 'Not Defined', abbreviation: 'X', weight: 1 }]))

      @properties.push(@availability_requirement =
                         CvssProperty.new(name: 'Availability Requirement', abbreviation: 'AR',
                                          values: [{ name: 'Low', abbreviation: 'L', weight: 0.5 },
                                                   { name: 'Medium', abbreviation: 'M', weight: 1.0 },
                                                   { name: 'High', abbreviation: 'H', weight: 1.5 },
                                                   { name: 'Not Defined', abbreviation: 'X', weight: 1 }]))
      @properties.push(@modified_attack_vector =
                         CvssProperty.new(name: 'Modified Attack Vector', abbreviation: 'MAV',
                                          values: [{ name: 'Network', abbreviation: 'N', weight: 0.85 },
                                                   { name: 'Adjacent Network', abbreviation: 'A', weight: 0.62 },
                                                   { name: 'Local', abbreviation: 'L', weight: 0.55 },
                                                   { name: 'Physical', abbreviation: 'P', weight: 0.2 },
                                                   { name: 'Not Defined', abbreviation: 'X', weight: 1 }]))
      @properties.push(@modified_attack_complexity =
                         CvssProperty.new(name: 'Modified Attack Complexity', abbreviation: 'MAC',
                                          values: [{ name: 'Low', abbreviation: 'L', weight: 0.77 },
                                                   { name: 'High', abbreviation: 'H', weight: 0.44 },
                                                   { name: 'Not Defined', abbreviation: 'X', weight: 1 }]))
      @properties.push(@modified_privileges_required =
                         CvssProperty.new(name: 'Modified Privileges Required', abbreviation: 'MPR',
                                          values: [{ name: 'None', abbreviation: 'N', weight: 0.85 },
                                                   { name: 'Low', abbreviation: 'L', weight: 0.62 },
                                                   { name: 'High', abbreviation: 'H', weight: 0.27 },
                                                   { name: 'Not Defined', abbreviation: 'X', weight: 1 }]))
      @properties.push(@modified_user_interaction =
                         CvssProperty.new(name: 'Modified User Interaction', abbreviation: 'MUI',
                                          values: [{ name: 'None', abbreviation: 'N', weight: 0.85 },
                                                   { name: 'Required', abbreviation: 'R', weight: 0.62 },
                                                   { name: 'Not Defined', abbreviation: 'X', weight: 1 }]))
      @properties.push(@modified_scope =
                         CvssProperty.new(name: 'Modified Scope', abbreviation: 'MS',
                                          values: [{ name: 'Changed', abbreviation: 'C' },
                                                   { name: 'Unchanged', abbreviation: 'U' },
                                                   { name: 'Not Defined', abbreviation: 'X' }]))
      @properties.push(@modified_confidentiality =
                         CvssProperty.new(name: 'Modified Confidentiality', abbreviation: 'MC',
                                          values: [{ name: 'None', abbreviation: 'N', weight: 0 },
                                                   { name: 'Low', abbreviation: 'L', weight: 0.22 },
                                                   { name: 'High', abbreviation: 'H', weight: 0.56 },
                                                   { name: 'Not Defined', abbreviation: 'X', weight: 1 }]))
      @properties.push(@modified_integrity =
                         CvssProperty.new(name: 'Modified Integrity', abbreviation: 'MI',
                                          values: [{ name: 'None', abbreviation: 'N', weight: 0 },
                                                   { name: 'Low', abbreviation: 'L', weight: 0.22 },
                                                   { name: 'High', abbreviation: 'H', weight: 0.56 },
                                                   { name: 'Not Defined', abbreviation: 'X', weight: 1 }]))
      @properties.push(@modified_availability =
                         CvssProperty.new(name: 'Modified Availability', abbreviation: 'MA',
                                          values: [{ name: 'None', abbreviation: 'N', weight: 0 },
                                                   { name: 'Low', abbreviation: 'L', weight: 0.22 },
                                                   { name: 'High', abbreviation: 'H', weight: 0.56 },
                                                   { name: 'Not Defined', abbreviation: 'X', weight: 1 }]))
    end

    def modified_impact_sub(isc_modified)
      if @modified_scope.selected_value[:name] == 'Not Defined'
        if @base.scope.selected_value[:name] == 'Changed'
          return 7.52 * (isc_modified - 0.029) - 3.25 * (isc_modified - 0.02)**15
        else
          return 6.42 * isc_modified
        end
      end

      if @modified_scope.selected_value[:name] == 'Changed'
        7.52 * (isc_modified - 0.029) - 3.25 * (isc_modified - 0.02)**15
      else
        6.42 * isc_modified
      end
    end

    def isc_modified
      merged_modified_confidentiality = @modified_confidentiality
      if @modified_confidentiality.selected_value[:name] == 'Not Defined'
        merged_modified_confidentiality = @base.confidentiality
      end

      merged_modified_integrity = @modified_integrity
      if @modified_integrity.selected_value[:name] == 'Not Defined'
        merged_modified_integrity = @base.integrity
      end

      merged_modified_availability = @modified_availability
      if @modified_availability.selected_value[:name] == 'Not Defined'
        merged_modified_availability = @base.availability
      end

      confidentiality_score = 1 - merged_modified_confidentiality.score * @confidentiality_requirement.score
      integrity_score = 1 - merged_modified_integrity.score * @integrity_requirement.score
      availability_score = 1 - merged_modified_availability.score * @availability_requirement.score

      [0.915, (1 - confidentiality_score * integrity_score * availability_score)].min
    end

    def modified_exploitability_sub(privilege_score)
      merged_modified_attack_vector = @modified_attack_vector
      if @modified_attack_vector.selected_value[:name] == 'Not Defined'
        merged_modified_attack_vector = @base.attack_vector
      end

      merged_modified_attack_complexity = @modified_attack_complexity
      if @modified_attack_complexity.selected_value[:name] == 'Not Defined'
        merged_modified_attack_complexity = @base.attack_complexity
      end

      merged_modified_user_interaction = @modified_user_interaction
      if @modified_user_interaction.selected_value[:name] == 'Not Defined'
        merged_modified_user_interaction = @base.user_interaction
      end

      8.22 * merged_modified_attack_vector.score * merged_modified_attack_complexity.score *
        privilege_score * merged_modified_user_interaction.score
    end

    def calculate_score(modified_impact_sub_score, modified_exploitability_sub_score, temporal_score)
      if @modified_scope.selected_value[:name] == 'Not Defined'
        factor = @base.scope.selected_value[:name] == 'Changed' ? 1.08 : 1.0
      else
        factor = @modified_scope.selected_value[:name] == 'Changed' ? 1.08 : 1.0
      end

      Cvss3Helper.round_up(
        [factor * (modified_impact_sub_score + modified_exploitability_sub_score), 10].min
      ) * temporal_score
    end
  end
end
