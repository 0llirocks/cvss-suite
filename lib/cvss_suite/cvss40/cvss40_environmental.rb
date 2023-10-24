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
  # This class represents a CVSS Environmental metric in version 4.0.
  class Cvss40Environmental < CvssMetric # rubocop:disable Metrics/ClassLength
    ##
    # Property of this metric
    attr_reader :confidentiality_requirement, :integrity_requirement, :availability_requirement,
                :modified_attack_vector, :modified_attack_complexity, :modified_privileges_required,
                :modified_user_interaction, :modified_vulnerable_confidentiality,
                :modified_vulnerable_integrity, :modified_vulnerable_availability,
                :modified_subsequent_confidentiality,
                :modified_subsequent_integrity, :modified_subsequent_availability

    ##
    # Returns score of this metric
    def score(base, temporal)
      @base = base

      merged_modified_privileges_required = @modified_privileges_required
      if @modified_privileges_required.selected_value[:name] == 'Not Defined'
        merged_modified_privileges_required = @base.privileges_required
      end

      merged_modified_scope = @modified_scope
      merged_modified_scope = @base.scope if @modified_scope.selected_value[:name] == 'Not Defined'

      privilege_score = Cvss3Helper.privileges_required_score(merged_modified_privileges_required,
                                                              merged_modified_scope)

      modified_exploitability_sub_score = modified_exploitability_sub(privilege_score)

      modified_impact_sub_score = modified_impact_sub(isc_modified)

      return 0 if modified_impact_sub_score <= 0

      calculate_score modified_impact_sub_score, modified_exploitability_sub_score, temporal.score
    end

    private

    def init_properties # rubocop:disable Metrics/MethodLength
      @properties.push(@confidentiality_requirement =
                         CvssProperty.new(name: 'Confidentiality Requirement', abbreviation: 'CR',
                                          values: [{ name: 'Low', abbreviation: 'L', default: false },
                                                   { name: 'Medium', abbreviation: 'M', default: false },
                                                   { name: 'High', abbreviation: 'H', default: false },
                                                   { name: 'Not Defined', abbreviation: 'X', default: true }]))
      @properties.push(@integrity_requirement =
                         CvssProperty.new(name: 'Integrity Requirement', abbreviation: 'IR',
                                          values: [{ name: 'Low', abbreviation: 'L', default: false },
                                                   { name: 'Medium', abbreviation: 'M', default: false },
                                                   { name: 'High', abbreviation: 'H', default: false },
                                                   { name: 'Not Defined', abbreviation: 'X', default: true }]))
      @properties.push(@availability_requirement =
                         CvssProperty.new(name: 'Availability Requirement', abbreviation: 'AR',
                                          values: [{ name: 'Low', abbreviation: 'L', default: false },
                                                   { name: 'Medium', abbreviation: 'M', default: false },
                                                   { name: 'High', abbreviation: 'H', default: false },
                                                   { name: 'Not Defined', abbreviation: 'X', default: true }]))
      @properties.push(@modified_attack_vector =
                         CvssProperty.new(name: 'Modified Attack Vector', abbreviation: 'MAV',
                                          values: [{ name: 'Network', abbreviation: 'N', default: false },
                                                   { name: 'Adjacent Network', abbreviation: 'A', default: false },
                                                   { name: 'Local', abbreviation: 'L', default: false },
                                                   { name: 'Physical', abbreviation: 'P', default: false },
                                                   { name: 'Not Defined', abbreviation: 'X', default: true }]))
      @properties.push(@modified_attack_complexity =
                         CvssProperty.new(name: 'Modified Attack Complexity', abbreviation: 'MAC',
                                          values: [{ name: 'Low', abbreviation: 'L', default: false },
                                                   { name: 'High', abbreviation: 'H', default: false },
                                                   { name: 'Not Defined', abbreviation: 'X', default: true }]))
      @properties.push(@modified_privileges_required =
                         CvssProperty.new(name: 'Modified Privileges Required', abbreviation: 'MPR',
                                          values: [{ name: 'None', abbreviation: 'N', default: false },
                                                   { name: 'Low', abbreviation: 'L', default: false },
                                                   { name: 'High', abbreviation: 'H', default: false },
                                                   { name: 'Not Defined', abbreviation: 'X', default: true }]))
      @properties.push(@modified_user_interaction =
                         CvssProperty.new(name: 'Modified User Interaction', abbreviation: 'MUI',
                                          values: [{ name: 'None', abbreviation: 'N', default: false },
                                                   { name: 'Required', abbreviation: 'R', default: false },
                                                   { name: 'Not Defined', abbreviation: 'X', default: true }]))
      @properties.push(@modified_vulnerable_confidentiality =
                         CvssProperty.new(name: 'Modified Vulnerable Confidentiality', abbreviation: 'MVC',
                                          values: [{ name: 'None', abbreviation: 'N', default: false },
                                                   { name: 'Low', abbreviation: 'L', default: false },
                                                   { name: 'High', abbreviation: 'H', default: false },
                                                   { name: 'Not Defined', abbreviation: 'X', default: true }]))
      @properties.push(@modified_vulnerable_integrity =
                         CvssProperty.new(name: 'Modified Vulnerable Integrity', abbreviation: 'MVI',
                                          values: [{ name: 'None', abbreviation: 'N', default: false },
                                                   { name: 'Low', abbreviation: 'L', default: false },
                                                   { name: 'High', abbreviation: 'H', default: false },
                                                   { name: 'Not Defined', abbreviation: 'X', default: true }]))
      @properties.push(@modified_vulnerable_availability =
                         CvssProperty.new(name: 'Modified Vulnerable Availability', abbreviation: 'MVA',
                                          values: [{ name: 'None', abbreviation: 'N', default: false },
                                                   { name: 'Low', abbreviation: 'L', default: false },
                                                   { name: 'High', abbreviation: 'H', default: false },
                                                   { name: 'Not Defined', abbreviation: 'X', default: true }]))
      @properties.push(@modified_subsequent_confidentiality =
                         CvssProperty.new(name: 'Modified Subsequent Confidentiality', abbreviation: 'MSC',
                                          values: [{ name: 'None', abbreviation: 'N', default: false },
                                                   { name: 'Low', abbreviation: 'L',
                                                     default: false },
                                                   { name: 'High', abbreviation: 'H',
                                                     default: false },
                                                   { name: 'Not Defined', abbreviation: 'X',
                                                     default: true }]))
      @properties.push(@modified_subsequent_integrity =
                         CvssProperty.new(name: 'Modified Subsequent Integrity', abbreviation: 'MVS',
                                          values: [{ name: 'None', abbreviation: 'N', default: false },
                                                   { name: 'Low', abbreviation: 'L',
                                                     default: false },
                                                   { name: 'High', abbreviation: 'H',
                                                     default: false },
                                                   { name: 'Not Defined', abbreviation: 'X',
                                                     default: true }]))
      @properties.push(@modified_subsequent_availability =
                         CvssProperty.new(name: 'Modified Subsequent Availability', abbreviation: 'MSA',
                                          values: [{ name: 'None', abbreviation: 'N', default: false },
                                                   { name: 'Low', abbreviation: 'L',
                                                     default: false },
                                                   { name: 'High', abbreviation: 'H',
                                                     default: false },
                                                   { name: 'Not Defined', abbreviation: 'X',
                                                     default: true }]))
    end

    def modified_impact_sub(isc_modified)
      if @modified_scope.selected_value[:name] == 'Not Defined'
        if @base.scope.selected_value[:name] == 'Changed'
          return 7.52 * (isc_modified - 0.029) - 3.25 * (isc_modified * 0.9731 - 0.02)**13
        end

        return 6.42 * isc_modified

      end

      if @modified_scope.selected_value[:name] == 'Changed'
        7.52 * (isc_modified - 0.029) - 3.25 * (isc_modified * 0.9731 - 0.02)**13
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
      merged_modified_integrity = @base.integrity if @modified_integrity.selected_value[:name] == 'Not Defined'

      merged_modified_availability = @modified_availability
      merged_modified_availability = @base.availability if @modified_availability.selected_value[:name] == 'Not Defined'

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

    def calculate_score(_modified_impact_sub_score, _modified_exploitability_sub_score, _temporal_score)
      if @modified_scope.selected_value[:name] == 'Not Defined'
        @base.scope.selected_value[:name] == 'Changed' ? 1.08 : 1.0
      else
        @modified_scope.selected_value[:name] == 'Changed' ? 1.08 : 1.0
      end
    end
  end
end
