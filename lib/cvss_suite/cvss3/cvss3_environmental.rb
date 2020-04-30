# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) Siemens AG, 2016
#
# Authors:
#   Oliver Hambörger <oliver.hamboerger@siemens.com>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'
require_relative '../helpers/cvss3_helper'

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

  def score(temporal_score)

    privilege_score = Cvss3Helper.privileges_required_score @modified_privileges_required, @modified_scope

    modified_exploitability_sub_score = modified_exploitability_sub privilege_score

    isc_modified_score = isc_modified

    modified_impact_sub_score = modified_impact_sub isc_modified_score

    return 0 if modified_impact_sub_score <= 0

    calculate_score modified_impact_sub_score, modified_exploitability_sub_score, temporal_score
  end

  private

  def init_properties
    @properties.push(@confidentiality_requirement =
                      CvssProperty.new(name: 'Confidentiality Requirement', abbreviation: 'CR', position: [8, 11],
                                       choices: [{name: 'Low', abbreviation: 'L', weight: 0.5},
                                                 {name: 'Medium', abbreviation: 'M', weight: 1.0},
                                                 {name: 'High', abbreviation: 'H', weight: 1.5},
                                                 {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @properties.push(@integrity_requirement =
                      CvssProperty.new(name: 'Integrity Requirement', abbreviation: 'IR', position: [9, 12],
                                       choices: [{name: 'Low', abbreviation: 'L', weight: 0.5},
                                                 {name: 'Medium', abbreviation: 'M', weight: 1.0},
                                                 {name: 'High', abbreviation: 'H', weight: 1.5},
                                                 {name: 'Not Defined', abbreviation: 'X', weight: 1}]))

    @properties.push(@availability_requirement =
                      CvssProperty.new(name: 'Availability Requirement', abbreviation: 'AR', position: [10, 13],
                                       choices: [{name: 'Low', abbreviation: 'L', weight: 0.5},
                                                 {name: 'Medium', abbreviation: 'M', weight: 1.0},
                                                 {name: 'High', abbreviation: 'H', weight: 1.5},
                                                 {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @properties.push(@modified_attack_vector =
                      CvssProperty.new(name: 'Modified Attack Vector', abbreviation: 'MAV', position: [11, 14],
                                       choices: [{name: 'Network', abbreviation: 'N', weight: 0.85},
                                                 {name: 'Adjacent Network', abbreviation: 'A', weight: 0.62},
                                                 {name: 'Local', abbreviation: 'L', weight: 0.55},
                                                 {name: 'Physical', abbreviation: 'P', weight: 0.2},
                                                 {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @properties.push(@modified_attack_complexity =
                      CvssProperty.new(name: 'Modified Attack Complexity', abbreviation: 'MAC', position: [12, 15],
                                       choices: [{name: 'Low', abbreviation: 'L', weight: 0.77},
                                                 {name: 'High', abbreviation: 'H', weight: 0.44},
                                                 {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @properties.push(@modified_privileges_required =
                      CvssProperty.new(name: 'Modified Privileges Required', abbreviation: 'MPR', position: [13, 16],
                                       choices: [{name: 'None', abbreviation: 'N', weight: 0.85},
                                                 {name: 'Low', abbreviation: 'L', weight: 0.62},
                                                 {name: 'High', abbreviation: 'H', weight: 0.27},
                                                 {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @properties.push(@modified_user_interaction =
                      CvssProperty.new(name: 'Modified User Interaction', abbreviation: 'MUI', position: [14, 17],
                                       choices: [{name: 'None', abbreviation: 'N', weight: 0.85},
                                                 {name: 'Required', abbreviation: 'R', weight: 0.62},
                                                 {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @properties.push(@modified_scope =
                      CvssProperty.new(name: 'Modified Scope', abbreviation: 'MS', position: [15, 18],
                                       choices: [{name: 'Changed', abbreviation: 'C'},
                                                 {name: 'Unchanged', abbreviation: 'U'}]))
    @properties.push(@modified_confidentiality =
                      CvssProperty.new(name: 'Modified Confidentiality', abbreviation: 'MC', position: [16, 19],
                                       choices: [{name: 'None', abbreviation: 'N', weight: 0},
                                                 {name: 'Low', abbreviation: 'L', weight: 0.22},
                                                 {name: 'High', abbreviation: 'H', weight: 0.56},
                                                 {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @properties.push(@modified_integrity =
                      CvssProperty.new(name: 'Modified Integrity', abbreviation: 'MI', position: [17, 20],
                                       choices: [{name: 'None', abbreviation: 'N', weight: 0},
                                                 {name: 'Low', abbreviation: 'L', weight: 0.22},
                                                 {name: 'High', abbreviation: 'H', weight: 0.56},
                                                 {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @properties.push(@modified_availability =
                      CvssProperty.new(name: 'Modified Availability', abbreviation: 'MA', position: [18, 21],
                                       choices: [{name: 'None', abbreviation: 'N', weight: 0},
                                                 {name: 'Low', abbreviation: 'L', weight: 0.22},
                                                 {name: 'High', abbreviation: 'H', weight: 0.56},
                                                 {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
  end

  def modified_impact_sub(isc_modified)
    if @modified_scope.selected_choice[:name] == 'Changed'
      7.52 * (isc_modified - 0.029) - 3.25 * (isc_modified - 0.02)**15
    else
      6.42 * isc_modified
    end
  end

  def isc_modified
    confidentiality_score = 1 - @modified_confidentiality.score * @confidentiality_requirement.score
    integrity_score = 1 - @modified_integrity.score * @integrity_requirement.score
    availability_score = 1 - @modified_availability.score * @availability_requirement.score

    [0.915, (1 - confidentiality_score * integrity_score * availability_score)].min
  end

  def modified_exploitability_sub(privilege_score)
    modified_exploitability_sub_score = 8.22 * @modified_attack_vector.score
    modified_exploitability_sub_score *= @modified_attack_complexity.score
    modified_exploitability_sub_score *= privilege_score
    modified_exploitability_sub_score *= @modified_user_interaction.score
  end

  def calculate_score(modified_impact_sub_score, modified_exploitability_sub_score, temporal_score)
    factor = @modified_scope.selected_choice[:name] == 'Changed' ? 1.08 : 1.0

    ([factor * (modified_impact_sub_score + modified_exploitability_sub_score), 10].min.round_up(1) * temporal_score)

  end
end
