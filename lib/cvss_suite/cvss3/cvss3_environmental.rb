require_relative '../cvss_property'

class Cvss3Environmental

  def initialize(metrics)
    @metrics = []
    init_metrics
    set_selected_choices metrics
  end

  def score(base, temporal_score)
    privilege_score = @modified_privileges_required.score
    privilege_score = 0.68 if @modified_scope.selected_choice[:name] == 'Changed' && @modified_privileges_required.selected_choice[:name] == 'Low'
    privilege_score = 0.50 if @modified_scope.selected_choice[:name] == 'Changed' && @modified_privileges_required.selected_choice[:name] == 'High'
    modified_exploitability_sub_score = 8.22 * @modified_attack_vector.score * @modified_attack_complexity.score * privilege_score * @modified_user_interaction.score
    isc_modified = [0.915, (1-(1-@modified_confidentiality.score * @confidentiality_requirement.score)*(1-@modified_integrity.score * @integrity_requirement.score)*(1-@modified_availability.score * @availability_requirement.score))].min
    if @modified_scope.selected_choice[:name] == 'Changed'
      modified_impact_sub_score = 7.52 * (isc_modified-0.029)-3.25 * (isc_modified-0.02)**15
    else
      modified_impact_sub_score = 6.42 * isc_modified
    end

    return 0 if modified_impact_sub_score <= 0
    if @modified_scope.selected_choice[:name] == 'Changed'
      (((((([1.08*(modified_impact_sub_score + modified_exploitability_sub_score), 10].min)*10.0).ceil/10.0)*temporal_score)*10.0).ceil/10.0)
    else
      (((((([modified_impact_sub_score + modified_exploitability_sub_score, 10].min)*10.0).ceil/10.0)*temporal_score)*10.0).ceil/10.0)
    end
  end

  def valid?
    @metrics.each do |metric|
      return false unless metric.valid?
    end
    true
  end

  private

  def init_metrics
    @metrics.push(@confidentiality_requirement = CvssProperty.new(name: 'Confidentiality Requirement', abbreviation: 'CR', position: [8, 11],
                                                                  choices: [{name: 'Low', abbreviation: 'L', weight: 0.5},
                                                                            {name: 'Medium', abbreviation: 'M', weight: 1.0},
                                                                            {name: 'High', abbreviation: 'H', weight: 1.5},
                                                                            {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @metrics.push(@integrity_requirement = CvssProperty.new(name: 'Integrity Requirement', abbreviation: 'IR', position: [9,12],
                                                            choices: [{name: 'Low', abbreviation: 'L', weight: 0.5},
                                                                      {name: 'Medium', abbreviation: 'M', weight: 1.0},
                                                                      {name: 'High', abbreviation: 'H', weight: 1.5},
                                                                      {name: 'Not Defined', abbreviation: 'X', weight: 1}]))

    @metrics.push(@availability_requirement = CvssProperty.new(name: 'Availability Requirement', abbreviation: 'AR', position: [10,13],
                                                               choices: [{name: 'Low', abbreviation: 'L', weight: 0.5},
                                                                         {name: 'Medium', abbreviation: 'M', weight: 1.0},
                                                                         {name: 'High', abbreviation: 'H', weight: 1.5},
                                                                         {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @metrics.push(@modified_attack_vector = CvssProperty.new(name: 'Modified Attack Vector', abbreviation: 'MAV', position: [11,14],
                                                               choices: [{name: 'Network', abbreviation: 'N', weight: 0.85},
                                                                         {name: 'Adjacent Network', abbreviation: 'A', weight: 0.62},
                                                                         {name: 'Local', abbreviation: 'L', weight: 0.55},
                                                                         {name: 'Physical', abbreviation: 'P', weight: 0.2},
                                                                         {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @metrics.push(@modified_attack_complexity = CvssProperty.new(name: 'Modified Attack Complexity', abbreviation: 'MAC', position: [12,15],
                                                             choices: [{name: 'Low', abbreviation: 'L', weight: 0.77},
                                                                       {name: 'High', abbreviation: 'H', weight: 0.44},
                                                                       {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @metrics.push(@modified_privileges_required = CvssProperty.new(name: 'Modified Privileges Required', abbreviation: 'MPR', position: [13,16],
                                                                 choices: [{name: 'None', abbreviation: 'N', weight: 0.85},
                                                                           {name: 'Low', abbreviation: 'L', weight: 0.62},
                                                                           {name: 'High', abbreviation: 'H', weight: 0.27},
                                                                           {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @metrics.push(@modified_user_interaction = CvssProperty.new(name: 'Modified User Interaction', abbreviation: 'MUI', position: [14,17],
                                                                   choices: [{name: 'None', abbreviation: 'N', weight: 0.85},
                                                                             {name: 'Required', abbreviation: 'R', weight: 0.62},
                                                                             {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @metrics.push(@modified_scope = CvssProperty.new(name: 'Modified Scope', abbreviation: 'MS', position: [15,18],
                                                                choices: [{name: 'Changed', abbreviation: 'C'},
                                                                          {name: 'Unchanged', abbreviation: 'U'}]))
    @metrics.push(@modified_confidentiality = CvssProperty.new(name: 'Modified Confidentiality', abbreviation: 'MC', position: [16,19],
                                                     choices: [{name: 'None', abbreviation: 'N', weight: 0},
                                                               {name: 'Low', abbreviation: 'L', weight: 0.22},
                                                               {name: 'High', abbreviation: 'H', weight: 0.56},
                                                               {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @metrics.push(@modified_integrity = CvssProperty.new(name: 'Modified Integrity', abbreviation: 'MI', position: [17,20],
                                                         choices: [{name: 'None', abbreviation: 'N', weight: 0},
                                                                   {name: 'Low', abbreviation: 'L', weight: 0.22},
                                                                   {name: 'High', abbreviation: 'H', weight: 0.56},
                                                                   {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @metrics.push(@modified_availability = CvssProperty.new(name: 'Modified Availability', abbreviation: 'MA', position: [18,21],
                                                            choices: [{name: 'None', abbreviation: 'N', weight: 0},
                                                                      {name: 'Low', abbreviation: 'L', weight: 0.22},
                                                                      {name: 'High', abbreviation: 'H', weight: 0.56},
                                                                      {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
  end

  def set_selected_choices(metrics)
    metrics.each do |metric|
      selected_metric = @metrics.select { |m| m.abbreviation == metric[:name] && m.position.include?(metric[:position]) }
      selected_metric.first.set_selected_choice metric[:selected] unless selected_metric.empty?
    end
  end
end