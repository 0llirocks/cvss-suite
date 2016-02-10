require_relative '../cvss_property'

class Cvss3Base

  def initialize(metrics)
    @metrics = []
    init_metrics
    set_selected_choices metrics
  end

  def score

    privilege_score = @privileges_required.score
    privilege_score = 0.68 if @scope.selected_choice[:name] == 'Changed' && @privileges_required.selected_choice[:name] == 'Low'
    privilege_score = 0.50 if @scope.selected_choice[:name] == 'Changed' && @privileges_required.selected_choice[:name] == 'High'

    exploitability = 8.22 * @attack_vector.score * @attack_complexity.score * privilege_score * @user_interaction.score

    isc_base = 1 - ((1-@confidentiality.score) * (1-@integrity.score) * (1-@availability.score))
    if @scope.selected_choice[:name] == 'Changed'
      impact_sub_score = 7.52 * (isc_base-0.029) - 3.25 * (isc_base-0.02)**15
    else
      impact_sub_score = 6.42 * isc_base
    end

     return 0 if impact_sub_score <= 0

    if @scope.selected_choice[:name] == 'Changed'
      (([10,  1.08 * (impact_sub_score + exploitability)].min)*10.0).ceil/10.0
    else
      (([10,impact_sub_score + exploitability].min)*10.0).ceil/10.0
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
    @metrics.push(@attack_vector = CvssProperty.new(name: 'Attack Vector', abbreviation: 'AV', position: [0],
                                                    choices: [{name: 'Network', abbreviation: 'N', weight: 0.85},
                                                              {name: 'Adjacent', abbreviation: 'A', weight: 0.62},
                                                              {name: 'Local', abbreviation: 'L', weight: 0.55},
                                                              {name: 'Physical', abbreviation: 'P', weight: 0.2}]))
    @metrics.push(@attack_complexity = CvssProperty.new(name: 'Attack Complexity', abbreviation: 'AC', position: [1],
                                                        choices: [{name: 'Low', abbreviation: 'L', weight: 0.77},
                                                                  {name: 'High', abbreviation: 'H', weight: 0.44}]))
    @metrics.push(@privileges_required = CvssProperty.new(name: 'Privileges Required', abbreviation: 'PR', position: [2],
                                                          choices: [{name: 'None', abbreviation: 'N', weight: 0.85},
                                                                    {name: 'Low', abbreviation: 'L', weight: 0.62},
                                                                    {name: 'High', abbreviation: 'H', weight: 0.27}]))
    @metrics.push(@user_interaction = CvssProperty.new(name: 'User Interaction', abbreviation: 'UI', position: [3],
                                                       choices: [{name: 'None', abbreviation: 'N', weight: 0.85},
                                                                 {name: 'Required', abbreviation: 'R', weight: 0.62}]))
    @metrics.push(@scope = CvssProperty.new(name: 'Scope', abbreviation: 'S', position: [4],
                                            choices: [{name: 'Unchanged', abbreviation: 'U'},
                                                      {name: 'Changed', abbreviation: 'C'}]))
    @metrics.push(@confidentiality = CvssProperty.new(name: 'Confidentiality', abbreviation: 'C', position: [5],
                                                      choices: [{name: 'None', abbreviation: 'N', weight: 0.0},
                                                                {name: 'Low', abbreviation: 'L', weight: 0.22},
                                                                {name: 'High', abbreviation: 'H', weight: 0.56}]))
    @metrics.push(@integrity = CvssProperty.new(name: 'Integrity', abbreviation: 'I', position: [6],
                                                choices: [{name: 'None', abbreviation: 'N', weight: 0.0},
                                                          {name: 'Low', abbreviation: 'L', weight: 0.22},
                                                          {name: 'High', abbreviation: 'H', weight: 0.56}]))
    @metrics.push(@availability = CvssProperty.new(name: 'Availability', abbreviation: 'A', position: [7],
                                                   choices: [{name: 'None', abbreviation: 'N', weight: 0.0},
                                                             {name: 'Low', abbreviation: 'L', weight: 0.22},
                                                             {name: 'High', abbreviation: 'H', weight: 0.56}]))
  end

  def set_selected_choices(metrics)
    metrics.each do |metric|
      selected_metric = @metrics.select { |m| m.abbreviation == metric[:name] && m.position.include?(metric[:position]) }
      selected_metric.first.set_selected_choice metric[:selected] unless selected_metric.empty?
    end
  end
end

