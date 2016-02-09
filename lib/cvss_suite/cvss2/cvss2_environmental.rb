require_relative '../cvss_property'

class Cvss2Environmental

  def initialize(metrics)
    @metrics = []
    init_metrics
    set_selected_choices metrics
  end

  def score(base, temporal_score)
    adjusted_impact = [10, 10.41*(1-(1-base.confidentiality_impact.score*@security_requirements_cr.score)*(1-base.integrity_impact.score*@security_requirements_ir.score) *(1-base.availability_impact.score*@security_requirements_ar.score))].min

    exploitability = 20* base.access_vector.score*base.access_complexity.score*base.authentication.score

    additional_impact = (adjusted_impact == 0 ? 0 : 1.176)

    base_score = (((0.6*adjusted_impact)+(0.4*exploitability)-1.5)*additional_impact).round(1)
    adjusted_temporal = (base_score * temporal_score).round(1)
    ((adjusted_temporal+(10-adjusted_temporal)*@collateral_damage_potential.score)*@target_distribution.score).round(1)

  end

  def valid?
    @metrics.each do |metric|
      return false unless metric.valid?
    end
    true
  end

  private

  def init_metrics
    @metrics.push(@collateral_damage_potential = CvssProperty.new(name: 'Collateral Damage Potential', abbreviation: 'CDP', position: [6, 9],
                                                                  choices: [{name: 'None', abbreviation: 'N', weight: 0.0},
                                                                            {name: 'Low', abbreviation: 'L', weight: 0.1},
                                                                            {name: 'Low-Medium', abbreviation: 'LM', weight: 0.3},
                                                                            {name: 'Medium-High', abbreviation: 'MH', weight: 0.4},
                                                                            {name: 'High', abbreviation: 'H', weight: 0.5},
                                                                            {name: 'Not Defined', abbreviation: 'ND', weight: 0.0}]))
    @metrics.push(@target_distribution = CvssProperty.new(name: 'Target Distribution', abbreviation: 'TD', position: [7, 10],
                                                          choices: [{name: 'None', abbreviation: 'N', weight: 0.0},
                                                                    {name: 'Low', abbreviation: 'L', weight: 0.25},
                                                                    {name: 'Medium', abbreviation: 'M', weight: 0.75},
                                                                    {name: 'High', abbreviation: 'H', weight: 1.0},
                                                                    {name: 'Not Defined', abbreviation: 'ND', weight: 1.0}]))
    @metrics.push(@security_requirements_cr = CvssProperty.new(name: 'Confidentiality Requirement', abbreviation: 'CR', position: [8, 11],
                                                               choices: [{name: 'Low', abbreviation: 'L', weight: 0.5},
                                                                         {name: 'Medium', abbreviation: 'M', weight: 1.0},
                                                                         {name: 'High', abbreviation: 'H', weight: 1.51},
                                                                         {name: 'Not Defined', abbreviation: 'ND', weight: 1.0}]))
    @metrics.push(@security_requirements_ir = CvssProperty.new(name: 'Integrity Requirement', abbreviation: 'IR', position: [9, 12],
                                                               choices: [{name: 'Low', abbreviation: 'L', weight: 0.5},
                                                                         {name: 'Medium', abbreviation: 'M', weight: 1.0},
                                                                         {name: 'High', abbreviation: 'H', weight: 1.51},
                                                                         {name: 'Not Defined', abbreviation: 'ND', weight: 1.0}]))
    @metrics.push(@security_requirements_ar = CvssProperty.new(name: 'Availability Requirement', abbreviation: 'AR', position: [10, 13],
                                                               choices: [{name: 'Low', abbreviation: 'L', weight: 0.5},
                                                                         {name: 'Medium', abbreviation: 'M', weight: 1.0},
                                                                         {name: 'High', abbreviation: 'H', weight: 1.51},
                                                                         {name: 'Not Defined', abbreviation: 'ND', weight: 1.0}]))
  end

  def set_selected_choices(metrics)
    metrics.each do |metric|
      selected_metric = @metrics.select { |m| m.abbreviation == metric[:name] && m.position.include?(metric[:position]) }
      selected_metric.first.set_selected_choice metric[:selected] unless selected_metric.empty?
    end
  end
end

