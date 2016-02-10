require_relative '../cvss_property'

class Cvss3Temporal
  def initialize(metrics)
    @metrics = []
    init_metrics
    set_selected_choices metrics
  end

  def score
    return 1 unless valid?
    @exploit_code_maturity.score*@remediation_level.score*@report_confidence.score
  end

  def valid?
    @metrics.each do |metric|
      return false unless metric.valid?
    end
    true
  end

  private

  def init_metrics
    @metrics.push(@exploit_code_maturity = CvssProperty.new(name: 'Exploit Code Maturity', abbreviation: 'E', position: [8],
                                                     choices: [{name: 'Unproven', abbreviation: 'U', weight: 0.91},
                                                               {name: 'Proof-of-Concept', abbreviation: 'P', weight: 0.94},
                                                               {name: 'Functional', abbreviation: 'F', weight: 0.97},
                                                               {name: 'High', abbreviation: 'H', weight: 1},
                                                               {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
    @metrics.push(@remediation_level = CvssProperty.new(name: 'Remediation Level', abbreviation: 'RL', position: [9],
                                                        choices: [{name: 'Official Fix', abbreviation: 'O', weight: 0.95},
                                                                  {name: 'Temporary Fix', abbreviation: 'T', weight: 0.96},
                                                                  {name: 'Workaround', abbreviation: 'W', weight: 0.97},
                                                                  {name: 'Unavailable', abbreviation: 'U', weight: 1},
                                                                  {name: 'Not Defined', abbreviation: 'X', weight: 1}]))

    @metrics.push(@report_confidence = CvssProperty.new(name: 'Report Confidence', abbreviation: 'RC', position: [10],
                                                        choices: [{name: 'Unknown', abbreviation: 'U', weight: 0.92},
                                                                  {name: 'Reasonable', abbreviation: 'R', weight: 0.96},
                                                                  {name: 'Confirmed', abbreviation: 'C', weight: 1},
                                                                  {name: 'Not Defined', abbreviation: 'X', weight: 1}]))
  end

  def set_selected_choices(metrics)
    metrics.each do |metric|
      selected_metric = @metrics.select { |m| m.abbreviation == metric[:name] && m.position.include?(metric[:position]) }
      selected_metric.first.set_selected_choice metric[:selected] unless selected_metric.empty?
    end
  end
end