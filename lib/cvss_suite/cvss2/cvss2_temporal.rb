require_relative '../cvss_property'

class Cvss2Temporal
  def initialize(metrics)
    @metrics = []
    init_metrics
    set_selected_choices metrics
  end

  def vector
    "#{exploitability.vector}/#{remediation_level.vector}/#{report_confidence.vector}"
  end

  def score
    return 1 unless valid?
    @exploitability.score*@remediation_level.score*@report_confidence.score
  end

  def valid?
    @metrics.each do |metric|
      return false unless metric.valid?
    end
    true
  end

  private

  def init_metrics
    @metrics.push(@exploitability = CvssProperty.new(name: 'Exploitability', abbreviation: 'E', position: [6],
                                      choices: [{name: 'Unproven', abbreviation: 'U', weight: 0.85},
                                                {name: 'Proof-of-Concept', abbreviation: 'POC', weight: 0.9},
                                                {name: 'Functional', abbreviation: 'F', weight: 0.95},
                                                {name: 'High', abbreviation: 'H', weight: 1},
                                                {name: 'Not Defined', abbreviation: 'ND', weight: 1}]))
    @metrics.push(@remediation_level = CvssProperty.new(name: 'Remediation Level', abbreviation: 'RL', position: [7],
                                         choices: [{name: 'Official Fix', abbreviation: 'OF', weight: 0.87},
                                                   {name: 'Temporary Fix', abbreviation: 'TF', weight: 0.9},
                                                   {name: 'Workaround', abbreviation: 'W', weight: 0.95},
                                                   {name: 'Unavailable', abbreviation: 'U', weight: 1},
                                                   {name: 'Not Defined', abbreviation: 'ND', weight: 1}]))

    @metrics.push(@report_confidence = CvssProperty.new(name: 'Report Confidence', abbreviation: 'RC', position: [8],
                                         choices: [{name: 'Unconfirmed', abbreviation: 'UC', weight: 0.9},
                                                   {name: 'Uncorroborated', abbreviation: 'UR', weight: 0.95},
                                                   {name: 'Confirmed', abbreviation: 'C', weight: 1},
                                                   {name: 'Not Defined', abbreviation: 'ND', weight: 1}]))
  end

  def set_selected_choices(metrics)
    metrics.each do |metric|
      selected_metric = @metrics.select { |m| m.abbreviation == metric[:name] && m.position.include?(metric[:position]) }
      selected_metric.first.set_selected_choice metric[:selected] unless selected_metric.empty?
    end
  end
end
