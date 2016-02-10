require_relative '../cvss_property'
require_relative '../cvss_metric'

class Cvss2Temporal < CvssMetric

  def score
    return 1 unless valid?
    @exploitability.score * @remediation_level.score * @report_confidence.score
  end

  private

  def init_metrics
    @metrics.push(@exploitability =
                      CvssProperty.new(name: 'Exploitability', abbreviation: 'E', position: [6],
                                       choices: [{ name: 'Unproven', abbreviation: 'U', weight: 0.85 },
                                                 { name: 'Proof-of-Concept', abbreviation: 'POC', weight: 0.9 },
                                                 { name: 'Functional', abbreviation: 'F', weight: 0.95 },
                                                 { name: 'High', abbreviation: 'H', weight: 1 },
                                                 { name: 'Not Defined', abbreviation: 'ND', weight: 1 }]))
    @metrics.push(@remediation_level =
                      CvssProperty.new(name: 'Remediation Level', abbreviation: 'RL', position: [7],
                                       choices: [{ name: 'Official Fix', abbreviation: 'OF', weight: 0.87 },
                                                 { name: 'Temporary Fix', abbreviation: 'TF', weight: 0.9 },
                                                 { name: 'Workaround', abbreviation: 'W', weight: 0.95 },
                                                 { name: 'Unavailable', abbreviation: 'U', weight: 1 },
                                                 { name: 'Not Defined', abbreviation: 'ND', weight: 1 }]))

    @metrics.push(@report_confidence =
                      CvssProperty.new(name: 'Report Confidence', abbreviation: 'RC', position: [8],
                                       choices: [{ name: 'Unconfirmed', abbreviation: 'UC', weight: 0.9 },
                                                 { name: 'Uncorroborated', abbreviation: 'UR', weight: 0.95 },
                                                 { name: 'Confirmed', abbreviation: 'C', weight: 1 },
                                                 { name: 'Not Defined', abbreviation: 'ND', weight: 1 }]))
  end
end
