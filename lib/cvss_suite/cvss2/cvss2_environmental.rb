require_relative '../cvss_property'
require_relative '../cvss_metric'

class Cvss2Environmental < CvssMetric

  attr_reader :collateral_damage_potential, :target_distribution, :security_requirements_cr,
              :security_requirements_ir, :security_requirements_ar

  def score(base, temporal_score)
    base_score = (base.score @security_requirements_cr.score, @security_requirements_ir.score, @security_requirements_ar.score).round(1)

    adjusted_temporal = (base_score * temporal_score).round(1)
    (adjusted_temporal + (10 - adjusted_temporal) * @collateral_damage_potential.score) * @target_distribution.score

  end

  private

  def init_metrics
    @metrics.push(@collateral_damage_potential =
                      CvssProperty.new(name: 'Collateral Damage Potential', abbreviation: 'CDP', position: [6, 9],
                                       choices: [{ name: 'None', abbreviation: 'N', weight: 0.0 },
                                                 { name: 'Low', abbreviation: 'L', weight: 0.1 },
                                                 { name: 'Low-Medium', abbreviation: 'LM', weight: 0.3 },
                                                 { name: 'Medium-High', abbreviation: 'MH', weight: 0.4 },
                                                 { name: 'High', abbreviation: 'H', weight: 0.5 },
                                                 { name: 'Not Defined', abbreviation: 'ND', weight: 0.0 }]))
    @metrics.push(@target_distribution =
                      CvssProperty.new(name: 'Target Distribution', abbreviation: 'TD', position: [7, 10],
                                       choices: [{ name: 'None', abbreviation: 'N', weight: 0.0 },
                                                 { name: 'Low', abbreviation: 'L', weight: 0.25 },
                                                 { name: 'Medium', abbreviation: 'M', weight: 0.75 },
                                                 { name: 'High', abbreviation: 'H', weight: 1.0 },
                                                 { name: 'Not Defined', abbreviation: 'ND', weight: 1.0 }]))
    @metrics.push(@security_requirements_cr =
                      CvssProperty.new(name: 'Confidentiality Requirement', abbreviation: 'CR', position: [8, 11],
                                       choices: [{ name: 'Low', abbreviation: 'L', weight: 0.5 },
                                                 { name: 'Medium', abbreviation: 'M', weight: 1.0 },
                                                 { name: 'High', abbreviation: 'H', weight: 1.51 },
                                                 { name: 'Not Defined', abbreviation: 'ND', weight: 1.0 }]))
    @metrics.push(@security_requirements_ir =
                      CvssProperty.new(name: 'Integrity Requirement', abbreviation: 'IR', position: [9, 12],
                                       choices: [{ name: 'Low', abbreviation: 'L', weight: 0.5 },
                                                 { name: 'Medium', abbreviation: 'M', weight: 1.0 },
                                                 { name: 'High', abbreviation: 'H', weight: 1.51 },
                                                 { name: 'Not Defined', abbreviation: 'ND', weight: 1.0 }]))
    @metrics.push(@security_requirements_ar =
                      CvssProperty.new(name: 'Availability Requirement', abbreviation: 'AR', position: [10, 13],
                                       choices: [{ name: 'Low', abbreviation: 'L', weight: 0.5 },
                                                 { name: 'Medium', abbreviation: 'M', weight: 1.0 },
                                                 { name: 'High', abbreviation: 'H', weight: 1.51 },
                                                 { name: 'Not Defined', abbreviation: 'ND', weight: 1.0 }]))
  end
end

