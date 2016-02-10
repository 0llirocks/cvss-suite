require_relative '../../../lib/cvss_suite/cvss'
require_relative 'cvss2_base'
require_relative 'cvss2_temporal'
require_relative 'cvss2_environmental'

class Cvss2 < Cvss

  def base_score
    @base.score.round(1)
  end

  def temporal_score
    (base_score * @temporal.score).round(1)
  end

  def environmental_score
    @environmental.score @base, @temporal.score
  end

  def init_metrics
    @base = Cvss2Base.new(@metrics)
    @temporal = Cvss2Temporal.new(@metrics)
    @environmental = Cvss2Environmental.new(@metrics)
  end

end