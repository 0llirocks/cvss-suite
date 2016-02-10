require_relative '../../../lib/cvss_suite/cvss'
require_relative 'cvss2_base'
require_relative 'cvss2_temporal'
require_relative 'cvss2_environmental'

class Cvss2 < Cvss

  def base_score
    check_valid
    @base.score.round(1)
  end

  def temporal_score
    raise 'Vector is not valid!' unless @temporal.valid?
    (base_score * @temporal.score).round(1)
  end

  def environmental_score
    raise 'Vector is not valid!' unless @environmental.valid?
    (@environmental.score @base, @temporal.score).round(1)
  end

  def init_metrics
    @base = Cvss2Base.new(@metrics)
    @temporal = Cvss2Temporal.new(@metrics)
    @environmental = Cvss2Environmental.new(@metrics)
  end

end