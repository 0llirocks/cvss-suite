require_relative '../../../lib/cvss_suite/cvss'
require_relative 'cvss3_base'
require_relative 'cvss3_temporal'
require_relative 'cvss3_environmental'

class Cvss3 < Cvss

  def base_score
    check_valid
    @base.score.round_up(1)
  end

  def temporal_score
    raise 'Vector is not valid!' unless @temporal.valid?
    (@base.score * @temporal.score).round_up(1)
  end

  def environmental_score
    raise 'Vector is not valid!' unless @environmental.valid?
    (@environmental.score @temporal.score).round_up(1)
  end

  def init_metrics
    @base = Cvss3Base.new(@metrics)
    @temporal = Cvss3Temporal.new(@metrics)
    @environmental = Cvss3Environmental.new(@metrics)
  end
end