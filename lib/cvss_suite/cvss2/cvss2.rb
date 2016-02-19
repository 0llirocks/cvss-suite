require_relative '../../../lib/cvss_suite/cvss'
require_relative 'cvss2_base'
require_relative 'cvss2_temporal'
require_relative 'cvss2_environmental'

##
# This class represents a CVSS vector in version 2.

class Cvss2 < Cvss

  ##
  # Returns the Base Score of the CVSS vector.

  def base_score
    check_valid
    @base.score.round(1)
  end

  ##
  # Returns the Temporal Score of the CVSS vector.

  def temporal_score
    (base_score * @temporal.score).round(1)
  end

  ##
  # Returns the Environmental Score of the CVSS vector.

  def environmental_score
    return temporal_score unless @environmental.valid?
    (@environmental.score @base, @temporal.score).round(1)
  end

  private

  def init_metrics
    @base = Cvss2Base.new(@metrics)
    @temporal = Cvss2Temporal.new(@metrics)
    @environmental = Cvss2Environmental.new(@metrics)
  end

end