require_relative '../../../lib/cvss_suite/cvss'
require_relative 'cvss3_base'
require_relative 'cvss3_temporal'
require_relative 'cvss3_environmental'

##
# This class represents a CVSS vector in version 2.

class Cvss3 < Cvss

  ##
  # Returns the Base Score of the CVSS vector.

  def base_score
    check_valid
    @base.score.round_up(1)
  end

  ##
  # Returns the Temporal Score of the CVSS vector.

  def temporal_score
    (@base.score * @temporal.score).round_up(1)
  end

  ##
  # Returns the Environmental Score of the CVSS vector.

  def environmental_score
    return temporal_score unless @environmental.valid?
    (@environmental.score @temporal.score).round_up(1)
  end

  private

  def init_metrics
    @base = Cvss3Base.new(@properties)
    @temporal = Cvss3Temporal.new(@properties)
    @environmental = Cvss3Environmental.new(@properties)
  end

end