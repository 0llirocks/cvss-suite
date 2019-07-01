# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) Siemens AG, 2019
#
# Authors:
#   Oliver Hambörger <oliver.hamboerger@siemens.com>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../../../lib/cvss_suite/cvss'
require_relative 'cvss31_base'
require_relative 'cvss31_temporal'
require_relative 'cvss31_environmental'

##
# This class represents a CVSS vector in version 3.1.

class Cvss31 < Cvss

  ##
  # Returns the Base Score of the CVSS vector.

  def base_score
    check_validity
    @base.score.roundup
  end

  ##
  # Returns the Temporal Score of the CVSS vector.

  def temporal_score
    (@base.score.roundup * @temporal.score).roundup
  end

  ##
  # Returns the Environmental Score of the CVSS vector.

  def environmental_score
    return temporal_score unless @environmental.valid?
    (@environmental.score @temporal.score).roundup
  end

  private

  def init_metrics
    @base = Cvss31Base.new(@properties)
    @temporal = Cvss31Temporal.new(@properties)
    @environmental = Cvss31Environmental.new(@properties)
  end

end