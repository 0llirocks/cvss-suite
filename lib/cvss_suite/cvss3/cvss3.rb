# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) Siemens AG, 2016
#
# Authors:
#   Oliver Hambörger <oliver.hamboerger@siemens.com>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss'
require_relative 'cvss3_base'
require_relative 'cvss3_temporal'
require_relative 'cvss3_environmental'

##
# This class represents a CVSS vector in version 3.0.

module CvssSuite
  class Cvss3 < Cvss
    ##
    # Returns the Version of the CVSS vector.

    def version
      3.0
    end

    ##
    # Returns the Base Score of the CVSS vector.

    def base_score
      check_validity
      Cvss3Helper.round_up(@base.score)
    end

    ##
    # Returns the Temporal Score of the CVSS vector.

    def temporal_score
      Cvss3Helper.round_up(Cvss3Helper.round_up(@base.score) * @temporal.score)
    end

    ##
    # Returns the Environmental Score of the CVSS vector.

    def environmental_score
      return temporal_score unless @environmental.valid?

      Cvss3Helper.round_up(@environmental.score(@temporal.score))
    end

    private

    def init_metrics
      @base = Cvss3Base.new(@properties)
      @temporal = Cvss3Temporal.new(@properties)
      @environmental = Cvss3Environmental.new(@properties)
    end
  end
end
