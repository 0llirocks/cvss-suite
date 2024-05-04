# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_31_and_before'
require_relative 'cvss3_base'
require_relative 'cvss3_temporal'
require_relative 'cvss3_environmental'

module CvssSuite
  ##
  # This class represents a CVSS vector in version 3.0.
  class Cvss3 < Cvss31AndBefore
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

      Cvss3Helper.round_up(@environmental.score(@base, @temporal))
    end

    ##
    # Returns the vector itself.
    def vector
      "#{CvssSuite::CVSS_VECTOR_BEGINNINGS.find { |beginning| beginning[:version] == version }[:string]}#{@vector}"
    end

    private

    def init_metrics
      @base = Cvss3Base.new(@properties)
      @temporal = Cvss3Temporal.new(@properties)
      @environmental = Cvss3Environmental.new(@properties)
    end
  end
end
