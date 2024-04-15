# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss'
require_relative 'cvss40_base'
# require_relative 'cvss40_threat'
# require_relative 'cvss40_environmental'
# require_relative 'cvss40_supplemental'

module CvssSuite
  ##
  # This class represents a CVSS vector in version 4.0.
  class Cvss40 < Cvss
    ##
    # Returns the Version of the CVSS vector.

    def version
      4.0
    end

    ##
    # Returns the Base Score of the CVSS vector.

    def base_score
      check_validity
      @base.score.round_up
    end

    ##
    # Returns the Temporal Score of the CVSS vector.

    def temporal_score
      raise 'Not Implemented'
      # Cvss31Helper.round_up(Cvss31Helper.round_up(@base.score) * @temporal.score)
    end

    ##
    # Returns the Environmental Score of the CVSS vector.

    def environmental_score
      return temporal_score unless @environmental.valid?

      raise 'Not Implemented'
      # Cvss31Helper.round_up(@environmental.score(@base, @temporal))
    end

    ##
    # Returns the vector itself.
    def vector
      raise 'Not Implemented'
      # "#{CvssSuite::CVSS_VECTOR_BEGINNINGS.find { |beginning| beginning[:version] == version }[:string]}#{@vector}"
    end

    private

    def init_metrics
      @base = Cvss40Base.new(@properties)
      # @temporal = Cvss40Threat.new(@properties)
      # @environmental = Cvss40Environmental.new(@properties)
      # @environmental = Cvss40Supplemental.new(@properties)
    end
  end
end
