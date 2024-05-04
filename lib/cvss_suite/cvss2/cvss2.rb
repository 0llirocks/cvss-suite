# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_31_and_before'
require_relative 'cvss2_base'
require_relative 'cvss2_temporal'
require_relative 'cvss2_environmental'

module CvssSuite
  ##
  # This class represents a CVSS vector in version 2.
  class Cvss2 < Cvss31AndBefore
    ##
    # Returns the Version of the CVSS vector.
    def version
      2
    end

    # Returns the severity of the CVSSv2 vector.
    # https://nvd.nist.gov/vuln-metrics/cvss
    def severity
      check_validity

      score = overall_score

      case score
      when 0.0..3.9
        'Low'
      when 4.0..6.9
        'Medium'
      when 7.0..10.0
        'High'
      else
        'None'
      end
    end

    ##
    # Returns the Base Score of the CVSS vector.
    def base_score
      check_validity
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
      @base = Cvss2Base.new(@properties)
      @temporal = Cvss2Temporal.new(@properties)
      @environmental = Cvss2Environmental.new(@properties)
    end
  end
end
