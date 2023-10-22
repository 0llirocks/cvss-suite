# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) 2019-2022 Siemens AG
# Copyright (c) 2022-2023 0llirocks
#
# Authors:
#   0llirocks <http://0lli.rocks>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss'
require_relative 'cvss40_base'
require_relative 'cvss40_threat'
require_relative 'cvss40_environmental'
require_relative 'cvss40_supplemental'

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
    # Returns the Base Score of the CVSS vector (aka CVSS-B).

    def base_score
      check_validity
      @base.score
    end

    ##
    # Returns the Threat Score of the CVSS vector (aka CVSS-BT).

    def temporal_score
      @base.score * @threat.score
    end

    ##
    # Returns the Threat Score of the CVSS vector (aka CVSS-BT).

    def threat_score
      @base.score * @threat.score
    end

    ##
    # Returns the Environmental and Threat Score of the CVSS vector (aka CVSS-BTE).

    def environmental_score
      threat_score unless @environmental.valid?
    end

    ##
    # Returns the Environmental Score of the CVSS vector (aka CVSS-BE).

    def environmental_only_score
      threat_score unless @environmental.valid?
    end

    ##
    # Returns the vector itself.
    def vector
      "#{CvssSuite::CVSS_VECTOR_BEGINNINGS.find { |beginning| beginning[:version] == version }[:string]}#{@vector}"
    end

    private

    def init_metrics
      @base = Cvss40Base.new(@properties)
      @threat = Cvss40Threat.new(@properties)
      @environmental = Cvss40Environmental.new(@properties)
      @supplemental = Cvss40Supplemental.new(@properties)
    end
  end
end
