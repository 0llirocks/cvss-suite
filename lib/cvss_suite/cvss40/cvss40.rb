# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_40_and_later'
require_relative 'cvss40_base'
require_relative 'cvss40_supplemental'
require_relative 'cvss40_threat'
require_relative 'cvss40_environmental'
require_relative 'cvss40_environmental_security'
require_relative 'cvss40_all_up'

module CvssSuite
  ##
  # This class represents a CVSS vector in version 4.0.
  class Cvss40 < Cvss40AndLater
    ##
    # Returns the Version of the CVSS vector.

    def version
      4.0
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
      @environmental_security = Cvss40EnvironmentalSecurity.new(@properties)
      @supplemental = Cvss40Supplemental.new(@properties)

      @all_up = Cvss40AllUp.new(@properties, @base, @threat, @environmental, @environmental_security, @supplemental)
    end
  end
end
