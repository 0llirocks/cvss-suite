# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'
require_relative 'cvss40_base'
require_relative 'cvss40_threat'

module CvssSuite
  ##
  # This class represents a CVSS Threat metric in version 3.1.
  class Cvss40AllUp < CvssMetric
    ##
    # Returns score of this metric
    def score
      Cvss40CalcHelper.new(@properties.map { |p| [p.abbreviation, p.selected_value[:abbreviation]] }.to_h).score
    end

    def initialize(properties, base, threat, environmental, environmental_security, supplemental)
      @properties_to_later_initialize_from = properties
      @base = base
      @threat = threat
      @environmental = environmental
      @environmental_security = environmental_security
      @supplemental = supplemental
      super(properties)
    end

    private

    def init_properties
      # All up takes it's properties from all other scores
      properties_to_add = @base.properties + @threat.properties + @environmental.properties +
                          @environmental_security.properties + @supplemental.properties
      properties_to_add.each { |p| @properties.push p }
    end
  end
end
