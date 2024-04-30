# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'

module CvssSuite
  ##
  # This class represents a CVSS Threat metric in version 3.1.
  class Cvss40Environmental < CvssMetric
    ##
    # Property of this metric
    # attr_reader :exploit_maturity

    ##
    # Returns score of this metric
    def score
      Cvss40CalcHelper.new(@properties.map { |p| [p.abbreviation, p.selected_value[:abbreviation]] }.to_h).score
    end

    private

    def init_properties
    end
  end
end
