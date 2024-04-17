# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'
require_relative "cvss40_calc_helper"

module CvssSuite
  ##
  # This class represents a CVSS invalid metric in 4.0. Mostly we use this because we haven't implemented other metric types yet.
  class Cvss40Invalid < CvssMetric
    ##
    # Returns score of this metric
    def score
        return 0.0
    end

    private

    def init_properties
      @properties.push(CvssProperty.new(name: 'Not used', abbreviation: 'NU',
                                          values: [{ name: 'NotUsed', abbreviation: 'NU', weight: 0.85 },
                                                   { name: 'ReallyNotUsed', abbreviation: 'RNU', weight: 0.62 }]))
    end
  end
end
