# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'

module CvssSuite
  ##
  # This class represents a CVSS Environmental Security metric in version 4.0.
  class Cvss40EnvironmentalSecurity < CvssMetric
    ##
    # Property of this metric
    attr_reader :confidentiality_requirements, :integrity_requirements, :availability_requirements

    ##
    # Returns score of this metric
    def score
      Cvss40CalcHelper.new(@properties.map { |p| [p.abbreviation, p.selected_value[:abbreviation]] }.to_h).score
    end

    private

    def init_properties
      @properties.push(@confidentiality_requirements =
                         CvssProperty.new(name: 'Confidentiality Requirements', abbreviation: 'CR',
                                          values: [{ name: 'Not Defined', abbreviation: 'X' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'Medium', abbreviation: 'M' },
                                                   { name: 'High', abbreviation: 'H' }]))
      @properties.push(@integrity_requirements =
                         CvssProperty.new(name: 'Integrity Requirements', abbreviation: 'IR',
                                          values: [{ name: 'Not Defined', abbreviation: 'X' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'Medium', abbreviation: 'M' },
                                                   { name: 'High', abbreviation: 'H' }]))
      @properties.push(@availability_requirements =
                         CvssProperty.new(name: 'Availability Requirements', abbreviation: 'AR',
                                          values: [{ name: 'Not Defined', abbreviation: 'X' },
                                                   { name: 'Low', abbreviation: 'L' },
                                                   { name: 'Medium', abbreviation: 'M' },
                                                   { name: 'High',
                                                     abbreviation: 'H' }]))
    end
  end
end
