# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative 'cvss'

module CvssSuite
  ##
  # This class represents any CVSS vector. Do not instantiate this class!
  class Cvss31AndBefore < Cvss
    ##
    # Metric of a CVSS vector for CVSS 2, 3, 3.1.
    attr_reader :temporal, :environmental

    ##
    # Creates a new CVSS vector by a +vector+, for all CVSS versions through 3.1.
    #
    # Raises an exception if it is called on Cvss31AndBefore class.
    def initialize(vector)
      raise CvssSuite::Errors::InvalidParentClass, 'Do not instantiate this class!' if instance_of? Cvss31AndBefore

      super
    end

    ##
    # Returns if CVSS vector is valid.
    def valid?
      if @amount_of_properties >= required_amount_of_properties
        entered_keys = @properties.collect { |p| p[:name] }
        return false if (entered_keys - allowed_abbreviations).size.positive?

        check_metrics_validity
      else
        false
      end
    end

    ##
    # Returns the Overall Score of the CVSS vector.
    def overall_score
      check_validity
      return temporal_score if @temporal.valid? && !@environmental.valid?
      return environmental_score if @environmental.valid?

      base_score
    end

    private

    def allowed_abbreviations
      @base.properties.collect(&:abbreviation) +
        @temporal.properties.collect(&:abbreviation) +
        @environmental.properties.collect(&:abbreviation)
    end

    def check_metrics_validity
      @base.valid? && @temporal&.valid? && @environmental&.valid?
    end
  end
end
