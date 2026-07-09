# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

module CvssSuite
  ##
  # This class represents any CVSS metric.
  class CvssMetric
    ##
    # Creates a new CVSS metric by +properties+
    def initialize(selected_properties)
      @properties = []
      init_properties
      extract_selected_values_from selected_properties
    end

    ##
    # Returns if the metric is valid.
    def valid?
      @properties.each do |property|
        return false unless property.valid?
      end
      true
    end

    ##
    # Returns if any property in this metric was explicitly provided
    # (i.e., set to a value other than the default 'X' or 'ND').
    def explicitly_provided?
      @properties.any? do |property|
        property.valid? &&
          property.selected_value[:abbreviation] != 'X' &&
          property.selected_value[:abbreviation] != 'ND'
      end
    end

    ##
    # Returns number of properties for this metric.
    def count
      @properties.count
    end

    ##
    # We aggregate these in some other classes
    attr_reader :properties

    private

    def extract_selected_values_from(selected_properties)
      selected_properties.each do |selected_property|
        property = @properties.detect do |p|
          p.abbreviation == selected_property[:name] &&
            (p.position&.include?(selected_property[:position]) || p.position.nil?)
        end
        property&.mark_selected selected_property[:selected]
      end
      @properties.select(&:non_selected?).each(&:mark_default)
    end
  end
end
