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
        property&.set_selected_value selected_property[:selected]
      end
      @properties.select(&:non_selected?).each(&:set_default_value)
    end
  end
end
