# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

module CvssSuite
  ##
  # This class represents a CVSS property of a CVSS metric.
  class CvssProperty
    ##
    # Creates a new CVSS property by a +property+.
    #
    # +Property+ needs to consist of a name, a abbreviation,
    # the possible positions in the CVSS vector, a weight, and the
    # available values for the property.

    def initialize(property)
      @property = property
      @property[:default_value] ||= 'Not Defined'
    end

    ##
    # Returns the full name of the property.

    def name
      @property[:name]
    end

    ##
    # Returns the abbreviation of the property.

    def abbreviation
      @property[:abbreviation]
    end

    ##
    # Returns all available values of the property.

    def values
      @property[:values]
    end

    ##
    # Returns the possible positions in the CVSS vector of the property.

    def position
      @property[:position]
    end

    ##
    # Returns the selected value of the property.

    def selected_value
      @selected_value || @property[:default_value]
    end

    ##
    # Returns true if the property is valid.

    def valid?
      !@selected_value.nil? && @property[:values].map { |p| p[:abbreviation] }.include?(@selected_value[:abbreviation])
    end

    ##
    # Returns the score of the selected value.

    def score
      @selected_value[:weight]
    end

    ##
    # Sets the selected value by a +value+.

    def set_selected_value(selected_value)
      values.each do |value|
        value[:selected] = selected_value.eql?(value[:abbreviation])
      end
      @selected_value = values.detect { |value| value[:selected] }
      return unless @selected_value.nil?

      @selected_value = { abbreviation: selected_value }
    end

    ##
    # Sets the default value.

    def set_default_value
      values.each do |value|
        value[:selected] = value[:abbreviation].eql?('X')
        value[:selected] ||= value[:abbreviation].eql?('ND')
      end
      @selected_value = values.detect { |value| value[:selected] }
    end

    ##
    # Returns whether a selected_value is set

    def non_selected?
      @selected_value.nil?
    end
  end
end
