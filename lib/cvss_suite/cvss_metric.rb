# © Siemens AG, 2016

##
# This class represents any CVSS metric.

class CvssMetric

  ##
  # Creates a new CVSS metric by +properties+

  def initialize(selected_properties)
    @properties = []
    init_properties
    extract_selected_choices_from selected_properties
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

  private

  def extract_selected_choices_from(selected_properties)
    selected_properties.each do |selected_property|
      property = @properties.detect {
          |p| p.abbreviation == selected_property[:name] && p.position.include?(selected_property[:position])
      }
      property.set_selected_choice selected_property[:selected] unless property.nil?
    end
  end

end