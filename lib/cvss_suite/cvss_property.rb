
##
# This class represents a CVSS property of a CVSS metric.

class CvssProperty

  ##
  # Creates a new CVSS property by a +property+.
  #
  # +Property+ needs to consist of a name, a abbreviation, the possible positions in the CVSS vector, a weight, and the
  # available choices for the property.

  def initialize(property)
    @property = property
    @property[:default_choice] ||= 'Not Available'
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
  # Returns all available choices of the property.

  def choices
    @property[:choices]
  end

  ##
  # Returns the possible positions in the CVSS vector of the property.

  def position
    @property[:position]
  end

  ##
  # Returns the selected choice of the property.

  def selected_choice
    @selected_choice || @property[:default_choice]
  end

  ##
  # Returns true if the property is valid.

  def valid?
    !@selected_choice.nil?
  end

  ##
  # Returns the score of the selected choice.

  def score
    @selected_choice[:weight]
  end

  ##
  # Sets the selected choice by a +choice+.

  def set_selected_choice(selected_choice)
    choices.each do |choice|
      choice[:selected] = selected_choice.eql?(choice[:abbreviation])
    end
    @selected_choice = choices.detect { |choice| choice[:selected] }
  end
end