class CvssProperty

  def initialize(property)
    @property = property
    @property[:default_choice] ||= 'Not Available'
  end

  def name
    @property[:name]
  end

  def abbreviation
    @property[:abbreviation]
  end

  def choices
    @property[:choices]
  end

  def position
    @property[:position]
  end

  def selected_choice
    @selected_choice || @property[:default_choice]
  end

  def vector
    "#{abbreviation}:#{@selected_choice[:abbreviation]}"
  end

  def valid?
    !@selected_choice.nil?
  end

  def score
    @selected_choice[:weight]
  end

  def set_selected_choice(selected_choice)
    choices.each do |choice|
      choice[:selected] = selected_choice.eql?(choice[:abbreviation])
    end
    @selected_choice = choices.detect { |choice| choice[:selected] }
  end
end