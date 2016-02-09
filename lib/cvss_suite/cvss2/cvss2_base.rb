require_relative '../cvss_property'

class Cvss2Base

  attr_reader :access_vector, :access_complexity, :authentication,
              :confidentiality_impact, :integrity_impact, :availability_impact

  def initialize(metrics)
    @metrics = []
    init_metrics
    set_selected_choices metrics
  end

  def score
    impact = 10.41*(1-(1-@confidentiality_impact.score)*(1-@integrity_impact.score)*(1-@availability_impact.score))

    exploitability = 20* @access_vector.score*@access_complexity.score*@authentication.score

    additional_impact = (impact == 0 ? 0 : 1.176)

    (((0.6*impact)+(0.4*exploitability)-1.5)*additional_impact).round(1)
  end

  def valid?
    @metrics.each do |metric|
      return false unless metric.valid?
    end
    true
  end

  private

  def init_metrics
    @metrics.push(@access_vector = CvssProperty.new(name: 'Access Vector', abbreviation: 'AV', position: [0],
                                                    choices: [{name: 'Network', abbreviation: 'N', weight: 1.0},
                                                              {name: 'Adjacent', abbreviation: 'A', weight: 0.646},
                                                              {name: 'Local', abbreviation: 'L', weight: 0.395}]))
    @metrics.push(@access_complexity = CvssProperty.new(name: 'Access Complexity', abbreviation: 'AC', position: [1],
                                                        choices: [{name: 'Low', abbreviation: 'L', weight: 0.71},
                                                                  {name: 'Medium', abbreviation: 'M', weight: 0.61},
                                                                  {name: 'High', abbreviation: 'H', weight: 0.35}]))
    @metrics.push(@authentication = CvssProperty.new(name: 'Authentication', abbreviation: 'Au', position: [2],
                                                     choices: [{name: 'None', abbreviation: 'N', weight: 0.704},
                                                               {name: 'Single', abbreviation: 'S', weight: 0.56},
                                                               {name: 'Multiple', abbreviation: 'M', weight: 0.45}]))
    @metrics.push(@confidentiality_impact = CvssProperty.new(name: 'Confidentiality Impact', abbreviation: 'C', position: [3],
                                                             choices: [{name: 'None', abbreviation: 'N', weight: 0.0},
                                                                       {name: 'Partial', abbreviation: 'P', weight: 0.275},
                                                                       {name: 'Complete', abbreviation: 'C', weight: 0.66}]))
    @metrics.push(@integrity_impact = CvssProperty.new(name: 'Integrity Impact', abbreviation: 'I', position: [4],
                                                       choices: [{name: 'None', abbreviation: 'N', weight: 0.0},
                                                                 {name: 'Partial', abbreviation: 'P', weight: 0.275},
                                                                 {name: 'Complete', abbreviation: 'C', weight: 0.66}]))
    @metrics.push(@availability_impact = CvssProperty.new(name: 'Availability Impact', abbreviation: 'A', position: [5],
                                                          choices: [{name: 'None', abbreviation: 'N', weight: 0.0},
                                                                    {name: 'Partial', abbreviation: 'P', weight: 0.275},
                                                                    {name: 'Complete', abbreviation: 'C', weight: 0.66}]))
  end

  def set_selected_choices(metrics)
    metrics.each do |metric|
      selected_metric = @metrics.select { |m| m.abbreviation == metric[:name] && m.position.include?(metric[:position]) }
      selected_metric.first.set_selected_choice metric[:selected] unless selected_metric.empty?
    end
  end
end

