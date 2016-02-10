
class CvssMetric

  def initialize(metrics)
    @metrics = []
    init_metrics
    set_selected_choices metrics
  end

  def valid?
    @metrics.each do |metric|
      return false unless metric.valid?
    end
  end

  def count
    @metrics.count
  end

  private

  def set_selected_choices(metrics)
    metrics.each do |metric|
      selected_metric = @metrics.select { |m| m.abbreviation == metric[:name] && m.position.include?(metric[:position]) }
      selected_metric.first.set_selected_choice metric[:selected] unless selected_metric.empty?
    end
  end

end