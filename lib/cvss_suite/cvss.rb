
class Cvss

  attr_reader :base, :temporal, :environmental, :version

  def initialize(vector, version)
    raise 'Do not instantiate this class!' if self.class == Cvss
    @version = version
    @vector = vector
    @metrics = []
    extract_metrics
    init_metrics
  end

  def valid?
    if @amount_of_properties == required_amount_of_properties
        base = @base.valid?
        temporal = @base.valid? && @temporal.valid?
        environmental = @base.valid? && @environmental.valid?
        full = @base.valid? && @temporal.valid? && @environmental.valid?
        base || temporal || environmental || full
      end
  end

  def overall_score
    check_valid
    return temporal_score if @temporal.valid? && !@environmental.valid?
    return environmental_score if @environmental.valid?
    base_score
  end

  private

  def extract_metrics
    properties = prepared_vector.split('/')
    @amount_of_properties = properties.size
    properties.each_with_index do |property, index|
      property = property.split(':')
      @metrics.push({name: property[0], selected: property[1], position: index})
    end
  end

  def check_valid
    raise 'Vector is not valid!' unless valid?
  end

  def prepared_vector
    start_of_vector = @vector.index('AV')
    @vector[start_of_vector..-1]
  end

  def required_amount_of_properties
    total = @base.count if @base.valid?
    total += @temporal.count if @temporal.valid?
    total += @environmental.count if @environmental.valid?
    total ||= 0
  end

end