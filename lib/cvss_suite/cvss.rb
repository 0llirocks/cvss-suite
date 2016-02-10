require_relative 'cvss2/cvss2_base'
require_relative 'cvss2/cvss2_temporal'
require_relative 'cvss2/cvss2_environmental'
require_relative 'cvss3/cvss3_base'
require_relative 'cvss3/cvss3_temporal'
require_relative 'cvss3/cvss3_environmental'

class Cvss

  CVSS_VECTOR_BEGINNINGS = [{:string => 'AV:', :version => 2}, {:string => 'CVSS:3.0/', :version => 3}]

  attr_reader :base, :temporal, :environmental

  def initialize(vector)
    @vector = vector
    @metrics = []
    extract_metrics
    init_metrics
  end

  def valid?
    case version
      when 2
        base = @base.valid? && @amount_of_properties == 6
        temporal = @base.valid? && @temporal.valid? && @amount_of_properties == 9
        environmental = @base.valid? && @environmental.valid? && @amount_of_properties == 11
        full = @base.valid? && @temporal.valid? && @environmental.valid? && @amount_of_properties == 14
        base || temporal || environmental || full
      when 3
        base = @base.valid? && @amount_of_properties == 8
        temporal = @base.valid? && @temporal.valid? && @amount_of_properties == 11
        environmental = @base.valid? && @environmental.valid? && @amount_of_properties == 19
        full = @base.valid? && @temporal.valid? && @environmental.valid? && @amount_of_properties == 22
        base || temporal || environmental || full
    end

  end

  def version
    CVSS_VECTOR_BEGINNINGS.each do |beginning|
      if @vector.start_with? beginning[:string]
        return beginning[:version]
      end
    end
  end

  def overall_score
    return (@base.score * @temporal.score).round(1) if @temporal.valid? && !@environmental.valid?
    return @environmental.score @base, @temporal.score if @environmental.valid?
    @base.score
  end

  def base_score
    @base.score
  end

  def temporal_score
    (@base.score * @temporal.score).round(1)
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

  def init_metrics
    case version
      when 2
        @base = Cvss2Base.new(@metrics)
        @temporal = Cvss2Temporal.new(@metrics)
        @environmental = Cvss2Environmental.new(@metrics)
      when 3
        @base = Cvss3Base.new(@metrics)
        @temporal = Cvss3Temporal.new(@metrics)
        @environmental = Cvss3Environmental.new(@metrics)
    end
  end

end