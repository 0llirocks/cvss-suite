class Cvss

  CVSS_VECTOR_BEGINNINGS = [{:string => 'AV:', :version => 2}, {:string => 'CVSS:3.0/', :version => 3}]

  def initialize(vector)
    @vector = vector
    @properties = []
  end

  def valid?
    true
  end

  def version
    check_valid
    CVSS_VECTOR_BEGINNINGS.each do |beginning|
      if @vector.start_with? beginning[:string]
        return beginning[:version]
      end
    end
  end

  private

  def extract_properties
    properties = prepared_vector.split('/')
    properties.each do |property|
      property = property.split(':')
      @properties.push({name: property[0], selected: property[1]})
    end
  end

  def check_valid
    raise 'Vector is not valid!' unless valid?
  end

  def prepared_vector
    start_of_vector = @vector.index('AV')
    @vector[start_of_vector..-1]
  end

end