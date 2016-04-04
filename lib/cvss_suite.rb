require 'cvss_suite/cvss2/cvss2'
require 'cvss_suite/cvss3/cvss3'
require 'cvss_suite/version'
require 'cvss_suite/helpers/extensions'

##
# Module of this gem.

module CvssSuite
  CVSS_VECTOR_BEGINNINGS = [{:string => 'AV:', :version => 2}, {:string => 'CVSS:3.0/', :version => 3}]

  ##
  # Returns a CVSS class by a +vector+.

  def self.new(vector)
    @vector = vector
    case self.version
      when 2
        Cvss2.new(@vector, self.version)
      when 3
        Cvss3.new(@vector, self.version)
      else
        raise 'Vector is not valid!'
    end
  end

  private

  def self.version
    CVSS_VECTOR_BEGINNINGS.each do |beginning|
      if @vector.start_with? beginning[:string]
        return beginning[:version]
      end
    end
  end

end
