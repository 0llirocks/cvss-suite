require 'cvss_suite/version'
require 'cvss_suite/cvss'

module CvssSuite
  def self.new(vector)
    Cvss.new(vector)
  end
end
