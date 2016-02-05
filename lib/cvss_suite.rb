require 'cvss_suite/version'
require 'cvss_suite/cvss'

module CvssSuite
  def self.hi
    test = Cvss.new
    test.test
  end
end
