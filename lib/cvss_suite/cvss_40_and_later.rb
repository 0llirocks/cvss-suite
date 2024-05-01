# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative 'cvss'

module CvssSuite
  ##
  # This class represents any CVSS vector. Do not instantiate this class!
  class Cvss40AndLater < Cvss
    ##
    # Metric of a CVSS vector for CVSS 2, 3, 3.1.
    attr_reader :temporal, :environmental

    ##
    # Creates a new CVSS vector by a +vector+, for all CVSS versions from 4.0.
    #
    # Raises an exception if it is called on Cvss40AndLater class.
    def initialize(vector)
      raise CvssSuite::Errors::InvalidParentClass, 'Do not instantiate this class!' if instance_of? Cvss40AndLater

      super
    end

    ##
    # Returns if CVSS vector is valid.
    def valid?
      if @amount_of_properties >= required_amount_of_properties
        @base.valid?

      else
        false
      end
    end

    ##
    # Returns the Overall Score of the CVSS vector.
    def overall_score
      check_validity

      @all_up.score
    end
  end
end
