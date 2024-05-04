# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

module CvssSuite
  ##
  # This class represents any CVSS vector. Do not instantiate this class!
  class Cvss
    ##
    # Metric of a CVSS vector.
    attr_reader :base

    ##
    # Creates a new CVSS vector by a +vector+.
    #
    # Raises an exception if it is called on Cvss class.
    def initialize(vector)
      raise CvssSuite::Errors::InvalidParentClass, 'Do not instantiate this class!' if instance_of? Cvss

      @vector = vector
      @properties = []
      extract_metrics
      init_metrics
    end

    ##
    # Returns the severity of the CVSS vector.
    def severity
      check_validity

      score = overall_score

      if score <= 0.0
        'None'
      elsif (0.1..3.9).cover? score
        'Low'
      elsif (4.0..6.9).cover? score
        'Medium'
      elsif (7.0..8.9).cover? score
        'High'
      elsif (9.0..10.0).cover? score
        'Critical'
      else
        'None'
      end
    end

    ##
    # Returns the vector itself.
    def vector
      @vector.to_s
    end

    private

    def extract_metrics
      properties = @vector.split('/')
      @amount_of_properties = properties.size
      properties.each_with_index do |property, index|
        property = property.split(':')
        @properties.push({ name: property[0], selected: property[1], position: index })
      end
      @properties = [] if @properties.group_by { |p| p[:name] }.select { |_k, v| v.size > 1 }.length.positive?
    end

    def check_validity
      raise CvssSuite::Errors::InvalidVector, 'Vector is not valid!' unless valid?
    end

    def required_amount_of_properties
      total = @base.count
      total || 0
    end
  end
end
