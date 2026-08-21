# frozen_string_literal: true

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
    # Creates a new CVSS vector by a +vector+. CvssSuite.new also passes the
    # +original+ string it was handed, because +vector+ reaches here with the
    # CVSS:x.x/ prefix or the CVSS 2 parentheses already stripped, and an error
    # has to name the vector the caller actually wrote.
    #
    # Raises an exception if it is called on Cvss class.
    def initialize(vector, original = vector)
      raise CvssSuite::Errors::InvalidParentClass, 'Do not instantiate this class!' if instance_of? Cvss

      @vector = vector
      @original = original
      @properties = []
      extract_metrics
      init_metrics
    end

    ##
    # Returns the severity of the CVSS vector.
    def severity
      check_validity

      score = overall_score

      # The explicit `<= 0.0` branch and the defensive `else` both yield 'None' by
      # design (zero score vs. out-of-range guard); kept distinct for readability.
      # rubocop:disable Lint/DuplicateBranch
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
      # rubocop:enable Lint/DuplicateBranch
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
      raise CvssSuite::Errors::InvalidVector.for(rejected_vector) unless valid?
    end

    # What the caller passed, not the normalized form. #vector would be the
    # tempting source, but it is lossy: Cvss2 does not restore the parentheses
    # that prepare_cvss2_vector strips, so a rejected '(AV:N/AC:L)' would be
    # reported as 'AV:N/AC:L', and a paren form it cannot parse at all as ''.
    def rejected_vector
      @original
    end

    def required_amount_of_properties
      total = @base.count
      total || 0
    end
  end
end
