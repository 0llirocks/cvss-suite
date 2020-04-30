# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) Siemens AG, 2016
#
# Authors:
#   Oliver Hambörger <oliver.hamboerger@siemens.com>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

##
# This class represents any CVSS vector. Do not instantiate this class!

class Cvss

  ##
  # Metric of a CVSS vector.

  attr_reader :base, :temporal, :environmental

  ##
  # Returns version of current CVSS vector.

  attr_reader :version

  ##
  # Returns the vector itself.

  attr_reader :vector

  ##
  # Creates a new CVSS vector by a +vector+ and a +version+.
  #
  # Raises an exception if it is called on Cvss class.

  def initialize(vector, version)
    raise CvssSuite::Errors::InvalidParentClass, 'Do not instantiate this class!' if self.class == Cvss
    @version = version
    @vector = vector
    @properties = []
    extract_metrics
    init_metrics
  end

  ##
  # Returns if CVSS vector is valid.

  def valid?
    if @amount_of_properties == required_amount_of_properties
      base = @base.valid?
      temporal = @base.valid? && @temporal.valid?
      environmental = @base.valid? && @environmental.valid?
      full = @base.valid? && @temporal.valid? && @environmental.valid?
      base || temporal || environmental || full
    else
      false
    end
  end

  ##
  # Returns the severity of the CVSS vector.

  def severity
    check_validity

    score = overall_score

    if 0.0 == score
      "None"
    elsif (0.1..3.9).include? score
      "Low"
    elsif (4.0..6.9).include? score
      "Medium"
    elsif (7.0..8.9).include? score
      "High"
    elsif (9.0..10.0).include? score
      "Critical"
    else
      "None"
    end
  end

  ##
  # Returns the Overall Score of the CVSS vector.

  def overall_score
    check_validity
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
      @properties.push({ name: property[0], selected: property[1], position: index })
    end
  end

  def check_validity
    raise CvssSuite::Errors::InvalidVector, 'Vector is not valid!' unless valid?
  end

  def prepared_vector
    start_of_vector = @vector.index('AV')

    if start_of_vector.nil?
      String.new
    else
      @vector[start_of_vector..-1]
    end
  end

  def required_amount_of_properties
    total = @base.count if @base.valid?
    total += @temporal.count if @temporal.valid?
    total += @environmental.count if @environmental.valid?
    total ||= 0
  end

end
