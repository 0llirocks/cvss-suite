# frozen_string_literal: true

# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require 'cvss_suite/cvss2/cvss2'
require 'cvss_suite/cvss3/cvss3'
require 'cvss_suite/cvss31/cvss31'
require 'cvss_suite/cvss40/cvss40'
require 'cvss_suite/version'
require 'cvss_suite/errors'
require 'cvss_suite/invalid_cvss'

##
# Module of this gem.
module CvssSuite
  CVSS_VECTOR_BEGINNINGS = [
    { string: 'AV:', version: 2 },
    { string: '(AV:', version: 2 },
    { string: 'CVSS:3.0/', version: 3.0 },
    { string: 'CVSS:3.1/', version: 3.1 },
    { string: 'CVSS:4.0/', version: 4.0 }
  ].freeze

  # The metric groups that make up each CVSS version, in vector order. Keyed by
  # the same version values as CVSS_VECTOR_BEGINNINGS and Cvss#version, so
  # CvssSuite.metrics(instance.version) works for every version.
  METRIC_GROUPS = {
    2 => [['Base', Cvss2Base], ['Temporal', Cvss2Temporal], ['Environmental', Cvss2Environmental]],
    3.0 => [['Base', Cvss3Base], ['Temporal', Cvss3Temporal], ['Environmental', Cvss3Environmental]],
    3.1 => [['Base', Cvss31Base], ['Temporal', Cvss31Temporal], ['Environmental', Cvss31Environmental]],
    4.0 => [['Base', Cvss40Base], ['Threat', Cvss40Threat], ['Environmental', Cvss40Environmental],
            ['Environmental Security Requirements', Cvss40EnvironmentalSecurity], ['Supplemental', Cvss40Supplemental]]
  }.freeze

  # Accepted version identifiers mapped to their canonical METRIC_GROUPS key, so
  # both the canonical value (2, 3.0, ...) and the human-friendly string
  # ('2', '2.0', '3.1', ...) resolve to the same schema.
  VERSION_ALIASES = {
    2 => 2, 2.0 => 2, '2' => 2, '2.0' => 2,
    3.0 => 3.0, '3.0' => 3.0,
    3.1 => 3.1, '3.1' => 3.1,
    4.0 => 4.0, '4.0' => 4.0
  }.freeze

  ##
  # Returns a CVSS class by a +vector+.
  def self.new(vector)
    return InvalidCvss.new unless vector.is_a? String

    @vector_string = if vector.frozen?
                       vector.dup
                     else
                       vector
                     end

    # version is a discrete value parsed from the vector and matched against exact
    # literals, not the result of float arithmetic, so these comparisons are reliable.
    # rubocop:disable Lint/FloatComparison
    case version
    when 2
      Cvss2.new(prepare_vector(@vector_string))
    when 3.0
      Cvss3.new(prepare_vector(@vector_string))
    when 3.1
      Cvss31.new(prepare_vector(@vector_string))
    when 4.0
      Cvss40.new(prepare_vector(@vector_string))
    else
      InvalidCvss.new
    end
    # rubocop:enable Lint/FloatComparison
  end

  ##
  # Returns a CVSS class by a +vector+, raising CvssSuite::Errors::InvalidVector
  # if the vector cannot be parsed.
  #
  # Prefer this over .new when a bad vector is a bug rather than an expected
  # input: .new answers with an InvalidCvss sentinel that only reports the
  # problem once a score is asked for, so a caller who forgets +valid?+ carries a
  # broken vector until something far from the parse blows up.
  def self.parse(vector)
    cvss = new(vector)
    raise Errors::InvalidVector, 'Vector is not valid!' unless cvss.valid?

    cvss
  end

  ##
  # Returns the static schema of metrics and their options for a CVSS +version+
  # (2, 3.0, 3.1 or 4.0; the equivalent strings are accepted too) without
  # constructing a vector. Each metric lists its options with the +default+
  # option flagged, so a caller can build input forms directly. Closes #8.
  def self.metrics(version)
    groups = METRIC_GROUPS[VERSION_ALIASES[version]]
    raise Errors::UnsupportedVersion, "Unsupported CVSS version: #{version.inspect}" if groups.nil?

    groups.map { |label, metric_class| { group: label, metrics: metric_schema(metric_class) } }
  end

  def self.metric_schema(metric_class)
    metric_class.new([]).properties.map do |property|
      options = property.values.map do |value|
        { name: value[:name], abbreviation: value[:abbreviation], default: value.fetch(:selected, false) }
      end
      { name: property.name, abbreviation: property.abbreviation, options: options }
    end
  end
  private_class_method :metric_schema

  def self.version
    CVSS_VECTOR_BEGINNINGS.each do |beginning|
      return beginning[:version] if @vector_string.start_with? beginning[:string]
    end
  end

  def self.prepare_vector(vector)
    vector = vector.clone

    return prepare_cvss2_vector(vector) if version == 2

    version_string = CVSS_VECTOR_BEGINNINGS.detect { |v| v[:version] == version }[:string]
    start_of_vector = vector.index(version_string)

    if start_of_vector.nil?
      ''
    else
      vector[version_string.length..]
    end
  end

  def self.prepare_cvss2_vector(vector)
    start_of_vector = vector.index('AV')

    if start_of_vector.nil?
      ''
    elsif start_of_vector == 1
      match_array = vector.scan(/\((?>[^)(]+|\g<0>)*\)/)
      if match_array.length == 1 && match_array[0] == vector
        vector.slice!(0)
        vector.slice!(vector.length - 1)
        vector
      else
        ''
      end
    else
      vector[start_of_vector..]
    end
  end

  # Parsing internals. They read module state set by .new, so calling them
  # directly was never meaningful; they were public only because .new needs them.
  private_class_method :version, :prepare_vector, :prepare_cvss2_vector
end
