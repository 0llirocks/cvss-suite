# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) 2019-2022 Siemens AG
# Copyright (c) 2022-2023 0llirocks
#
# Authors:
#   0llirocks <http://0lli.rocks>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss_property'
require_relative '../cvss_metric'

module CvssSuite
  ##
  # This class represents a CVSS Temporal metric in version 4.0.
  class Cvss40Threat < CvssMetric
    ##
    # Property of this metric
    attr_reader :exploit_maturity

    ##
    # Returns score of this metric
    def score
      return 1.0 unless valid?

      @exploit_code_maturity.score * @remediation_level.score * @report_confidence.score
    end

    private

    def init_properties
      @properties.push(@exploit_maturity =
                         CvssProperty.new(name: 'Exploit Maturity', abbreviation: 'E',
                                          values: [{ name: 'Not Defined', abbreviation: 'X', default: true },
                                                   { name: 'Attacked', abbreviation: 'A', default: false },
                                                   { name: 'Proof-of-Concept', abbreviation: 'P', default: false },
                                                   { name: 'Unreported', abbreviation: 'U', default: false }]))
    end
  end
end