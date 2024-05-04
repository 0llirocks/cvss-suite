# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

module CvssSuite
  ##
  # This class represents a invalid CVSS vector.
  class InvalidCvss < Cvss
    # rubocop:disable Lint/MissingSuper
    ##
    # Creates a new invalid CVSS vector.
    def initialize; end
    # rubocop:enable Lint/MissingSuper

    ##
    # Since this is an invalid CVSS vector, it always returns false.
    def valid?
      false
    end

    ##
    # Since this is an invalid CVSS vector, it always throws an exception.
    def version
      check_validity
    end

    ##
    # Since this is an invalid CVSS vector, it always throws an exception.
    def base_score
      check_validity
    end

    ##
    # Since this is an invalid CVSS vector, it always throws an exception.
    def temporal_score
      check_validity
    end

    ##
    # Since this is an invalid CVSS vector, it always throws an exception.
    def environmental_score
      check_validity
    end
  end
end
