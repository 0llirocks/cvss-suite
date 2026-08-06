# frozen_string_literal: true

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
    # Creates a new invalid CVSS vector, remembering the +vector+ that was
    # rejected so the error it raises can name it. Cannot call super: that
    # parses the vector, which is the thing that already failed.
    #
    # Deliberately not stored as @vector: #vector reads that through to_s, and
    # .new accepts any object, so an object with a hostile to_s would turn a
    # total reader into one that raises.
    def initialize(vector = nil)
      @rejected = vector
    end
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

    ##
    # Since this is an invalid CVSS vector, it always throws an exception.
    def overall_score
      check_validity
    end

    private

    # The raw input. .new accepts anything, so nil has to read as nil and 1337
    # as 1337 rather than both arriving in the message as an empty string.
    def rejected_vector
      @rejected
    end
  end
end
