# frozen_string_literal: true

# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

module CvssSuite
  ##
  # Included by every error this gem raises, so one rescue catches them all:
  #
  #   rescue CvssSuite::Error => e
  #
  # A module rather than a base class, so the concrete errors keep the ancestors
  # callers already rescue: InvalidVector stays a RuntimeError, and the argument
  # errors stay ArgumentErrors. f7e9866 moved them off a shared base class in
  # 2018 for exactly that compatibility, and this does not take it back.
  module Error; end

  ##
  # The concrete errors this gem raises. Each one includes Error above.
  module Errors
    ##
    # Raised for a vector this gem cannot parse, and by every score reader on a
    # vector +valid?+ has rejected.
    class InvalidVector < RuntimeError
      include Error

      # Caps the vector echoed back, so arbitrary input cannot push arbitrary
      # length into an exception message and from there into a log. It caps
      # what is echoed, not the message: escaping expands it, and 200 NUL bytes
      # inspect to roughly 1.2 KB. Bounded either way, just not at 200.
      #
      # A CVSS 4.0 vector carrying every metric the specification defines, each
      # at its longest option, is 178 characters, so a real vector is always
      # repeated back whole.
      MAX_REPORTED_LENGTH = 200

      UNINSPECTABLE = '(an object that could not be inspected)'
      private_constant :MAX_REPORTED_LENGTH, :UNINSPECTABLE

      ##
      # Builds the error for the +vector+ that was rejected, naming it in the
      # message. Takes the raw input rather than a string, so a caller who
      # passed nil or an Integer is told that, instead of being shown '""'.
      def self.for(vector)
        new("Vector is not valid: #{describe(vector)}")
      end

      # Strings are trimmed before inspect, not after, so the escaping is never
      # cut mid-sequence and the closing quote survives -- and a huge input is
      # not escaped in full only to be thrown away.
      #
      # CvssSuite.new accepts any object, so #inspect here runs on something the
      # gem never validated. A broken one must not become the exception raised
      # in place of the one it was helping to describe.
      def self.describe(vector)
        return trim(vector).inspect if vector.is_a?(String)

        described = vector.inspect
        # Tested for String rather than trimmed blind: Array and Hash answer
        # #length and #[] too, so duck-typing here would let an #inspect that
        # returns a collection walk straight past MAX_REPORTED_LENGTH.
        described.is_a?(String) ? trim(described) : UNINSPECTABLE
        # SystemStackError is not a StandardError, and a self-recursive #inspect
        # raises exactly that.
      rescue StandardError, SystemStackError
        UNINSPECTABLE
      end

      def self.trim(text)
        return text if text.length <= MAX_REPORTED_LENGTH

        "#{text[0, MAX_REPORTED_LENGTH]}..."
      end
      private_class_method :describe, :trim
    end

    ##
    # Raised when an abstract class is instantiated directly.
    class InvalidParentClass < ArgumentError
      include Error
    end

    ##
    # Raised for a CVSS version this gem does not implement.
    class UnsupportedVersion < ArgumentError
      include Error
    end
  end
end
