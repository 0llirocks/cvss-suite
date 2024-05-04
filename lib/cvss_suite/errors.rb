# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

module CvssSuite
  ##
  # This will define classed errors to be expected
  module Errors
    ##
    # The base error class to be inherited by more specific classes
    class CvssError < StandardError
      attr_accessor :message

      def initialize(message)
        @message = message
        super
      end
    end

    class InvalidVector < RuntimeError; end

    class InvalidParentClass < ArgumentError; end
  end
end
