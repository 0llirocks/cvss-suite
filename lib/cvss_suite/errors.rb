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
      end
    end

    class InvalidVector < CvssError; end
    class InvalidParentClass < CvssError; end
  end
end
