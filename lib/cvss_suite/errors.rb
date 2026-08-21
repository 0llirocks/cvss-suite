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
    class InvalidVector < RuntimeError
      include Error
    end

    class InvalidParentClass < ArgumentError
      include Error
    end

    class UnsupportedVersion < ArgumentError
      include Error
    end
  end
end
