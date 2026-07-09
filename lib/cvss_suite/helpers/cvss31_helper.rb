# frozen_string_literal: true

# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

module CvssSuite
  ##
  # This module includes methods which are used by the CVSS 3 classes.
  module Cvss31Helper
    ##
    # Since CVSS 3 all float values are rounded up, therefore this method is used
    # instead of the mathematically correct method round().
    # This is the exact Roundup from CVSS v3.1 Appendix A, which works on integer
    # arithmetic (x100000) to avoid the floating-point edge cases that plain
    # ceil(1) hits -- the reason v3.1 replaced v3.0's rounding.
    # https://www.first.org/cvss/v3.1/specification-document
    def self.round_up(float)
      output = (float * 100_000).round
      if (output % 10_000).zero?
        output / 100_000.0
      else
        ((output / 10_000).floor + 1) / 10.0
      end
    end
  end
end
