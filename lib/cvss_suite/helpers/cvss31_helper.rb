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
