# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

module CvssSuite
  ##
  # This module includes methods which are used by the CVSS 3 classes.
  module Cvss3Helper
    ##
    # Since CVSS 3 all float values are rounded up, therefore this method is used
    # instead of the mathematically correct method round().
    def self.round_up(float)
      float.ceil(1).to_f
    end

    ##
    # Since CVSS 3 the Privilege Required score depends on the selected value of the Scope metric.
    # This method takes a +Privilege+ +Required+ and a +Scope+ metric and returns the newly calculated score.
    def self.privileges_required_score(privileges_required, scope)
      changed = scope.selected_value[:name] == 'Changed'
      privilege_score = privileges_required.score
      if changed
        privilege_score = 0.68 if privileges_required.selected_value[:name] == 'Low'
        privilege_score = 0.50 if privileges_required.selected_value[:name] == 'High'
      end
      privilege_score
    end
  end
end
