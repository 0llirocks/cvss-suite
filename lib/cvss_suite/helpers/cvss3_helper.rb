# © Siemens AG, 2016

##
# This module includes methods which are used by the CVSS 3 classes.

module Cvss3Helper

  ##
  # Since CVSS 3 the Privilege Required score depends on the selected choice of the Scope metric.
  # This method takes a +Privilege+ +Required+ and a +Scope+ metric and returns the newly calculated score.

  def self.privileges_required_score(privileges_required, scope)
    changed =  scope.selected_choice[:name] == 'Changed'
    privilege_score = privileges_required.score
    if changed
      privilege_score = 0.68 if privileges_required.selected_choice[:name] == 'Low'
      privilege_score = 0.50 if privileges_required.selected_choice[:name] == 'High'
    end
    privilege_score
  end
end