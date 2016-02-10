
module Cvss3Helper
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