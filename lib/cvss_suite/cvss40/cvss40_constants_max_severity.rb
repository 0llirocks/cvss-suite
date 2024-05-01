module CvssSuite
  module Cvss40Constants
    # These constants were almost directly ported from the CVSS 4.0 calculator code found at https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/ac71416d935ad2ac87cd107ff87024561ea954a7/max_severity.js#L1
    MAX_SEVERITY = {
      'eq1' => {
        0 => 1,
        1 => 4,
        2 => 5
      },
      'eq2' => {
        0 => 1,
        1 => 2
      },
      'eq3eq6' => {
        0 => { 0 => 7, 1 => 6 },
        1 => { 0 => 8, 1 => 8 },
        2 => { 1 => 10 }
      },
      'eq4' => {
        0 => 6,
        1 => 5,
        2 => 4
      },
      'eq5' => {
        0 => 1,
        1 => 1,
        2 => 1
      }
    }.freeze
  end
end
