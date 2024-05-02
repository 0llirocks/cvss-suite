module CvssSuite
  module Cvss40Constants
    # These constants were almost directly ported from the CVSS 4.0 calculator code found at https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/ac71416d935ad2ac87cd107ff87024561ea954a7/app.js#L278C17-L278C18

    AV_LEVELS = { 'N' => 0.0, 'A' => 0.1, 'L' => 0.2, 'P' => 0.3 }.freeze
    PR_LEVELS = { 'N' => 0.0, 'L' => 0.1, 'H' => 0.2 }.freeze
    UI_LEVELS = { 'N' => 0.0, 'P' => 0.1, 'A' => 0.2 }.freeze

    AC_LEVELS = { 'L' => 0.0, 'H' => 0.1 }.freeze
    AT_LEVELS = { 'N' => 0.0, 'P' => 0.1 }.freeze

    VC_LEVELS = { 'H' => 0.0, 'L' => 0.1, 'N' => 0.2 }.freeze
    VI_LEVELS = { 'H' => 0.0, 'L' => 0.1, 'N' => 0.2 }.freeze
    VA_LEVELS = { 'H' => 0.0, 'L' => 0.1, 'N' => 0.2 }.freeze

    SC_LEVELS = { 'H' => 0.1, 'L' => 0.2, 'N' => 0.3 }.freeze
    SI_LEVELS = { 'S' => 0.0, 'H' => 0.1, 'L' => 0.2, 'N' => 0.3 }.freeze
    SA_LEVELS = { 'S' => 0.0, 'H' => 0.1, 'L' => 0.2, 'N' => 0.3 }.freeze

    CR_LEVELS = { 'H' => 0.0, 'M' => 0.1, 'L' => 0.2 }.freeze
    IR_LEVELS = { 'H' => 0.0, 'M' => 0.1, 'L' => 0.2 }.freeze
    AR_LEVELS = { 'H' => 0.0, 'M' => 0.1, 'L' => 0.2 }.freeze

    E_LEVELS = { 'U' => 0.2, 'P' => 0.1, 'A' => 0 }.freeze
  end
end
