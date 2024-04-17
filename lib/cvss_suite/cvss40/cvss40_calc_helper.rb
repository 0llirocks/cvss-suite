module CvssSuite
  class Cvss40CalcHelper
    def initialize(cvss_property_bag)
      @cvss_property_bag = cvss_property_bag
    end

    def m(metric)
      selected = @cvss_property_bag[metric]

      # If E=X it will default to the worst case i.e. E=A
      return 'A' if metric == 'E' && selected == 'X'
      # If CR=X, IR=X or AR=X they will default to the worst case i.e. CR=H, IR=H and AR=H
      return 'H' if metric == 'CR' && selected == 'X'
      # IR:X is the same as IR:H
      return 'H' if metric == 'IR' && selected == 'X'
      # AR:X is the same as AR:H
      return 'H' if metric == 'AR' && selected == 'X'

      # All other environmental metrics just overwrite base score values,
      # so if they’re not defined just use the base score value.
      if @cvss_property_bag.include?("M#{metric}")
        modified_selected = @cvss_property_bag["M#{metric}"]
        return modified_selected if modified_selected != 'X'
      end

      selected
    end

    def retrieve_macro_vector
      # EQ1: 0-AV:N and PR:N and UI:N
      #      1-(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
      #      2-AV:P or not(AV:N or PR:N or UI:N)

      if m('AV') == 'N' && m('PR') == 'N' && m('UI') == 'N'
        eq1 = '0'
      elsif (m('AV') == 'N' || m('PR') == 'N' || m('UI') == 'N') &&
            !(m('AV') == 'N' && m('PR') == 'N' && m('UI') == 'N') &&
            (m('AV') != 'P')
        eq1 = '1'
      elsif m('AV') == 'P' ||
            !(m('AV') == 'N' ||
            m('PR') == 'N' ||
            m('UI') == 'N')
        eq1 = '2'
      end

      # EQ2: 0-(AC:L and AT:N)
      #      1-(not(AC:L and AT:N))

      if m('AC') == 'L' && m('AT') == 'N'
        eq2 = '0'
      elsif !(m('AC') == 'L' && m('AT') == 'N')
        eq2 = '1'
      end

      # EQ3: 0-(VC:H and VI:H)
      #      1-(not(VC:H and VI:H) and (VC:H or VI:H or VA:H))
      #      2-not (VC:H or VI:H or VA:H)
      if m('VC') == 'H' && m('VI') == 'H'
        eq3 = '0'
      elsif !(m('VC') == 'H' && m('VI') == 'H') &&
            (m('VC') == 'H' || m('VI') == 'H' || m('VA') == 'H')
        eq3 = '1'
      elsif !(m('VC') == 'H' || m('VI') == 'H' || m('VA') == 'H')
        eq3 = '2'
      end

      # EQ4: 0-(MSI:S or MSA:S)
      #      1-not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)
      #      2-not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)

      if m('MSI') == 'S' || m('MSA') == 'S'
        eq4 = '0'
      elsif !(m('MSI') == 'S' || m('MSA') == 'S') &&
            (m('SC') == 'H' || m('SI') == 'H' || m('SA') == 'H')
        eq4 = '1'
      elsif !(m('MSI') == 'S' || m('MSA') == 'S') &&
            !(m('SC') == 'H' || m('SI') == 'H' || m('SA') == 'H')
        eq4 = '2'
      end

      # EQ5: 0-E:A
      #      1-E:P
      #      2-E:U

      if m('E') == 'A'
        eq5 = '0'
      elsif m('E') == 'P'
        eq5 = '1'
      elsif m('E') == 'U'
        eq5 = '2'
      else
        # brphelps TODO added figure it out
        eq5 = '0'
      end

      # EQ6: 0-(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
      #      1-not[(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]

      if (m('CR') == 'H' && m('VC') == 'H') ||
         (m('IR') == 'H' && m('VI') == 'H') ||
         (m('AR') == 'H' && m('VA') == 'H')
        eq6 = '0'
      elsif !((m('CR') == 'H' && m('VC') == 'H') ||
          (m('IR') == 'H' && m('VI') == 'H') ||
          (m('AR') == 'H' && m('VA') == 'H'))
        eq6 = '1'
      end

      eq1 + eq2 + eq3 + eq4 + eq5 + eq6
    end

    AV_LEVELS = { "N"=> 0.0, "A"=> 0.1, "L"=> 0.2, "P"=> 0.3 }.freeze
    PR_LEVELS = { "N"=> 0.0, "L"=> 0.1, "H"=> 0.2 }.freeze
    UI_LEVELS = { "N"=> 0.0, "P"=> 0.1, "A"=> 0.2 }.freeze

    AC_LEVELS = { 'L'=> 0.0, 'H'=> 0.1 }.freeze
    AT_LEVELS = { 'N'=> 0.0, 'P'=> 0.1 }.freeze

    VC_LEVELS = { 'H'=> 0.0, 'L'=> 0.1, 'N'=> 0.2 }.freeze
    VI_LEVELS = { 'H'=> 0.0, 'L'=> 0.1, 'N'=> 0.2 }.freeze
    VA_LEVELS = { 'H'=> 0.0, 'L'=> 0.1, 'N'=> 0.2 }.freeze

    SC_LEVELS = { 'H'=> 0.1, 'L'=> 0.2, 'N'=> 0.3 }.freeze
    SI_LEVELS = { 'S'=> 0.0, 'H'=> 0.1, 'L'=> 0.2, 'N'=> 0.3 }.freeze
    SA_LEVELS = { 'S'=> 0.0, 'H'=> 0.1, 'L'=> 0.2, 'N'=> 0.3 }.freeze

    CR_LEVELS = { 'H'=> 0.0, 'M'=> 0.1, 'L'=> 0.2 }.freeze
    IR_LEVELS = { 'H'=> 0.0, 'M'=> 0.1, 'L'=> 0.2 }.freeze
    AR_LEVELS = { 'H'=> 0.0, 'M'=> 0.1, 'L'=> 0.2 }.freeze

    E_LEVELS = { 'U'=> 0.2, 'P'=> 0.1, 'A'=> 0 }.freeze

    def score
      # The following defines the index of each metric's values.
      # It is used when looking for the highest vector part of the
      # combinations produced by the MacroVector respective highest vectors.

      macro_vector = retrieve_macro_vector

      # Exception for no impact on system (shortcut)
      return 0.0 if ['VC','VI','VA','SC','SI','SA'].all? { |metric| m(metric) == 'N'}

      value = LOOKUP[macro_vector]

      # 1. For each of the EQs:
      #   a. The maximal scoring difference is determined as the difference
      #      between the current MacroVector and the lower MacroVector.
      #     i. If there is no lower MacroVector the available distance is
      #        set to NaN and then ignored in the further calculations.
      eq1_val = parse_int(macro_vector[0])
      eq2_val = parse_int(macro_vector[1])
      eq3_val = parse_int(macro_vector[2])
      eq4_val = parse_int(macro_vector[3])
      eq5_val = parse_int(macro_vector[4])
      eq6_val = parse_int(macro_vector[5])

      # compute next lower macro, it can also not exist
      eq1_next_lower_macro = ''.concat(eq1_val + 1, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val)
      eq2_next_lower_macro = ''.concat(eq1_val, eq2_val + 1, eq3_val, eq4_val, eq5_val, eq6_val)

      # eq3 and eq6 are related
      if eq3_val == 1 && eq6_val == 1
        # 11 --> 21
        eq3eq6_next_lower_macro = ''.concat(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val)
      elsif eq3_val.zero? && eq6_val == 1
        # 01 --> 11
        eq3eq6_next_lower_macro = ''.concat(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val)
      elsif eq3_val == 1 && eq6_val.zero?
        # 10 --> 11
        eq3eq6_next_lower_macro = ''.concat(eq1_val, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val + 1)
      elsif eq3_val.zero? && eq6_val.zero?
        # 00 --> 01
        # 00 --> 10
        eq3eq6_next_lower_macro_left = ''.concat(eq1_val, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val + 1)
        eq3eq6_next_lower_macro_right = ''.concat(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val)
      else
        # 21 --> 32 (do not exist)
        eq3eq6_next_lower_macro = ''.concat(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val + 1)
      end

      eq4_next_lower_macro = ''.concat(eq1_val, eq2_val, eq3_val, eq4_val + 1, eq5_val, eq6_val)
      eq5_next_lower_macro = ''.concat(eq1_val, eq2_val, eq3_val, eq4_val, eq5_val + 1, eq6_val)

      # get their score, if the next lower macro score do not exist the result is NaN
      score_eq1_next_lower_macro = LOOKUP[eq1_next_lower_macro]
      score_eq2_next_lower_macro = LOOKUP[eq2_next_lower_macro]

      if eq3_val.zero? && eq6_val.zero?
        # multiple path take the one with higher score
        score_eq3eq6_next_lower_macro_left = LOOKUP[eq3eq6_next_lower_macro_left]
        score_eq3eq6_next_lower_macro_right = LOOKUP[eq3eq6_next_lower_macro_right]

        score_eq3eq6_next_lower_macro = if score_eq3eq6_next_lower_macro_left > score_eq3eq6_next_lower_macro_right
                                          score_eq3eq6_next_lower_macro_left
                                        else
                                          score_eq3eq6_next_lower_macro_right
                                        end
      else
        score_eq3eq6_next_lower_macro = LOOKUP[eq3eq6_next_lower_macro]
      end

      score_eq4_next_lower_macro = LOOKUP[eq4_next_lower_macro]
      score_eq5_next_lower_macro = LOOKUP[eq5_next_lower_macro]

      #   b. The severity distance of the to-be scored vector from a
      #      highest severity vector in the same MacroVector is determined.
      eq1_maxes = get_eq_maxes(macro_vector, 1)
      eq2_maxes = get_eq_maxes(macro_vector, 2)
      eq3_eq6_maxes = get_eq_maxes(macro_vector, 3)[macro_vector[5]]
      eq4_maxes = get_eq_maxes(macro_vector, 4)
      eq5_maxes = get_eq_maxes(macro_vector, 5)

      # compose them
      max_vectors = []
      eq1_maxes.each do |eq1_max|
        eq2_maxes.each do |eq2_max|
          eq3_eq6_maxes.each do |eq3_eq6_max|
            eq4_maxes.each do |eq4_max|
              eq5_maxes.each do |eq5max|
                max_vectors.push(eq1_max + eq2_max + eq3_eq6_max + eq4_max + eq5max)
              end
            end
          end
        end
      end

      severity_distance_av = severity_distance_pr = severity_distance_ui = 0
      severity_distance_ac = severity_distance_at = severity_distance_vc = 0
      severity_distance_vi = severity_distance_va = severity_distance_sc = 0
      severity_distance_si = severity_distance_sa = 0

      # Find the max vector to use i.e. one in the combination of all the highests
      # that is greater or equal (severity distance) than the to-be scored vector.
      max_vectors.each do |max_vector|
        severity_distance_av = AV_LEVELS[m('AV')] - AV_LEVELS[extract_value_metric('AV', max_vector)]
        severity_distance_pr = PR_LEVELS[m('PR')] - PR_LEVELS[extract_value_metric('PR', max_vector)]
        severity_distance_ui = UI_LEVELS[m('UI')] - UI_LEVELS[extract_value_metric('UI', max_vector)]

        severity_distance_ac = AC_LEVELS[m('AC')] - AC_LEVELS[extract_value_metric('AC', max_vector)]
        severity_distance_at = AT_LEVELS[m('AT')] - AT_LEVELS[extract_value_metric('AT', max_vector)]

        severity_distance_vc = VC_LEVELS[m('VC')] - VC_LEVELS[extract_value_metric('VC', max_vector)]
        severity_distance_vi = VI_LEVELS[m('VI')] - VI_LEVELS[extract_value_metric('VI', max_vector)]
        severity_distance_va = VA_LEVELS[m('VA')] - VA_LEVELS[extract_value_metric('VA', max_vector)]

        severity_distance_sc = SC_LEVELS[m('SC')] - SC_LEVELS[extract_value_metric('SC', max_vector)]
        severity_distance_si = SI_LEVELS[m('SI')] - SI_LEVELS[extract_value_metric('SI', max_vector)]
        severity_distance_sa = SA_LEVELS[m('SA')] - SA_LEVELS[extract_value_metric('SA', max_vector)]

        # TODO environmental? figure it out
        # severity_distance_cr = CR_LEVELS[m('CR')] - CR_LEVELS[extract_value_metric('CR', max_vector)]
        # severity_distance_ir = IR_LEVELS[m('IR')] - IR_LEVELS[extract_value_metric('IR', max_vector)]
        # severity_distance_ar = AR_LEVELS[m('AR')] - AR_LEVELS[extract_value_metric('AR', max_vector)]

        # if any is less than zero this is not the right max
        if [severity_distance_av, severity_distance_pr, severity_distance_ui, severity_distance_ac,
            severity_distance_at, severity_distance_vc, severity_distance_vi, severity_distance_va,
            severity_distance_sc, severity_distance_si, severity_distance_sa, 
            # severity_distance_cr,
            # severity_distance_ir, severity_distance_ar
        ].any? { |met| met < 0 }
          next
        end

        # if multiple maxes exist to reach it it is enough the first one
        break
      end

      current_severity_distance_eq1 = severity_distance_av + severity_distance_pr + severity_distance_ui
      current_severity_distance_eq2 = severity_distance_ac + severity_distance_at
      current_severity_distance_eq3eq6 = severity_distance_vc + severity_distance_vi + severity_distance_va # +
                                         # severity_distance_cr + severity_distance_ir + severity_distance_ar
      current_severity_distance_eq4 = severity_distance_sc + severity_distance_si + severity_distance_sa
      current_severity_distance_eq5 = 0

      step = 0.1

      # if the next lower macro score do not exist the result is Nan
      # Rename to maximal scoring difference (aka MSD)
      available_distance_eq1 = score_eq1_next_lower_macro ? value - score_eq1_next_lower_macro : nil
      available_distance_eq2 = score_eq2_next_lower_macro ? value - score_eq2_next_lower_macro : nil
      available_distance_eq3eq6 = score_eq3eq6_next_lower_macro ? value - score_eq3eq6_next_lower_macro : nil
      available_distance_eq4 = score_eq4_next_lower_macro ? value - score_eq4_next_lower_macro : nil
      available_distance_eq5 = score_eq5_next_lower_macro ? value - score_eq5_next_lower_macro : nil

      percent_to_next_eq1_severity = 0
      percent_to_next_eq2_severity = 0
      percent_to_next_eq3eq6_severity = 0
      percent_to_next_eq4_severity = 0
      percent_to_next_eq5_severity = 0

      # some of them do not exist, we will find them by retrieving the score. If score null then do not exist
      n_existing_lower = 0

      normalized_severity_eq1 = 0
      normalized_severity_eq2 = 0
      normalized_severity_eq3eq6 = 0
      normalized_severity_eq4 = 0
      normalized_severity_eq5 = 0

      # multiply by step because distance is pure
      max_severity_eq1 = MAX_SEVERITY['eq1'][eq1_val] * step
      max_severity_eq2 = MAX_SEVERITY['eq2'][eq2_val] * step
      max_severity_eq3eq6 = MAX_SEVERITY['eq3eq6'][eq3_val][eq6_val] * step
      max_severity_eq4 = MAX_SEVERITY['eq4'][eq4_val] * step

      #   c. The proportion of the distance is determined by dividing
      #      the severity distance of the to-be-scored vector by the depth
      #      of the MacroVector.
      #   d. The maximal scoring difference is multiplied by the proportion of
      #      distance.
      unless nan?(available_distance_eq1)
        n_existing_lower += 1
        percent_to_next_eq1_severity = current_severity_distance_eq1 / max_severity_eq1
        normalized_severity_eq1 = available_distance_eq1 * percent_to_next_eq1_severity
      end

      unless nan?(available_distance_eq2)
        n_existing_lower += 1
        percent_to_next_eq2_severity = current_severity_distance_eq2 / max_severity_eq2
        normalized_severity_eq2 = available_distance_eq2 * percent_to_next_eq2_severity
      end

      unless nan?(available_distance_eq3eq6)
        n_existing_lower += 1
        percent_to_next_eq3eq6_severity = current_severity_distance_eq3eq6 / max_severity_eq3eq6
        normalized_severity_eq3eq6 = available_distance_eq3eq6 * percent_to_next_eq3eq6_severity
      end

      unless nan?(available_distance_eq4)
        n_existing_lower += 1
        percent_to_next_eq4_severity = current_severity_distance_eq4 / max_severity_eq4
        normalized_severity_eq4 = available_distance_eq4 * percent_to_next_eq4_severity
      end

      unless nan?(available_distance_eq5)
        # for eq5 is always 0 the percentage
        n_existing_lower += 1
        percent_to_next_eq5_severity = 0
        normalized_severity_eq5 = available_distance_eq5 * percent_to_next_eq5_severity
      end

      # 2. The mean of the above computed proportional distances is computed.
      mean_distance = if n_existing_lower.zero?
                        0
                      else # sometimes we need to go up but there is nothing there, or down
                        # but there is nothing there so it's a change of 0.
                        (normalized_severity_eq1 + normalized_severity_eq2 + normalized_severity_eq3eq6 +
                                        normalized_severity_eq4 + normalized_severity_eq5) / n_existing_lower
                      end

      # 3. The score of the vector is the score of the MacroVector
      #    (i.e. the score of the highest severity vector) minus the mean
      #    distance so computed. This score is rounded to one decimal place.
      value -= mean_distance
      value = 0.0 if value.negative?
      value = 10.0 if value > 10
      value
    end

    def get_eq_maxes(lookup, eq_value)
      MAX_COMPOSED["eq#{eq_value}"][lookup[eq_value - 1]]
    end

    def nan?(value)
      value.nil?
    end

    LOOKUP = {
      "000000"=> 10,
      "000001"=> 9.9,
      "000010"=> 9.8,
      "000011"=> 9.5,
      "000020"=> 9.5,
      "000021"=> 9.2,
      "000100"=> 10,
      "000101"=> 9.6,
      "000110"=> 9.3,
      "000111"=> 8.7,
      "000120"=> 9.1,
      "000121"=> 8.1,
      "000200"=> 9.3,
      "000201"=> 9,
      "000210"=> 8.9,
      "000211"=> 8,
      "000220"=> 8.1,
      "000221"=> 6.8,
      "001000"=> 9.8,
      "001001"=> 9.5,
      "001010"=> 9.5,
      "001011"=> 9.2,
      "001020"=> 9,
      "001021"=> 8.4,
      "001100"=> 9.3,
      "001101"=> 9.2,
      "001110"=> 8.9,
      "001111"=> 8.1,
      "001120"=> 8.1,
      "001121"=> 6.5,
      "001200"=> 8.8,
      "001201"=> 8,
      "001210"=> 7.8,
      "001211"=> 7,
      "001220"=> 6.9,
      "001221"=> 4.8,
      "002001"=> 9.2,
      "002011"=> 8.2,
      "002021"=> 7.2,
      "002101"=> 7.9,
      "002111"=> 6.9,
      "002121"=> 5,
      "002201"=> 6.9,
      "002211"=> 5.5,
      "002221"=> 2.7,
      "010000"=> 9.9,
      "010001"=> 9.7,
      "010010"=> 9.5,
      "010011"=> 9.2,
      "010020"=> 9.2,
      "010021"=> 8.5,
      "010100"=> 9.5,
      "010101"=> 9.1,
      "010110"=> 9,
      "010111"=> 8.3,
      "010120"=> 8.4,
      "010121"=> 7.1,
      "010200"=> 9.2,
      "010201"=> 8.1,
      "010210"=> 8.2,
      "010211"=> 7.1,
      "010220"=> 7.2,
      "010221"=> 5.3,
      "011000"=> 9.5,
      "011001"=> 9.3,
      "011010"=> 9.2,
      "011011"=> 8.5,
      "011020"=> 8.5,
      "011021"=> 7.3,
      "011100"=> 9.2,
      "011101"=> 8.2,
      "011110"=> 8,
      "011111"=> 7.2,
      "011120"=> 7,
      "011121"=> 5.9,
      "011200"=> 8.4,
      "011201"=> 7,
      "011210"=> 7.1,
      "011211"=> 5.2,
      "011220"=> 5,
      "011221"=> 3,
      "012001"=> 8.6,
      "012011"=> 7.5,
      "012021"=> 5.2,
      "012101"=> 7.1,
      "012111"=> 5.2,
      "012121"=> 2.9,
      "012201"=> 6.3,
      "012211"=> 2.9,
      "012221"=> 1.7,
      "100000"=> 9.8,
      "100001"=> 9.5,
      "100010"=> 9.4,
      "100011"=> 8.7,
      "100020"=> 9.1,
      "100021"=> 8.1,
      "100100"=> 9.4,
      "100101"=> 8.9,
      "100110"=> 8.6,
      "100111"=> 7.4,
      "100120"=> 7.7,
      "100121"=> 6.4,
      "100200"=> 8.7,
      "100201"=> 7.5,
      "100210"=> 7.4,
      "100211"=> 6.3,
      "100220"=> 6.3,
      "100221"=> 4.9,
      "101000"=> 9.4,
      "101001"=> 8.9,
      "101010"=> 8.8,
      "101011"=> 7.7,
      "101020"=> 7.6,
      "101021"=> 6.7,
      "101100"=> 8.6,
      "101101"=> 7.6,
      "101110"=> 7.4,
      "101111"=> 5.8,
      "101120"=> 5.9,
      "101121"=> 5,
      "101200"=> 7.2,
      "101201"=> 5.7,
      "101210"=> 5.7,
      "101211"=> 5.2,
      "101220"=> 5.2,
      "101221"=> 2.5,
      "102001"=> 8.3,
      "102011"=> 7,
      "102021"=> 5.4,
      "102101"=> 6.5,
      "102111"=> 5.8,
      "102121"=> 2.6,
      "102201"=> 5.3,
      "102211"=> 2.1,
      "102221"=> 1.3,
      "110000"=> 9.5,
      "110001"=> 9,
      "110010"=> 8.8,
      "110011"=> 7.6,
      "110020"=> 7.6,
      "110021"=> 7,
      "110100"=> 9,
      "110101"=> 7.7,
      "110110"=> 7.5,
      "110111"=> 6.2,
      "110120"=> 6.1,
      "110121"=> 5.3,
      "110200"=> 7.7,
      "110201"=> 6.6,
      "110210"=> 6.8,
      "110211"=> 5.9,
      "110220"=> 5.2,
      "110221"=> 3,
      "111000"=> 8.9,
      "111001"=> 7.8,
      "111010"=> 7.6,
      "111011"=> 6.7,
      "111020"=> 6.2,
      "111021"=> 5.8,
      "111100"=> 7.4,
      "111101"=> 5.9,
      "111110"=> 5.7,
      "111111"=> 5.7,
      "111120"=> 4.7,
      "111121"=> 2.3,
      "111200"=> 6.1,
      "111201"=> 5.2,
      "111210"=> 5.7,
      "111211"=> 2.9,
      "111220"=> 2.4,
      "111221"=> 1.6,
      "112001"=> 7.1,
      "112011"=> 5.9,
      "112021"=> 3,
      "112101"=> 5.8,
      "112111"=> 2.6,
      "112121"=> 1.5,
      "112201"=> 2.3,
      "112211"=> 1.3,
      "112221"=> 0.6,
      "200000"=> 9.3,
      "200001"=> 8.7,
      "200010"=> 8.6,
      "200011"=> 7.2,
      "200020"=> 7.5,
      "200021"=> 5.8,
      "200100"=> 8.6,
      "200101"=> 7.4,
      "200110"=> 7.4,
      "200111"=> 6.1,
      "200120"=> 5.6,
      "200121"=> 3.4,
      "200200"=> 7,
      "200201"=> 5.4,
      "200210"=> 5.2,
      "200211"=> 4,
      "200220"=> 4,
      "200221"=> 2.2,
      "201000"=> 8.5,
      "201001"=> 7.5,
      "201010"=> 7.4,
      "201011"=> 5.5,
      "201020"=> 6.2,
      "201021"=> 5.1,
      "201100"=> 7.2,
      "201101"=> 5.7,
      "201110"=> 5.5,
      "201111"=> 4.1,
      "201120"=> 4.6,
      "201121"=> 1.9,
      "201200"=> 5.3,
      "201201"=> 3.6,
      "201210"=> 3.4,
      "201211"=> 1.9,
      "201220"=> 1.9,
      "201221"=> 0.8,
      "202001"=> 6.4,
      "202011"=> 5.1,
      "202021"=> 2,
      "202101"=> 4.7,
      "202111"=> 2.1,
      "202121"=> 1.1,
      "202201"=> 2.4,
      "202211"=> 0.9,
      "202221"=> 0.4,
      "210000"=> 8.8,
      "210001"=> 7.5,
      "210010"=> 7.3,
      "210011"=> 5.3,
      "210020"=> 6,
      "210021"=> 5,
      "210100"=> 7.3,
      "210101"=> 5.5,
      "210110"=> 5.9,
      "210111"=> 4,
      "210120"=> 4.1,
      "210121"=> 2,
      "210200"=> 5.4,
      "210201"=> 4.3,
      "210210"=> 4.5,
      "210211"=> 2.2,
      "210220"=> 2,
      "210221"=> 1.1,
      "211000"=> 7.5,
      "211001"=> 5.5,
      "211010"=> 5.8,
      "211011"=> 4.5,
      "211020"=> 4,
      "211021"=> 2.1,
      "211100"=> 6.1,
      "211101"=> 5.1,
      "211110"=> 4.8,
      "211111"=> 1.8,
      "211120"=> 2,
      "211121"=> 0.9,
      "211200"=> 4.6,
      "211201"=> 1.8,
      "211210"=> 1.7,
      "211211"=> 0.7,
      "211220"=> 0.8,
      "211221"=> 0.2,
      "212001"=> 5.3,
      "212011"=> 2.4,
      "212021"=> 1.4,
      "212101"=> 2.4,
      "212111"=> 1.2,
      "212121"=> 0.5,
      "212201"=> 1,
      "212211"=> 0.3,
      "212221"=> 0.1
    }.freeze

    def parse_int(string_to_parse)
      Integer(string_to_parse)
    end

    MAX_COMPOSED = {
      # // EQ1
      "eq1"=> {
        "0" => ['AV:N/PR:N/UI:N/'],
        "1" => ['AV:A/PR:N/UI:N/', 'AV:N/PR:L/UI:N/', 'AV:N/PR:N/UI:P/'],
        "2" => ['AV:P/PR:N/UI:N/', 'AV:A/PR:L/UI:P/']
      },
      # // EQ2
      "eq2"=> {
        "0" => ['AC:L/AT:N/'],
        "1" => ['AC:H/AT:N/', 'AC:L/AT:P/']
      },
      # // EQ3+EQ6
      "eq3"=> {
        "0" => { "0"=> ['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'],
               "1"=> ['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/'] },
        "1" => { "0"=> ['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/'],
               "1"=> ['VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/', 'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/',
                     'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/', 'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/',
                     'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/'] },
        "2" => { "1"=> ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/'] }
      },
      # // EQ4
      "eq4"=> {
        "0" => ['SC:H/SI:S/SA:S/'],
        "1" => ['SC:H/SI:H/SA:H/'],
        "2" => ['SC:L/SI:L/SA:L/']
      },
      # // EQ5
      "eq5"=> {
        "0" => ['E:A/'],
        "1" => ['E:P/'],
        "2" => ['E:U/']
      }
    }.freeze

    def extract_value_metric(metric, str)
      # indexOf gives first index of the metric, we then need to go over its size
      index = str.index(metric) + metric.length + 1
      extracted = str.slice(index..)
      # remove what follow
      if extracted.index('/').positive?
        metric_val = extracted[..(extracted.index('/') - 1)]
      elsif extracted
        metric_val = extracted
        # case where it is the last metric so no ending /
      end

      metric_val
    end

    MAX_SEVERITY = {
      "eq1"=> {
        0 => 1,
        1 => 4,
        2 => 5
      },
      "eq2"=> {
        0 => 1,
        1 => 2
      },
      "eq3eq6"=> {
        0 => { 0 => 7, 1 => 6 },
        1 => { 0 => 8, 1 => 8 },
        2 => { 1 => 10 }
      },
      "eq4"=> {
        0 => 6,
        1 => 5,
        2 => 4
      },
      "eq5"=> {
        0 => 1,
        1 => 1,
        2 => 1
      }
    }.freeze
  end
end
