require_relative 'cvss40_constants_macro_vector_lookup'
require_relative 'cvss40_constants_max_composed'
require_relative 'cvss40_constants_max_severity'
require_relative 'cvss40_constants_levels'

module CvssSuite
  # This class performs much of the score calculation logic for CVSS 4.0.
  # It is heavily ported from the m and scoring methods in https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/ac71416d935ad2ac87cd107ff87024561ea954a7/app.js#L121
  # This class has a few rubocop exclusions but maintaining parity with the ported
  #  code seems more valuable than trying to follow the cops in this case.
  class Cvss40CalcHelper
    include Cvss40Constants

    def initialize(cvss_property_bag)
      @cvss_property_bag = cvss_property_bag
    end

    def m(metric)
      selected = @cvss_property_bag[metric]

      # If E=X it will default to the worst case i.e. E=A
      return 'A' if metric == 'E' && (selected == 'X' || selected.nil?)
      # If CR=X, IR=X or AR=X they will default to the worst case i.e. CR=H, IR=H and AR=H
      return 'H' if metric == 'CR' && (selected == 'X' || selected.nil?)
      # IR:X is the same as IR:H
      return 'H' if metric == 'IR' && (selected == 'X' || selected.nil?)
      # AR:X is the same as AR:H
      return 'H' if metric == 'AR' && (selected == 'X' || selected.nil?)

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

      eq5 = case m('E')
            when 'A'
              '0'
            when 'P'
              '1'
            when 'U'
              '2'
            else
              # brphelps TODO added figure it out
              '0'
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

    def score
      # The following defines the index of each metric's values.
      # It is used when looking for the highest vector part of the
      # combinations produced by the MacroVector respective highest vectors.

      macro_vector = retrieve_macro_vector

      # Exception for no impact on system (shortcut)
      return 0.0 if %w[VC VI VA SC SI SA].all? { |metric| m(metric) == 'N' }

      value = LOOKUP[macro_vector]

      # 1. For each of the EQs:
      #   a. The maximal scoring difference is determined as the difference
      #      between the current MacroVector and the lower MacroVector.
      #     i. If there is no lower MacroVector the available distance is
      #        set to nil and then ignored in the further calculations.
      eq1_val = parse_int(macro_vector[0])
      eq2_val = parse_int(macro_vector[1])
      eq3_val = parse_int(macro_vector[2])
      eq4_val = parse_int(macro_vector[3])
      eq5_val = parse_int(macro_vector[4])
      eq6_val = parse_int(macro_vector[5])

      # compute next lower macro, it can also not exist
      eq1_next_lower_macro = concat_and_stringify(eq1_val + 1, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val)
      eq2_next_lower_macro = concat_and_stringify(eq1_val, eq2_val + 1, eq3_val, eq4_val, eq5_val, eq6_val)

      # eq3 and eq6 are related
      if eq3_val == 1 && eq6_val == 1
        # 11 --> 21
        eq3eq6_next_lower_macro = concat_and_stringify(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val)
      elsif eq3_val.zero? && eq6_val == 1
        # 01 --> 11
        eq3eq6_next_lower_macro = concat_and_stringify(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val)
      elsif eq3_val == 1 && eq6_val.zero?
        # 10 --> 11
        eq3eq6_next_lower_macro = concat_and_stringify(eq1_val, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val + 1)
      elsif eq3_val.zero? && eq6_val.zero?
        # 00 --> 01
        # 00 --> 10
        eq3eq6_next_lower_macro_left = concat_and_stringify(eq1_val, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val + 1)
        eq3eq6_next_lower_macro_right = concat_and_stringify(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val)
      else
        # 21 --> 32 (do not exist)
        eq3eq6_next_lower_macro = concat_and_stringify(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val + 1)
      end

      eq4_next_lower_macro = concat_and_stringify(eq1_val, eq2_val, eq3_val, eq4_val + 1, eq5_val, eq6_val)
      eq5_next_lower_macro = concat_and_stringify(eq1_val, eq2_val, eq3_val, eq4_val, eq5_val + 1, eq6_val)

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
      severity_distance_si = severity_distance_sa = severity_distance_cr = 0
      severity_distance_ir = severity_distance_ar = 0

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

        severity_distance_cr = subtract_or_nil(CR_LEVELS[m('CR')], CR_LEVELS[extract_value_metric('CR', max_vector)])
        severity_distance_ir = subtract_or_nil(IR_LEVELS[m('IR')], IR_LEVELS[extract_value_metric('IR', max_vector)])
        severity_distance_ar = subtract_or_nil(AR_LEVELS[m('AR')], AR_LEVELS[extract_value_metric('AR', max_vector)])

        # if any is less than zero this is not the right max
        if [severity_distance_av, severity_distance_pr, severity_distance_ui, severity_distance_ac,
            severity_distance_at, severity_distance_vc, severity_distance_vi, severity_distance_va,
            severity_distance_sc, severity_distance_si, severity_distance_sa,
            severity_distance_cr,
            severity_distance_ir, severity_distance_ar].compact.any?(&:negative?)
          next
        end

        # if multiple maxes exist to reach it it is enough the first one
        break
      end

      current_severity_distance_eq1 = severity_distance_av + severity_distance_pr + severity_distance_ui
      current_severity_distance_eq2 = severity_distance_ac + severity_distance_at
      current_severity_distance_eq3eq6 = sum_or_nil([severity_distance_vc, severity_distance_vi, severity_distance_va,
                                                     severity_distance_cr, severity_distance_ir, severity_distance_ar])
      current_severity_distance_eq4 = severity_distance_sc + severity_distance_si + severity_distance_sa

      step = 0.1

      # if the next lower macro score do not exist the result is Nan
      # Rename to maximal scoring difference (aka MSD)
      available_distance_eq1 = score_eq1_next_lower_macro ? value - score_eq1_next_lower_macro : nil
      available_distance_eq2 = score_eq2_next_lower_macro ? value - score_eq2_next_lower_macro : nil
      available_distance_eq3eq6 = score_eq3eq6_next_lower_macro ? value - score_eq3eq6_next_lower_macro : nil
      available_distance_eq4 = score_eq4_next_lower_macro ? value - score_eq4_next_lower_macro : nil
      available_distance_eq5 = score_eq5_next_lower_macro ? value - score_eq5_next_lower_macro : nil

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
      unless nil?(available_distance_eq1)
        n_existing_lower += 1
        percent_to_next_eq1_severity = current_severity_distance_eq1 / max_severity_eq1
        normalized_severity_eq1 = available_distance_eq1 * percent_to_next_eq1_severity
      end

      unless nil?(available_distance_eq2)
        n_existing_lower += 1
        percent_to_next_eq2_severity = current_severity_distance_eq2 / max_severity_eq2
        normalized_severity_eq2 = available_distance_eq2 * percent_to_next_eq2_severity
      end

      unless nil?(available_distance_eq3eq6)
        n_existing_lower += 1
        percent_to_next_eq3eq6_severity = current_severity_distance_eq3eq6 / max_severity_eq3eq6
        normalized_severity_eq3eq6 = available_distance_eq3eq6 * percent_to_next_eq3eq6_severity
      end

      unless nil?(available_distance_eq4)
        n_existing_lower += 1
        percent_to_next_eq4_severity = current_severity_distance_eq4 / max_severity_eq4
        normalized_severity_eq4 = available_distance_eq4 * percent_to_next_eq4_severity
      end

      unless nil?(available_distance_eq5)
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
      value.round(1)
    end

    def get_eq_maxes(lookup, eq_value)
      MAX_COMPOSED["eq#{eq_value}"][lookup[eq_value - 1]]
    end

    def nil?(value)
      value.nil?
    end

    def concat_and_stringify(first, second, third, fourth, fifth, sixth)
      String.new.concat(first.to_s, second.to_s, third.to_s, fourth.to_s, fifth.to_s, sixth.to_s)
    end

    def sum_or_nil(values)
      return nil if values.any?(&:nil?)

      values.sum
    end

    def subtract_or_nil(left, right)
      return nil if left.nil? || right.nil?

      left - right
    end

    def parse_int(string_to_parse)
      Integer(string_to_parse)
    end

    def extract_value_metric(metric, str)
      # indexOf gives first index of the metric, we then need to go over its size
      index = str.index(metric) + metric.length + 1
      extracted = str.slice(index..)
      # remove what follow
      if extracted.index('/').positive?
        index_to_drop_after = extracted.index('/') - 1
        metric_val = truncate(extracted, index_to_drop_after)
      elsif extracted
        metric_val = extracted
        # case where it is the last metric so no ending /
      end

      metric_val
    end

    # rails defines this method on String, so we need to avoid polluting the
    #  String class to preserve Rails behavior.
    def truncate(string_to_truncate, truncate_to)
      return string_to_truncate.dup unless string_to_truncate.length > truncate_to

      (string_to_truncate[0, truncate_to + 1]).to_s
    end
  end
end
