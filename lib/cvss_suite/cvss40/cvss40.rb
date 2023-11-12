# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) 2019-2022 Siemens AG
# Copyright (c) 2022-2023 0llirocks
#
# Authors:
#   0llirocks <http://0lli.rocks>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

require_relative '../cvss'
require_relative 'cvss40_base'
require_relative 'cvss40_threat'
require_relative 'cvss40_environmental'
require_relative 'cvss40_supplemental'

# rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/ClassLength, Metrics/AbcSize

module CvssSuite
  ##
  # This class represents a CVSS vector in version 4.0.
  class Cvss40 < Cvss
    ##
    # Returns the Version of the CVSS vector.

    def version
      4.0
    end

    ##
    # Returns the Base Score of the CVSS vector (aka CVSS-B).

    def base_score
      check_validity
      calculate_score(@base.properties)
    end

    ##
    # Returns the Threat Score of the CVSS vector (aka CVSS-BT).

    def temporal_score
      threat_score
    end

    ##
    # Returns the Threat Score of the CVSS vector (aka CVSS-BT).

    def threat_score
      check_validity
      calculate_score(@base.properties + @threat.properties)
    end

    ##
    # Returns the Environmental and Threat Score of the CVSS vector (aka CVSS-BTE).

    def environmental_score
      check_validity
      calculate_score(@base.properties + @threat.properties + @environmental.properties)
    end

    ##
    # Returns the Environmental Score of the CVSS vector (aka CVSS-BE).

    def environmental_only_score
      check_validity
      calculate_score(@base.properties + @environmental.properties)
    end

    ##
    # Returns the vector itself.
    def vector
      "#{CvssSuite::CVSS_VECTOR_BEGINNINGS.find { |beginning| beginning[:version] == version }[:string]}#{@vector}"
    end

    ##
    # Returns if CVSS vector is valid.
    def valid?
      if @amount_of_properties >= required_amount_of_properties
        base = @base.valid?
        threat = @base.valid? && @threat.valid?
        environmental = @base.valid? && @environmental.valid?
        full = @base.valid? && @threat.valid? && @environmental.valid?
        base || threat || environmental || full
      else
        false
      end
    end

    ##
    # Returns the Overall Score of the CVSS vector.
    def overall_score
      check_validity
      return threat_score if @threat.valid? && !@environmental.valid?
      return environmental_score if @environmental.valid?

      base_score
    end

    private

    def init_metrics
      @base = Cvss40Base.new(@properties)
      @threat = Cvss40Threat.new(@properties)
      @environmental = Cvss40Environmental.new(@properties)
      @supplemental = Cvss40Supplemental.new(@properties)
    end

    def calculate_score(properties)
      properties = Hash[properties.map{ |a| [a[:abbreviation], a[:selected_value]] }]
      properties.key?('E') && properties['E'] == 'X' && properties['E'] = 'A'
      properties.key?('CR') && properties['CR'] == 'X' && properties['CR'] = 'H'
      properties.key?('IR') && properties['IR'] == 'X' && properties['IR'] = 'H'
      properties.key?('AR') && properties['AR'] == 'X' && properties['AR'] = 'H'

      properties.keys.find { |k| k.starts_with? 'M' }.each do |modified_key|
        properties[modified_key[1..]] = properties[modified_key] unless properties[modified_key] == 'X'
        properties.delete(modified_key)
      end

      macro_vector = get_eq_1(properties) + get_eq_2(properties) + get_eq_3(properties)
      get_score(properties, macro_vector)
    end

    def get_eq1(properties)
      # AV:N and PR:N and UI:N
      if properties['AV'] == 'N' && properties['PR'] == 'N' && properties['UI'] == 'N'
        '0'
      # (AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
      elsif (properties['AV'] == 'N' || properties['PR'] == 'N' || properties['UI'] == 'N') && properties['AV'] != 'P'
        '1'
      # AV:P or not(AV:N or PR:N or UI:N)
      elsif properties['AV'] == 'P' || !(properties['AV'] == 'N' || properties['PR'] == 'N' || properties['UI'] == 'N')
        '2'
      end
    end

    def get_eq2(properties)
      # AC:L and AT:N
      if properties['AC'] == 'L' && properties['AT'] == 'N'
        '0'
      # not (AC:L and AT:N)
      elsif !(properties['AC'] == 'L' && properties['AT'] == 'N')
        '1'
      end
    end

    def get_eq3(properties)
      # VC:H and VI:H
      if properties['VC'] == 'H' && properties['VI'] == 'H'
        '0'
      # not (VC:H and VI:H) and (VC:H or VI:H or VA:H)
      elsif !(properties['VC'] == 'H' && properties['VI'] == 'H') && (properties['VC'] == 'H' || properties['VI'] == 'H' || properties['VA'] == 'H')
        '1'
      # not (VC:H or VI:H or VA:H)
      elsif !(properties['VC'] == 'H' || properties['VI'] == 'H' || properties['VA'] == 'H')
        '2'
      end
    end

    def get_eq4(properties)
      # MSI:S or MSA:S
      if properties['SI'] == 'S' || properties['SA'] == 'S'
        '0'
      # not (MSI:S and MSA:S) and (SC:H or SI:H or SA:H)
      elsif !(properties['SI'] == 'S' && properties['SA'] == 'S') && (properties['SC'] == 'H' || properties['SI'] == 'H' || properties['SA'] == 'H')
        '1'
      # not (MSI:S and MSA:S) and not (SC:H or SI:H or SA:H)
      elsif !(properties['SI'] == 'S' && properties['SA'] == 'S') && !(properties['SC'] == 'H' || properties['SI'] == 'H' || properties['SA'] == 'H')
        '2'
      else
        '0'
      end
    end

    def get_eq5(properties)
      # E:A
      if properties['E'] == 'A'
        '0'
      # E:P
      elsif properties['E'] == 'P'
        '1'
      # E:U
      elsif properties['E'] == 'U'
        '2'
      else
        '0'
      end
    end

    def get_eq6(properties)
      # AV:N and PR:N and UI:N
      if properties['AV'] == 'N' && properties['PR'] == 'N' && properties['UI'] == 'N'
        '0'
      # (CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
      elsif (properties['CR'] == 'H' && properties['VC'] == 'H') || (properties['IR'] == 'H' && properties['VI'] == 'H') || (properties['AR'] == 'H' && properties['VA'] == 'H')
        '1'
      else
        '0'
      end
    end

    def get_score(properties, macro_vector)
      av_levels = { "N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3 }
      pr_levels = { "N": 0.0, "L": 0.1, "H": 0.2 }
      ui_levels = { "N": 0.0, "P": 0.1, "A": 0.2 }

      ac_levels = { 'L': 0.0, 'H': 0.1 }
      at_levels = { 'N': 0.0, 'P': 0.1 }

      vc_levels = { 'H': 0.0, 'L': 0.1, 'N': 0.2 }
      vi_levels = { 'H': 0.0, 'L': 0.1, 'N': 0.2 }
      va_levels = { 'H': 0.0, 'L': 0.1, 'N': 0.2 }

      sc_levels = { 'H': 0.1, 'L': 0.2, 'N': 0.3 }
      si_levels = { 'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3 }
      sa_levels = { 'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3 }

      cr_levels = { 'H': 0.0, 'M': 0.1, 'L': 0.2 }
      ir_levels = { 'H': 0.0, 'M': 0.1, 'L': 0.2 }
      ar_levels = { 'H': 0.0, 'M': 0.1, 'L': 0.2 }

      e_levels = { 'U': 0.2, 'P': 0.1, 'A': 0 }

      return 0.0 if (["VC", "VI", "VA", "SC", "SI", "SA"].every((metric) => properties[metric] == "N"))

      value = lookup(macroVector)

      eq1_val = Integer(macroVector[0])
      eq2_val = Integer(macroVector[1])
      eq3_val = Integer(macroVector[2])
      eq4_val = Integer(macroVector[3])
      eq5_val = Integer(macroVector[4])
      eq6_val = Integer(macroVector[5])

      eq1_next_lower_macro = "#{eq1_val + 1}#{eq2_val}#{eq3_val}#{eq4_val}#{eq5_val}#{eq6_val}"
      eq2_next_lower_macro = "#{eq1_val}#{eq2_val + 1}#{eq3_val}#{eq4_val}#{eq5_val}#{eq6_val}"

      if eq3_val == 1 && eq6_val == 1 
          # 11 --> 21
          eq3eq6_next_lower_macro = "#{eq1_val}#{eq2_val}#{eq3_val + 1}#{eq4_val}#{eq5_val}#{eq6_val}"
      elsif (eq3_val == 0 && eq6_val == 1) 
          # 01 --> 11
          eq3eq6_next_lower_macro = "#{eq1_val}#{eq2_val}#{eq3_val + 1}#{eq4_val}#{eq5_val}#{eq6_val}"
      elsif (eq3_val == 1 && eq6_val == 0) 
          # 10 --> 11
          eq3eq6_next_lower_macro = "#{eq1_val}#{eq2_val}#{eq3_val}#{eq4_val}#{eq5_val}#{eq6_val + 1}"
      elsif (eq3_val == 0 && eq6_val == 0) 
          # 00 --> 01
          # 00 --> 10
          eq3eq6_next_lower_macro_left = "#{eq1_val}#{eq2_val}#{eq3_val}#{eq4_val}#{eq5_val}#{eq6_val + 1}"
          eq3eq6_next_lower_macro_right = "#{eq1_val}#{eq2_val}#{eq3_val + 1}#{eq4_val}#{eq5_val}#{eq6_val}"
      else
          # 21 --> 32 (do not exist)
          eq3eq6_next_lower_macro = "#{eq1_val}#{eq2_val}#{eq3_val + 1}#{eq4_val}#{eq5_val}#{eq6_val + 1}"
      end

      eq4_next_lower_macro = "#{eq1_val}#{eq2_val}#{eq3_val}#{eq4_val + 1}#{eq5_val}#{eq6_val}"
      eq5_next_lower_macro = "#{eq1_val}#{eq2_val}#{eq3_val}#{eq4_val}#{eq5_val + 1}#{eq6_val}"

      score_eq1_next_lower_macro = lookup(eq1_next_lower_macro)
      score_eq2_next_lower_macro = lookup(eq2_next_lower_macro)

      if (eq3_val == 0 && eq6_val == 0) 
          score_eq3eq6_next_lower_macro_left = lookup(eq3eq6_next_lower_macro_left)
          score_eq3eq6_next_lower_macro_right = lookup(eq3eq6_next_lower_macro_right)

          if (score_eq3eq6_next_lower_macro_left > score_eq3eq6_next_lower_macro_right) 
              score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_left
          else 
              score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_right
          end
      
      else 
          score_eq3eq6_next_lower_macro = lookup(eq3eq6_next_lower_macro)
      end
    end

    def lookup(macroVector)
      {
        "000000": 10,
        "000001": 9.9,
        "000010": 9.8,
        "000011": 9.5,
        "000020": 9.5,
        "000021": 9.2,
        "000100": 10,
        "000101": 9.6,
        "000110": 9.3,
        "000111": 8.7,
        "000120": 9.1,
        "000121": 8.1,
        "000200": 9.3,
        "000201": 9,
        "000210": 8.9,
        "000211": 8,
        "000220": 8.1,
        "000221": 6.8,
        "001000": 9.8,
        "001001": 9.5,
        "001010": 9.5,
        "001011": 9.2,
        "001020": 9,
        "001021": 8.4,
        "001100": 9.3,
        "001101": 9.2,
        "001110": 8.9,
        "001111": 8.1,
        "001120": 8.1,
        "001121": 6.5,
        "001200": 8.8,
        "001201": 8,
        "001210": 7.8,
        "001211": 7,
        "001220": 6.9,
        "001221": 4.8,
        "002001": 9.2,
        "002011": 8.2,
        "002021": 7.2,
        "002101": 7.9,
        "002111": 6.9,
        "002121": 5,
        "002201": 6.9,
        "002211": 5.5,
        "002221": 2.7,
        "010000": 9.9,
        "010001": 9.7,
        "010010": 9.5,
        "010011": 9.2,
        "010020": 9.2,
        "010021": 8.5,
        "010100": 9.5,
        "010101": 9.1,
        "010110": 9,
        "010111": 8.3,
        "010120": 8.4,
        "010121": 7.1,
        "010200": 9.2,
        "010201": 8.1,
        "010210": 8.2,
        "010211": 7.1,
        "010220": 7.2,
        "010221": 5.3,
        "011000": 9.5,
        "011001": 9.3,
        "011010": 9.2,
        "011011": 8.5,
        "011020": 8.5,
        "011021": 7.3,
        "011100": 9.2,
        "011101": 8.2,
        "011110": 8,
        "011111": 7.2,
        "011120": 7,
        "011121": 5.9,
        "011200": 8.4,
        "011201": 7,
        "011210": 7.1,
        "011211": 5.2,
        "011220": 5,
        "011221": 3,
        "012001": 8.6,
        "012011": 7.5,
        "012021": 5.2,
        "012101": 7.1,
        "012111": 5.2,
        "012121": 2.9,
        "012201": 6.3,
        "012211": 2.9,
        "012221": 1.7,
        "100000": 9.8,
        "100001": 9.5,
        "100010": 9.4,
        "100011": 8.7,
        "100020": 9.1,
        "100021": 8.1,
        "100100": 9.4,
        "100101": 8.9,
        "100110": 8.6,
        "100111": 7.4,
        "100120": 7.7,
        "100121": 6.4,
        "100200": 8.7,
        "100201": 7.5,
        "100210": 7.4,
        "100211": 6.3,
        "100220": 6.3,
        "100221": 4.9,
        "101000": 9.4,
        "101001": 8.9,
        "101010": 8.8,
        "101011": 7.7,
        "101020": 7.6,
        "101021": 6.7,
        "101100": 8.6,
        "101101": 7.6,
        "101110": 7.4,
        "101111": 5.8,
        "101120": 5.9,
        "101121": 5,
        "101200": 7.2,
        "101201": 5.7,
        "101210": 5.7,
        "101211": 5.2,
        "101220": 5.2,
        "101221": 2.5,
        "102001": 8.3,
        "102011": 7,
        "102021": 5.4,
        "102101": 6.5,
        "102111": 5.8,
        "102121": 2.6,
        "102201": 5.3,
        "102211": 2.1,
        "102221": 1.3,
        "110000": 9.5,
        "110001": 9,
        "110010": 8.8,
        "110011": 7.6,
        "110020": 7.6,
        "110021": 7,
        "110100": 9,
        "110101": 7.7,
        "110110": 7.5,
        "110111": 6.2,
        "110120": 6.1,
        "110121": 5.3,
        "110200": 7.7,
        "110201": 6.6,
        "110210": 6.8,
        "110211": 5.9,
        "110220": 5.2,
        "110221": 3,
        "111000": 8.9,
        "111001": 7.8,
        "111010": 7.6,
        "111011": 6.7,
        "111020": 6.2,
        "111021": 5.8,
        "111100": 7.4,
        "111101": 5.9,
        "111110": 5.7,
        "111111": 5.7,
        "111120": 4.7,
        "111121": 2.3,
        "111200": 6.1,
        "111201": 5.2,
        "111210": 5.7,
        "111211": 2.9,
        "111220": 2.4,
        "111221": 1.6,
        "112001": 7.1,
        "112011": 5.9,
        "112021": 3,
        "112101": 5.8,
        "112111": 2.6,
        "112121": 1.5,
        "112201": 2.3,
        "112211": 1.3,
        "112221": 0.6,
        "200000": 9.3,
        "200001": 8.7,
        "200010": 8.6,
        "200011": 7.2,
        "200020": 7.5,
        "200021": 5.8,
        "200100": 8.6,
        "200101": 7.4,
        "200110": 7.4,
        "200111": 6.1,
        "200120": 5.6,
        "200121": 3.4,
        "200200": 7,
        "200201": 5.4,
        "200210": 5.2,
        "200211": 4,
        "200220": 4,
        "200221": 2.2,
        "201000": 8.5,
        "201001": 7.5,
        "201010": 7.4,
        "201011": 5.5,
        "201020": 6.2,
        "201021": 5.1,
        "201100": 7.2,
        "201101": 5.7,
        "201110": 5.5,
        "201111": 4.1,
        "201120": 4.6,
        "201121": 1.9,
        "201200": 5.3,
        "201201": 3.6,
        "201210": 3.4,
        "201211": 1.9,
        "201220": 1.9,
        "201221": 0.8,
        "202001": 6.4,
        "202011": 5.1,
        "202021": 2,
        "202101": 4.7,
        "202111": 2.1,
        "202121": 1.1,
        "202201": 2.4,
        "202211": 0.9,
        "202221": 0.4,
        "210000": 8.8,
        "210001": 7.5,
        "210010": 7.3,
        "210011": 5.3,
        "210020": 6,
        "210021": 5,
        "210100": 7.3,
        "210101": 5.5,
        "210110": 5.9,
        "210111": 4,
        "210120": 4.1,
        "210121": 2,
        "210200": 5.4,
        "210201": 4.3,
        "210210": 4.5,
        "210211": 2.2,
        "210220": 2,
        "210221": 1.1,
        "211000": 7.5,
        "211001": 5.5,
        "211010": 5.8,
        "211011": 4.5,
        "211020": 4,
        "211021": 2.1,
        "211100": 6.1,
        "211101": 5.1,
        "211110": 4.8,
        "211111": 1.8,
        "211120": 2,
        "211121": 0.9,
        "211200": 4.6,
        "211201": 1.8,
        "211210": 1.7,
        "211211": 0.7,
        "211220": 0.8,
        "211221": 0.2,
        "212001": 5.3,
        "212011": 2.4,
        "212021": 1.4,
        "212101": 2.4,
        "212111": 1.2,
        "212121": 0.5,
        "212201": 1,
        "212211": 0.3,
        "212221": 0.1,
      }[macroVector]
    end
  end
end

# rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/ClassLength, Metrics/AbcSize
