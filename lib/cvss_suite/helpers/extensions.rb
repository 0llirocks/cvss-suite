# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# Copyright (c) Siemens AG, 2016
#
# Authors:
#   Oliver Hambörger <oliver.hamboerger@siemens.com>
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

##
# This class includes extensions for the Float datatype.

class Float
  ##
  # Since CVSS 3 all float values are rounded up, therefore this method is used instead of the mathematically correct method round().

  def round_up(decimal_paces = 0)
    ceil(decimal_paces).to_f
  end

  ##
  # The “Round up” function in CVSS v3.0 has been renamed Roundup and is now defined more precisely to minimize the possibility of implementations generating different scores due to small floating-point inaccuracies. This can happen due to differences in floating point arithmetic between different languages and hardware platforms.

  def roundup
    round(2).ceil(1).to_f
  end
end

class Integer
  ##
  # Since CVSS 3 all float values are rounded up, therefore this method is used instead of the mathematically correct method round().

  def round_up(decimal_paces = 0)
    ceil(decimal_paces).to_f
  end

  ##
  # The “Round up” function in CVSS v3.0 has been renamed Roundup and is now defined more precisely to minimize the possibility of implementations generating different scores due to small floating-point inaccuracies. This can happen due to differences in floating point arithmetic between different languages and hardware platforms.

  def roundup
    round(2).ceil(1).to_f
  end
end
