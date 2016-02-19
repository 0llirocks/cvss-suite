##
# This class includes extensions for the Float datatype.

class Float

  ##
  # Since CVSS 3 all float values are rounded up, therefore this method is used instead of the mathematically correct method round().

  def round_up(decimal_paces = 0)
    (self * 10.0**decimal_paces).ceil / 10.0**decimal_paces
  end
end