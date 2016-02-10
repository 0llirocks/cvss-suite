class Float
  def round_up(decimal_paces = 0)
    (self * 10.0**decimal_paces).ceil / 10.0**decimal_paces
  end
end