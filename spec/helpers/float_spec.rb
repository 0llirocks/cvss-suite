require_relative '../spec_helper'

describe Float do

  let(:float_without_decimal_places) { 2.0 }
  let(:float_with_one_decimal_place) { 2.1 }
  let(:float_with_two_decimal_places) { 2.11 }
  let(:float_with_two_decimal_places2) { 2.01 }
  let(:float_with_three_decimal_places) { 2.111 }

  it 'should roundup by none decimal place' do
    expect(float_without_decimal_places.round_up).to eql(2.0)
    expect(float_with_one_decimal_place.round_up).to eql(3.0)
    expect(float_with_two_decimal_places.round_up).to eql(3.0)
    expect(float_with_three_decimal_places.round_up).to eql(3.0)
  end

  it 'should roundup by one decimal place' do
    expect(float_without_decimal_places.round_up(1)).to eql(2.0)
    expect(float_with_one_decimal_place.round_up(1)).to eql(2.1)
    expect(float_with_two_decimal_places.round_up(1)).to eql(2.2)
    expect(float_with_two_decimal_places2.round_up(1)).to eql(2.1)
    expect(float_with_three_decimal_places.round_up(1)).to eql(2.2)
  end

  it 'should roundup by two decimal place' do
    expect(float_without_decimal_places.round_up(2)).to eql(2.0)
    expect(float_with_one_decimal_place.round_up(2)).to eql(2.1)
    expect(float_with_two_decimal_places.round_up(2)).to eql(2.11)
    expect(float_with_three_decimal_places.round_up(2)).to eql(2.12)
  end

  it 'should roundup by three decimal place' do
    expect(float_without_decimal_places.round_up(3)).to eql(2.0)
    expect(float_with_one_decimal_place.round_up(3)).to eql(2.1)
    expect(float_with_two_decimal_places.round_up(3)).to eql(2.11)
    expect(float_with_three_decimal_places.round_up(3)).to eql(2.111)
  end

  it 'should roundup by minus one decimal place' do
    expect(float_without_decimal_places.round_up(-1)).to eql(10.0)
    expect(float_with_one_decimal_place.round_up(-1)).to eql(10.0)
    expect(float_with_two_decimal_places.round_up(-1)).to eql(10.0)
    expect(float_with_three_decimal_places.round_up(-1)).to eql(10.0)
  end
end