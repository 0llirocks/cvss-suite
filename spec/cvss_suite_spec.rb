# © Siemens AG, 2016

require_relative 'spec_helper'

describe CvssSuite do
  it 'has a version number' do
    expect(CvssSuite::VERSION).not_to be nil
  end

  it 'is invalid' do
    expect{CvssSuite.new('Not a valid vector!')}.to raise_error(RuntimeError, 'Vector is not valid!')
  end
end
