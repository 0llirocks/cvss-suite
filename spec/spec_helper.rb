# © Siemens AG, 2016

require 'simplecov'

SimpleCov.start do
  add_filter "/spec/"
end

$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'cvss_suite'
require 'cvss_suite/helpers/extensions'
require 'rspec/its'
require 'shared_examples'

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end