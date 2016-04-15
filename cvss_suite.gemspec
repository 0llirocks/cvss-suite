# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'cvss_suite/version'

Gem::Specification.new do |spec|
  spec.name          = 'cvss-suite'
  spec.version       = CvssSuite::VERSION
  spec.license       = 'MIT'
  spec.authors       = ["Oliver Hamboerger"]
  spec.email         = ["oliver.hamboerger@siemens.com"]

  spec.summary       = %q{Ruby gem for processing cvss vectors.}
  spec.description   = %q{This Ruby gem helps you to process the vector of the Common Vulnerability Scoring System (https://www.first.org/cvss/specification-document).
Besides calculating the Base, Temporal and Environmental Score, you are able to extract the selected option.}
  spec.homepage      = "TODO"

  # Prevent pushing this gem to RubyGems.org by setting 'allowed_push_host', or
  # delete this section to allow pushing this gem to any host.
  # if spec.respond_to?(:metadata)
  #   spec.metadata['allowed_push_host'] = "TODO: Set to 'http://mygemserver.com'"
  # else
  #   raise "RubyGems 2.0 or newer is required to protect against public gem pushes."
  # end

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.10"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec"
  spec.add_development_dependency "rspec-its"
  spec.add_development_dependency "rdoc", "~> 4.2"
  spec.add_development_dependency "simplecov"
  spec.add_development_dependency "badgerbadgerbadger"
end
