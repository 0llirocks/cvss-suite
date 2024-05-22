# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

# coding: utf-8

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'cvss_suite/version'

Gem::Specification.new do |spec|
  spec.name          = 'cvss-suite'
  spec.version       = CvssSuite::VERSION
  spec.license       = 'MIT'
  spec.authors       = ['0llirocks']

  spec.summary       = 'Ruby gem for processing cvss vectors.'
  spec.description   = 'This Ruby gem calculates the score based on the vector of the
Common Vulnerability Scoring System (https://www.first.org/cvss/specification-document)
in version 4.0, 3.1, 3.0 and 2.'

  spec.homepage      = 'https://cvss-suite.0lli.rocks'

  spec.metadata = {
    'bug_tracker_uri' => 'https://github.com/0llirocks/cvss-suite/issues',
    'changelog_uri' => 'https://github.com/0llirocks/cvss-suite/blob/master/CHANGES.md',
    'documentation_uri' => "https://www.rubydoc.info/gems/cvss-suite/#{CvssSuite::VERSION}",
    'homepage_uri' => 'https://cvss-suite.0lli.rocks',
    'source_code_uri' => 'https://github.com/0llirocks/cvss-suite'
  }

  spec.required_ruby_version = '>= 2.6.0'
  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '2.4.22'
  spec.add_development_dependency 'rspec', '~> 3.4'
  spec.add_development_dependency 'rspec-its', '~> 1.2'
  spec.add_development_dependency 'rubocop', '1.50.2'
  spec.add_development_dependency 'simplecov', '~> 0.18'
end
