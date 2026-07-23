# CVSS-Suite, a Ruby gem to manage the CVSS vector
#
# This work is licensed under the terms of the MIT license.
# See the LICENSE.md file in the top-level directory.

# frozen_string_literal: true

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
    'changelog_uri' => 'https://github.com/0llirocks/cvss-suite/releases',
    'documentation_uri' => "https://www.rubydoc.info/gems/cvss-suite/#{CvssSuite::VERSION}",
    'homepage_uri' => 'https://cvss-suite.0lli.rocks',
    'source_code_uri' => 'https://github.com/0llirocks/cvss-suite',
    'rubygems_mfa_required' => 'true'
  }

  spec.required_ruby_version = '>= 3.3'
  # Package only what's needed at runtime -- the library code plus its docs and
  # licence. Dev-only files (CI config, Rakefile, bin/, editor/docs-site config)
  # are deliberately excluded to keep the published gem minimal.
  spec.files         = `git ls-files -z -- lib exe LICENSE.md README.md CHANGES.md`.split("\x0")
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'bigdecimal', '>= 3.1'
end
