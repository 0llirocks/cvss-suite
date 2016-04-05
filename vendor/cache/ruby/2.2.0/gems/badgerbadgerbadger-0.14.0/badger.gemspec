# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'badger/version'

Gem::Specification.new do |spec|
  spec.name          = 'badgerbadgerbadger'
  spec.version       = Badger::VERSION
  spec.authors       = ['pikesley']
  spec.email         = ['sam@pikesley.org']
  spec.description   = %q{Generate Github project badges like a boss}
  spec.summary       = %q{Badge-Driven Development made easy. Generate a set of Github badges for your project without cutting-n-pasting every time}
  spec.homepage      = 'http://badges.github.io/badgerbadgerbadger/'
  spec.license       = 'MIT'
  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_dependency 'thor', '~> 0.18'
  spec.add_dependency 'git', '~> 1.2'

  spec.add_development_dependency 'bundler', '~> 1.5'
  spec.add_development_dependency 'rake', '~> 10.1'
  spec.add_development_dependency 'rspec', '~> 3'
  spec.add_development_dependency 'cucumber', '~> 1.3'
  spec.add_development_dependency 'aruba', '~> 0.5'
  spec.add_development_dependency 'guard', '~> 2.3'
  spec.add_development_dependency 'guard-rspec', '~> 4.2'
  spec.add_development_dependency 'guard-cucumber', '~> 1.4'
  spec.add_development_dependency 'terminal-notifier-guard', '~> 1.5'
  spec.add_development_dependency 'coveralls', '~> 0.7'
  spec.add_development_dependency 'webmock', '~> 1.17'
end
