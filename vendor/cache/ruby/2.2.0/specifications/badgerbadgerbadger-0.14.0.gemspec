# -*- encoding: utf-8 -*-
# stub: badgerbadgerbadger 0.14.0 ruby lib

Gem::Specification.new do |s|
  s.name = "badgerbadgerbadger"
  s.version = "0.14.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib"]
  s.authors = ["pikesley"]
  s.date = "2016-01-19"
  s.description = "Generate Github project badges like a boss"
  s.email = ["sam@pikesley.org"]
  s.executables = ["badger"]
  s.files = ["bin/badger"]
  s.homepage = "http://badges.github.io/badgerbadgerbadger/"
  s.licenses = ["MIT"]
  s.rubygems_version = "2.4.8"
  s.summary = "Badge-Driven Development made easy. Generate a set of Github badges for your project without cutting-n-pasting every time"

  s.installed_by_version = "2.4.8" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<thor>, ["~> 0.18"])
      s.add_runtime_dependency(%q<git>, ["~> 1.2"])
      s.add_development_dependency(%q<bundler>, ["~> 1.5"])
      s.add_development_dependency(%q<rake>, ["~> 10.1"])
      s.add_development_dependency(%q<rspec>, ["~> 3"])
      s.add_development_dependency(%q<cucumber>, ["~> 1.3"])
      s.add_development_dependency(%q<aruba>, ["~> 0.5"])
      s.add_development_dependency(%q<guard>, ["~> 2.3"])
      s.add_development_dependency(%q<guard-rspec>, ["~> 4.2"])
      s.add_development_dependency(%q<guard-cucumber>, ["~> 1.4"])
      s.add_development_dependency(%q<terminal-notifier-guard>, ["~> 1.5"])
      s.add_development_dependency(%q<coveralls>, ["~> 0.7"])
      s.add_development_dependency(%q<webmock>, ["~> 1.17"])
    else
      s.add_dependency(%q<thor>, ["~> 0.18"])
      s.add_dependency(%q<git>, ["~> 1.2"])
      s.add_dependency(%q<bundler>, ["~> 1.5"])
      s.add_dependency(%q<rake>, ["~> 10.1"])
      s.add_dependency(%q<rspec>, ["~> 3"])
      s.add_dependency(%q<cucumber>, ["~> 1.3"])
      s.add_dependency(%q<aruba>, ["~> 0.5"])
      s.add_dependency(%q<guard>, ["~> 2.3"])
      s.add_dependency(%q<guard-rspec>, ["~> 4.2"])
      s.add_dependency(%q<guard-cucumber>, ["~> 1.4"])
      s.add_dependency(%q<terminal-notifier-guard>, ["~> 1.5"])
      s.add_dependency(%q<coveralls>, ["~> 0.7"])
      s.add_dependency(%q<webmock>, ["~> 1.17"])
    end
  else
    s.add_dependency(%q<thor>, ["~> 0.18"])
    s.add_dependency(%q<git>, ["~> 1.2"])
    s.add_dependency(%q<bundler>, ["~> 1.5"])
    s.add_dependency(%q<rake>, ["~> 10.1"])
    s.add_dependency(%q<rspec>, ["~> 3"])
    s.add_dependency(%q<cucumber>, ["~> 1.3"])
    s.add_dependency(%q<aruba>, ["~> 0.5"])
    s.add_dependency(%q<guard>, ["~> 2.3"])
    s.add_dependency(%q<guard-rspec>, ["~> 4.2"])
    s.add_dependency(%q<guard-cucumber>, ["~> 1.4"])
    s.add_dependency(%q<terminal-notifier-guard>, ["~> 1.5"])
    s.add_dependency(%q<coveralls>, ["~> 0.7"])
    s.add_dependency(%q<webmock>, ["~> 1.17"])
  end
end
