# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'sand/version'

Gem::Specification.new do |spec|
  spec.name          = "sand-ruby"
  spec.version       = Sand::VERSION
  spec.authors       = ["Coupa Software Incorporated"]
  spec.email         = ["test@coupatest.com"]

  spec.summary       = %q{SAND client handlers for clients and services.}
  spec.description   = %q{The client portion can request tokens from SAND. The service portion can verify a token with SAND.}
  spec.homepage      = "https://github.com/coupa/sand-ruby"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", ">= 1.12"
  spec.add_development_dependency "rake", ">= 10.0"
  spec.add_development_dependency "rspec", ">= 3.0"

  spec.add_runtime_dependency 'oauth2', '>= 1.2.0', '<= 1.4.0'
  spec.add_runtime_dependency 'faraday', '>= 0.9.0'
end
