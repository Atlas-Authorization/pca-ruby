# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name        = 'atlas-pca'
  spec.version     = '0.5.0'
  spec.authors     = ['Atlas']
  spec.email       = ['support@atlasauth.net']
  spec.summary     = 'Offline verifier for Proof-Carrying Actions (PCActns) in Ruby, with a Rack middleware.'
  spec.description = 'Verifies a PCActn locally (signature, chain, audience, validity, replay, revocation, policy) and ' \
                     'passes the same shared conformance corpus as every other PCA verifier. Dependency-free.'
  spec.homepage    = 'https://atlasauth.net'
  spec.license     = 'MIT'
  spec.required_ruby_version = '>= 3.3'

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/Atlas-Authorization/pca-ruby'
  spec.metadata['rubygems_mfa_required'] = 'true'
  # Maturity tier: stable | production | experimental (the PCA maturity tiers page defines them)
  spec.metadata['maturity'] = 'stable'

  spec.files = Dir.glob('lib/**/*.rb') + %w[CHANGELOG.md]
  spec.require_paths = ['lib']
end
