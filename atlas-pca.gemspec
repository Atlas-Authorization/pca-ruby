# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name        = 'atlas-pca'
  spec.version     = '0.5.0'
  spec.authors     = ['Atlas']
  spec.email       = ['support@atlasauth.net']
  spec.summary     = 'Proof-Carrying Authority for Ruby: an offline PCActn verifier with a Rack middleware, and the agent side.'
  spec.description = 'Verifies a PCActn locally (signature, chain, audience, validity, replay, revocation, policy) and ' \
                     'passes the same shared conformance corpus as every other PCA verifier. Also the agent side: mints ' \
                     'grants, delegates to sub-agents and signs one proof per action. Only the ratchet module needs the ffi gem and libsodium.'
  spec.homepage    = 'https://atlasauth.net'
  spec.license     = 'MIT'
  spec.required_ruby_version = '>= 3.3'

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/Atlas-Authorization/pca-ruby'
  spec.metadata['rubygems_mfa_required'] = 'true'
  # Maturity tier: stable | production | experimental (the PCA maturity tiers page defines them)
  spec.metadata['maturity'] = 'stable'

  spec.add_dependency 'ffi', '~> 1.17'
  spec.add_dependency 'tzinfo', '~> 2.0.6'
  spec.add_development_dependency 'ffi-icu', '~> 0.5' # optional at run time: guardian ids order by ICU root collation (atlas_pca/collation); without it a Latin-text approximation
  spec.add_development_dependency 'wasmtime', '>= 30' # only atlas_pca/sandbox_wasm (core-module host) needs it
  spec.files = Dir.glob('lib/**/*.rb') + %w[README.md CHANGELOG.md]
  # The release's native-gem job puts libada, libsodium and the opt-in module libraries (blst, SEAL, lwe-ot, fndsa, zk, LESS, sandbox host) in lib/atlas_pca/native and sets the target platform (e.g. x86_64-linux); the plain gem has none.
  native = Dir.glob('lib/atlas_pca/native/*').reject { |f| File.directory?(f) }
  unless native.empty?
    spec.platform = ENV.fetch('ATLAS_PCA_GEM_PLATFORM')
    spec.files += native
  end
  spec.require_paths = ['lib']
end
