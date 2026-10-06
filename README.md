# pca-ruby

Proof-Carrying Authority (PCA) verifier for Ruby. **Preview.**

PCA is authF: instead of verifying a token, you verify a proof-carrying action (a PCActn) - the capability chain, Merkle plan inclusion, Ed25519 leaf signature and counter. This is a reference verifier that passes the shared conformance vectors.

> Preview: the wire format and API may change before 1.0.

## Install

Preview: `gem install atlas-pca` once published; until then `gem 'atlas_pca', git: 'https://github.com/Atlas-Authorization/pca-ruby'` or require `lib/atlas_pca.rb` directly. Stdlib only (OpenSSL >= 3).

## Verify

```ruby
require 'atlas_pca'

v = AtlasPca.verify_pcactn_core(pcactn, grant) # both parsed JSON hashes
if v['allow']
  puts 'authorized' # chain, plan_inclusion, leaf_signature, counter all passed
else
  puts v['reason']
end
```

## Conformance tests

The shared golden vectors are vendored in `conformance/` (synced from the hub). Run:

```
ruby conformance.rb
```

The reference verifier must produce the same `allow` and the same pass/fail for each of the four checks on every vector.

## Links

- Hub (spec, other languages): https://github.com/Atlas-Authorization/pca
- Live docs: https://atlasauth.net/pca
- TypeScript reference: npm `@atlasauth/pca`

## License

MIT
