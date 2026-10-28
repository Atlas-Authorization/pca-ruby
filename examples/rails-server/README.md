# Refund server with Proof-Carrying Authority

A minimal Rack server that protects `POST /refunds` with `AtlasPca.protect`. It refuses every request that does not carry
a proof signed for exactly the operation the route executes, and it explains each refusal.

## What it shows

- `AtlasPca.protect(audience:, grants:, operation:)` returns the option set for `AtlasPca::RackMiddleware`: the grants come
  from your own list (never from the request), replay protection uses an in-memory store, revocation is wired up, and the
  plan is `single-step`.
- `operation` maps the request to what the route will run. The proof must be signed for that verb, resource and params.
- `protected.revoke(grant_id)` refuses every further action under that grant.
- Every 401 and 403 body has a `doc` member that links to the page explaining the refusing check.
  `AtlasPca.explain_refusal(reason)` returns the meaning and the fix for a reason string.

## Run it

```sh
bundle install
bundle exec ruby test/smoke_test.rb   # allow, replay, wrong amount, no proof, revoked
bundle exec rackup                     # serves on port 9292
```

The smoke test uses a proof from the PCA conformance fixtures (`fixtures/refund_proof.json`) and the grant in
`grants.json`. The proof is bound to the sample verb `payments.send` on `payments/acme` for an amount of 50 USD. Send it
in the `PCA-Action` header, base64url-encoded canonical JSON, with a body such as
`{"account":"acme","amount":50,"currency":"usd"}`. The sample proof was signed for a fixed moment, so against the running
server (which uses the wall clock) it is refused with a `validity` reason. That is the guard working; mint your own proofs
with an agent SDK for live use.

Set `PCA_GRANTS` (a JSON file with an array of grants) and `PCA_AUDIENCE` to use your own.

## Using it in Rails

This example is plain Rack so it boots without a Rails app. In Rails, mount the same options as middleware:

```ruby
# config/application.rb
prot = AtlasPca.protect(audience: "payments-rs", grants: -> (ref) { Grant.find_by(ref: ref)&.document },
                        operation: ->(env) { operation_for(env) })
config.middleware.use AtlasPca::RackMiddleware, **prot.options
```

The in-memory replay store is correct for one process only. Use a shared store (see the gem's README) when you run more
than one worker.
