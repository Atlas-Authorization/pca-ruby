# pca-ruby — Proof-Carrying Authority verifier for Ruby

An **offline verifier for Proof-Carrying Actions (PCActns)** in Ruby. A PCActn is the credential an
autonomous agent presents with *every* action it takes: a self-contained, cryptographically-checkable
object proving the action is a faithful execution of authority its principal actually granted. Your
resource server verifies it locally — no token introspection, no network call on the hot path.

This library is the Ruby member of the PCA verifier family. It is a faithful port of the TypeScript
reference implementation and passes the **same shared conformance corpus** as every other language
verifier, so a PCActn that verifies here verifies identically everywhere.

## Install

The verifier is a single dependency-free file, `lib/atlas_pca.rb` (module `AtlasPca`). Vendor it into
your project, or add the repo to your `Gemfile` directly:

```ruby
gem "atlas-pca", git: "https://github.com/Atlas-Authorization/pca-ruby"
```

```ruby
require "atlas_pca"
```

## Verify a PCActn

A verifier is stateless. Give it the received PCActn (a parsed object, or raw JSON via
`AtlasPca.parse_json`), the Root Intent Grant it claims to derive from, the current time (epoch
**milliseconds**), and *your own* audience id. It returns an allow/deny verdict plus the per-check
results.

```ruby
require "atlas_pca"

# `raw` is the PCActn as received (strict canonical JSON, wire version 2).
# `grant` is the Root Intent Grant the action's capability chain roots in.
actn    = AtlasPca.parse_json(raw)
verdict = AtlasPca.verify_pcactn(
  actn,
  grant,
  now: (Time.now.to_f * 1000).to_i,
  audience: "https://api.example.com",
)

if verdict.allow
  # every core check passed — execute the action
else
  warn "denied: #{verdict.reason} #{verdict.checks}"
end
```

The verdict reports each core check (`wire`, `version`, `audience`, `validity`, `chain`,
`plan_inclusion`, `leaf_signature`, `counter_format`). Every check is **fail-closed** — the action is allowed
only if none reports failure — and a `wire` failure is terminal (nothing else is evaluated).

## Authorize an operation

`AtlasPca.authorize` is the full decision for one operation. It runs the core checks above, then:

- binds the proof to the operation your handler will execute: the signed verb, resource and params digest must equal
  it, and the grant's predicates and caveats are evaluated against those params (a proof signed for $50 cannot pay
  $400);
- evaluates the grant's envelope predicates (default deny), the envelope's caveats, caveats placed on the root grant
  and caveats added by delegation (`max_spend`, `predicates`, `tool_schema`, `expires`, `rate`, ...; an unknown type is
  refused);
- checks revocation with your `is_revoked` (only `false` passes);
- consumes the replay counter through an atomic store, only when everything else passed.

Every component is required. Without `audience:`, `resolve_grant:`, `state_store:`, `is_revoked:` or `operation:`, the
call is refused and `result.missing` names what is absent. `authorize` never raises: an internal error is a denial.

```ruby
require "atlas_pca"

# needs the sqlite3 gem; one row per (grant, agent); safe across threads and processes
store = AtlasPca::SqliteStateStore.new("pca-replay.db")

result = AtlasPca.authorize(
  pcactn,
  operation: { verb: "payments.send", resource: "payments/acme", params: body }, # what you will execute
  audience: "payments-rs",
  resolve_grant: ->(grant_ref) { grants[grant_ref] }, # grant_ref -> grant, from your own store
  state_store: store,
  is_revoked: ->(_pcactn, grant) { revoked_grant_ids.include?(grant["id"]) },
  plan: "single-step",
)
raise SecurityError, result.reason unless result.allow # e.g. "policy: caveat(s) not satisfied: max_spend"

send_payment(body)
```

- `plan: "single-step"` accepts a proof whose plan is this one operation. For a multi-step plan, pass
  `context: ->(pcactn) { { plan: nodes, plan_authorized: true } }` with the plan the principal authorized.
- `result.status` is 200, 401 (no proof, or one that fails authentication) or 403. `result.checks` maps every check to
  `"pass"`, `"fail"` or `"not-enforced"`, and `result.reason` is the decisive failure. On success `result.operation` is
  the bound operation (verb, resource, params digest, and an `id` for the proof), and
  `AtlasPca.is_authorized_for(result, operation)` re-checks it where the side effect runs.
- `operation:` comes from your own routing and parsed request, never from the proof. Its params must be a Hash; keys
  may be Strings or Symbols.
- `AtlasPca::MemoryStateStore` is for a single process. `AtlasPca::SqlStateStore` runs the same single
  `INSERT ... ON CONFLICT(key) DO UPDATE ... WHERE excluded.last_counter > last_counter` statement through any database
  adapter you give it (`execute:` returns the number of rows the statement changed, `select:` reads the stored counter;
  `placeholders: :dollar` for PostgreSQL). Your own store implements `claim(key, counter)` as one atomic operation and
  returns `AtlasPca::ClaimResult.new(ok, last_counter)`.
- Not covered by `authorize` here: the risk score, trust budget and threshold co-signature from the grant's
  `risk_policy`, revocation epochs and liveness beacons. A grant that pins the agent (`agent_binding`) needs an
  attestation verifier and is refused, and so is a proof carrying `zk_compliance`. The TypeScript `authorize` covers
  these.

The Rack middleware runs this pipeline by default; the `authorize:` option carries its components. Without `authorize:`
(and without `signature_only: true`) the option set is empty and every request is refused with a 403 `authorize_config`
whose `missing` list names the absent components.

```ruby
require "atlas_pca/rack_middleware"
require "json"

use AtlasPca::RackMiddleware,
    audience: "payments-rs",
    resolve_grant: ->(grant_ref) { grants[grant_ref] },
    authorize: {
      state_store: store,
      is_revoked: ->(_pcactn, grant) { revoked_grant_ids.include?(grant["id"]) },
      # the operation this request executes (nil denies); plan: "single-step" by default
      operation: lambda do |env|
        next nil unless env["REQUEST_METHOD"] == "POST" && env["PATH_INFO"] == "/payments"

        body = env["rack.input"].read
        env["rack.input"].rewind
        { verb: "payments.send", resource: "payments/acme", params: JSON.parse(body) }
      end,
    }
```

A denial is a 401 or 403 JSON response before your app runs (`error_description` holds the reason, `failed_checks` the
failing checks). On success `env["pca"]["operation"]` is the bound operation and `env["pca"]["authorization"]` the full
result. The `authorize:` option also accepts `context:`, `require:` (extra checks that must pass) and `plan:`.

To verify the signature and chain only, opt in explicitly with `signature_only: true`. It cannot be combined with
`authorize:` (the constructor raises `ArgumentError`).

```ruby
use AtlasPca::RackMiddleware, audience: "payments-rs", resolve_grant: ->(ref) { grants[ref] }, signature_only: true
```

### Check names

The core verifier reports the counter's format as `counter_format`. `authorize` reports the stateful check as `replay`,
with the reasons `replay: N is not greater than last seen M (replay)`, `replay: N was already claimed (replay)` and
`replay: the replay store failed (fail closed)`. `replay` is required, like `counter_format`, `revocation`,
`plan_root_authorized`, `audience`, `validity`, `grant_ref_bound`, `operation`, `params_digest` and `policy`. In
`require:`, the name `counter` is an alias of `replay`.

### Limit-naming denial reasons

When an action's verb and resource are covered by an envelope predicate but one of its `where` limits is not met, the
reason names the limit instead of the generic text:

```
policy: amount <= 100 not satisfied for payments.send on payments/acme
```

A condition renders as `name op operand` (`==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `not in`, `starts with`, `like`,
`matches`, `is a`, `member of`, `present`, `absent`); a `field` loses its `action.params.` prefix; an `all_of` shows its
first unmet child. Operands are shown only when they are safe integers, booleans, null, short plain strings or short
lists of those; anything else prints as `<value>`. When no predicate covers the verb and resource the text stays
`no predicate permits <verb> on <resource>`, and an empty list stays `envelope grants no predicates`.

### Upgrading to 0.5

- The Rack middleware now runs `authorize` by default. Add `authorize: { state_store:, is_revoked:, operation: }`, or pass
  `signature_only: true` to keep the old signature-only behaviour.
- The core `counter` check is now `counter_format`; the stateful check in `authorize` is `replay`.
- A `require:` entry `counter` still works and means `replay`.

## Caveats (policy layer)

The core verifier checks that the PCActn is well formed and authentic; like every PCA core verifier it does not decide
whether the action satisfies the grant's caveats (`authorize` above does). To evaluate caveats yourself, use your own
action parameters: `AtlasPca.evaluate_caveats(AtlasPca.policy_caveats(grant, chain), ctx)`. `policy_caveats` is every caveat on the root grant except its first `envelope` caveat (0.4.1: root caveats
are enforced exactly like delegated ones) followed by the caveats the delegation hops appended. Supported types: `expires`,
`not_before`, `rate`, `max_blast_radius`, `reversibility_max`, `delegation_depth`, `budget_alloc` and `max_spend`; any other
type is unsatisfied (fail closed). The `PCA-Action` header must be strict unpadded base64url of UTF-8 text (`AtlasPca.decode_pca_header(value)`).

## What a passing result does not cover

For `verify_pcactn` (and the Rack middleware with `signature_only: true`), `counter_format: pass` is a format check (a non-negative
integer); it does **not** mean the action was not replayed. Verification is stateless, so either use `authorize` with a
replay store, or persist, per grant and agent, the last accepted counter and refuse anything not strictly greater,
atomically across all of your processes.

With `signature_only: true`, `AtlasPca::RackMiddleware` runs the core verifier only. It does not check replay, revocation,
caveats, envelope predicates or plan authorization, and it does not compare the request body with the signed
`params_digest`. The default (`authorize:`) does all of those.

## Conformance

The repo ships a vendored copy of the shared **conformance corpus** (`conformance/vectors.json` +
`conformance/keys.json`): 676 golden and adversarial PCActns with their expected verdicts,
plus canonical-JSON, strict-base64url, and Merkle primitive vectors. `ruby conformance.rb` runs the
verifier against every vector; it must reproduce `allow` and every listed check exactly.

## Supported signature suites

- `ed25519` (default)
- `ml-dsa-65` (FIPS-204, post-quantum)
- `hybrid-ed25519-ml-dsa-65` (classical + post-quantum)

The suite id and post-quantum public key are part of the signed body, so a suite downgrade or key swap
invalidates the action.

## Capability maturity

The PCActn wire format and the eight core offline checks are stable and conformance-covered. The broader
framework surface is implemented and tested in the reference implementation: threshold/step-up co-signing
(a real FROST threshold signature over a DKG-established group key, released only on a Policy-VM allow),
TEE/hardware and model-weights attestation, zero-knowledge proof-of-compliance (a real Groth16 proof),
optimistic bonds and the contestable dispute game, and the malicious-secure MPC Policy VM (SPDZ-style MACs
with abort). A few rungs carry a remaining production requirement, stated plainly rather than hidden
behind a label: a live TEE/hardware attestation needs real SEV-SNP/TDX silicon (the verifier is tested
against real-crypto mock reports); unforgeable FROST guardian custody needs each share in a separate trust
domain / HSM with a network signing protocol (the reference runs the signing round in-process); the MPC
Policy VM's offline triple generation is trusted-dealer today (a no-dealer OT/HE phase is designed); and
the zero-knowledge circuit proves a decision subset (plan-membership + risk ≤ budget), with fuller
policy coverage ongoing. See the [PCA framework repo](https://github.com/Atlas-Authorization/pca) for the
full model.

## License

See `LICENSE`.
