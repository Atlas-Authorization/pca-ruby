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
- runs the provenance gate (`provenance_flow`, always on): a sensitive action whose choice or arguments do not derive from
  the principal is escalated (see [Provenance by default](#provenance-by-default));
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
  provenance: { mediators: mediator_pins }, # the agent harnesses whose provenance receipts you trust
  provenance_bundle: bundle,                 # what the agent presented with the call (header PCA-Provenance)
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
  `risk_policy`, and liveness beacons (signed revocation epochs are covered by `revocation_staleness`, below). A grant that pins the agent (`agent_binding`) needs an
  attestation verifier and is refused, and so is a proof carrying `zk_compliance`. The TypeScript `authorize` covers
  these.

The Rack middleware runs this pipeline by default; the `authorize:` option carries its components (including `revocation_staleness`, `require_assurance` and `plans`; the `executor:` option is described below). Without `authorize:`
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
      # the agent harnesses you trust; the bundle is read from the PCA-Provenance header or the body member pca_provenance
      provenance: { mediators: mediator_pins },
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
result. The `authorize:` option also accepts `context:`, `require:` (extra checks that must pass), `plan:`, `provenance:` and
`undo:`.

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
- With `revocation_staleness:`, every capability id in the proof's chain now needs a non-membership proof by default; pass `ids: ->(_pcactn) { [] }` to check freshness only.
- With `require_assurance:` set, a denial can name the new `assurance` check.
- Provenance by default: every sensitive operation now needs a provenance bundle from a mediator you pin (or the grant
  names), otherwise it is escalated. Pin your agent harness with `provenance: { mediators: [...] }` and have it present the
  bundle; see [Provenance by default](#provenance-by-default).

### Approved goal binding

An intent policy can commit to a goal the principal approved. `approved_goal` is a closed object of exactly
`goal_digest` and `policy_digest`, each canonical unpadded base64url of 32 bytes:

```ruby
policy = { "approved_goal" => { "goal_digest" => goal_digest, "policy_digest" => policy_digest } }
result = AtlasPca.authorize(pcactn, intent_policy: policy, operation: op, audience: aud, resolve_grant: resolver,
                                    state_store: store, is_revoked: revoked)
```

The root grant's goal commitment then opens only against that approved goal: a grant committed the older way does not
open under it, and a v3 grant does not open under a verifier without `approved_goal`. An extra member or a short, padded
or empty digest is a misconfiguration and denies. `approved_goal` alone switches the intent check on; the fidelity and
risk thresholds still apply. `AtlasPca.intent_goal_commit_v3(ref, salt)` builds the commitment the grant should carry,
and `AtlasPca.approved_goal_ref?(value)` validates a reference. The same `intent_policy:` option works on
`verify_pcactn` and on the Rack middleware.

### Revocation staleness

A signed revocation epoch carries its own expiry, chosen by the signer. `AtlasPca::RevocationStaleness` lets the
verifier cap how old the revocation state may be, with a tighter window for actions that cannot be undone. The action's
class is the stricter of your own class (the `"reversibility_class"` member of `context`) and the class the proof signed; a missing or
unknown class counts as irreversible.

```ruby
staleness = AtlasPca::RevocationStaleness.new(
  guardian_public: guardian_key,            # the pinned key a signed epoch must verify under
  max_revocation_age_ms: 5 * 60_000,        # any action (default 5 minutes)
  staleness: { "irreversible" => 60_000 },  # per class (defaults: irreversible 2 minutes, costly = the maximum)
  proofs: ->(id, _pcactn) { proofs_by_capability_id[id] },
)

result = AtlasPca.authorize(
  pcactn, operation: op, audience: aud, resolve_grant: resolver, state_store: store, is_revoked: revoked,
  revocation_staleness: staleness,
  context: ->(_pcactn) { { "revocation_state" => { "kind" => "epoch", "epoch" => signed_epoch } } },
)
```

- `revocation_state` is either `{ "kind" => "epoch", "epoch" => <guardian-signed epoch> }` (signature, grant binding,
  expiry, rollback and the proof's own epoch are checked, then the age cap) or `{ "kind" => "root", "root" => ...,
  "issued_at" => <ms> }` for a root that is not signed. An unsigned root is refused for an irreversible action unless
  `allow_unsigned_root_for_irreversible: true`, and an unknown `issued_at` denies.
- A state that is too old, from the future, unverifiable or missing for an irreversible action fails the `freshness`
  check. Your boolean `is_revoked` hook keeps deciding revocation itself.
- **Per-capability proofs.** Alongside the age check, every capability id in the proof's chain must have a valid
  non-membership proof against the state's root. `ids:` (`->(pcactn) { [...] }`) overrides which ids are proven; the
  default is every id in the chain, so a revoked ancestor kills its descendants. `proofs:` is a `->(id, pcactn)` callable
  or a Hash keyed by id. A missing proof source or proof denies (`no non-membership proof for <id>`), and so does a
  revoked id or an invalid proof (`capability <id> is revoked or proof invalid`). To check freshness only, pass
  `ids: ->(_pcactn) { [] }`. `AtlasPca.verify_non_membership(root, proof, id)` checks one proof on its own.
- `on_epoch_accepted: ->(epoch, pcactn) { ... }` runs after an admitted action whose epoch passed every check; persist
  it as your rollback pin (`"last_accepted_epoch"` in the state).
- The window helpers are public: `AtlasPca.check_revocation_state`, `check_revocation_age`, `check_revocation_epoch`,
  `revocation_max_age_ms` and `effective_reversibility`. The Rack middleware takes `revocation_staleness:` in its
  `authorize:` options and reads the state from `context`.

### Operation records and the executor

`authorize` consumes the proof's counter, but a crash, a client retry or two workers can still run the side effect twice
or lose track of it. `AtlasPca.execute_authorized` runs an authorized operation at most once and keeps a durable record
per operation id (the digest of the presented proof):

```ruby
ops = AtlasPca::MemoryOperationStore.new # process-local; use a shared, durable store in production

outcome = AtlasPca.execute_authorized(
  result,                                   # an allowing AuthorizeResult
  store: ops,
  operation: { verb: "payments.send", resource: "payments/acme", params: body },
  recheck: ->(handle) { revoked?(handle.pcactn) ? { "ok" => false, "reason" => "revoked" } : { "ok" => true } },
) do |handle|
  charge(body, idempotency_key: handle.idempotency_key) # pass the key to the downstream call
end

outcome.status # "committed", "failed", "aborted", "pending", "uncertain", "refused"
```

- The record is created `pending` before anything runs (one atomic create, so of N concurrent executions exactly one runs
  the block), moves to `executing`, then `committed` (with the block's result) or `failed` (with its error). A second call
  with the same id is answered from the record (`outcome.replayed`) and never runs the block again; a raise from the
  block is recorded, not re-raised.
- An irreversible operation (your `reversibility_class:` or the signed one; unknown counts as irreversible) needs a
  `recheck:`, called immediately before the block; the proof's own expiry is always checked. A refusal records `aborted`.
- `recover_operations(store, older_than_ms:)` (needs `store.list_open`) and `recover_operation(store, id)` settle stale
  records: a `pending` one becomes `aborted` (the side effect never started), an `executing` one `uncertain` (it may or may
  not have happened). Reconcile an uncertain record with the downstream system, using the idempotency key, and settle it with
  `resolve_operation(store, id, { "state" => "committed", "result" => ... })` or `{ "state" => "failed", "error" => ... }`.
- Stores: `MemoryOperationStore`; `KvOperationStore` over `MemoryAtomicKv` or `SqliteAtomicKv`; `AtlasPca.sqlite_operation_store(path)`
  (the `sqlite3` gem, loaded on first use) for a crash-safe store shared by threads and processes. Your own store
  implements `create(record)` (insert if absent, else return the existing one), `get(id)` and `transition(id, from_state, next_record)`
  (a compare-and-set on the state), each atomic across everything that shares it.

`AtlasPca.create_executor` combines `authorize` and `execute_authorized`, so a retry of the same proof is answered from
its record instead of a bare replay denial:

```ruby
executor = AtlasPca.create_executor(
  operations: ops,
  options: AtlasPca::AuthorizeOptions.new(state_store: store, is_revoked: revoked, plans: registry),
  audience: "payments-rs",
  resolve_grant: ->(ref) { grants[ref] },
  reversibility_class_of: ->(operation) { catalog_class(operation) }, # your authoritative class per operation
)

outcome = executor.call(pcactn, operation) { |handle| charge(body, idempotency_key: handle.idempotency_key) }
```

The executor re-runs `is_revoked`, checks the proof's expiry and, with `plans`, that a registered plan is still
executable, right before the block. A denial comes back as `outcome.status == "denied"` with the `AuthorizeResult` in
`outcome.authorization`.

The Rack middleware takes the same thing as `executor: { operations: ops }` (optionally `recheck:`, `recheck_for:`,
`reversibility_class_of:` and `pending_timeout_ms:`): the app runs at most once per authorization, a retry is answered
from the record with a `PCA-Replayed: true` header, a failure answers 500 `operation_failed` without the error text, an
execution still in flight or uncertain answers 409, and a refused re-check answers 403 `operation_aborted`.

### Plan lifecycle

A plan is the list of steps an agent commits to; its Merkle root is signed into every proof. `AtlasPca::PlanRegistry`
gives the principal's approval of a plan an explicit lifecycle (draft, validated, committed, authorized, revoked), and
`authorize` consults it:

```ruby
registry = AtlasPca::PlanRegistry.new # or kv: AtlasPca::SqliteAtomicKv.new("plans.db") for a shared, durable registry

draft = registry.draft(grant_ref, [{ "id" => "pay", "verb" => "payments.send", "resource" => "payments/acme" }])
root  = draft["record"]["root"]          # computed from the nodes, never taken from the caller
registry.validate(grant_ref, root)       # structural checks, then your optional validator: ->(record) { { "ok" => true } }
registry.commit(grant_ref, root)         # the root is fixed; still not executable
registry.authorize(grant_ref, root, { "by" => "principal", "expiresAt" => expires_ms }) # after verifying the principal's consent

AtlasPca.authorize(pcactn, operation: op, audience: aud, resolve_grant: resolver, state_store: store, is_revoked: revoked,
                           plans: registry)
```

Each call returns a Hash with `"ok"`, the `"state"` and a `"reason"` when refused. A plan is executable only while it
is authorized, the approval has not expired and its stored nodes still hash to the root; that is evaluated at the moment of
use, not stored. `revoke(grant_ref, root, reason)` is terminal. `status`, `check(grant_ref, root, node_id:, operation:)` and
`plan_authorized?` answer questions about a plan, and `context(grant_ref, root)` returns what `authorize` needs. With
`plans:`, an unregistered root is refused unless `plan: "single-step"` applies, and a denial names the plan's state in the
`plan_state` check. Concurrent transitions are atomic: of N racing callers exactly one moves the plan.

### Assurance labels

A check's status says whether it held; the assurance report says what a pass rests on: software or hardware attestation,
a SNARK or an attested-VM statement, a post-quantum or an Ed25519 signature, independent shares or an aggregate awaiting audit.
Labels come from your configuration, never from presented evidence. `authorize` verifies no attestation, zk proof or
threshold co-signature itself, so on that path the report rests on the signature suites and on what the proof carries
(a carried feature this SDK does not verify is reported `unsupported`). When you run your own verifiers, label them and
build the report with them:

```ruby
quote_check = AtlasPca.set_assurance_label(->(evidence) { check_quote(evidence) }, "hardware", vendor: "amd-sev-snp")
report = AtlasPca.assurance_report(pcactn, checks, hooks: { "attestation" => quote_check })
AtlasPca.unmet_assurance(report, { "attestation" => "hardware" }) # nil when met, else an "assurance: ..." reason

result = AtlasPca.authorize(pcactn, operation: op, audience: aud, resolve_grant: resolver, state_store: store,
                                    is_revoked: revoked, require_assurance: { "signature" => "pq" })
result.assurance # what every check rests on (present with or without a requirement)
```

An unlabelled hook is `unknown` and satisfies no requirement.

- `require_assurance:` turns the report into a gate. Evidence that is weaker, missing, failed, unlabelled, awaiting-audit,
  degraded or unsupported fails the `assurance` check, and the request is denied before any replay state is written, so
  the counter is not consumed. The reason is prefixed `assurance:`. An unknown requirement key or value is refused.
- Requirement keys: `attestation` (`software` < `hardware` < `multi_root`), `zk` (`attested_vm`, `attested_vm_hardware`,
  `proof`, `snark`), `signature` (`pq`), `threshold` (a list of schemes) and `allow_awaiting_audit`.
- Features this SDK does not verify, such as a carried `bond_ref`, are reported `unsupported`; they are never counted as a pass.
- `AtlasPca.assurance_report`, `unmet_assurance`, `multi_root_level(roots, threshold)` and `signature_level(alg)` are
  public for custom gates.

### Step-up client

When an action needs more than the agent's signature, a step-up asks the principal's device for a co-signature.
`AtlasPca::StepUp::Client` lists pending step-ups and approves or denies them with an Ed25519 device key:

```ruby
store = AtlasPca::StepUp::FileSecretStore.new("device.key") # a mode-0600 file; implement SecretStore for a platform keystore
key   = AtlasPca::StepUp::PrincipalDeviceKey.new(store)
key.generate unless key.exists?

client = AtlasPca::StepUp::Client.new(dashboard_url, instance_url, account_id, instance_id, key, -> { dashboard_token })

client.pending.each do |step_up|          # not-yet-expired step-ups
  puts "#{step_up.action_verb} on #{step_up.action_resource}"
  result = client.approve(step_up)        # signs the threshold message with the device key
  puts result.anchored ? "anchored" : "waiting for more roles"
end
client.deny(other_step_up, "not expected")
```

`approve` and `deny` go to the endpoints your instance and dashboard expose; the dashboard token is a callable, read per
request, and redirects are never followed, so it cannot leak to another host. Errors are typed under `AtlasPca::StepUp`:
`NoDeviceKey`, `InvalidSecret`, `InvalidThresholdMessage`, `PrincipalMismatch` (the server refused this key), `ApiError`
and `TransportError`. The key is a software key; for a phone or desktop app back the secret store with the platform keystore
and gate approvals behind user presence.

### Store conformance

If you write your own replay store or operation store, run the contract against it from a factory that opens a handle on the
backend (one handle is one verifier instance's connection):

```ruby
report = AtlasPca.run_state_store_conformance(-> { MyStateStore.new(dsn) })
raise report.render unless report.ok?

ops_report = AtlasPca.run_operation_store_conformance(-> { MyOperationStore.new(dsn) })
```

The state-store profile checks `claim` over a strictly increasing sequence, a burst of threads on one handle, the same race
across several handles, durability across closing every handle (and `restart:` when given) and crash-after-claim (`crash:`).
The operation-store profile checks atomic create, compare-and-set transitions, copies instead of aliases, races and
durability. Declare `durable: false` or `shared: false` for a process-local store to skip the checks that cannot apply; any
other failure is reported, never skipped. `report.ok?` is false on any failure, `report.failures` lists them and `report.render`
prints every result. Run it more than once for a store you wrote: a racy store is caught with high probability per round.

## Acting as an agent (producing proofs)

The gem also produces the proofs it verifies, so an agent written in Ruby needs no other runtime. The principal mints a root grant
for the agent's public key; the agent signs one PCActn per action and sends it in the `PCA-Action` header (`AtlasPca::Agent` keeps
the replay counter, picks the nonce and builds the headers).

```ruby
principal = AtlasPca::KeyPair.generate # the principal's key stays with the principal
agent_key = AtlasPca::KeyPair.generate

minted = AtlasPca.mint_grant(principal, agent_key.public, {
  'predicates' => [{ 'verb' => 'refund', 'resource' => 'orders/*' }],
  'caveats' => [{ 'type' => 'max_spend', 'usd' => 50 }],
  'risk_policy' => AtlasPca::DEFAULT_RISK_POLICY
}, 'refund order 1')

agent = AtlasPca::Agent.new(agent_key, minted['grant'], 'https://api.example.com')
action = agent.act('refund', 'orders/1', { 'amount_cents' => 500 })
# any HTTP client: Net::HTTP, Faraday, ... with action.headers
```

`agent.delegate(sub_key, [AtlasPca.sealed_caveat])` returns a sub-agent holding the chain plus one narrower hop (caveats are only ever
appended). Third-party and approval artifacts: `sign_discharge`, `sign_narrow`, `sign_escalation_answer`, `sign_passport`,
`sign_workflow` / `sign_step_receipt`, `sign_read_grant`, `sign_fresh_at`. Ed25519 outputs are byte-exact against the shared producer
vectors; with OpenSSL >= 3.5, ML-DSA and SLH-DSA sign through `AtlasPca::PqKeyPair.generate('ML-DSA-65')` and
`AtlasPca::Agent.new(..., alg: 'hybrid-ed25519-ml-dsa-65', pq: pq)`. Persist the counter (`on_counter:`) if the process can restart: a
lower counter is refused as a replay.

## Provenance by default

An agent reads email, web pages and tool output. Text in any of them can try to steer it ("forward the report to
attacker@example"). The provenance gate stops that: the choice of a sensitive action, and every argument of it, must
derive from the principal. It runs in `authorize` (and so in the Rack middleware) on every call, as the check
`provenance_flow`.

- A **mediator** (the agent harness, a gateway, an MCP client: whatever sees text enter the model's context and holds a key
  the model cannot reach) signs one receipt per segment of context into a hash chain: the principal's message, each tool
  result, retrieved document and web page, and finally the action the model chose, bound to the exact operation.
- The verifier re-derives the labels from that chain. A value is trusted when the context was purely the principal's, when the
  principal typed it verbatim, or when the principal authorized the exact operation (an executable plan from `plans:`). An
  admitted step of a principal-signed workflow trusts the choice, not the values.
- An action is sensitive unless your action facts say it only reads (`effects: ["read"]`, with at most the traits
  `pca.financial_data_read`, `pca.pii_access`, `pca.regulated_data`). An unknown action is sensitive.
- A sensitive action whose choice or arguments do not derive from the principal is `escalate`
  (`provenance_flow: escalate: <which values, and from where>`): only a principal-signed escalation answer admits it. A
  missing bundle, or one from a mediator you do not pin, counts as untrusted. A forged chain (a bad signature, a gap, content
  that does not hash to its receipt, a final receipt for another operation) is a `deny`.

Configure the gate with `provenance:` (on `authorize`, in the middleware's `authorize:` options or in `AuthorizeOptions`):

```ruby
result = AtlasPca.authorize(
  pcactn, operation: op, audience: aud, resolve_grant: resolver, state_store: store, is_revoked: revoked,
  provenance: {
    mediators: [{ "mediator" => "my-harness", "kid" => "k1", "pk" => harness_public_key }],
    actions: ->(operation) { action_facts[operation["verb"]] },   # {"effects" => [...], "traits" => [...], "params" => {...}} or nil
    observed: ->(_pcactn, _operation, _session) { [] },             # untrusted content this server itself saw reach the agent
  },
  provenance_bundle: bundle, # or let the middleware read the PCA-Provenance header / pca_provenance body member
)
```

The principal can add its own harness keys in the grant's signed envelope (`provenance: { mediators: [...] }`). The only
opt-out is the same envelope member `provenance: { mode: "insecure_off" }`, which reports the check `not-enforced`. It is
dangerous: injected content can then steer the grant's sensitive actions. Use it only for grants whose every action is
harmless.

**Recording provenance on the agent side.** Run one recorder per agent session where text enters the model's context, with a key
the model cannot reach, and present its bundle with the call:

```ruby
harness_key = AtlasPca::KeyPair.generate
rec = AtlasPca::ProvenanceRecorder.new(mediator: "my-harness", kid: "k1", key: harness_key)
rec.pin                                  # what the verifier pins (or the grant envelope names)

rec.principal("Email the Q3 report to bob@acme.example")  # trusted
rec.tool("crm.lookup", crm_result)                         # untrusted (non-string output is recorded as JSON)
rec.retrieval("doc-17", document_text)                     # untrusted
rec.web("https://example.com/page", page_text)             # untrusted
bundle = rec.for_action(verb: "email.send", resource: "mail", params: { "to" => "bob@acme.example" })

headers["PCA-Provenance"] = AtlasPca.b64e(AtlasPca.canon_bytes(bundle))
```

For an operation that comes straight from the user (your own UI acting on explicit input, no model in between),
`AtlasPca.principal_direct_provenance(rec, operation)` records the operation itself as the principal's message.
`AtlasPca.decide_arg_provenance(input)` is the pure decision, and `occurs_as_token`, `prov_leaves`, `read_only_action?` and
`prov_envelope_error` are public helpers.

## Undo windows

A reversible action can run at once under a veto window instead of waiting for approval: the principal gets a one-click
link to undo it until the window closes. The coordinator that opens windows, runs compensations and notifies the principal
is the TypeScript server or the hosted ledger; this gem verifies what it produces and enforces its admissions.

**Admission in `authorize`.** Pass `undo: ->(pcactn, grant, operation) { admission | nil }`. It is consulted only for an
`escalate` with no escalation answer presented, and never when the escalation came from provenance (`provenance_flow` or
`provenance` failing): reversibility does not make an action injected content chose safe. Return an admission
`{"id", "window_end", "compensation" => {"verb", "resource"}}` only after your undo coordinator has durably opened the window's
record; return nil (or raise) and the escalation stands. On an admission the call is allowed, `result.undo` is the admission,
the check `undo_window` passes, and `result.obligations` carries `{"kind" => "undo_window", "params" => {"id", "window_end"},
"due" => window_end}`. An enforcement point that does not run undo windows must not list `undo_window` as supported:
`AtlasPca.pep_obligation_gate` then turns the allow into a deny.

**Verifying tokens and receipts.**

```ruby
token = AtlasPca.decode_undo_token(params["t"])          # nil unless a token-shaped JSON object
case AtlasPca.undo_token_check(token, undo_service_public_key, record, now_ms)
when "ok" then veto!(record)                             # valid through window_end inclusive
else refuse                                              # malformed, signer, signature, record, binding or expired
end

AtlasPca.undo_receipt_chain_error(record, undo_service_public_key) # nil when the record's receipt chain is sound
```

`AtlasPca.undo_transition(record, event, now)` is the state machine (`open`, `vetoed`, `compensated`,
`compensation_failed`, `finalized`): it returns the next record (version bumped) and the receipt to sign, a replay, or a
refusal code. Also public: `compensation_digest`, `sign_undo_token`, `encode_undo_token`, `undo_token_digest`,
`sign_undo_receipt`, `verify_undo_receipt`, `undo_receipt_digest`, `undo_with_receipt` and `resolve_undo_window`
(clamped to 30 seconds .. 24 hours, default 15 minutes).

## Caveats (policy layer)

The core verifier checks that the PCActn is well formed and authentic; like every PCA core verifier it does not decide
whether the action satisfies the grant's caveats (`authorize` above does). To evaluate caveats yourself, use your own
action parameters: `AtlasPca.evaluate_caveats(AtlasPca.policy_caveats(grant, chain), ctx)`. `policy_caveats` is every caveat on the root grant except its first `envelope` caveat (0.4.1: root caveats
are enforced exactly like delegated ones) followed by the caveats the delegation hops appended. Supported types: `expires`,
`not_before`, `rate`, `max_blast_radius`, `reversibility_max`, `delegation_depth`, `budget_alloc` and `max_spend`; any other
type is unsatisfied (fail closed). The `PCA-Action` header must be strict unpadded base64url of UTF-8 text (`AtlasPca.decode_pca_header(value)`).

## One call: `AtlasPca.protect`, and explaining a refusal

```ruby
prot = AtlasPca.protect(audience: 'payments-rs',
                        grants: ->(ref) { Grant.find_by(ref: ref)&.document },   # or an Array of grants looked up by 'id'
                        operation: ->(env) { operation_for(env) })              # from your routing and body, never the proof
config.middleware.use AtlasPca::RackMiddleware, **prot.options
prot.revoke(grant_id)   # every further action under that grant is refused
```

`protect` fills in the grant lookup (never from the request), an in-memory replay store, a revocation source and
`plan: 'single-step'`. Any `authorize` option you pass wins. The in-memory store is for one process; pass a shared
`state_store` for several workers. This SDK has no connector catalog, so risk is not priced for you.

`AtlasPca.explain_refusal(reason)` returns `check`, `meaning`, `fix` and `docs` for any refusal reason and never raises.
Every 401 and 403 body from the Rack middleware has a `doc` member linking the refusing check; the reason strings are
unchanged. A runnable server is in `examples/rails-server`.

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
