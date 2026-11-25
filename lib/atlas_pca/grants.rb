# frozen_string_literal: true

# The producing side of the operational plane (the TypeScript reference, @atlasauth/pca-grants): domain-separated Ed25519 signing,
# the signers for leases, revocations, blueprints and break-glass records, policy bundle signing and assembly, the decision log (hash
# chain, Merkle commitment, signed heads, inclusion proofs, streaming batches), replay tooling, consistency-token issuing, lease
# renewal, group kill, attestation-gated blueprint admission and the lease-store conformance kit.
#
# The verification side is lease.rb, blueprint.rb, break_glass.rb, fresh_at.rb and k3.rb. A secret is an AtlasPca::KeyPair; a signer
# raises (ArgumentError) on a malformed record, exactly where the reference throws. Records are String-keyed Hashes with the wire keys.
require_relative 'agent'
require_relative 'k3'
require_relative 'lease'
require_relative 'blueprint'
require_relative 'break_glass'
require_relative 'atomic_kv'
require_relative 'js_compat'

module AtlasPca
  module Grants
    module_function

    # JavaScript object spread ({...x}): a Hash copies, an Array or String spreads its indices, anything else adds nothing.
    def spread(x)
      return x.dup if x.is_a?(Hash)
      return x.each_with_index.to_h { |v, i| [i.to_s, v] } if x.is_a?(Array)
      return x.chars.each_with_index.to_h { |v, i| [i.to_s, v] } if x.is_a?(String)

      {}
    end

    def without(o, *drop) = o.reject { |k, _| drop.include?(k) }

    # Object.entries over the shapes a JSON value can take.
    def entries(x)
      return x.to_a if x.is_a?(Hash)
      return x.each_with_index.map { |v, i| [i.to_s, v] } if x.is_a?(Array)
      return x.chars.each_with_index.map { |v, i| [i.to_s, v] } if x.is_a?(String)

      []
    end

    def deep_copy(x) = Marshal.load(Marshal.dump(x))

    # ---- sig.ts ---------------------------------------------------------------------------------------------------------

    def signer_of(key) = key.public

    # Domain-separated Ed25519 signature over strict-canonical JSON (raises on a body outside the strict profile).
    def sign_body(domain, body, key) = AtlasPca.b64e(key.sign(domain.b + AtlasPca.strict_bytes(body)))

    # The reference's signDomainBody: sign_body with the signing key given as a KeyPair or a 32-byte Ed25519 seed.
    def sign_domain_body(domain, body, key) = sign_body(domain, body, key.is_a?(String) ? AtlasPca::KeyPair.new(key) : key)

    def verify_domain_body(domain, body, signer, sig) = AtlasPca.k3_verify_body(domain, body, signer, sig)

    # ---- signers --------------------------------------------------------------------------------------------------------

    def sign_lease(key, l)
      base = { 'v' => 1 }.merge(spread(l)).merge('authority' => signer_of(key))
      raise ArgumentError, 'signLease: a malformed lease, or one past issued_at + max_ttl' if !AtlasPca.lease_well_formed?(base) || base['expires_at'] > AtlasPca.lease_cap(base)

      base.merge('sig' => sign_body(LEASE_DOMAIN, LEASE_BODY_KEYS.to_h { |k| [k, base[k]] }, key))
    end

    # Conformance-vector builder only: signs a record that outlives its cap, to prove verifiers refuse it.
    def sign_lease_unsafe_over_cap(key, l)
      base = { 'v' => 1 }.merge(spread(l)).merge('authority' => signer_of(key))
      raise ArgumentError, 'signLeaseUnsafeOverCap: malformed' unless AtlasPca.lease_well_formed?(base)

      base.merge('sig' => sign_body(LEASE_DOMAIN, LEASE_BODY_KEYS.to_h { |k| [k, base[k]] }, key))
    end

    def sign_lease_revocation(key, r)
      base = { 'v' => 1 }.merge(spread(r)).merge('authority' => signer_of(key))
      raise ArgumentError, 'signLeaseRevocation: malformed' unless AtlasPca.lease_revocation_well_formed?(base)

      base.merge('sig' => sign_body(LEASE_REVOKE_DOMAIN, LEASE_REVOKE_KEYS.to_h { |k| [k, base[k]] }, key))
    end

    def blueprint_body(b) = BLUEPRINT_BODY_KEYS.each_with_object({}) { |k, h| h[k] = b[k] if b.key?(k) }

    def sign_blueprint(key, b)
      base = { 'v' => 1 }.merge(spread(b)).merge('operator' => signer_of(key))
      raise ArgumentError, 'signBlueprint: a malformed blueprint' unless AtlasPca.blueprint_well_formed?(base)

      base.merge('sig' => sign_body(AGENT_BLUEPRINT_DOMAIN, blueprint_body(base), key))
    end

    def sign_break_glass(key, b)
      base = { 'v' => 1 }.merge(spread(b)).merge('authority' => signer_of(key))
      raise ArgumentError, 'signBreakGlass: malformed, or the window is longer than 24 hours, or the budget is outside 1..16' unless AtlasPca.break_glass_well_formed?(base)

      base.merge('sig' => sign_body(BREAK_GLASS_DOMAIN, BREAK_GLASS_BODY_KEYS.to_h { |k| [k, base[k]] }, key))
    end

    def sign_break_glass_review(key, r)
      base = { 'v' => 1 }.merge(spread(r)).merge('reviewer' => signer_of(key))
      raise ArgumentError, 'signBreakGlassReview: malformed' unless AtlasPca.break_glass_review_well_formed?(base)

      base.merge('sig' => sign_body(BREAK_GLASS_REVIEW_DOMAIN, BREAK_GLASS_REVIEW_KEYS.to_h { |k| [k, base[k]] }, key))
    end

    # ---- policy bundles -------------------------------------------------------------------------------------------------

    # One signer's signature over the bundle body: { 'signer', 'sig' }. Collect k of them and call assemble_bundle.
    def sign_bundle(body, key)
      e = AtlasPca.bundle_shape_error(body)
      raise ArgumentError, "signBundle: #{e}" if e

      { 'signer' => signer_of(key), 'sig' => sign_body(BUNDLE_DOMAIN, without(body, 'sigs'), key) }
    end

    def assemble_bundle(body, sigs) = without(body, 'sigs').merge('sigs' => sigs)

    def verify_bundle(b, o) = AtlasPca.verify_bundle(b, o)

    # ---- decision records -----------------------------------------------------------------------------------------------

    # Mask by data CLASS: every detail field whose class is in mask_classes becomes a commitment.
    def mask_record(r, mask_classes)
      return r if !Js.truthy?(r['detail']) || !Js.truthy?(r['classes'])

      classes = r['classes']
      detail = {}
      entries(r['detail']).each do |k, v|
        cls = classes.is_a?(Hash) ? classes[k] : nil
        detail[k] = !cls.nil? && mask_classes.include?(cls) ? "masked:#{Js.string(cls)}:#{AtlasPca.hash_canonical({ 'd' => 'atlas-pca/mask/v1', 'k' => k, 'v' => v })}" : v
      end
      r.merge('detail' => detail)
    end

    # RFC 6962 audit path of leaf `index`: { index, size, path: [{side, hash}] }. Raises on an index out of range.
    def merkle_proof(leaves, index)
      ok = (index.is_a?(Integer) || (index.is_a?(Float) && index.finite? && index == index.floor)) && index >= 0 && index < leaves.length
      raise RangeError, 'merkleProof: index out of range' unless ok

      path = []
      prove = nil
      prove = lambda do |hs, idx|
        next if hs.length == 1

        k = AtlasPca.split_point(hs.length)
        if idx < k
          prove.call(hs[0, k], idx)
          path << { 'side' => 'R', 'hash' => AtlasPca.b64e(AtlasPca.build(hs[k..])) }
        else
          prove.call(hs[k..], idx - k)
          path << { 'side' => 'L', 'hash' => AtlasPca.b64e(AtlasPca.build(hs[0, k])) }
        end
      end
      prove.call(leaves.map { |x| AtlasPca.leaf_hash(x) }, index.to_i)
      { 'index' => index, 'size' => leaves.length, 'path' => path }
    end

    # Append-only decision log: hash-chained, Merkle-committed, with signed heads and inclusion proofs.
    class DecisionLog
      def initialize(key, mask_classes = nil)
        @key = key
        @mask = mask_classes.nil? ? [] : mask_classes.to_a
        @recs = []
      end

      def size = @recs.length
      def signer = @key.public

      def append(r)
        masked = Grants.mask_record(r, @mask)
        rec = { 'v' => 1 }.merge(Grants.spread(masked)).merge('seq' => @recs.length, 'prev' => @recs.empty? ? '' : AtlasPca.record_commit(@recs.last))
        @recs << rec
        rec
      end

      def head(now)
        last = @recs.last
        base = { 'v' => 1, 'size' => @recs.length, 'root' => AtlasPca.merkle_root(@recs.map { |r| AtlasPca.record_commit(r) }),
                 'last_commit' => last.nil? ? '' : AtlasPca.record_commit(last), 'issued_at' => now, 'signer' => signer }
        base.merge('sig' => Grants.sign_body(LOG_HEAD_DOMAIN, base, @key))
      end

      def proof(seq) = Grants.merkle_proof(@recs.map { |r| AtlasPca.record_commit(r) }, seq)

      def slice(start, finish) = @recs[start...finish] || []
    end

    # The next batch of at most max records starting at `from` (the stream cursor) with a freshly signed head.
    def next_batch(log, from, max, now)
      raise ArgumentError, 'nextBatch: bad cursor or size' if !Js.safe_integer?(from) || from.negative? || !Js.safe_integer?(max) || max < 1

      { 'from' => from, 'records' => log.slice(from.to_i, from.to_i + max.to_i), 'head' => log.head(now) }
    end

    RANK = { 'deny' => 0, 'escalate' => 1, 'allow' => 2 }.freeze

    def rank(x) = x.is_a?(String) ? RANK[x] : nil
    def rank_gt?(a, b) = !a.nil? && !b.nil? && a > b

    # "What would have changed": re-run the pure decision function over recorded traffic under two revisions.
    def semantic_diff(cases, old_decide, new_decide)
      out = []
      cases.each do |c|
        before = old_decide.call(c['input'])
        after = new_decide.call(c['input'])
        next if before == after

        out << { 'action_digest' => c['action_digest'], 'before' => before, 'after' => after,
                 'direction' => rank_gt?(rank(after), rank(before)) ? 'widened' : 'tightened' }
      end
      out
    end

    # Records whose logged decision differs from a replay under their own revision's decide function (tamper or drift).
    def audit_replay(records, cases, decide)
      by_action = cases.to_h { |c| [c['action_digest'], c['input']] }
      records.select { |r| by_action.key?(r['action_digest']) && decide.call(by_action[r['action_digest']], r['bundle_revision']) != r['decision'] }
    end

    # ---- consistency tokens (issuing side) ------------------------------------------------------------------------------

    def fresh_body(t)
      %w[v scope revocation_epoch ledger_tree_size budget_version policy_revision policy_digest issued_at signer].to_h { |k| [k, t[k]] }
    end

    def sign_fresh_at(key, scope, state, issued_at)
      ok = AtlasPca.k3_str?(scope, 256) && AtlasPca.k3_str?(state['policy_digest'], 128) && FRESH_AT_NUMERIC.all? { |k| AtlasPca.k3_int?(state[k]) } && AtlasPca.k3_int?(issued_at)
      raise ArgumentError, 'signFreshAt: a malformed state' unless ok

      base = { 'v' => 1, 'scope' => scope }.merge(state).merge('issued_at' => issued_at, 'signer' => signer_of(key))
      base.merge('sig' => sign_body(FRESH_AT_DOMAIN, fresh_body(base), key))
    end

    # Field-wise maximum of two states (the client-side fold). Equal revisions with different digests keep a's digest.
    def merge_fresh_at(a, b)
      {
        'revocation_epoch' => [a['revocation_epoch'], b['revocation_epoch']].max,
        'ledger_tree_size' => [a['ledger_tree_size'], b['ledger_tree_size']].max,
        'budget_version' => [a['budget_version'], b['budget_version']].max,
        'policy_revision' => [a['policy_revision'], b['policy_revision']].max,
        'policy_digest' => b['policy_revision'] > a['policy_revision'] ? b['policy_digest'] : a['policy_digest']
      }
    end

    # Compose a freshness verdict into a decision: it can only tighten (allow -> escalate/deny), never loosen.
    def gate_decision(decision, v)
      return 'deny' if decision == 'deny' || v['decision'] == 'deny'
      return 'escalate' if v['decision'] == 'escalate'

      decision
    end

    # Verifier-side state holder: advance on every write, mint the token for the write, check incoming tokens.
    class FreshAtIssuer
      attr_reader :scope

      def initialize(key, scope, initial)
        @key = key
        @scope = scope
        @state = initial.dup
      end

      def current = @state.dup

      # Apply a write (any subset of counters; each only moves forward) and return its token.
      def advance(patch, now)
        @state = Grants.merge_fresh_at(@state, @state.merge(patch))
        Grants.sign_fresh_at(@key, @scope, @state, now)
      end

      def check(token, now, max_token_age_ms = nil)
        AtlasPca.check_fresh_at(token, @state, signer: @key.public, scope: @scope, now: now, max_token_age_ms: max_token_age_ms)
      end
    end

    # ---- leases: renewal ------------------------------------------------------------------------------------------------

    # Authority side: sign and register the next record of a lease. veto.(current) == true refuses a renewal; it can never lengthen one.
    def renew_lease(key, registry, lease_id, now, increment, justification_digest, approvers: nil, veto: nil, chain: nil)
      return { 'ok' => false, 'code' => 'bad_input' } if !AtlasPca.k3_int?(now) || !AtlasPca.k3_int?(increment) || increment < 1

      cur = registry.get(lease_id)
      return { 'ok' => false, 'code' => 'unknown_lease' } if cur.nil?
      return { 'ok' => false, 'code' => 'vetoed' } if !veto.nil? && veto.call(cur) == true

      expires = [now + increment, AtlasPca.lease_cap(cur)].min
      rest = without(cur, 'v', 'sig', 'authority')
      begin
        record = sign_lease(key, rest.merge('seq' => cur['seq'] + 1, 'renewed_at' => now, 'expires_at' => expires,
                                            'justification_digest' => justification_digest, 'approvers' => approvers.nil? ? cur['approvers'] : approvers))
      rescue StandardError
        return { 'ok' => false, 'code' => expires <= now ? 'expired_lease' : 'bad_input' }
      end
      r = registry.accept(record, chain.nil? ? [] : chain)
      r['ok'] ? { 'ok' => true, 'record' => record } : { 'ok' => false, 'code' => r['code'] }
    end

    # ---- blueprints: group kill and attestation-gated admission ---------------------------------------------------------

    # GROUP KILL: the operator signs the blueprint as disabled at the next epoch; the registry accepts it and, given `revocation`
    # (revoke({kind, value, reason, revokedAt})), also revokes the blueprint key as an issuer; given `fresh_at` (a FreshAtIssuer)
    # its revocation_epoch advances to the record's epoch and the token is returned.
    def group_kill(key, registry, bp_key, now, reason: nil, revocation: nil, fresh_at: nil)
      cur = registry.get(bp_key)
      return { 'ok' => false, 'code' => 'unknown_blueprint' } if cur.nil?

      record = sign_blueprint(key, without(cur, 'sig', 'operator', 'v').merge('status' => 'disabled', 'epoch' => cur['epoch'] + 1, 'issued_at' => now))
      r = registry.accept(record)
      return r unless r['ok']

      revocation&.revoke({ 'kind' => 'issuer', 'value' => bp_key, 'reason' => reason.nil? ? 'blueprint disabled (group kill)' : reason, 'revokedAt' => now })
      out = { 'ok' => true, 'record' => record }
      out['freshAt'] = fresh_at.advance({ 'revocation_epoch' => record['epoch'] }, now) unless fresh_at.nil?
      out
    end

    def pin_matches?(pin, ident)
      ents = entries(pin)
      !ents.empty? && ents.all? { |k, v| !v.nil? && ident.is_a?(Hash) && ident.key?(k) && ident[k] == v }
    end

    # Admit from adapter evidence { ok, bound, identity?, reason? }: ok and bound must both be exactly true, and the identity the
    # adapter established must match one runtime pin. A raised error or malformed result denies.
    def admit_with_evidence(blueprint, get_evidence)
      pins = blueprint['runtime_pins']
      return { 'admitted' => false, 'code' => 'no_pins' } if pins.nil? || pins.length.zero?

      begin
        r = get_evidence.call
      rescue StandardError => e
        return { 'admitted' => false, 'code' => 'verifier_error', 'reason' => e.class.name.split('::').last }
      end
      g = ->(k) { r.is_a?(Hash) ? r[k] : nil }
      unless g.call('ok') == true
        return { 'admitted' => false, 'code' => 'not_ok' }.merge(g.call('reason').is_a?(String) ? { 'reason' => g.call('reason') } : {})
      end
      return { 'admitted' => false, 'code' => 'not_bound' } unless g.call('bound') == true

      ident = g.call('identity')
      return { 'admitted' => false, 'code' => 'no_identity' } unless ident.is_a?(Hash) || ident.is_a?(Array)

      pins.each { |p| return { 'admitted' => true, 'identity' => ident, 'pin' => p } if pin_matches?(p, ident) }
      { 'admitted' => false, 'code' => 'no_matching_pin' }
    end

    # Admit through a hardware attestation verifier: verifier.({document, ctx, nowMs, expected}) -> {ok, bound, measured?, reason?}.
    # No pins or no evidence is a denial.
    def admit_blueprint_instance(blueprint, document, verifier, now_ms, ctx = nil, expected = nil)
      pins = blueprint['runtime_pins']
      return { 'admitted' => false, 'code' => 'no_pins' } if pins.nil? || pins.length.zero?
      return { 'admitted' => false, 'code' => 'not_ok', 'reason' => 'no evidence' } if document.nil?

      evidence = lambda do
        h = verifier.call({ 'document' => document, 'ctx' => ctx, 'nowMs' => now_ms, 'expected' => expected })
        g = ->(k) { h.is_a?(Hash) ? h[k] : nil }
        out = { 'ok' => g.call('ok') == true, 'bound' => g.call('bound') == true }
        out['identity'] = g.call('measured') if Js.truthy?(g.call('measured'))
        out['reason'] = g.call('reason') if g.call('reason').is_a?(String)
        out
      end
      admit_with_evidence(blueprint, evidence)
    end

    # Holds admissions by instance key, blueprint key and the blueprint EPOCH they were made under; plug checker(now) into the check as `admitted`.
    class AdmissionRegistry
      def initialize = @m = {}

      def admit(instance_key, bp, til)
        @m["#{bp['key']}\0#{instance_key}"] = { 'epoch' => bp['epoch'], 'until' => til }
        nil
      end

      def revoke(instance_key, bp_key) = !@m.delete("#{bp_key}\0#{instance_key}").nil?

      def checker(now)
        lambda do |instance_key, bp|
          a = @m["#{bp['key']}\0#{instance_key}"]
          !a.nil? && a['epoch'] == bp['epoch'] && now < a['until']
        end
      end
    end

    # ---- lease store conformance kit ------------------------------------------------------------------------------------

    class LeaseStoreConformanceError < StandardError; end

    CONF_SK = ([61] * 32).pack('C*').freeze
    CONF_T0 = 1_800_000_000_000
    CONF_DAY = 86_400_000

    def conf_mk(lease_id, **over)
      base = { 'lease_id' => lease_id, 'path' => "svc/#{lease_id.length % 3}/#{lease_id}", 'grant_ref' => "g-#{lease_id}", 'holder' => 'agent',
               'requester' => 'alice', 'approvers' => ['bob'], 'justification_digest' => 'j1', 'seq' => 1, 'issued_at' => CONF_T0, 'renewed_at' => CONF_T0,
               'expires_at' => CONF_T0 + 600_000, 'max_ttl' => 3_600_000 }
      over.each { |k, v| base[k.to_s] = v }
      base
    end

    def conf_fail(check, detail) = raise(LeaseStoreConformanceError, "lease store conformance: #{check}: #{detail}")

    def conf_expect_eq(check, got, want)
      conf_fail(check, "got #{AtlasPca.canonicalize(got)}, want #{AtlasPca.canonicalize(want)}") unless AtlasPca.canonicalize(got) == AtlasPca.canonicalize(want)
    end

    # Run against any lease key-value store (get(key) and an atomic update(key) { |prev| next }) before trusting it with leases.
    # open_ returns a fresh empty store; reopen.(kv) the same store opened again as a restarted process would (nil skips the restart
    # check). Raises LeaseStoreConformanceError on the first failure and returns the names of the checks passed.
    def run_lease_store_conformance(open_, reopen: nil, shards: 16)
      passed = []
      key = KeyPair.new(CONF_SK)
      auth = key.public
      policy = { 'authorities' => [auth] }
      mk = method(:conf_mk)

      # 1. spread
      reg = LeaseRegistry.new(policy, open_.call, shards: shards)
      ids = (0...256).map { |i| "lease-#{i}" }
      ids.each { |i| conf_expect_eq("spread: issue #{i}", reg.accept(sign_lease(key, mk.call(i)))['ok'], true) }
      per = Array.new(shards, 0)
      ids.each { |i| per[AtlasPca.kv_shard_of(i, shards)] += 1 }
      conf_fail('spread', "256 leases landed #{AtlasPca.canonicalize(per)}") if per.max > ids.length / 4.0 || per.count(&:positive?) < shards / 2.0
      ids.each do |i|
        got = reg.get(i)
        conf_fail('spread', "#{i} not found after issue") if got.nil? || got['lease_id'] != i
      end
      passed << 'spread'

      # 2. atomic update: of many concurrent renewals of one lease exactly one wins and the rest are forks
      reg = LeaseRegistry.new(policy, open_.call, shards: shards)
      reg.accept(sign_lease(key, mk.call('hot')))
      rivals = (0...8).map do |i|
        sign_lease(key, mk.call('hot', seq: 2, renewed_at: CONF_T0 + 1000, expires_at: CONF_T0 + 700_000 + i, justification_digest: "r#{i}"))
      end
      results = rivals.map { |r| Thread.new { reg.accept(r) } }.map(&:value)
      conf_expect_eq('atomic: one winner', results.count { |r| r['ok'] }, 1)
      conf_expect_eq('atomic: the rest are forks', results.count { |r| !r['ok'] && r['code'] == 'lease_fork' }, 7)
      conf_expect_eq('atomic: ledger length', reg.history('hot').map { |h| h['seq'] }, [1, 2])
      passed << 'atomic update'

      # 3. independence
      reg = LeaseRegistry.new(policy, open_.call, shards: shards)
      ids = (0...32).map { |i| "ind-#{i}" }
      ids.each { |i| reg.accept(sign_lease(key, mk.call(i))) }
      renewed = ids.map { |i| reg.accept(sign_lease(key, mk.call(i, seq: 2, renewed_at: CONF_T0 + 10, expires_at: CONF_T0 + 900_000, justification_digest: 'j2'))) }
      conf_expect_eq('independence', renewed.all? { |r| r['ok'] }, true)
      passed << 'independent leases'

      # 4 + 5. revocation placement
      reg = LeaseRegistry.new(policy, open_.call, shards: shards)
      ids = (0...64).map { |i| "rv-#{i}" }
      ids.each { |i| reg.accept(sign_lease(key, mk.call(i, path: 'db/prod/ro'))) }
      lone = sign_lease(key, mk.call('lone', path: 'other/x'))
      reg.accept(lone)
      by_lease = sign_lease_revocation(key, { 'target' => 'lease', 'value' => 'lone', 'revoked_at' => CONF_T0 + 5 })
      conf_expect_eq('revoke by lease', reg.revoke(by_lease), { 'ok' => true, 'revoked' => 1 })
      holders = (0...shards).count { |i| !reg.shard_revocations(i).empty? }
      conf_expect_eq('lease revocation lands in exactly one shard', holders, 1)
      conf_expect_eq('revoked lease is dead', AtlasPca.check_lease(lone, reg, CONF_T0 + 6)['decision'], 'deny')
      by_prefix = sign_lease_revocation(key, { 'target' => 'prefix', 'value' => 'db/prod', 'revoked_at' => CONF_T0 + 10 })
      conf_expect_eq('revoke by prefix covers every lease in every shard', reg.revoke(by_prefix), { 'ok' => true, 'revoked' => 64 })
      conf_expect_eq('revoke twice is idempotent', reg.revoke(by_prefix), { 'ok' => true, 'revoked' => 64 })
      shards.times do |i|
        lst = reg.shard_revocations(i)
        conf_fail('prefix revocation in every shard', "shard #{i} lacks it") unless lst.any? { |r| r['sig'] == by_prefix['sig'] }
        conf_expect_eq("no duplicate in shard #{i}", lst.count { |r| r['sig'] == by_prefix['sig'] }, 1)
      end
      ids.each do |i|
        cur = reg.get(i)
        conf_expect_eq("check #{i}", AtlasPca.check_lease(cur, reg, CONF_T0 + 11)['decision'], 'deny')
        conf_expect_eq("renewal of #{i} refused",
                       reg.accept(sign_lease(key, mk.call(i, path: 'db/prod/ro', seq: 2, renewed_at: CONF_T0 + 20, expires_at: CONF_T0 + 700_000, justification_digest: 'x')))['ok'], false)
      end
      fresh = sign_lease(key, mk.call('after', path: 'db/prod/ro', issued_at: CONF_T0 + 100, renewed_at: CONF_T0 + 100, expires_at: CONF_T0 + 900_000))
      conf_expect_eq('a lease issued after the revocation is new', reg.accept(fresh)['ok'], true)
      passed << 'revocation placement'

      # 6. shard-count mismatch
      kv = open_.call
      LeaseRegistry.new(policy, kv, shards: shards).accept(sign_lease(key, mk.call('m1')))
      other = LeaseRegistry.new(policy, kv, shards: shards * 2)
      conf_expect_eq('shard mismatch accept', other.accept(sign_lease(key, mk.call('m2'))), { 'ok' => false, 'code' => 'store_unreachable' })
      conf_expect_eq('shard mismatch check', AtlasPca.check_lease(sign_lease(key, mk.call('m1')), other, CONF_T0 + 1)['decision'], 'deny')
      passed << 'shard count is pinned'

      # 7. restart
      unless reopen.nil?
        kv = open_.call
        reg = LeaseRegistry.new(policy, kv, shards: shards)
        l = sign_lease(key, mk.call('persist'))
        reg.accept(l)
        reg.accept(sign_lease(key, mk.call('persist', seq: 2, renewed_at: CONF_T0 + 5, expires_at: CONF_T0 + 800_000, justification_digest: 'j2')))
        reg.revoke(sign_lease_revocation(key, { 'target' => 'prefix', 'value' => 'gone', 'revoked_at' => CONF_T0 + 50 }))
        again = LeaseRegistry.new(policy, reopen.call(kv), shards: shards)
        conf_expect_eq('restart: renewal ledger', again.history('persist').map { |h| h['seq'] }, [1, 2])
        conf_expect_eq('restart: revocation kept', again.shard_revocations(0).length, 1)
        conf_expect_eq('restart: old record still superseded', AtlasPca.check_lease(l, again, CONF_T0 + 6)['decision'], 'deny')
        passed << 'state survives a restart'
      end

      # 8. ceiling and pruning
      now = [CONF_T0]
      reg = LeaseRegistry.new({ 'authorities' => [auth], 'maxTtlCeiling' => CONF_DAY }, open_.call, shards: shards, clock: -> { now[0] })
      conf_expect_eq('ceiling refuses a longer max_ttl', reg.accept(sign_lease(key, mk.call('big', max_ttl: CONF_DAY + 1, expires_at: CONF_T0 + 1000))), { 'ok' => false, 'code' => 'ttl_ceiling' })
      reg.accept(sign_lease(key, mk.call('small', max_ttl: CONF_DAY)))
      reg.revoke(sign_lease_revocation(key, { 'target' => 'prefix', 'value' => 'svc', 'revoked_at' => CONF_T0 }))
      shards.times { |i| conf_expect_eq("kept before the ceiling passes (shard #{i})", reg.shard_revocations(i).length, 1) }
      now[0] = CONF_T0 + CONF_DAY + 1
      reg.accept(sign_lease(key, mk.call('trigger', issued_at: now[0], renewed_at: now[0], expires_at: now[0] + 1000, max_ttl: 5000)))
      reg.revoke(sign_lease_revocation(key, { 'target' => 'prefix', 'value' => 'zzz', 'revoked_at' => now[0] }))
      shards.times do |i|
        left = reg.shard_revocations(i).map { |r| r['value'] }
        conf_fail('pruning', "shard #{i} still holds the expired revocation") if left.include?('svc')
        conf_fail('pruning', "shard #{i} lost the fresh revocation") unless left.include?('zzz')
      end
      passed << 'pruning bounds revocations'
      passed
    end
  end
end
