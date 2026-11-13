# frozen_string_literal: true

# c28: survivors of lib/atlas_pca/caveat_lang.rb, lib/atlas_pca/assurance.rb and lib/atlas_pca/missing_context.rb (round 2).
# Every expected value is derived by reading the library and the TypeScript reference (caveat-lang.ts, missing-context.ts);
# AtlasPca is resolved at CALL time inside each block (the oracle drops and re-evaluates the module for every mutant).
# The tests that sign real Ed25519 artifacts use literal domain strings, never the library constants.
require 'timeout'
require 'openssl'
require 'base64'
require 'digest'

module MutationKill
  module C28
    GATE = %w[caveat_lang.rb assurance.rb missing_context.rb].freeze
    NOW = 1_800_000_000_000
    KEY = OpenSSL::PKey.generate_key('ED25519')
    PK = Base64.urlsafe_encode64(KEY.raw_public_key, padding: false)
    CAP = Base64.urlsafe_encode64("\x07".b * 32, padding: false)
    LEAF = { 'id' => 'leaf', 'issuer' => 'i', 'holder' => PK, 'caveats' => [] }.freeze

    # A store that records its calls: both consume_once and claim.
    class SpyStore
      attr_reader :calls

      def initialize(ret)
        @ret = ret
        @calls = []
      end

      def consume_once(slot, till, now)
        @calls << [:consume_once, slot, till, now]
        raise 'runaway store loop' if @calls.size > 100

        @ret
      end

      def claim(slot, count)
        @calls << [:claim, slot, count]
        raise 'runaway store loop' if @calls.size > 100

        @ret
      end
    end

    # A store with only claim (the fallback path).
    class ClaimOnly
      attr_reader :calls

      def initialize(ret)
        @ret = ret
        @calls = []
      end

      def claim(slot, count)
        @calls << [:claim, slot, count]
        @ret
      end
    end

    class Boom
      def consume_once(_slot, _till, _now) = raise(ArgumentError, 'boom')
    end

    module_function

    def skip? = (f = ENV['MUT_FILE']) && !f.empty? && !GATE.include?(f)

    def b64(bin) = Base64.urlsafe_encode64(bin, padding: false)

    def same?(a, b) = a == b && a.class == b.class

    def eq(label, got, want)
      raise "c28 #{label}: got #{got.inspect}, want #{want.inspect}" unless same?(got, want)

      true
    end

    # An object that is not a String but answers to_str and equals `str` (Array#include? / String#== then accept it).
    def duck(str)
      Class.new do
        define_method(:to_str) { str }
        define_method(:==) { |o| o.to_s == str }
      end.new
    end

    def slot(cap, id, i)
      b64(Digest::SHA256.digest("atlas-pca/max-uses/v1\x00".b + cap.to_s.b + "\x00".b + id.to_s.b + "\x00".b + i.to_s.b))
    end

    def grant(*caveats)
      { 'id' => 'g', 'issuer' => 'i', 'holder' => 'h', 'caveats' => caveats }
    end

    def nd_caveat(extra = {})
      { 'type' => 'needs_discharge', 'id' => 'kyc', 'issuer' => 'bank', 'issuer_class' => 'org', 'bind' => 'chain_hop',
        'ttl_ms' => 3_600_000, 'require' => [] }.merge(extra)
    end

    def pin(extra = {})
      { 'label' => 'bank', 'class' => 'org', 'pk' => PK }.merge(extra)
    end

    def discharge(cap, claims: {}, nonce: 1, caveat_id: 'kyc', issuer: 'bank', signed: true)
      d = { 'v' => 1, 'kind' => 'pca-discharge', 'caveat_id' => caveat_id, 'issuer' => issuer, 'cap_hash' => cap, 'bind' => 'chain_hop',
            'claims' => claims, 'iat' => NOW - 1000, 'not_after' => NOW + 1000, 'nonce' => b64([nonce].pack('C') * 16) }
      d['sig'] = signed ? b64(KEY.sign(nil, AtlasPca.wb_artifact_message("atlas-pca/discharge/v1\x00", d))) : 'x'
      d
    end

    def narrow(cap, extra: {}, signed: true)
      n = { 'v' => 1, 'kind' => 'pca-narrow', 'cap_hash' => cap, 'holder' => PK, 'caveats' => [{ 'type' => 'note' }],
            'iat' => NOW - 1000, 'not_after' => NOW + 1000, 'nonce' => b64("\x02".b * 16) }.merge(extra)
      n['sig'] = signed ? b64(KEY.sign(nil, AtlasPca.wb_artifact_message("atlas-pca/narrow/v1\x00", n))) : 'x'
      n
    end

    def derive_caveat(score)
      { 'type' => 'derive', 'id' => 'dv', 'defs' => [{ 'name' => 's', 'kind' => 'claim', 'caveat_id' => 'kyc', 'claim' => 'score' }],
        'check' => { 'op' => 'eq', 'a' => { 'ref' => 's' }, 'b' => { 'const' => score } } }
    end

    def hook(level, **kw) = AtlasPca.set_assurance_label(Object.new, level, **kw)

    # =================================================================================================================
    # caveat_lang.rb
    # =================================================================================================================

    MutationKill.t('c28 caveat_lang: k1_type? exact over every operand') do
      next true if skip?

      d = duck('sealed')
      [[{ 'type' => 'sealed' }, true], [{ 'type' => 'max_uses' }, true], [{ 'type' => 'zzz' }, false], [{ 'type' => 5 }, false],
       [{ 'type' => nil }, false], [{}, false], [nil, false], [5, false], ['sealed', false], [[], false],
       [{ 'type' => d }, false]].each_with_index do |(c, want), i|
        eq("k1_type? #{i}", AtlasPca.k1_type?(c), want)
      end
      true
    end

    MutationKill.t('c28 caveat_lang: k1_err_text is the message as a String') do
      next true if skip?

      odd = Class.new(StandardError) { def message = 5 }
      eq('plain', AtlasPca.k1_err_text(RuntimeError.new('x')), 'x')
      eq('non-string message', AtlasPca.k1_err_text(odd.new), '5')
    end

    MutationKill.t('c28 caveat_lang: spiffe_id_error reads bytes (a UTF-16 string is not spiffe://)') do
      next true if skip?

      eq('utf16', AtlasPca.spiffe_id_error('spiffe://a'.encode('UTF-16LE')), 'SPIFFE ID must begin with spiffe://')
      eq('ok', AtlasPca.spiffe_id_error('spiffe://a.b/x/y'), nil)
      eq('trailing slash', AtlasPca.spiffe_id_error('spiffe://a/x/'), 'path must not end with a slash')
      eq('empty segment', AtlasPca.spiffe_id_error('spiffe://a//x'), 'invalid path segment')
      eq('dot segment', AtlasPca.spiffe_id_error('spiffe://a/./x'), 'invalid path segment')
      eq('empty td', AtlasPca.spiffe_id_error('spiffe:///x'), 'invalid trust domain')
    end

    MutationKill.t('c28 caveat_lang: bound_caveats ignores non-Hash hops and non-Array caveat lists, totals on a duck leaf') do
      next true if skip?

      leaf = { 'id' => 'l', 'caveats' => [{ 'type' => 'note' }] }
      want = [{ 'caveat' => { 'type' => 'note' }, 'hop' => 1, 'cap_hash' => AtlasPca.cap_hash(leaf) }]
      eq('object hop skipped', AtlasPca.bound_caveats(leaf, [Object.new, leaf]), want)
      eq('nil hop skipped', AtlasPca.bound_caveats(leaf, [nil, leaf]), want)
      eq('string caveats hop skipped', AtlasPca.bound_caveats(leaf, [{ 'caveats' => 'zzzz' }, leaf]), want)
      leaf_duck = Class.new { def [](_k) = [] }.new
      eq('duck leaf is malformed', AtlasPca.bound_caveats(leaf_duck, nil), nil)
      eq('duck leaf in chain', AtlasPca.bound_caveats(leaf, [leaf_duck]), nil)
      eq('no chain, no caveats array', AtlasPca.bound_caveats({ 'caveats' => 'x' }), nil)
      eq('nil grant', AtlasPca.bound_caveats(nil), nil)
    end

    MutationKill.t('c28 caveat_lang: bound_caveats hashes each hop once, and a hashing fault is nil') do
      next true if skip?

      leaf = { 'id' => 'l', 'caveats' => [{ 'type' => 'a' }, { 'type' => 'b' }] }
      calls = 0
      r = MutationKill::Seam.with(AtlasPca, { cap_hash: ->(_c) { calls += 1; 'H' } }) { AtlasPca.bound_caveats(leaf, nil) }
      eq('result', r, [{ 'caveat' => { 'type' => 'a' }, 'hop' => 0, 'cap_hash' => 'H' }, { 'caveat' => { 'type' => 'b' }, 'hop' => 0, 'cap_hash' => 'H' }])
      eq('one hash per hop', calls, 1)
      r = MutationKill::Seam.with(AtlasPca, { cap_hash: ->(_c) { raise 'boom' } }) { AtlasPca.bound_caveats(leaf, nil) }
      eq('fault', r, nil)
    end

    MutationKill.t('c28 caveat_lang: bound_caveats falls back to the last hop when no hop reports a longer list') do
      next true if skip?

      liar = Class.new(Array) { def length = 0 }.new
      liar << { 'type' => 'note' }
      leaf = { 'id' => 'l', 'caveats' => liar }
      r = MutationKill::Seam.with(AtlasPca, { cap_hash: ->(_c) { 'H' } }) { AtlasPca.bound_caveats(leaf, nil) }
      eq('fallback hop', r, [{ 'caveat' => { 'type' => 'note' }, 'hop' => 0, 'cap_hash' => 'H' }])
    end

    MutationKill.t('c28 caveat_lang: k1_require_error is nil on a good requirement') do
      next true if skip?

      eq('ok', AtlasPca.k1_require_error({ 'claim' => 'a', 'op' => 'eq', 'value' => 1 }), nil)
      eq('not object', AtlasPca.k1_require_error(5), 'requirement must be an object')
    end

    MutationKill.t('c28 caveat_lang: discharge_action_digest pins domain and member names') do
      next true if skip?

      pc = { 'a' => 1, 'sig' => 'x' }
      want = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/discharge-action/v1', 'pcactn' => pc })
      eq('digest', AtlasPca.discharge_action_digest(pc), want)
      eq('literal domain', AtlasPca::DISCHARGE_ACTION_DOMAIN, 'atlas-pca/discharge-action/v1')
    end

    MutationKill.t('c28 caveat_lang: k1_claim_holds? is exactly false for a missing claim and an unknown op') do
      next true if skip?

      eq('missing', AtlasPca.k1_claim_holds?({ 'claim' => 'x', 'op' => 'eq', 'value' => 1 }, {}), false)
      eq('unknown op', AtlasPca.k1_claim_holds?({ 'claim' => 'x', 'op' => 'zz', 'value' => 1 }, { 'x' => 1 }), false)
      eq('eq', AtlasPca.k1_claim_holds?({ 'claim' => 'x', 'op' => 'eq', 'value' => 1 }, { 'x' => 1 }), true)
      eq('in', AtlasPca.k1_claim_holds?({ 'claim' => 'x', 'op' => 'in', 'value' => [2, 1] }, { 'x' => 1 }), true)
    end

    MutationKill.t('c28 caveat_lang: verify_discharge is ok without issuer_spiffe whatever spiffe_id the pin carries') do
      next true if skip?

      d = discharge(CAP, claims: { 'score' => 2 })
      c = nd_caveat('require' => [{ 'claim' => 'score', 'op' => 'gte', 'value' => 1 }])
      bind = { 'cap_hash' => CAP, 'pins' => [pin('spiffe_id' => 'spiffe://other/x')], 'now' => NOW }
      r = AtlasPca.verify_discharge(d, c, bind)
      eq('ok', r, { ok: true, digest: AtlasPca.discharge_digest(d), claims: { 'score' => 2 } })
      c2 = nd_caveat('issuer_spiffe' => 'spiffe://bank/x')
      r = AtlasPca.verify_discharge(d, c2, bind)
      eq('pinned spiffe differs', r, { ok: false, reason: 'the pinned issuer does not carry the SPIFFE ID the caveat requires' })
      r = AtlasPca.verify_discharge(d, c2, bind.merge('pins' => [pin('spiffe_id' => 'spiffe://bank/x')]))
      eq('pinned spiffe matches', r[:ok], true)
    end

    MutationKill.t('c28 caveat_lang: verify_narrow reasons, the leaf-holder_pq pin and the fail-closed rescue') do
      next true if skip?

      bind = { 'now' => NOW }
      n = narrow(CAP)
      eq('nil leaf', AtlasPca.verify_narrow(n, nil, nil, bind), { ok: false, reason: 'malformed capability chain' })
      eq('string leaf', AtlasPca.verify_narrow(n, 'x', nil, bind), { ok: false, reason: 'malformed capability chain' })
      # a good Ed25519 narrow, the leaf commits to a PQ key but the block carries none
      leaf2 = LEAF.merge('holder_pq' => AtlasPca.holder_pq_commitment('PQPK'))
      n2 = narrow(AtlasPca.cap_hash(leaf2))
      eq('ed25519 under holder_pq leaf', AtlasPca.verify_narrow(n2, leaf2, nil, bind), { ok: true, caveats: [{ 'type' => 'note' }] })
      n3 = narrow(AtlasPca.cap_hash(LEAF))
      eq('ed25519 plain leaf', AtlasPca.verify_narrow(n3, LEAF, nil, bind), { ok: true, caveats: [{ 'type' => 'note' }] })
      # the pin handed to the signature check
      pins = []
      stubs = { wb_verify_artifact_sig: ->(_d, _a, p) { pins << p; true }, wb_artifact_suite_error: ->(_a) {} }
      pq = { 'alg' => 'hybrid-ed25519-ml-dsa-65', 'pq_pk' => 'PQPK', 'pq_sig' => 'x' }
      leaf_match = LEAF.merge('holder_pq' => AtlasPca.holder_pq_commitment('PQPK'))
      leaf_other = LEAF.merge('holder_pq' => AtlasPca.holder_pq_commitment('OTHER'))
      MutationKill::Seam.with(AtlasPca, stubs) do
        [leaf_match, leaf_other, LEAF].each do |lf|
          r = AtlasPca.verify_narrow(narrow(AtlasPca.cap_hash(lf), extra: pq, signed: false), lf, nil, bind)
          eq('seamed ok', r[:ok], true)
        end
      end
      eq('pins', pins, [{ 'pk' => PK, 'pq_pk' => 'PQPK' }, { 'pk' => PK }, { 'pk' => PK }])
      # a leaf with no holder_pq at all never pins a PQ key, even if the commitment of the block's key were nil
      pins2 = []
      stubs2 = { wb_verify_artifact_sig: ->(_d, _a, p) { pins2 << p; true }, wb_artifact_suite_error: ->(_a) {}, holder_pq_commitment: ->(_k) {} }
      MutationKill::Seam.with(AtlasPca, stubs2) do
        r = AtlasPca.verify_narrow(narrow(AtlasPca.cap_hash(LEAF), extra: pq, signed: false), LEAF, nil, bind)
        eq('seamed ok (no holder_pq)', r[:ok], true)
      end
      eq('pins (no holder_pq)', pins2, [{ 'pk' => PK }])
      # a fault inside is a refusal with the message
      r = MutationKill::Seam.with(AtlasPca, { cap_hash: ->(_c) { raise 'boom' } }) { AtlasPca.verify_narrow(n3, LEAF, nil, bind) }
      eq('fault', r, { ok: false, reason: 'narrow error (fail closed): boom' })
    end

    MutationKill.t('c28 caveat_lang: a non-String nonce is never decoded and the holder bound is 64 bytes') do
      next true if skip?

      orig = AtlasPca.method(:b64d)
      zeros = ->(s, len = nil) { s.is_a?(String) ? orig.call(s, len) : ("\x00".b * 16) }
      nonce_msg = 'nonce must be canonical base64url of at least 16 bytes'
      MutationKill::Seam.with(AtlasPca, { b64d: zeros }) do
        eq('discharge nonce 5', AtlasPca.discharge_shape_error(discharge(CAP).merge('nonce' => 5)), nonce_msg)
        eq('discharge nonce nil', AtlasPca.discharge_shape_error(discharge(CAP).merge('nonce' => nil)), nonce_msg)
        eq('narrow nonce 5', AtlasPca.narrow_shape_error(narrow(CAP).merge('nonce' => 5)), nonce_msg)
        eq('narrow nonce nil', AtlasPca.narrow_shape_error(narrow(CAP).merge('nonce' => nil)), nonce_msg)
        eq('discharge ok', AtlasPca.discharge_shape_error(discharge(CAP)), nil)
        eq('narrow ok', AtlasPca.narrow_shape_error(narrow(CAP)), nil)
      end
      # every string starting with H "decodes" to 32 bytes: only the 64-byte holder bound can refuse it
      h = ->(s, len = nil) { s.is_a?(String) && s.start_with?('H') ? ("\x00".b * (len || 16)) : orig.call(s, len) }
      MutationKill::Seam.with(AtlasPca, { b64d: h }) do
        eq('holder 64', AtlasPca.narrow_shape_error(narrow(CAP).merge('holder' => 'H' * 64)), nil)
        eq('holder 65', AtlasPca.narrow_shape_error(narrow(CAP).merge('holder' => 'H' * 65)), 'holder must be canonical base64url (32 bytes)')
      end
      true
    end

    MutationKill.t('c28 caveat_lang: max_uses_slot_key stringifies every part') do
      next true if skip?

      eq('plain', AtlasPca.max_uses_slot_key('c', 'u', 0), slot('c', 'u', 0))
      eq('integers', AtlasPca.max_uses_slot_key(5, 7, 3), slot(5, 7, 3))
      eq('nils', AtlasPca.max_uses_slot_key(nil, nil, 1), slot(nil, nil, 1))
    end

    MutationKill.t('c28 caveat_lang: reserve_max_uses slots, store calls, exhaustion, expiry and faults') do
      next true if skip?

      cav = { 'type' => 'max_uses', 'id' => 'u', 'n' => 2, 'until' => NOW + 10_000 }
      bound = [{ 'caveat' => cav, 'cap_hash' => 'CAP' }]
      # consume_once is preferred when the store has it
      st = SpyStore.new(true)
      eq('consume_once ok', AtlasPca.reserve_max_uses(st, bound, NOW), { ok: true, spent: 1 })
      eq('consume_once call', st.calls, [[:consume_once, slot('CAP', 'u', 0), NOW + 10_000, NOW]])
      # claim(slot, 1) when it has not
      st = ClaimOnly.new(true)
      eq('claim ok', AtlasPca.reserve_max_uses(st, bound, NOW), { ok: true, spent: 1 })
      eq('claim call', st.calls, [[:claim, slot('CAP', 'u', 0), 1]])
      # every slot is tried, in order, then the caveat is exhausted (a loop that never advances would never end)
      cav3 = cav.merge('n' => 3)
      st = SpyStore.new(false)
      r = Timeout.timeout(2) { AtlasPca.reserve_max_uses(st, [{ 'caveat' => cav3, 'cap_hash' => 'CAP' }], NOW) }
      eq('exhausted', r, { ok: false, reason: "max_uses 'u' is exhausted" })
      eq('slots tried', st.calls, (0..2).map { |i| [:consume_once, slot('CAP', 'u', i), NOW + 10_000, NOW] })
      # the second slot is the first free one
      seq = SpyStore.new(false)
      def seq.consume_once(slot, till, now) = (@calls << [:consume_once, slot, till, now]; @calls.size == 2)
      eq('second slot', AtlasPca.reserve_max_uses(seq, bound, NOW), { ok: true, spent: 1 })
      eq('stopped after taking', seq.calls.length, 2)
      # an expired caveat names its id
      exp = [{ 'caveat' => cav.merge('until' => NOW), 'cap_hash' => 'CAP' }]
      eq('expired', AtlasPca.reserve_max_uses(SpyStore.new(true), exp, NOW), { ok: false, reason: "max_uses 'u' has expired" })
      # a caveat that is not a Hash is skipped (not read)
      skipped = [{ 'caveat' => nil, 'cap_hash' => 'c' }, { 'caveat' => Object.new, 'cap_hash' => 'c' }, { 'caveat' => { 'type' => 'sealed' }, 'cap_hash' => 'c' }]
      eq('skipped', AtlasPca.reserve_max_uses(SpyStore.new(true), skipped, NOW), { ok: true, spent: 0 })
      # a fault in the store is a refusal with the message
      eq('fault', AtlasPca.reserve_max_uses(Boom.new, bound, NOW), { ok: false, reason: 'max_uses error (fail closed): boom' })
    end

    MutationKill.t('c28 caveat_lang: k1_expr_error accepts a ref only for a real String name') do
      next true if skip?

      eq('duck ref', AtlasPca.k1_expr_error({ 'ref' => duck('p') }, ['p'], 1, [0]), 'ref names no earlier def')
      eq('ref ok', AtlasPca.k1_expr_error({ 'ref' => 'p' }, { 'p' => true }, 1, [0]), nil)
      eq('ref unknown', AtlasPca.k1_expr_error({ 'ref' => 'q' }, { 'p' => true }, 1, [0]), 'ref names no earlier def')
      eq('and returns nil', AtlasPca.k1_expr_error({ 'op' => 'and', 'args' => [{ 'const' => true }] }, {}, 1, [0]), nil)
    end

    MutationKill.t('c28 caveat_lang: k1_def_error keeps the FIRST count-def error') do
      next true if skip?

      base = { 'name' => 'n', 'kind' => 'count' }
      e = ->(extra) { AtlasPca.k1_def_error(base.merge(extra), {}, [0]) }
      eq('window first', e.call('window_ms' => 0, 'verb' => '', 'resource_prefix' => ''), 'window_ms out of range')
      eq('verb before prefix', e.call('window_ms' => 1000, 'verb' => '', 'resource_prefix' => ''), 'verb must be a non-empty string')
      eq('prefix', e.call('window_ms' => 1000, 'resource_prefix' => ''), 'resource_prefix must be a non-empty string')
      eq('ok', e.call('window_ms' => 1000, 'verb' => 'v', 'resource_prefix' => 'p'), nil)
    end

    MutationKill.t('c28 caveat_lang: evaluate_derive action, claims and prefix semantics') do
      next true if skip?

      # a duck action is not an action
      c = { 'type' => 'derive', 'id' => 'd', 'defs' => [{ 'name' => 'p', 'kind' => 'param', 'path' => 'amount' }],
            'check' => { 'op' => 'eq', 'a' => { 'ref' => 'p' }, 'b' => { 'const' => 5 } } }
      action_duck = Class.new { def [](k) = k == 'params' ? { 'amount' => 5 } : nil }.new
      eq('duck action', AtlasPca.evaluate_derive(c, { 'now' => NOW, 'claims' => {}, 'action' => action_duck }), nil)
      eq('real action', AtlasPca.evaluate_derive(c, { 'now' => NOW, 'claims' => {}, 'action' => { 'params' => { 'amount' => 5 } } }), true)
      # claims: only an own key of a Hash counts
      cc = { 'type' => 'derive', 'id' => 'd', 'defs' => [{ 'name' => 'v', 'kind' => 'claim', 'caveat_id' => 'x', 'claim' => 'k' }],
             'check' => { 'op' => 'eq', 'a' => { 'ref' => 'v' }, 'b' => { 'const' => 7 } } }
      eq('claims default hash', AtlasPca.evaluate_derive(cc, { 'now' => NOW, 'claims' => Hash.new({ 'k' => 7 }) }), nil)
      eq('claims nil', AtlasPca.evaluate_derive(cc, { 'now' => NOW, 'claims' => nil }), nil)
      eq('claims string', AtlasPca.evaluate_derive(cc, { 'now' => NOW, 'claims' => 'x' }), nil)
      eq('inner default hash', AtlasPca.evaluate_derive(cc, { 'now' => NOW, 'claims' => { 'x' => Hash.new(7) } }), nil)
      eq('claim present', AtlasPca.evaluate_derive(cc, { 'now' => NOW, 'claims' => { 'x' => { 'k' => 7 } } }), true)
      # resource_prefix compares bytes (a non-ASCII prefix against a non-ASCII resource)
      cp = { 'type' => 'derive', 'id' => 'd',
             'defs' => [{ 'name' => 'n', 'kind' => 'count', 'window_ms' => 1000, 'resource_prefix' => 'é' }],
             'check' => { 'op' => 'eq', 'a' => { 'ref' => 'n' }, 'b' => { 'const' => 1 } } }
      hist = [{ 't' => NOW - 1, 'verb' => 'v', 'resource' => 'é/x' }]
      eq('non-ascii prefix', AtlasPca.evaluate_derive(cp, { 'now' => NOW, 'claims' => {}, 'history' => hist }), true)
      other = [{ 't' => NOW - 1, 'verb' => 'v', 'resource' => 'x/é' }]
      eq('prefix is a prefix', AtlasPca.evaluate_derive(cp, { 'now' => NOW, 'claims' => {}, 'history' => other }), false)
    end

    MutationKill.t('c28 caveat_lang: evaluate_derive hands nil (not false) for a non-object action and ignores a value that was not found') do
      next true if skip?

      c = { 'type' => 'derive', 'id' => 'd', 'defs' => [{ 'name' => 'p', 'kind' => 'param', 'path' => 'amount' }],
            'check' => { 'op' => 'eq', 'a' => { 'ref' => 'p' }, 'b' => { 'const' => 5 } } }
      seen = []
      spy = ->(params, _path) { seen << params; [false, nil] }
      [5, nil, 'x', []].each do |act|
        MutationKill::Seam.with(AtlasPca, { wb_resolve: spy }) { AtlasPca.evaluate_derive(c, { 'now' => NOW, 'claims' => {}, 'action' => act }) }
      end
      eq('params argument', seen, [nil, nil, nil, nil])
      r = MutationKill::Seam.with(AtlasPca, { wb_resolve: ->(_p, _path) { [false, 5] } }) do
        AtlasPca.evaluate_derive(c, { 'now' => NOW, 'claims' => {}, 'action' => { 'params' => { 'amount' => 5 } } })
      end
      eq('not found stays unknown', r, nil)
    end

    MutationKill.t('c28 caveat_lang: k1_spiffe_satisfied? is exactly false for a bad caveat or peer, and compares bytes') do
      next true if skip?

      id = { 'type' => 'spiffe_bound', 'spiffe_id' => 'spiffe://a/b' }
      pre = { 'type' => 'spiffe_bound', 'spiffe_prefix' => 'spiffe://a' }
      eq('bad peer', AtlasPca.k1_spiffe_satisfied?(id, 'bad'), false)
      eq('nil peer', AtlasPca.k1_spiffe_satisfied?(id, nil), false)
      eq('bad caveat', AtlasPca.k1_spiffe_satisfied?({ 'type' => 'spiffe_bound' }, 'spiffe://a/b'), false)
      eq('id equal', AtlasPca.k1_spiffe_satisfied?(id, 'spiffe://a/b'), true)
      eq('id differs', AtlasPca.k1_spiffe_satisfied?(id, 'spiffe://a/c'), false)
      eq('prefix equal', AtlasPca.k1_spiffe_satisfied?(pre, 'spiffe://a'), true)
      eq('prefix below', AtlasPca.k1_spiffe_satisfied?(pre, 'spiffe://a/b'), true)
      eq('prefix is a path prefix only', AtlasPca.k1_spiffe_satisfied?(pre, 'spiffe://ab'), false)
      # a peer whose encoding is not ASCII-compatible but whose bytes are a valid ID is compared by bytes, never raising
      odd = 'spiffe://a/b'.dup.force_encoding('UTF-7')
      eq('byte compare', AtlasPca.k1_spiffe_satisfied?(pre, odd), true)
    end

    MutationKill.t('c28 caveat_lang: evaluate_k1 refusals, id counting, discharge selection and fault result') do
      next true if skip?

      gr = grant
      # a ctx that is not a Hash is replaced by {} (so the clock refusal, not a fault)
      clock = { ok: false, failed: ['<malformed>'], reasons: ['the verifier clock is not a safe integer (fail closed)'], plain: [], bound: [] }
      eq('array ctx', AtlasPca.evaluate_k1(gr, nil, {}, []), clock)
      eq('nil ctx', AtlasPca.evaluate_k1(gr, nil, {}, nil), clock)
      # ids are unique per type among STRING ids only: an Integer 5 does not collide with "5"
      u = NOW + 1000
      g2 = grant({ 'type' => 'max_uses', 'id' => 5, 'n' => 1, 'until' => u }, { 'type' => 'max_uses', 'id' => '5', 'n' => 1, 'until' => u })
      r = AtlasPca.evaluate_k1(g2, nil, {}, { 'now' => NOW })
      eq('integer id', [r[:ok], r[:failed], r[:reasons]], [false, ['max_uses'], ['id is malformed']])
      # a non-Array discharges member is no discharge; a missing pins member is an empty list
      g3 = grant(nd_caveat)
      cap3 = AtlasPca.cap_hash(g3)
      r = AtlasPca.evaluate_k1(g3, nil, { 'discharges' => 'x', 'pins' => [pin] }, { 'now' => NOW })
      eq('string discharges', [r[:ok], r[:failed], r[:reasons]], [false, ['needs_discharge'], ['no discharge presented']])
      r = AtlasPca.evaluate_k1(g3, nil, { 'discharges' => [discharge(cap3, signed: false)] }, { 'now' => NOW })
      eq('no pins', [r[:ok], r[:failed], r[:reasons]], [false, ['needs_discharge'], ['the issuer is not pinned by this verifier']])
      # the FIRST verifying discharge is used
      g4 = grant(nd_caveat, derive_caveat(1))
      cap4 = AtlasPca.cap_hash(g4)
      d1 = discharge(cap4, claims: { 'score' => 1 }, nonce: 1)
      d2 = discharge(cap4, claims: { 'score' => 2 }, nonce: 2)
      r = AtlasPca.evaluate_k1(g4, nil, { 'pins' => [pin], 'discharges' => [d1, d2] }, { 'now' => NOW })
      eq('first discharge', [r[:ok], r[:failed], r[:reasons]], [true, [], []])
      r = AtlasPca.evaluate_k1(g4, nil, { 'pins' => [pin], 'discharges' => [d2, d1] }, { 'now' => NOW })
      eq('first discharge (other order)', [r[:ok], r[:failed], r[:reasons]], [false, ['derive'], ['derive check is false']])
      # a fault is a refusal that carries the message, in the full result shape
      r = MutationKill::Seam.with(AtlasPca, { bound_caveats: ->(*) { raise 'boom' } }) { AtlasPca.evaluate_k1(gr, nil, {}, { 'now' => NOW }) }
      eq('fault', r, { ok: false, failed: ['<malformed>'], reasons: ['caveat language error (fail closed): boom'], plain: [], bound: [] })
    end

    MutationKill.t('c28 caveat_lang: evaluate_k1 labels a failure by its type only when it has a String type') do
      next true if skip?

      # a Hash whose type is not a String (reached only if k1_type? let it through): '<malformed>'
      msg = 'the caveat language is not configured (no k1 input)'
      r = MutationKill::Seam.with(AtlasPca, { k1_type?: ->(_c) { true } }) do
        AtlasPca.evaluate_k1(grant({ 'type' => 5 }, {}), nil, nil, { 'now' => NOW })
      end
      eq('hash with non-string type', [r[:ok], r[:failed], r[:reasons]], [false, ['<malformed>', '<malformed>'], [msg, msg]])
      # an object that is not a Hash but answers [] with a String type: still '<malformed>'
      odd = Class.new { def [](k) = k == 'type' ? 'sealed' : nil }.new
      stubs = { cap_hash: ->(_c) { 'H' }, k1_type?: ->(_c) { true }, wb_closed_members: ->(*) { 'boom' } }
      r = MutationKill::Seam.with(AtlasPca, stubs) do
        AtlasPca.evaluate_k1({ 'id' => 'g', 'issuer' => 'i', 'holder' => 'h', 'caveats' => [odd] }, nil, {}, { 'now' => NOW })
      end
      eq('non-hash caveat', [r[:ok], r[:failed], r[:reasons]], [false, ['<malformed>'], ['boom']])
    end

    MutationKill.t('c28 caveat_lang: evaluate_k1 passes optional bindings only when the k1 input has them') do
      next true if skip?

      # narrow: the binding carries action_digest only when k1 does
      binds = []
      spy = ->(_n, _g, _c, bind) { binds << bind.dup; { ok: true, caveats: [] } }
      MutationKill::Seam.with(AtlasPca, { verify_narrow: spy }) do
        AtlasPca.evaluate_k1(grant, nil, { 'narrow' => {} }, { 'now' => NOW })
        AtlasPca.evaluate_k1(grant, nil, { 'narrow' => {}, 'action_digest' => 'AD' }, { 'now' => NOW })
      end
      eq('narrow bindings', binds, [{ 'now' => NOW }, { 'now' => NOW, 'action_digest' => 'AD' }])
      # discharge: action_digest, revoked and pins
      g = grant(nd_caveat)
      cap = AtlasPca.cap_hash(g)
      dbinds = []
      dspy = ->(_d, _c, bind) { dbinds << bind.dup; { ok: false, reason: 'r' } }
      probe = [{ 'caveat_id' => 'kyc' }]
      MutationKill::Seam.with(AtlasPca, { verify_discharge: dspy }) do
        AtlasPca.evaluate_k1(g, nil, { 'discharges' => probe }, { 'now' => NOW })
        AtlasPca.evaluate_k1(g, nil, { 'discharges' => probe, 'pins' => [pin], 'action_digest' => 'AD', 'revoked_discharges' => ['R'] }, { 'now' => NOW })
      end
      eq('discharge bindings', dbinds, [{ 'cap_hash' => cap, 'pins' => [], 'now' => NOW },
                                        { 'cap_hash' => cap, 'pins' => [pin], 'now' => NOW, 'action_digest' => 'AD', 'revoked' => ['R'] }])
      # derive: action and history only when present
      gd = grant(derive_caveat(1))
      inps = []
      espy = ->(_c, inp) { inps << inp.dup; true }
      MutationKill::Seam.with(AtlasPca, { evaluate_derive: espy }) do
        AtlasPca.evaluate_k1(gd, nil, {}, { 'now' => NOW })
        AtlasPca.evaluate_k1(gd, nil, { 'history' => [] }, { 'now' => NOW, 'action' => { 'verb' => 'v' } })
      end
      eq('derive inputs', inps, [{ 'now' => NOW, 'claims' => {} }, { 'now' => NOW, 'claims' => {}, 'action' => { 'verb' => 'v' }, 'history' => [] }])
    end

    MutationKill.t('c28 caveat_lang: presented_k1 reasons and symbol header names') do
      next true if skip?

      eq('nil', AtlasPca.presented_k1(nil), { ok: false, reason: 'headers is not a Hash' })
      eq('array', AtlasPca.presented_k1([]), { ok: false, reason: 'headers is not a Hash' })
      eq('bad discharges', AtlasPca.presented_k1({ 'pca-discharges' => '!!' }), { ok: false, reason: 'PCA-Discharges is not canonical base64url' })
      eq('bad narrow', AtlasPca.presented_k1({ 'pca-narrow' => '!!' }), { ok: false, reason: 'PCA-Narrow is not canonical base64url' })
      eq('object discharges', AtlasPca.presented_k1({ 'pca-discharges' => b64('{}') }), { ok: false, reason: 'PCA-Discharges must be a JSON array' })
      eq('symbol key', AtlasPca.presented_k1({ 'pca-narrow': b64('{"a":1}') }), { ok: true, value: { 'narrow' => { 'a' => 1 } } })
      eq('mixed case', AtlasPca.presented_k1({ 'PCA-Discharges' => b64('[]') }), { ok: true, value: { 'discharges' => [] } })
    end

    MutationKill.t('c28 caveat_lang: evaluate_caveats_k1 context, stock list and evaluation error') do
      next true if skip?

      gr = grant
      eq('array context', AtlasPca.evaluate_caveats_k1(gr, nil, {}, []), [false, ['<malformed>']])
      eq('string caveats', AtlasPca.evaluate_caveats_k1({ 'caveats' => 'x' }, nil, {}, { 'now' => NOW }), [false, ['<malformed caveats>', '<malformed>']])
      pred = { 'type' => 'predicates', 'allow' => [{ 'verb' => 'pay', 'resource' => 'inv:*' }] }
      ctx = { 'now' => NOW, 'action' => { 'verb' => 'pay', 'resource' => 'inv:1', 'params' => {} } }
      eq('predicates see the action', AtlasPca.evaluate_caveats_k1(grant(pred), nil, {}, ctx), [true, []])
      other = ctx.merge('action' => { 'verb' => 'pay', 'resource' => 'zzz', 'params' => {} })
      eq('predicates refuse', AtlasPca.evaluate_caveats_k1(grant(pred), nil, {}, other), [false, ['predicates']])
      r = MutationKill::Seam.with(AtlasPca, { policy_caveats: ->(*) { raise 'boom' } }) { AtlasPca.evaluate_caveats_k1(gr, nil, {}, ctx) }
      eq('fault', r, [false, ['<evaluation error>']])
    end

    # =================================================================================================================
    # assurance.rb
    # =================================================================================================================

    MutationKill.t('c28 assurance: the label table is private, frozen and holds only Hash labels with a String level') do
      next true if skip?

      begin
        AtlasPca::ASSURANCE_LABELS
        raise 'c28 ASSURANCE_LABELS is reachable'
      rescue NameError
        nil
      end
      t1 = Object.new
      eq('returns target', AtlasPca.set_assurance_label(t1, 'hardware').equal?(t1), true)
      eq('bare label', AtlasPca.assurance_label_of(t1), { 'level' => 'hardware' })
      eq('frozen', AtlasPca.assurance_label_of(t1).frozen?, true)
      t2 = Object.new
      AtlasPca.set_assurance_label(t2, 'groth16', vendor: 'v', awaiting_audit: false, ceremony: 'multi-party')
      eq('full label', AtlasPca.assurance_label_of(t2), { 'level' => 'groth16', 'vendor' => 'v', 'awaiting_audit' => false, 'ceremony' => 'multi-party' })
      t3 = Object.new
      AtlasPca.set_assurance_label(t3, 'x', ceremony: 'single-party')
      eq('only the given members', AtlasPca.assurance_label_of(t3), { 'level' => 'x', 'ceremony' => 'single-party' })
      t4 = Object.new
      AtlasPca.set_assurance_label(t4, 'x', awaiting_audit: true)
      eq('awaiting only', AtlasPca.assurance_label_of(t4), { 'level' => 'x', 'awaiting_audit' => true })
      # a label that is not a Hash with a String level is no label
      wk = AtlasPca.module_eval('ASSURANCE_LABELS')
      a = Object.new
      b = Object.new
      c = Object.new
      wk[a] = []
      wk[b] = 'str'
      wk[c] = { 'level' => 5 }
      eq('array label', AtlasPca.assurance_label_of(a), nil)
      eq('string label', AtlasPca.assurance_label_of(b), nil)
      eq('non-string level', AtlasPca.assurance_label_of(c), nil)
      eq('level nil', AtlasPca.assurance_label_of(AtlasPca.set_assurance_label(Object.new, nil)), nil)
      eq('unlabelled', AtlasPca.assurance_label_of(Object.new), nil)
    end

    MutationKill.t('c28 assurance: assurance_label_of never looks up nil, a Symbol or an Integer') do
      next true if skip?

      wk = AtlasPca.module_eval('ASSURANCE_LABELS')
      wk.define_singleton_method(:[]) { |_k| raise 'c28 label lookup for a non-collectable target' }
      begin
        [nil, :sym, 7].each { |t| eq("guard #{t.inspect}", AtlasPca.assurance_label_of(t), nil) }
      ensure
        wk.singleton_class.send(:remove_method, :[])
      end
      true
    end

    MutationKill.t('c28 assurance: the rank tables are the reference tables (assurance.ts ATT_RANK, ZK_RANK, ZK_NEED)') do
      next true if skip?

      eq('ATT_RANK', AtlasPca::ASSURANCE_ATT_RANK, { 'unknown' => 0, 'software' => 1, 'hardware' => 2, 'multi_root' => 3 })
      eq('ZK_RANK', AtlasPca::ASSURANCE_ZK_RANK,
         { 'unknown' => 0, 'attested_vm' => 1, 'attested_vm_hw' => 1, 'stark' => 2, 'zkvm' => 2, 'groth16' => 3, 'policyvm_snark' => 3 })
      eq('ZK_NEED', AtlasPca::ASSURANCE_ZK_NEED, { 'attested_vm' => 1, 'attested_vm_hardware' => 1, 'proof' => 2, 'snark' => 3 })
    end

    MutationKill.t('c28 assurance: a check with no hook looks up no label') do
      next true if skip?

      asked = []
      spy = ->(h) { asked << h; nil }
      r = MutationKill::Seam.with(AtlasPca, { assurance_label_of: spy }) do
        AtlasPca.assurance_report({}, { 'revocation' => 'pass', 'threshold' => 'pass' }, hooks: {})
      end
      eq('report', r, { 'revocation' => { 'outcome' => 'pass' }, 'threshold' => { 'outcome' => 'pass' } })
      eq('no lookup', asked, [])
    end

    MutationKill.t('c28 assurance: multi_root_level picks the weakest accepted quorum') do
      next true if skip?

      root = ->(level, req = nil) { { 'verifier' => level.nil? ? Object.new : hook(level), 'required' => req } }
      r = AtlasPca.method(:multi_root_level)
      sw = root.call('software', true)
      eq('req + weakest optional', r.call([sw, root.call('hardware'), root.call('hardware')], 2), 'hardware')
      eq('all three', r.call([sw, root.call('hardware'), root.call('hardware')], 3), 'multi_root')
      eq('required hw wins over optional sw', r.call([root.call('hardware', true), root.call('software'), root.call('software')], 1), 'hardware')
      eq('optional sorted weakest first (2)', r.call([root.call('hardware'), root.call('hardware'), root.call('software')], 2), 'hardware')
      eq('optional sorted weakest first (1)', r.call([root.call('hardware'), root.call('hardware'), root.call('software')], 1), 'software')
      five = Array.new(5) { root.call('hardware') } + [root.call('software')]
      eq('weakest last of six', r.call(five, 1), 'software')
      eq('weakest first of six', r.call([root.call('software')] + Array.new(5) { root.call('hardware') }, 1), 'software')
      eq('unlabelled', r.call([root.call(nil)], 1), 'unknown')
      eq('unknown level name', r.call([root.call('xyz')], 1), 'unknown')
      eq('empty quorum', r.call([root.call('hardware')], 0), 'software')
      eq('nil threshold = required only', r.call([root.call('hardware', true), root.call('software')], nil), 'hardware')
      eq('string threshold', r.call([sw, root.call('hardware'), root.call('hardware')], '2'), 'hardware')
      eq('required must be true', r.call([root.call('software', 'true'), root.call('hardware')], 1), 'software')
    end

    MutationKill.t('c28 assurance: signature_level classifies a suite name by type') do
      next true if skip?

      eq('nil', AtlasPca.signature_level(nil), 'ed25519')
      eq('ed25519', AtlasPca.signature_level('ed25519'), 'ed25519')
      eq('pq', AtlasPca.signature_level('ml-dsa-65'), 'pq')
      eq('hybrid', AtlasPca.signature_level('hybrid-ed25519-ml-dsa-65'), 'hybrid')
      eq('unregistered', AtlasPca.signature_level('nope'), 'unknown')
      eq('integer', AtlasPca.signature_level(5), 'unknown')
      eq('duck', AtlasPca.signature_level(duck('ml-dsa-65')), 'unknown')
    end

    MutationKill.t('c28 assurance: assurance_unavailable? is a registered suite this runtime lacks') do
      next true if skip?

      table = lambda do |supported|
        MutationKill::Seam.with(AtlasPca, { supported_suites: -> { supported } }) do
          [nil, 'ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'bogus', 5, duck('ml-dsa-65')].map { |a| AtlasPca.assurance_unavailable?(a) }
        end
      end
      eq('nothing supported', table.call([]), [true, true, true, true, false, false, false])
      eq('ed25519 + ml-dsa-65 supported', table.call(%w[ed25519 ml-dsa-65]), [false, false, false, true, false, false, false])
    end

    MutationKill.t('c28 assurance: assurance_report without hooks reports the unimplemented checks') do
      next true if skip?

      eq('zk + threshold carried', AtlasPca.assurance_report({ 'zk_compliance' => {}, 'threshold' => {} }, {}),
         { 'zk_compliance' => { 'outcome' => 'unsupported', 'reason' => 'zk compliance verification is not implemented by this SDK' },
           'threshold' => { 'outcome' => 'unsupported', 'reason' => 'threshold co-signatures are not verified by this SDK' } })
      eq('nothing carried', AtlasPca.assurance_report({}, {}), {})
      eq('failed attestation', AtlasPca.assurance_report({}, { 'attestation' => 'fail' }),
         { 'attestation' => { 'outcome' => 'unsupported', 'reason' => 'attestation verification is not implemented by this SDK' } })
      eq('passed attestation unlabelled', AtlasPca.assurance_report({}, { 'attestation' => 'pass' }), { 'attestation' => { 'outcome' => 'pass', 'level' => 'unknown' } })
      eq('with hooks nothing is replaced', AtlasPca.assurance_report({ 'zk_compliance' => {}, 'threshold' => {} }, { 'attestation' => 'fail' }, hooks: {}),
         { 'attestation' => { 'outcome' => 'fail' } })
      eq('a failed check names its own outcome', AtlasPca.assurance_report({}, { 'replay' => 'fail', 'x' => 'unsupported' }),
         { 'replay' => { 'outcome' => 'fail' }, 'x' => { 'outcome' => 'unsupported', 'reason' => 'x is not implemented by this verifier' } })
      eq('non-Hash pcactn', AtlasPca.assurance_report('x', {}), {})
      eq('nil pcactn leaf', AtlasPca.assurance_report(nil, { 'leaf_signature' => 'pass' }), { 'leaf_signature' => { 'outcome' => 'pass' } })
    end

    MutationKill.t('c28 assurance: assurance_report marks a missing suite backend unsupported (seamed runtime)') do
      next true if skip?

      only_ed = { supported_suites: -> { ['ed25519'] } }
      MutationKill::Seam.with(AtlasPca, only_ed) do
        pq = { 'alg' => 'ml-dsa-65' }
        eq('leaf fail', AtlasPca.assurance_report(pq, { 'leaf_signature' => 'fail' }),
           { 'leaf_signature' => { 'outcome' => 'unsupported', 'reason' => "signature suite 'ml-dsa-65' has no backend in this runtime" } })
        eq('leaf pass stays', AtlasPca.assurance_report(pq, { 'leaf_signature' => 'pass' }),
           { 'leaf_signature' => { 'outcome' => 'pass', 'suites' => ['ml-dsa-65'], 'level' => 'pq' } })
        eq('leaf ed25519 fail stays', AtlasPca.assurance_report({}, { 'leaf_signature' => 'fail' }), { 'leaf_signature' => { 'outcome' => 'fail' } })
        eq('leaf without pcactn', AtlasPca.assurance_report(nil, { 'leaf_signature' => 'fail' }), { 'leaf_signature' => { 'outcome' => 'fail' } })
        chain = { 'cap_chain' => [{ 'alg' => 'ml-dsa-65' }] }
        eq('chain fail', AtlasPca.assurance_report(chain, { 'chain' => 'fail' }),
           { 'chain' => { 'outcome' => 'unsupported', 'reason' => 'a capability suite has no backend in this runtime' } })
        eq('chain pass stays', AtlasPca.assurance_report(chain, { 'chain' => 'pass' }),
           { 'chain' => { 'outcome' => 'pass', 'suites' => ['ml-dsa-65'], 'level' => 'pq' } })
        eq('ed25519 chain fail stays', AtlasPca.assurance_report({ 'cap_chain' => [{}] }, { 'chain' => 'fail' }), { 'chain' => { 'outcome' => 'fail' } })
        eq('hop that is not a Hash is ed25519', AtlasPca.assurance_report({ 'cap_chain' => [5] }, { 'chain' => 'fail' }), { 'chain' => { 'outcome' => 'fail' } })
      end
      true
    end

    MutationKill.t('c28 assurance: assurance_report levels come from the verifier labels, never the evidence') do
      next true if skip?

      rep = ->(checks, **kw) { AtlasPca.assurance_report({}, checks, **kw) }
      eq('attestation hook', rep.call({ 'attestation' => 'pass' }, hooks: { 'attestation' => hook('hardware', vendor: 'amd') }),
         { 'attestation' => { 'outcome' => 'pass', 'level' => 'hardware', 'vendor' => 'amd' } })
      eq('symbol-keyed hooks', rep.call({ 'attestation' => 'pass' }, hooks: { attestation: hook('software') }),
         { 'attestation' => { 'outcome' => 'pass', 'level' => 'software' } })
      eq('attestation_hook wins', rep.call({ 'attestation' => 'pass' }, hooks: { 'attestation' => hook('software') }, attestation_hook: hook('multi_root')),
         { 'attestation' => { 'outcome' => 'pass', 'level' => 'multi_root' } })
      eq('hooks that are not a Hash', rep.call({ 'attestation' => 'pass' }, hooks: []), { 'attestation' => { 'outcome' => 'pass', 'level' => 'unknown' } })
      eq('zk hook', rep.call({ 'zk_compliance' => 'pass' }, hooks: { 'zk' => hook('groth16', ceremony: 'multi-party') }),
         { 'zk_compliance' => { 'outcome' => 'pass', 'level' => 'groth16', 'ceremony' => 'multi-party' } })
      eq('attestation does not report a ceremony', rep.call({ 'attestation' => 'pass' }, hooks: { 'attestation' => hook('hardware', ceremony: 'c') }),
         { 'attestation' => { 'outcome' => 'pass', 'level' => 'hardware' } })
      eq('threshold hook + t', rep.call({ 'threshold' => 'pass' }, hooks: { 'threshold' => hook('frost') }, threshold_t: 2),
         { 'threshold' => { 'outcome' => 'pass', 'level' => 'frost', 'awaiting_audit' => true, 't' => 2 } })
      eq('threshold t float', rep.call({ 'threshold' => 'pass' }, hooks: { 'threshold' => hook('multisig') }, threshold_t: 2.5),
         { 'threshold' => { 'outcome' => 'pass', 'level' => 'multisig', 't' => 2.5 } })
      eq('threshold t not a number', rep.call({ 'threshold' => 'pass' }, hooks: { 'threshold' => hook('multisig') }, threshold_t: 'x'),
         { 'threshold' => { 'outcome' => 'pass', 'level' => 'multisig' } })
      eq('threshold unlabelled hook', rep.call({ 'threshold' => 'pass' }, hooks: { 'threshold' => Object.new }, threshold_t: 3),
         { 'threshold' => { 'outcome' => 'pass', 'level' => 'unknown', 't' => 3 } })
      eq('threshold without hook', rep.call({ 'threshold' => 'pass' }, hooks: {}, threshold_t: 3), { 'threshold' => { 'outcome' => 'pass' } })
      eq('label flag on a plain check', rep.call({ 'revocation' => 'pass' }, hooks: { 'revocation' => hook('x', vendor: 'v', awaiting_audit: true) }),
         { 'revocation' => { 'outcome' => 'pass', 'level' => 'x', 'vendor' => 'v', 'awaiting_audit' => true } })
      eq('flag false is no flag', rep.call({ 'revocation' => 'pass' }, hooks: { 'revocation' => hook('x', awaiting_audit: false) }),
         { 'revocation' => { 'outcome' => 'pass', 'level' => 'x' } })
      eq('plain check with no label', rep.call({ 'revocation' => 'pass' }, hooks: { 'revocation' => Object.new }), { 'revocation' => { 'outcome' => 'pass' } })
    end

    MutationKill.t('c28 assurance: assurance_report suites and levels of the leaf and the chain') do
      next true if skip?

      rep = ->(p, checks, **kw) { AtlasPca.assurance_report(p, checks, **kw) }
      leaf = { 'leaf_signature' => 'pass' }
      eq('leaf pq', rep.call({ 'alg' => 'ml-dsa-65' }, leaf), { 'leaf_signature' => { 'outcome' => 'pass', 'suites' => ['ml-dsa-65'], 'level' => 'pq' } })
      eq('leaf unbound', rep.call({ 'alg' => 'ml-dsa-65' }, leaf, allow_unbound_pq: true),
         { 'leaf_signature' => { 'outcome' => 'pass', 'suites' => ['ml-dsa-65'], 'level' => 'unbound_pq' } })
      eq('leaf ed25519 default', rep.call({}, leaf), { 'leaf_signature' => { 'outcome' => 'pass', 'suites' => ['ed25519'], 'level' => 'ed25519' } })
      eq('leaf ed25519 unbound flag', rep.call({}, leaf, allow_unbound_pq: true), { 'leaf_signature' => { 'outcome' => 'pass', 'suites' => ['ed25519'], 'level' => 'ed25519' } })
      eq('leaf integer alg', rep.call({ 'alg' => 5 }, leaf), { 'leaf_signature' => { 'outcome' => 'pass', 'suites' => ['5'], 'level' => 'unknown' } })
      hyb = 'hybrid-ed25519-ml-dsa-65'
      mixed = { 'cap_chain' => [nil, 5, { 'alg' => hyb }] }
      eq('chain mixed', rep.call(mixed, { 'chain' => 'pass' }),
         { 'chain' => { 'outcome' => 'pass', 'suites' => ['ed25519', 'ed25519', hyb], 'level' => 'ed25519' } })
      eq('chain under the other name', rep.call(mixed, { 'cap_chain' => 'pass' }),
         { 'cap_chain' => { 'outcome' => 'pass', 'suites' => ['ed25519', 'ed25519', hyb], 'level' => 'ed25519' } })
      eq('chain integer alg', rep.call({ 'cap_chain' => [{ 'alg' => 5 }] }, { 'chain' => 'pass' }),
         { 'chain' => { 'outcome' => 'pass', 'suites' => ['5'], 'level' => 'unknown' } })
      eq('chain hybrid', rep.call({ 'cap_chain' => [{ 'alg' => hyb }] }, { 'chain' => 'pass' }),
         { 'chain' => { 'outcome' => 'pass', 'suites' => [hyb], 'level' => 'hybrid' } })
      eq('chain unbound', rep.call({ 'cap_chain' => [{ 'alg' => hyb }] }, { 'chain' => 'pass' }, allow_unbound_pq: true),
         { 'chain' => { 'outcome' => 'pass', 'suites' => [hyb], 'level' => 'unbound_pq' } })
      eq('ed25519 chain, unbound flag', rep.call({ 'cap_chain' => [{}, { 'alg' => 'ed25519' }] }, { 'chain' => 'pass' }, allow_unbound_pq: true),
         { 'chain' => { 'outcome' => 'pass', 'suites' => %w[ed25519 ed25519], 'level' => 'ed25519' } })
      eq('chain not an Array', rep.call({ 'cap_chain' => 'x' }, { 'chain' => 'pass' }), { 'chain' => { 'outcome' => 'pass' } })
      eq('chain absent', rep.call({}, { 'chain' => 'pass' }), { 'chain' => { 'outcome' => 'pass' } })
      eq('no pcactn', rep.call(nil, { 'chain' => 'pass' }), { 'chain' => { 'outcome' => 'pass' } })
    end

    MutationKill.t('c28 assurance: unmet_assurance messages for unsupported, degraded and malformed requirements') do
      next true if skip?

      u = ->(report, req) { AtlasPca.unmet_assurance(report, req) }
      tail = '; a high-assurance policy never accepts it'
      eq('unsupported no reason', u.call({ 'x' => { 'outcome' => 'unsupported' } }, {}), "assurance: unsupported: x (not implemented)#{tail}")
      eq('unsupported empty reason', u.call({ 'x' => { 'outcome' => 'unsupported', 'reason' => '' } }, {}), "assurance: unsupported: x (not implemented)#{tail}")
      eq('unsupported zero reason', u.call({ 'x' => { 'outcome' => 'unsupported', 'reason' => 0 } }, {}), "assurance: unsupported: x (not implemented)#{tail}")
      eq('unsupported reason', u.call({ 'x' => { 'outcome' => 'unsupported', 'reason' => 'why' } }, {}), "assurance: unsupported: x (why)#{tail}")
      eq('degraded no reason', u.call({ 'x' => { 'outcome' => 'pass', 'degraded' => true } }, {}),
         "assurance: x rests on a degraded compatibility mode (degraded)#{tail}")
      eq('degraded empty reason', u.call({ 'x' => { 'outcome' => 'pass', 'degraded' => true, 'reason' => '' } }, {}),
         "assurance: x rests on a degraded compatibility mode (degraded)#{tail}")
      eq('degraded reason', u.call({ 'x' => { 'outcome' => 'pass', 'degraded' => true, 'reason' => 'r' } }, {}),
         "assurance: x rests on a degraded compatibility mode (r)#{tail}")
      eq('degraded but failed is not degraded', u.call({ 'x' => { 'outcome' => 'fail', 'degraded' => true } }, {}), nil)
      eq('requirement not a Hash (nil)', u.call({}, nil), 'assurance: unknown assurance requirement(s): invalid (fail closed)')
      eq('requirement not a Hash (array)', u.call({}, []), 'assurance: unknown assurance requirement(s): invalid (fail closed)')
      eq('requirement not a Hash (string)', u.call({}, 'x'), 'assurance: unknown assurance requirement(s): invalid (fail closed)')
      eq('requirement not a Hash (integer)', u.call({}, 5), 'assurance: unknown assurance requirement(s): invalid (fail closed)')
      eq('unknown keys sorted', u.call({}, { 'zz' => 1, 'aa' => 2, 'attestation' => 'hardware' }),
         'assurance: unknown assurance requirement(s): aa, zz (fail closed)')
      hw = { 'attestation' => { 'outcome' => 'pass', 'level' => 'hardware' } }
      eq('symbol keys are read', u.call(hw, { attestation: 'hardware' }), nil)
      eq('symbol keys refuse', u.call({ 'attestation' => { 'outcome' => 'pass', 'level' => 'software' } }, { attestation: 'hardware' }),
         'assurance: hardware attestation required but the evidence is software')
      eq('unknown attestation', u.call(hw, { 'attestation' => 'tpm' }), 'assurance: unknown attestation requirement "tpm" (fail closed)')
      eq('unknown zk', u.call(hw, { 'zk' => 'magic' }), 'assurance: unknown zk requirement "magic" (fail closed)')
      eq('unknown signature', u.call(hw, { 'signature' => 'any' }), 'assurance: unknown signature requirement "any" (fail closed)')
      eq('unknown threshold (string)', u.call(hw, { 'threshold' => 'multisig' }), 'assurance: unknown threshold requirement "multisig" (fail closed)')
      eq('unknown threshold (integers)', u.call(hw, { 'threshold' => [1, 2] }), 'assurance: unknown threshold requirement [1, 2] (fail closed)')
      eq('empty threshold list is a list of strings', u.call(hw, { 'threshold' => [] }), 'assurance: threshold () required but there is no threshold evidence')
    end

    MutationKill.t('c28 assurance: attestation requirement against every evidence level') do
      next true if skip?

      rank = { 'unknown' => 0, 'software' => 1, 'hardware' => 2, 'multi_root' => 3 }
      [nil, 'unknown', 'software', 'hardware', 'multi_root', 'bogus'].each do |lvl|
        %w[software hardware multi_root].each do |att|
          e = { 'outcome' => 'pass' }
          e['level'] = lvl unless lvl.nil?
          want = rank.fetch(lvl || 'unknown', 0) < rank[att] ? "assurance: #{att} attestation required but the evidence is #{lvl || 'unknown'}" : nil
          eq("att #{lvl.inspect} vs #{att}", AtlasPca.unmet_assurance({ 'attestation' => e }, { 'attestation' => att }), want)
        end
      end
      eq('no evidence', AtlasPca.unmet_assurance({}, { 'attestation' => 'software' }), 'assurance: software attestation required but there is no attestation evidence')
      eq('failed evidence', AtlasPca.unmet_assurance({ 'attestation' => { 'outcome' => 'fail' } }, { 'attestation' => 'software' }),
         'assurance: software attestation required but the attestation check is fail')
    end

    MutationKill.t('c28 assurance: zk requirement against every evidence level') do
      next true if skip?

      rank = { 'unknown' => 0, 'attested_vm' => 1, 'attested_vm_hw' => 1, 'stark' => 2, 'zkvm' => 2, 'groth16' => 3, 'policyvm_snark' => 3 }
      need = { 'attested_vm' => 1, 'attested_vm_hardware' => 1, 'proof' => 2, 'snark' => 3 }
      [nil, 'unknown', 'attested_vm', 'attested_vm_hw', 'stark', 'zkvm', 'groth16', 'policyvm_snark', 'bogus'].each do |lvl|
        need.each do |zk, n|
          e = { 'outcome' => 'pass' }
          e['level'] = lvl unless lvl.nil?
          want = if zk == 'attested_vm_hardware' && ['attested_vm', 'unknown', nil].include?(lvl)
                   'assurance: zk compliance (attested_vm_hardware) required but the prover key is not bound to hardware evidence'
                 elsif rank.fetch(lvl || 'unknown', 0) < n
                   "assurance: zk compliance (#{zk}) required but the evidence is #{lvl || 'unknown'}"
                 end
          eq("zk #{lvl.inspect} vs #{zk}", AtlasPca.unmet_assurance({ 'zk_compliance' => e }, { 'zk' => zk }), want)
        end
      end
      eq('no evidence', AtlasPca.unmet_assurance({}, { 'zk' => 'proof' }), 'assurance: zk compliance (proof) required but there is no zk_compliance evidence')
    end

    MutationKill.t('c28 assurance: signature, threshold and awaiting-audit requirements') do
      next true if skip?

      u = ->(report, req) { AtlasPca.unmet_assurance(report, req) }
      pass = ->(lvl) { lvl.nil? ? { 'outcome' => 'pass' } : { 'outcome' => 'pass', 'level' => lvl } }
      # signature: pq
      eq('pq via cap_chain', u.call({ 'leaf_signature' => pass.call('pq'), 'cap_chain' => pass.call('hybrid') }, { 'signature' => 'pq' }), nil)
      eq('pq via chain', u.call({ 'leaf_signature' => pass.call('pq'), 'chain' => pass.call('pq') }, { 'signature' => 'pq' }), nil)
      eq('cap_chain is preferred', u.call({ 'leaf_signature' => pass.call('pq'), 'cap_chain' => pass.call('ed25519'), 'chain' => pass.call('pq') },
                                          { 'signature' => 'pq' }), 'assurance: post-quantum signatures required but cap_chain is ed25519')
      eq('chain is used when cap_chain is absent', u.call({ 'leaf_signature' => pass.call('pq'), 'chain' => pass.call('ed25519') }, { 'signature' => 'pq' }),
         'assurance: post-quantum signatures required but chain is ed25519')
      eq('no chain evidence', u.call({ 'leaf_signature' => pass.call('pq') }, { 'signature' => 'pq' }),
         'assurance: post-quantum signatures required but there is no cap_chain evidence')
      eq('leaf without level', u.call({ 'leaf_signature' => pass.call(nil), 'cap_chain' => pass.call('pq') }, { 'signature' => 'pq' }),
         'assurance: post-quantum signatures required but leaf_signature is unknown')
      eq('leaf missing', u.call({ 'cap_chain' => pass.call('pq') }, { 'signature' => 'pq' }),
         'assurance: post-quantum signatures required but there is no leaf_signature evidence')
      # threshold
      th = ->(lvl, extra = {}) { { 'threshold' => pass.call(lvl).merge(extra) } }
      eq('threshold listed', u.call(th.call('multisig'), { 'threshold' => %w[multisig frost] }), nil)
      eq('threshold not listed', u.call(th.call('multisig'), { 'threshold' => ['frost'] }), 'assurance: threshold (frost) required but the scheme is multisig')
      eq('threshold unenforced', u.call(th.call(nil), { 'threshold' => %w[multisig frost] }),
         'assurance: threshold (multisig | frost) required but no threshold verifier enforced it')
      eq('threshold absent', u.call({}, { 'threshold' => ['multisig'] }), 'assurance: threshold (multisig) required but there is no threshold evidence')
      eq('audited scheme named is accepted', u.call(th.call('frost', 'awaiting_audit' => true), { 'threshold' => ['frost'] }), nil)
      # awaiting audit
      aa = { 'x' => { 'outcome' => 'pass', 'awaiting_audit' => true, 'level' => 'frost' } }
      msg = 'assurance: x rests on crypto awaiting audit (frost); set allowAwaitingAudit or list the scheme to accept it'
      eq('refused by default', u.call(aa, {}), msg)
      %w[allowAwaitingAudit allow_awaiting_audit allowPreview allow_preview].each do |k|
        eq("#{k} true", u.call(aa, { k => true }), nil)
        eq("#{k} false", u.call(aa, { k => false }), msg)
      end
      eq('level unknown in the message', u.call({ 'x' => { 'outcome' => 'pass', 'awaiting_audit' => true } }, {}),
         'assurance: x rests on crypto awaiting audit (unknown); set allowAwaitingAudit or list the scheme to accept it')
      eq('preview counts', u.call({ 'x' => { 'outcome' => 'pass', 'preview' => true, 'level' => 'p' } }, {}),
         'assurance: x rests on crypto awaiting audit (p); set allowAwaitingAudit or list the scheme to accept it')
      eq('failed entries are not audited', u.call({ 'x' => { 'outcome' => 'fail', 'awaiting_audit' => true } }, {}), nil)
      # only the threshold entry is excused by a listed scheme
      both = th.call('multisig').merge('other' => { 'outcome' => 'pass', 'awaiting_audit' => true, 'level' => 'multisig' })
      eq('listed scheme does not excuse another check', u.call(both, { 'threshold' => ['multisig'] }),
         'assurance: other rests on crypto awaiting audit (multisig); set allowAwaitingAudit or list the scheme to accept it')
    end

    # =================================================================================================================
    # missing_context.rb
    # =================================================================================================================

    MutationKill.t('c28 missing_context: supplier_of takes the longest segment-aligned prefix') do
      next true if skip?

      t = { 'env.obs' => 'rs_observation', 'env' => 'discharge_issuer' }
      eq('exact', AtlasPca.supplier_of('env.obs', t), 'rs_observation')
      eq('below', AtlasPca.supplier_of('env.obs.load', t), 'rs_observation')
      eq('shorter prefix', AtlasPca.supplier_of('env.observed', t), 'discharge_issuer')
      eq('root', AtlasPca.supplier_of('env', t), 'discharge_issuer')
      eq('default', AtlasPca.supplier_of('subject.id', t), 'principal')
      eq('empty table', AtlasPca.supplier_of('env.obs', {}), 'principal')
    end

    MutationKill.t('c28 missing_context: supplier_of keeps the first of two equally long matching prefixes') do
      next true if skip?

      twin = Class.new do
        define_method(:to_str) { 'env.a' }
        define_method(:to_s) { 'env.a' }
        define_method(:length) { 5 }
        define_method(:==) { |o| o.to_s == 'env.a' }
      end.new
      eq('first wins', AtlasPca.supplier_of('env.a', { 'env.a' => 'principal', twin => 'rs_observation' }), 'principal')
    end

    MutationKill.t('c28 missing_context: supplier_table_error') do
      next true if skip?

      s = ->(t) { AtlasPca.supplier_table_error(t) }
      msg = 'the supplier table must be an object'
      [nil, [], 'x', 5].each { |t| eq("not an object #{t.inspect}", s.call(t), msg) }
      eq('empty', s.call({}), nil)
      eq('all four suppliers', s.call({ 'env.a' => 'principal', 'env.b' => 'discharge_issuer', 'env.c' => 'rs_observation', 'env.d' => 'agent_declared_untrusted' }), nil)
      eq('integer key', s.call({ 5 => 'principal' }), "bad supplier path '5'")
      eq('symbol key', s.call({ 'env.a': 'principal' }), "bad supplier path 'env.a'")
      eq('unknown root', s.call({ 'foo' => 'principal' }), "bad supplier path 'foo'")
      %w[env.__proto__ subject.constructor action.params.prototype env.a.__proto__.b].each do |k|
        eq("forbidden #{k}", s.call({ k => 'principal' }), "bad supplier path '#{k}'")
      end
      eq('unknown supplier', s.call({ 'env.a' => 'everyone' }), "bad supplier for 'env.a'")
      eq('integer supplier', s.call({ 'env.a' => 5 }), "bad supplier for 'env.a'")
      eq('duck supplier', s.call({ 'env.a' => duck('principal') }), "bad supplier for 'env.a'")
    end

    MutationKill.t('c28 missing_context: mc_leaves depth bound, empty objects, forbidden keys and key order') do
      next true if skip?

      nest = ->(levels, leaf) { levels.times.inject(leaf) { |acc, _| { 'a' => acc } } }
      out = {}
      AtlasPca.mc_leaves(nest.call(20, 1), 'p', out)
      eq('depth 17 stops', out, { ('p' + ('.a' * 17)) => nest.call(3, 1) })
      out = {}
      AtlasPca.mc_leaves(nest.call(16, 1), 'p', out)
      eq('depth 16 does not stop', out, { ('p' + ('.a' * 16)) => 1 })
      out = {}
      AtlasPca.mc_leaves({ 'a' => {} }, 'p', out)
      eq('empty object is a leaf', out, { 'p.a' => {} })
      out = {}
      AtlasPca.mc_leaves(5, 'p', out)
      eq('scalar', out, { 'p' => 5 })
      out = {}
      AtlasPca.mc_leaves({ 'b' => 1, 'a' => 2, '__proto__' => 3, 'constructor' => { 'x' => 1 }, 'prototype' => 4 }, 'p', out)
      eq('forbidden skipped', out, { 'p.a' => 2, 'p.b' => 1 })
      eq('sorted insertion', out.keys, %w[p.a p.b])
    end

    MutationKill.t('c28 missing_context: mc_set_path replaces a non-object on the way') do
      next true if skip?

      root = { 'a' => 5 }
      AtlasPca.mc_set_path(root, %w[a b], 1)
      eq('replaced', root, { 'a' => { 'b' => 1 } })
      root = { 'a' => { 'k' => 1 } }
      AtlasPca.mc_set_path(root, %w[a b], 2)
      eq('kept', root, { 'a' => { 'k' => 1, 'b' => 2 } })
    end

    MutationKill.t('c28 missing_context: bind_context shapes, defaults and conflicts') do
      next true if skip?

      empty = { 'conflicts' => [], 'dropped' => [] }
      eq('bound not a Hash', AtlasPca.bind_context([], { 'env' => { 'a' => 1 } }), empty.merge('context' => []))
      bound = { 'action' => { 'verb' => 'v', 'resource' => 'r', 'params' => { 'amount' => 1 } }, 'env' => {} }
      eq('params not an object', AtlasPca.bind_context(bound, { 'action' => { 'params' => 'x' } }), empty.merge('context' => bound))
      eq('action not an object', AtlasPca.bind_context(bound, { 'action' => [] }), empty.merge('context' => bound))
      eq('subject not an object', AtlasPca.bind_context(bound, { 'subject' => 'x' }), empty.merge('context' => bound))
      eq('env not an object', AtlasPca.bind_context(bound, { 'env' => 'x' }), empty.merge('context' => bound))
      eq('supplied not a Hash', AtlasPca.bind_context(bound, 'x'), empty.merge('context' => bound))
      # no bound action: the default action is created
      eq('default action', AtlasPca.bind_context({}, { 'action' => { 'params' => { 'x' => 1 } } }),
         empty.merge('context' => { 'action' => { 'verb' => '', 'resource' => '', 'params' => { 'x' => 1 } } }))
      # an action without params gets params and no stray member
      bare = { 'action' => { 'verb' => 'v', 'resource' => 'r' } }
      eq('params created', AtlasPca.bind_context(bare, { 'action' => { 'params' => { 'x' => 1 } } }),
         empty.merge('context' => { 'action' => { 'verb' => 'v', 'resource' => 'r', 'params' => { 'x' => 1 } } }))
      # bound params survive a new sibling
      eq('params kept', AtlasPca.bind_context({ 'action' => { 'verb' => 'v', 'resource' => 'r', 'params' => { 'a' => 1 } } }, { 'action' => { 'params' => { 'b' => 2 } } }),
         empty.merge('context' => { 'action' => { 'verb' => 'v', 'resource' => 'r', 'params' => { 'a' => 1, 'b' => 2 } } }))
      # a bound scalar above a supplied path blocks it
      eq('blocked by a scalar', AtlasPca.bind_context({ 'env' => 5 }, { 'env' => { 'a' => 1 } }), { 'context' => { 'env' => 5 }, 'conflicts' => ['env.a'], 'dropped' => [] })
      # an agent-declared path is dropped
      eq('dropped', AtlasPca.bind_context({ 'env' => {} }, { 'env' => { 'a' => 1 } }, { 'env.a' => 'agent_declared_untrusted' }),
         { 'context' => { 'env' => {} }, 'conflicts' => [], 'dropped' => ['env.a'] })
    end

    MutationKill.t('c28 missing_context: bind_context asks about the prefixes from the first segment on, and a non-object action is replaced') do
      next true if skip?

      orig = AtlasPca.method(:resolve_path)
      asked = []
      MutationKill::Seam.with(AtlasPca, { resolve_path: ->(c, p) { asked << p; orig.call(c, p) } }) do
        AtlasPca.bind_context({ 'env' => {} }, { 'env' => { 'a' => 1 } })
      end
      eq('asked', asked, %w[env.a env])
      # nothing is found (seam): the bound action is a string, so it is replaced, never indexed
      r = MutationKill::Seam.with(AtlasPca, { resolve_path: ->(_c, _p) { { 'found' => false } } }) do
        AtlasPca.bind_context({ 'action' => 'str' }, { 'action' => { 'params' => { 'x' => 1 } } })
      end
      eq('replaced', r, { 'context' => { 'action' => { 'params' => { 'x' => 1 } } }, 'conflicts' => [], 'dropped' => [] })
    end

    MutationKill.t('c28 missing_context: decide_with_missing passes nil supplied, a fresh ill flag, and trusts paths over the group verdict') do
      next true if skip?

      bound = { 'action' => { 'verb' => 'v', 'resource' => 'r', 'params' => {} }, 'env' => { 'tier' => 'gold' } }
      leaf = { 'field' => 'env.approved', 'op' => 'eq', 'value' => true }
      ob = AtlasPca.method(:bind_context)
      got = []
      MutationKill::Seam.with(AtlasPca, { bind_context: ->(b, s, t = {}) { got << [s, t]; ob.call(b, s, t) } }) do
        AtlasPca.decide_with_missing([leaf], bound)
      end
      eq('bind_context arguments', got, [[nil, {}]])
      oc = AtlasPca.method(:mc_collect)
      ills = []
      MutationKill::Seam.with(AtlasPca, { mc_collect: ->(c, x, out, ill, depth = 0) { ills << ill.dup if depth.zero?; oc.call(c, x, out, ill, depth) } }) do
        AtlasPca.decide_with_missing([leaf], bound)
      end
      eq('ill flag', ills, [{ v: false }])
      # the group is undecided but every leaf is decided: nothing is named, so it is ill-typed
      stub = ->(c, _x) { c.is_a?(Hash) && c.key?('all_of') ? 'unknown' : 'true' }
      r = MutationKill::Seam.with(AtlasPca, { evaluate_condition_tri: stub }) { AtlasPca.decide_with_missing([leaf], bound) }
      eq('no path, no ill flag', r, { 'decision' => 'deny', 'reason' => 'ill_typed_context', 'missing' => [] })
    end

    MutationKill.t('c28 missing_context: mc_collect depth limit is 64 from depth 0') do
      next true if skip?

      leaf = { 'field' => 'env.zz', 'op' => 'eq', 'value' => 1 }
      ctx = { 'env' => {} }
      wrap = ->(n) { n.times.inject(leaf) { |acc, _| { 'all_of' => [acc] } } }
      [[64, ['env.zz'], false], [65, [], true], [63, ['env.zz'], false]].each do |n, want_out, want_ill|
        out = []
        ill = { v: false }
        AtlasPca.mc_collect(wrap.call(n), ctx, out, ill)
        eq("nest #{n} out", out, want_out)
        eq("nest #{n} ill", ill, { v: want_ill })
      end
      # an explicit depth is honoured
      out = []
      ill = { v: false }
      AtlasPca.mc_collect(leaf, ctx, out, ill, 65)
      eq('depth 65 leaf', [out, ill], [[], { v: true }])
      out = []
      ill = { v: false }
      AtlasPca.mc_collect(leaf, ctx, out, ill, 64)
      eq('depth 64 leaf', [out, ill], [['env.zz'], { v: false }])
    end

    MutationKill.t('c28 missing_context: mc_collect groups, non-objects and decided leaves') do
      next true if skip?

      ctx = { 'env' => { 'tier' => 'gold' } }
      a = { 'field' => 'env.a', 'op' => 'eq', 'value' => 1 }
      b = { 'field' => 'env.b', 'op' => 'eq', 'value' => 1 }
      run = lambda do |c, x = ctx|
        out = []
        ill = { v: false }
        AtlasPca.mc_collect(c, x, out, ill)
        [out, ill]
      end
      eq('all_of', run.call({ 'all_of' => [a, b] }), [%w[env.a env.b], { v: false }])
      eq('any_of', run.call({ 'any_of' => [a, b] }), [%w[env.a env.b], { v: false }])
      eq('not', run.call({ 'not' => a }), [%w[env.a], { v: false }])
      eq('all_of empty', run.call({ 'all_of' => [] }), [[], { v: true }])
      eq('any_of empty', run.call({ 'any_of' => [] }), [[], { v: true }])
      eq('all_of string', run.call({ 'all_of' => 'x' }), [[], { v: true }])
      eq('any_of integer', run.call({ 'any_of' => 5 }), [[], { v: true }])
      eq('not nil', run.call({ 'not' => nil }), [[], { v: true }])
      [nil, 5, 'x', []].each { |c| eq("non-object #{c.inspect}", run.call(c), [[], { v: true }]) }
      # decided leaves name nothing and are not ill
      eq('decided true', run.call({ 'field' => 'env.tier', 'op' => 'eq', 'value' => 'gold' }), [[], { v: false }])
      eq('decided false', run.call({ 'field' => 'env.tier', 'op' => 'eq', 'value' => 'silver' }), [[], { v: false }])
      # a present value of the wrong type is ill-typed, not missing
      eq('ill typed', run.call({ 'field' => 'env.tier', 'op' => 'lt', 'value' => 5 }), [[], { v: true }])
      # a ref that is empty or not a String names nothing
      eq('empty ref', run.call({ 'field' => 'env.tier', 'op' => 'eq', 'ref' => '' }), [[], { v: true }])
      eq('integer ref', run.call({ 'field' => 'env.tier', 'op' => 'eq', 'ref' => 5 }), [[], { v: true }])
      eq('missing ref', run.call({ 'field' => 'env.tier', 'op' => 'eq', 'ref' => 'env.want' }), [%w[env.want], { v: false }])
      eq('integer field', run.call({ 'field' => 5, 'op' => 'eq', 'value' => 1 }), [[], { v: true }])
      eq('no field', run.call({ 'op' => 'eq', 'value' => 1 }), [[], { v: true }])
    end

    MutationKill.t('c28 missing_context: mc_collect names action.params when the params are not an object') do
      next true if skip?

      leaf = { 'field' => 'action.params.x', 'op' => 'eq', 'value' => 1 }
      run = lambda do |c, x|
        out = []
        ill = { v: false }
        AtlasPca.mc_collect(c, x, out, ill)
        [out, ill]
      end
      twice = [%w[action.params.x action.params.x], { v: false }]
      eq('no action', run.call(leaf, {}), twice)
      eq('nil context', run.call(leaf, nil), twice)
      eq('array context', run.call(leaf, []), twice)
      eq('array action', run.call(leaf, { 'action' => [] }), twice)
      eq('string action', run.call(leaf, { 'action' => 'x' }), twice)
      exact = { 'field' => 'action.params', 'op' => 'lt', 'value' => 5 }
      once = [%w[action.params], { v: false }]
      eq('exact, params a string', run.call(exact, { 'action' => { 'params' => 'str' } }), once)
      eq('exact, params nil', run.call(exact, { 'action' => { 'params' => nil } }), once)
      eq('exact, params an object', run.call(exact, { 'action' => { 'params' => {} } }), [[], { v: true }])
      eq('exact, params an array', run.call(exact, { 'action' => { 'params' => [] } }), [[], { v: true }])
      eq('other field, no params', run.call({ 'field' => 'env.tier', 'op' => 'lt', 'value' => 5 }, { 'env' => { 'tier' => 'gold' } }), [[], { v: true }])
    end

    MutationKill.t('c28 missing_context: decide_with_missing decisions, reasons and totality') do
      next true if skip?

      bound = { 'action' => { 'verb' => 'v', 'resource' => 'r', 'params' => { 'amount' => 50 } }, 'subject' => { 'id' => 'u1' }, 'env' => { 'tier' => 'gold' } }
      ill_leaf = { 'field' => 'env.tier', 'op' => 'lt', 'value' => 5 }
      missing = { 'field' => 'env.approved', 'op' => 'eq', 'value' => true }
      d = ->(where, b = bound, supplied = nil, suppliers = nil) { AtlasPca.decide_with_missing(where, b, supplied, suppliers) }
      deny = ->(reason, miss = []) { { 'decision' => 'deny', 'reason' => reason, 'missing' => miss } }
      # the optional arguments really are optional
      eq('allow', AtlasPca.decide_with_missing([{ 'field' => 'env.tier', 'op' => 'eq', 'value' => 'gold' }], bound), { 'decision' => 'allow', 'missing' => [] })
      # an ill-typed leaf beside a missing one makes the whole ill-typed
      eq('ill beside missing', d.call([ill_leaf, missing]), deny.call('ill_typed_context'))
      eq('empty all_of beside missing', d.call([{ 'all_of' => [] }, missing]), deny.call('ill_typed_context'))
      eq('string all_of beside missing', d.call([{ 'all_of' => 'x' }, missing]), deny.call('ill_typed_context'))
      eq('nil entry beside missing', d.call([nil, missing]), deny.call('ill_typed_context'))
      eq('deep nest beside missing', d.call([(1..65).inject(ill_leaf) { |acc, _| { 'all_of' => [acc] } }, missing]), deny.call('ill_typed_context'))
      eq('integer field beside missing', d.call([{ 'field' => 5, 'op' => 'eq', 'value' => 1 }, missing]), deny.call('ill_typed_context'))
      eq('missing alone', d.call([missing]),
         { 'decision' => 'escalate', 'reason' => 'escalate: missing_context principal:env.approved', 'missing' => [{ 'path' => 'env.approved', 'supplier' => 'principal' }] })
      # a params-rooted leaf over a non-object params is missing; over an object it is ill-typed
      str_params = bound.merge('action' => { 'verb' => 'v', 'resource' => 'r', 'params' => 'str' })
      eq('params a string', d.call([{ 'field' => 'action.params', 'op' => 'lt', 'value' => 5 }], str_params),
         { 'decision' => 'escalate', 'reason' => 'escalate: missing_context principal:action.params', 'missing' => [{ 'path' => 'action.params', 'supplier' => 'principal' }] })
      eq('params an object', d.call([{ 'field' => 'action.params', 'op' => 'lt', 'value' => 5 }]), deny.call('ill_typed_context'))
      no_params = bound.merge('action' => { 'verb' => 'v', 'resource' => 'r' })
      eq('ill-typed env leaf, no params', d.call([ill_leaf], no_params), deny.call('ill_typed_context'))
      # untrusted paths are listed with commas
      sup = { 'env.a' => 'agent_declared_untrusted', 'env.b' => 'agent_declared_untrusted' }
      two = [{ 'field' => 'env.b', 'op' => 'eq', 'value' => 1 }, { 'field' => 'env.a', 'op' => 'eq', 'value' => 1 }]
      eq('untrusted', d.call(two, bound, nil, sup),
         deny.call('missing_context_untrusted: env.a,env.b', [{ 'path' => 'env.a', 'supplier' => 'agent_declared_untrusted' }, { 'path' => 'env.b', 'supplier' => 'agent_declared_untrusted' }]))
      # bound shapes
      eq('action not an object', d.call([missing], { 'action' => 'x', 'env' => { 'tier' => 'gold' } }), deny.call('bad_context'))
      eq('bound an array', d.call([missing], []), deny.call('bad_context'))
      eq('bound nil', d.call([missing], nil), deny.call('bad_context'))
      eq('bad table', d.call([missing], bound, nil, 'x'), deny.call("bad supplier table: the supplier table must be an object"))
      eq('empty where', d.call([]), deny.call('condition_false'))
      # a fault is a refusal in the full shape
      r = MutationKill::Seam.with(AtlasPca, { supplier_table_error: ->(_t) { raise 'boom' } }) { d.call([missing]) }
      eq('fault', r, { 'decision' => 'deny', 'reason' => 'evaluation error (fail closed)', 'missing' => [] })
    end
  end
end
