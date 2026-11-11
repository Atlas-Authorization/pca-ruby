# frozen_string_literal: true

# c26: mutation-kill tests for lib/atlas_pca/lease.rb and lib/atlas_pca/operations.rb.
# AtlasPca is resolved at CALL time everywhere (the oracle re-evaluates it per mutant). Only plain helper classes that do not
# inherit from AtlasPca are defined at load. Lease signatures are real Ed25519 (a fixed test seed; no secret is committed that
# guards anything); the registry logic is driven with the signature check stubbed where the signature is not the point.
require 'base64'
require 'openssl'
require 'json'
require 'timeout'

module MutationKill
  module C26
    module_function

    def skip?(base) = (f = ENV['MUT_FILE']) && !f.empty? && f != base

    # Exact comparison: booleans and nil by identity, everything else by ==. Raises (= the test fails) with a label.
    def same(got, want, label)
      ok = want.nil? || want == true || want == false ? got.equal?(want) : got == want
      raise "#{label}: got #{got.inspect}, want #{want.inspect}" unless ok

      true
    end

    def seam(mod, stubs)
      orig = stubs.keys.to_h { |n| [n, mod.method(n)] }
      stubs.each { |n, impl| mod.define_singleton_method(n, &impl) }
      yield
    ensure
      orig&.each { |n, m| mod.define_singleton_method(n, m) }
    end

    # ------------------------------------------------------------------------------------------------------------------
    module Lz
      SEED = ("\x07".b * 32).freeze
      LEASE_KEYS = %w[v lease_id path grant_ref holder requester approvers justification_digest seq issued_at renewed_at expires_at max_ttl authority].freeze
      REV_KEYS = %w[v target value revoked_at authority].freeze
      LEASE_DOM = "atlas-pca/lease/v1\x00".b.freeze
      REV_DOM = "atlas-pca/lease-revoke/v1\x00".b.freeze

      class << self
        def pkey = (@pkey ||= OpenSSL::PKey.new_raw_private_key('ED25519', SEED))
        def pub = (@pub ||= Base64.urlsafe_encode64(pkey.raw_public_key, padding: false))

        def sign(dom, body)
          Base64.urlsafe_encode64(pkey.sign(nil, dom + AtlasPca.canon_bytes(body)), padding: false)
        end

        def base(over = {})
          { 'v' => 1, 'lease_id' => 'L1', 'path' => 'db/prod', 'grant_ref' => 'g1', 'holder' => 'agent', 'requester' => 'alice',
            'approvers' => ['bob'], 'justification_digest' => 'j1', 'seq' => 1, 'issued_at' => 1000, 'renewed_at' => 1000,
            'expires_at' => 2000, 'max_ttl' => 5000, 'authority' => pub }.merge(over)
        end

        def signed(over = {})
          @sl ||= {}
          @sl[over] ||= begin
            b = base(over)
            b.merge('sig' => sign(LEASE_DOM, LEASE_KEYS.to_h { |k| [k, b[k]] }))
          end
        end

        def rbase(over = {})
          { 'v' => 1, 'target' => 'lease', 'value' => 'L1', 'revoked_at' => 1500, 'authority' => pub }.merge(over)
        end

        def rsigned(over = {})
          @sr ||= {}
          @sr[over] ||= begin
            b = rbase(over)
            b.merge('sig' => sign(REV_DOM, REV_KEYS.to_h { |k| [k, b[k]] }))
          end
        end

        # a record with a distinct fake signature (for the registry logic with verify_lease stubbed)
        def rec(over = {}) = base(over).merge('sig' => "sig-#{over.sort_by { |k, _| k }.inspect}")
        def rrec(over = {}) = rbase(over).merge('sig' => "rsig-#{over.sort_by { |k, _| k }.inspect}")

        def stubbed
          C26.seam(AtlasPca, verify_lease: ->(_r) { true }, verify_lease_revocation: ->(_r) { true }) { yield }
        end

        def registry(pol = {}) = AtlasPca::LeaseRegistry.new({ 'authorities' => [pub] }.merge(pol), AtlasPca::MemoryLeaseKv.new)
      end
    end
  end

  # ==================================================================================================================
  # lease.rb
  # ==================================================================================================================
  t('c26 lease: domains are frozen binary strings with the exact bytes') do
    next true if C26.skip?('lease.rb')

    [[AtlasPca::LEASE_DOMAIN, "atlas-pca/lease/v1\x00".b], [AtlasPca::LEASE_REVOKE_DOMAIN, "atlas-pca/lease-revoke/v1\x00".b]].each do |got, want|
      C26.same(got.encoding, Encoding::BINARY, 'domain encoding')
      C26.same(got.frozen?, true, 'domain frozen')
      C26.same(got.bytes, want.bytes, 'domain bytes')
    end
    C26.same(AtlasPca::LEASE_BODY_KEYS, C26::Lz::LEASE_KEYS, 'body keys')
    C26.same(AtlasPca::LEASE_REVOKE_KEYS, C26::Lz::REV_KEYS, 'revoke keys')
  end

  t('c26 lease_well_formed?: every operand and every bound decides, exact booleans') do
    next true if C26.skip?('lease.rb')

    b = C26::Lz.base
    ov = ->(h) { b.merge(h) }
    del = ->(k) { b.reject { |kk, _| kk == k } }
    seg = 'a' * 64
    valid = [b, ov.({ 'seq' => 2, 'renewed_at' => 1500 }), ov.({ 'seq' => 2, 'renewed_at' => 1000 }), ov.({ 'expires_at' => 1001 }),
             ov.({ 'max_ttl' => 1 }), ov.({ 'max_ttl' => (2**53) - 1 }), ov.({ 'lease_id' => 'a' * 128 }), ov.({ 'grant_ref' => 'a' * 256 }),
             ov.({ 'holder' => 'a' * 128 }), ov.({ 'requester' => 'a' * 128 }), ov.({ 'authority' => 'a' * 128 }),
             ov.({ 'justification_digest' => 'a' * 128 }), ov.({ 'path' => 'a' }), ov.({ 'path' => seg }),
             ov.({ 'path' => ([seg] * 8).join('/') }), ov.({ 'path' => 'a-b_c.d0/x' }), ov.({ 'approvers' => [] }),
             ov.({ 'approvers' => ['a' * 128] }), ov.({ 'approvers' => Array.new(16) { |i| "x#{i}" } })]
    valid.each_with_index { |l, i| C26.same(AtlasPca.lease_well_formed?(l), true, "valid #{i}") }
    bad = [nil, [], 'x', 5, 1.0, {}, ov.({ 'v' => 2 }), ov.({ 'v' => 1.0 }), ov.({ 'v' => '1' }), ov.({ 'v' => nil }), del.('v'),
           ov.({ 'lease_id' => '' }), ov.({ 'lease_id' => 5 }), ov.({ 'lease_id' => 'a' * 129 }), del.('lease_id'),
           ov.({ 'grant_ref' => '' }), ov.({ 'grant_ref' => 'a' * 257 }), ov.({ 'holder' => '' }), ov.({ 'holder' => 'a' * 129 }),
           ov.({ 'requester' => '' }), ov.({ 'requester' => 'a' * 129 }), ov.({ 'authority' => '' }), ov.({ 'authority' => 'a' * 129 }),
           ov.({ 'justification_digest' => '' }), ov.({ 'justification_digest' => 'a' * 129 }), ov.({ 'justification_digest' => 5 }),
           ov.({ 'path' => nil }), ov.({ 'path' => 5 }), ov.({ 'path' => '' }), ov.({ 'path' => 'A' }), ov.({ 'path' => 'a b' }),
           ov.({ 'path' => 'a//b' }), ov.({ 'path' => '/a' }), ov.({ 'path' => 'a/' }), ov.({ 'path' => 'a' * 65 }),
           ov.({ 'path' => (['a'] * 9).join('/') }), ov.({ 'path' => "a\n" }), ov.({ 'path' => "a/b\n" }), ov.({ 'path' => 'a/B' }),
           ov.({ 'seq' => 0 }), ov.({ 'seq' => -1 }), ov.({ 'seq' => 'x' }), ov.({ 'seq' => 1.0 }), ov.({ 'seq' => nil }),
           ov.({ 'seq' => 2**53 }), ov.({ 'issued_at' => -1 }), ov.({ 'issued_at' => 'x' }), ov.({ 'issued_at' => nil }),
           ov.({ 'renewed_at' => 'x' }), ov.({ 'renewed_at' => nil }), ov.({ 'expires_at' => 'x' }), ov.({ 'expires_at' => 2**53 }),
           ov.({ 'max_ttl' => 0 }), ov.({ 'max_ttl' => -1 }), ov.({ 'max_ttl' => 'x' }), ov.({ 'max_ttl' => 1.0 }), del.('max_ttl'),
           ov.({ 'seq' => 2, 'renewed_at' => 999 }), ov.({ 'expires_at' => 1000 }), ov.({ 'expires_at' => 999 }),
           ov.({ 'seq' => 1, 'renewed_at' => 1500 }), ov.({ 'seq' => 2, 'renewed_at' => 2000 }),
           ov.({ 'approvers' => nil }), ov.({ 'approvers' => 'abc' }), ov.({ 'approvers' => {} }), del.('approvers'),
           ov.({ 'approvers' => Array.new(17) { |i| "x#{i}" } }), ov.({ 'approvers' => [''] }), ov.({ 'approvers' => [5] }),
           ov.({ 'approvers' => [nil] }), ov.({ 'approvers' => ['a' * 129] })]
    bad.each_with_index { |l, i| C26.same(AtlasPca.lease_well_formed?(l), false, "bad #{i}") }
    C26.same(AtlasPca.lease_cap({ 'issued_at' => 1000, 'max_ttl' => 5000 }), 6000, 'cap')
  end

  t('c26 verify_lease: real signature over exactly the content; malformed-but-signed and a faulting verifier are exactly false') do
    next true if C26.skip?('lease.rb')

    lz = C26::Lz
    good = lz.signed
    C26.same(AtlasPca.verify_lease(good), true, 'good')
    C26.same(AtlasPca.verify_lease(good.merge('holder' => 'mallory')), false, 'tampered')
    C26.same(AtlasPca.verify_lease(good.reject { |k, _| k == 'sig' }), false, 'no sig')
    C26.same(AtlasPca.verify_lease(good.merge('sig' => 5)), false, 'sig not string')
    # signed correctly but not well formed (seq 0): the well-formedness guard alone refuses it
    mal = lz.signed({ 'seq' => 0 })
    C26.same(AtlasPca.lease_well_formed?(mal), false, 'mal wf')
    C26.same(AtlasPca.verify_lease(mal), false, 'mal signed')
    [nil, [], 'x', 5].each { |x| C26.same(AtlasPca.verify_lease(x), false, 'non-hash') }
    C26.seam(AtlasPca, k3_verify_body: ->(*_a) { raise 'boom' }) { C26.same(AtlasPca.verify_lease(good), false, 'fault') }
    true
  end

  t('c26 lease_revocation_well_formed? / verify_lease_revocation: every operand decides') do
    next true if C26.skip?('lease.rb')

    lz = C26::Lz
    b = lz.rbase
    ov = ->(h) { b.merge(h) }
    valid = [b, ov.({ 'target' => 'grant' }), ov.({ 'target' => 'prefix', 'value' => 'db/prod' }), ov.({ 'target' => 'lease', 'value' => 'A B' }),
             ov.({ 'value' => 'a' * 256 }), ov.({ 'authority' => 'a' * 128 }), ov.({ 'revoked_at' => 0 })]
    valid.each_with_index { |r, i| C26.same(AtlasPca.lease_revocation_well_formed?(r), true, "valid #{i}") }
    bad = [nil, [], 'x', 5, {}, ov.({ 'v' => 2 }), ov.({ 'v' => 1.0 }), ov.({ 'v' => '1' }), ov.({ 'value' => '' }),
           ov.({ 'value' => 'a' * 257 }), ov.({ 'value' => 5 }), ov.({ 'authority' => '' }), ov.({ 'authority' => 'a' * 129 }),
           ov.({ 'revoked_at' => -1 }), ov.({ 'revoked_at' => 'x' }), ov.({ 'revoked_at' => 2**53 }), ov.({ 'revoked_at' => 1.5 }),
           ov.({ 'target' => 'bogus' }), ov.({ 'target' => nil }), ov.({ 'target' => 'Lease' }), ov.({ 'target' => '' }),
           ov.({ 'target' => 'prefix', 'value' => 'DB' }), ov.({ 'target' => 'prefix', 'value' => 'a b' }),
           ov.({ 'target' => 'prefix', 'value' => 'a//b' }), ov.({ 'target' => 'prefix', 'value' => "a\n" })]
    bad.each_with_index { |r, i| C26.same(AtlasPca.lease_revocation_well_formed?(r), false, "bad #{i}") }
    good = lz.rsigned
    C26.same(AtlasPca.verify_lease_revocation(good), true, 'good')
    C26.same(AtlasPca.verify_lease_revocation(good.merge('value' => 'L2')), false, 'tampered')
    C26.same(AtlasPca.verify_lease_revocation(good.reject { |k, _| k == 'sig' }), false, 'no sig')
    # signed correctly but target unknown / prefix not a path: only the well-formedness guard refuses
    C26.same(AtlasPca.verify_lease_revocation(lz.rsigned({ 'target' => 'bogus' })), false, 'bogus target signed')
    C26.same(AtlasPca.verify_lease_revocation(lz.rsigned({ 'target' => 'prefix', 'value' => 'A B' })), false, 'bad prefix signed')
    [nil, [], 'x', 5].each { |x| C26.same(AtlasPca.verify_lease_revocation(x), false, 'non-hash') }
    C26.seam(AtlasPca, k3_verify_body: ->(*_a) { raise 'boom' }) { C26.same(AtlasPca.verify_lease_revocation(good), false, 'fault') }
    true
  end

  t('c26 path_under / lease_covers?: segment boundary, issued_at <= revoked_at, each target') do
    next true if C26.skip?('lease.rb')

    [['a', 'a', true], ['a/b', 'a', true], ['a/b/c', 'a/b', true], ['ab', 'a', false], ['a', 'a/b', false], ['db/production', 'db/prod', false],
     ['b/a', 'a', false]].each { |p, pre, want| C26.same(AtlasPca.path_under(p, pre), want, "path_under #{p} #{pre}") }
    l = C26::Lz.base
    cov = ->(r) { AtlasPca.lease_covers?(r, l) }
    rb = C26::Lz.rbase
    C26.same(cov.(rb.merge('revoked_at' => 1000)), true, 'equal time covers')
    C26.same(cov.(rb.merge('revoked_at' => 999)), false, 'revocation before issue')
    C26.same(cov.(rb.merge('revoked_at' => 1001)), true, 'later covers')
    C26.same(cov.(rb.merge('value' => 'L2')), false, 'other lease')
    C26.same(cov.(rb.merge('target' => 'grant', 'value' => 'g1')), true, 'grant')
    C26.same(cov.(rb.merge('target' => 'grant', 'value' => 'g2')), false, 'other grant')
    C26.same(cov.(rb.merge('target' => 'grant', 'value' => 'L1')), false, 'grant is not lease id')
    C26.same(cov.(rb.merge('target' => 'prefix', 'value' => 'db')), true, 'prefix')
    C26.same(cov.(rb.merge('target' => 'prefix', 'value' => 'db/prod')), true, 'prefix equal')
    C26.same(cov.(rb.merge('target' => 'prefix', 'value' => 'db/pro')), false, 'prefix not on a boundary')
    C26.same(cov.(rb.merge('target' => 'prefix', 'value' => 'db/prod', 'revoked_at' => 999)), false, 'prefix before issue')
    true
  end

  t('c26 sod_error: each rule and its exact message; p tolerates non-hash') do
    next true if C26.skip?('lease.rb')

    l = ->(ap, over = {}) { { 'requester' => 'alice', 'holder' => 'agent', 'approvers' => ap }.merge(over) }
    C26.same(AtlasPca.sod_error(l.(['bob'])), nil, 'default ok')
    C26.same(AtlasPca.sod_error(l.(['bob']), {}), nil, 'empty policy ok')
    [nil, 5, [], 'x'].each { |p| C26.same(AtlasPca.sod_error(l.(['bob']), p), nil, "non-hash policy #{p.inspect}") }
    msg = 'minApprovals must be a positive integer'
    [0, -1, '1', 1.0, true, 2**53, [1]].each { |k| C26.same(AtlasPca.sod_error(l.(['bob']), { 'minApprovals' => k }), msg, "k=#{k.inspect}") }
    C26.same(AtlasPca.sod_error(l.(['bob']), { 'minApprovals' => 1 }), nil, 'k=1')
    C26.same(AtlasPca.sod_error(l.(['bob']), { 'minApprovals' => (2**53) - 1 }), '1 approver(s), need 9007199254740991', 'k=max safe')
    C26.same(AtlasPca.sod_error(l.(['bob']), { 'minApprovals' => 2 }), '1 approver(s), need 2', 'k=2')
    C26.same(AtlasPca.sod_error(l.(['bob', 'carol']), { 'minApprovals' => 2 }), nil, 'k met')
    C26.same(AtlasPca.sod_error(l.([])), '0 approver(s), need 1', 'none')
    C26.same(AtlasPca.sod_error(l.(%w[bob bob])), 'an approver is listed twice', 'twice')
    C26.same(AtlasPca.sod_error(l.(['alice'])), 'the requester may not approve their own request', 'requester')
    C26.same(AtlasPca.sod_error(l.(['agent'])), 'the holder may not approve its own lease', 'holder')
    C26.same(AtlasPca.sod_error(l.(['bob']), {}, ['bob']), "an approver appears in the holder's delegation chain", 'chain')
    C26.same(AtlasPca.sod_error(l.(['bob']), {}, ['zed']), nil, 'chain other')
    C26.same(AtlasPca.sod_error(l.(['bob']), { 'eligibleApprovers' => ['carol'] }), 'an approver is not eligible', 'not eligible')
    C26.same(AtlasPca.sod_error(l.(['bob']), { 'eligibleApprovers' => [] }), 'an approver is not eligible', 'eligible empty')
    C26.same(AtlasPca.sod_error(l.(['bob']), { 'eligibleApprovers' => ['bob'] }), nil, 'eligible')
    # order: duplicate before requester; requester before holder
    C26.same(AtlasPca.sod_error(l.(%w[alice alice])), 'the requester may not approve their own request', 'order 1')
    C26.same(AtlasPca.sod_error(l.(['x'], { 'requester' => 'x', 'holder' => 'x' })), 'the requester may not approve their own request', 'order 2')
    true
  end

  t('c26 LeaseRegistry#accept: issue, replay, fork, renewals, every refusal code with the exact hash') do
    next true if C26.skip?('lease.rb')

    lz = C26::Lz
    s = C26.method(:same)
    lz.stubbed do
      reg = lz.registry
      r1 = lz.rec
      s.(reg.accept(r1), { 'ok' => true, 'replaced' => true, 'seq' => 1 }, 'issue')
      s.(reg.get('L1'), r1, 'current')
      s.(reg.history('L1'), [{ 'seq' => 1, 'renewed_at' => 1000, 'expires_at' => 2000, 'justification_digest' => 'j1' }], 'history 1')
      s.(reg.accept(r1), { 'ok' => true, 'replaced' => false, 'seq' => 1 }, 'replay')
      s.(reg.accept(lz.rec({ 'justification_digest' => 'jx' })), { 'ok' => false, 'code' => 'lease_fork' }, 'fork')
      s.(reg.accept(lz.rec({ 'seq' => 3, 'renewed_at' => 1500, 'expires_at' => 3000, 'justification_digest' => 'j2' })), { 'ok' => false, 'code' => 'bad_seq' }, 'skip')
      r2 = lz.rec({ 'seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000, 'justification_digest' => 'j2' })
      s.(reg.accept(r2), { 'ok' => true, 'replaced' => true, 'seq' => 2 }, 'renew')
      s.(reg.history('L1'), [{ 'seq' => 1, 'renewed_at' => 1000, 'expires_at' => 2000, 'justification_digest' => 'j1' },
                             { 'seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000, 'justification_digest' => 'j2' }], 'history 2')
      s.(reg.accept(r1), { 'ok' => false, 'code' => 'stale_seq' }, 'stale')
      # a renewal with an equal renewed_at is allowed; a smaller one is not_extending
      r3b = lz.rec({ 'seq' => 3, 'renewed_at' => 1400, 'expires_at' => 4000, 'justification_digest' => 'j3' })
      s.(reg.accept(r3b), { 'ok' => false, 'code' => 'not_extending' }, 'renewed earlier')
      r3 = lz.rec({ 'seq' => 3, 'renewed_at' => 1500, 'expires_at' => 4000, 'justification_digest' => 'j3' })
      s.(reg.accept(r3), { 'ok' => true, 'replaced' => true, 'seq' => 3 }, 'equal renewed_at ok')
      s.(reg.history('L1').map { |e| e['seq'] }, [1, 2, 3], 'history 3')
      h = reg.history('L1')
      h << :junk
      s.(reg.history('L1').length, 3, 'history is a copy')
      s.(reg.history('nope'), [], 'history unknown')
    end
    true
  end

  t('c26 LeaseRegistry#accept: refusal codes and their order') do
    next true if C26.skip?('lease.rb')

    lz = C26::Lz
    s = C26.method(:same)
    lz.stubbed do
      bad = ->(code) { { 'ok' => false, 'code' => code } }
      after1 = lambda do |pol = {}|
        reg = lz.registry({ 'authorities' => [lz.pub, 'other'] }.merge(pol))
        reg.accept(lz.rec)
        reg
      end
      s.(lz.registry.accept(lz.rec({ 'seq' => 2, 'renewed_at' => 1500 })), bad.('bad_seq'), 'first record seq 2')
      s.(lz.registry.accept(lz.rec({ 'authority' => 'zzz' })), bad.('unknown_authority'), 'unknown authority')
      C26.seam(AtlasPca, verify_lease: ->(_r) { false }) { s.(lz.registry.accept(lz.rec), bad.('bad_record'), 'bad record') }
      s.(lz.registry.accept(lz.rec({ 'approvers' => ['alice'] })),
         { 'ok' => false, 'code' => 'sod', 'reason' => 'the requester may not approve their own request' }, 'sod requester')
      s.(lz.registry.accept(lz.rec, ['bob']),
         { 'ok' => false, 'code' => 'sod', 'reason' => "an approver appears in the holder's delegation chain" }, 'sod chain')
      s.(lz.registry('minApprovals' => 2).accept(lz.rec),
         { 'ok' => false, 'code' => 'sod', 'reason' => '1 approver(s), need 2' }, 'sod k')
      s.(lz.registry.accept(lz.rec({ 'expires_at' => 6001 })), bad.('over_max_ttl'), 'over cap')
      s.(lz.registry.accept(lz.rec({ 'expires_at' => 6000 })), { 'ok' => true, 'replaced' => true, 'seq' => 1 }, 'at cap')
      s.(lz.registry('maxTtlCeiling' => 4000).accept(lz.rec), bad.('ttl_ceiling'), 'ceiling')
      s.(lz.registry('maxTtlCeiling' => 5000).accept(lz.rec), { 'ok' => true, 'replaced' => true, 'seq' => 1 }, 'at ceiling')
      s.(lz.registry('maxTtlCeiling' => 4000).accept(lz.rec({ 'expires_at' => 6001 })), bad.('over_max_ttl'), 'over cap before ceiling')
      # renewal mismatches: each identity field
      { 'authority' => 'other', 'path' => 'db/other', 'grant_ref' => 'g9', 'holder' => 'h2', 'requester' => 'r2', 'max_ttl' => 6000,
        'issued_at' => 500 }.each do |k, v|
        s.(after1.().accept(lz.rec({ 'seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000, 'justification_digest' => 'j2', k => v })),
           bad.('renewal_mismatch'), "mismatch #{k}")
      end
      s.(after1.().accept(lz.rec({ 'seq' => 2, 'renewed_at' => 2000, 'expires_at' => 3000, 'justification_digest' => 'j2' })), bad.('expired_lease'), 'renewed at expiry')
      s.(after1.().accept(lz.rec({ 'seq' => 2, 'renewed_at' => 1999, 'expires_at' => 3000, 'justification_digest' => 'j2' })),
         { 'ok' => true, 'replaced' => true, 'seq' => 2 }, 'renewed just before expiry')
      s.(after1.().accept(lz.rec({ 'seq' => 2, 'renewed_at' => 1500, 'expires_at' => 2000, 'justification_digest' => 'j2' })), bad.('not_extending'), 'same expiry')
      s.(after1.().accept(lz.rec({ 'seq' => 2, 'renewed_at' => 1500, 'expires_at' => 1999, 'justification_digest' => 'j2' })), bad.('not_extending'), 'shorter expiry')
      s.(after1.().accept(lz.rec({ 'seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000 })), bad.('stale_justification'), 'same justification (default)')
      s.(after1.('freshJustification' => true).accept(lz.rec({ 'seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000 })),
         bad.('stale_justification'), 'same justification (true)')
      s.(after1.('freshJustification' => false).accept(lz.rec({ 'seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000 })),
         { 'ok' => true, 'replaced' => true, 'seq' => 2 }, 'same justification allowed when freshJustification false')
      # a revocation covering the lease; one before it does not
      reg = lz.registry
      reg.revoke(lz.rrec({ 'target' => 'lease', 'value' => 'L1', 'revoked_at' => 1000 }))
      s.(reg.accept(lz.rec), bad.('revoked'), 'revoked lease')
      reg = lz.registry
      reg.revoke(lz.rrec({ 'target' => 'lease', 'value' => 'L1', 'revoked_at' => 999 }))
      s.(reg.accept(lz.rec), { 'ok' => true, 'replaced' => true, 'seq' => 1 }, 'revoked before issue does not cover')
    end
    true
  end

  t('c26 LeaseRegistry: a fault inside accept / revoke is exactly store_unreachable') do
    next true if C26.skip?('lease.rb')

    lz = C26::Lz
    boom = ->(_r) { raise 'boom' }
    C26.seam(AtlasPca, verify_lease: boom) do
      C26.same(lz.registry.accept(lz.rec), { 'ok' => false, 'code' => 'store_unreachable' }, 'accept')
    end
    C26.seam(AtlasPca, verify_lease_revocation: boom) do
      C26.same(lz.registry.revoke(lz.rrec), { 'ok' => false, 'code' => 'store_unreachable' }, 'revoke')
    end
    true
  end

  t('c26 LeaseRegistry#revoke: refusals, counts per target, signature de-duplication') do
    next true if C26.skip?('lease.rb')

    lz = C26::Lz
    s = C26.method(:same)
    lz.stubbed do
      reg = lz.registry
      reg.accept(lz.rec)
      reg.accept(lz.rec({ 'lease_id' => 'L2', 'path' => 'other/x', 'grant_ref' => 'g2' }))
      C26.seam(AtlasPca, verify_lease_revocation: ->(_r) { false }) do
        s.(reg.revoke(lz.rrec), { 'ok' => false, 'code' => 'bad_record' }, 'bad record')
      end
      s.(reg.revoke(lz.rrec({ 'authority' => 'zzz' })), { 'ok' => false, 'code' => 'unknown_authority' }, 'unknown authority')
      s.(reg.revocations, [], 'nothing stored by refusals')
      s.(reg.revoke(lz.rrec({ 'target' => 'prefix', 'value' => 'db' })), { 'ok' => true, 'revoked' => 1 }, 'prefix')
      s.(reg.revoke(lz.rrec({ 'target' => 'lease', 'value' => 'L2' })), { 'ok' => true, 'revoked' => 1 }, 'lease')
      s.(reg.revoke(lz.rrec({ 'target' => 'grant', 'value' => 'g1' })), { 'ok' => true, 'revoked' => 1 }, 'grant')
      s.(reg.revoke(lz.rrec({ 'target' => 'prefix', 'value' => 'db/pro' })), { 'ok' => true, 'revoked' => 0 }, 'not a boundary')
      s.(reg.revoke(lz.rrec({ 'target' => 'lease', 'value' => 'L1', 'revoked_at' => 500 })), { 'ok' => true, 'revoked' => 0 }, 'before issue')
      s.(reg.revocations.length, 5, 'five distinct signatures stored')
      before = reg.revocations
      again = lz.rrec({ 'target' => 'grant', 'value' => 'g1' })
      s.(reg.revoke(again), { 'ok' => true, 'revoked' => 1 }, 'duplicate answers ok')
      s.(reg.revocations.length, 5, 'duplicate signature not stored twice')
      s.(before.length, 5, 'list not mutated in place')
      reg.revoke(lz.rrec({ 'target' => 'grant', 'value' => 'g3' }))
      s.(reg.revocations.length, 6, 'a new one is appended')
      s.(before.length, 5, 'the earlier list object is untouched (check_lease reads it unlocked)')
    end
    true
  end

  t('c26 check_lease: every decision with its exact hash, boundaries of the time checks') do
    next true if C26.skip?('lease.rb')

    lz = C26::Lz
    s = C26.method(:same)
    lz.stubbed do
      reg = lz.registry
      r1 = lz.rec
      reg.accept(r1)
      deny = ->(code, id = 'L1') { { 'decision' => 'deny', 'code' => code, 'lease_id' => id } }
      [1.5, 'x', -1, nil, 2**53].each { |n| s.(AtlasPca.check_lease(r1, reg, n), { 'decision' => 'deny', 'code' => 'bad_input' }, "now #{n.inspect}") }
      C26.seam(AtlasPca, verify_lease: ->(_r) { false }) do
        s.(AtlasPca.check_lease(r1, reg, 1500), { 'decision' => 'deny', 'code' => 'bad_record' }, 'bad record')
      end
      s.(AtlasPca.check_lease(lz.rec({ 'lease_id' => 'L9' }), reg, 1500), deny.('unknown_lease', 'L9'), 'unknown')
      s.(AtlasPca.check_lease(r1, reg, 999), deny.('not_yet_valid'), 'before renewed_at')
      s.(AtlasPca.check_lease(r1, reg, 1000), { 'decision' => 'allow', 'lease_id' => 'L1', 'expires_at' => 2000 }, 'at renewed_at')
      s.(AtlasPca.check_lease(r1, reg, 1999), { 'decision' => 'allow', 'lease_id' => 'L1', 'expires_at' => 2000 }, 'just before expiry')
      s.(AtlasPca.check_lease(r1, reg, 2000), deny.('expired'), 'at expiry')
      s.(AtlasPca.check_lease(r1, reg, 5999), deny.('expired'), 'before the cap')
      s.(AtlasPca.check_lease(r1, reg, 6000), deny.('past_max_ttl'), 'at the cap')
      reg.accept(lz.rec({ 'seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000, 'justification_digest' => 'j2' }))
      s.(AtlasPca.check_lease(r1, reg, 1500), deny.('superseded'), 'superseded')
      reg.revoke(lz.rrec({ 'target' => 'lease', 'value' => 'L1' }))
      s.(AtlasPca.check_lease(lz.rec({ 'seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000, 'justification_digest' => 'j2' }), reg, 1600),
         deny.('revoked'), 'revoked')
      # a registry that faults: the lease id of a hash, nil for anything else
      broken = Object.new
      def broken.lookup(_id) = raise('down')
      s.(AtlasPca.check_lease(r1, broken, 1500), { 'decision' => 'deny', 'code' => 'store_unreachable', 'lease_id' => 'L1' }, 'registry fault')
      [nil, 5, 2.5, true].each do |p|
        s.(AtlasPca.check_lease(p, reg, 1500), { 'decision' => 'deny', 'code' => 'store_unreachable', 'lease_id' => nil }, "non-hash presented #{p.inspect}")
      end
    end
    true
  end

  t('c26 lease end to end with real signatures: accept, check, revoke, check') do
    next true if C26.skip?('lease.rb')

    lz = C26::Lz
    s = C26.method(:same)
    reg = lz.registry
    l1 = lz.signed
    s.(reg.accept(l1), { 'ok' => true, 'replaced' => true, 'seq' => 1 }, 'accept')
    s.(AtlasPca.check_lease(l1, reg, 1500), { 'decision' => 'allow', 'lease_id' => 'L1', 'expires_at' => 2000 }, 'allow')
    s.(reg.accept(l1.merge('holder' => 'mallory')), { 'ok' => false, 'code' => 'bad_record' }, 'tampered refused')
    s.(reg.revoke(lz.rsigned), { 'ok' => true, 'revoked' => 1 }, 'revoke')
    s.(AtlasPca.check_lease(l1, reg, 1500), { 'decision' => 'deny', 'code' => 'revoked', 'lease_id' => 'L1' }, 'revoked')
    s.(reg.revoke(lz.rsigned.merge('value' => 'L7')), { 'ok' => false, 'code' => 'bad_record' }, 'tampered revocation refused')
    true
  end

  # ==================================================================================================================
  # operations.rb
  # ==================================================================================================================
  module C26
    module Ops
      Allowed = Struct.new(:allow, :pcactn, :operation)

      class Script
        attr_reader :calls

        def initialize(create: nil, get: nil, transition: nil)
          @calls = []
          @p = { create: create, get: get, transition: transition }
        end

        def create(rec) = (@calls << [:create, rec]; @p[:create] ? @p[:create].call(rec) : nil)
        def get(id) = (@calls << [:get, id]; @p[:get] ? @p[:get].call(id) : nil)

        def transition(id, from, nxt)
          @calls << [:transition, id, from, nxt]
          @p[:transition] ? @p[:transition].call(id, from, nxt) : true
        end
      end

      class ScriptOpen < Script
        def initialize(open_list, **kw)
          super(**kw)
          @open = open_list
        end

        def list_open = @open
      end

      # a kv that stores the very object it is given (no copy) and one that never calls the update block
      class RefKv
        def initialize
          @m = {}
        end

        def get(k) = @m[k]

        def put(k, v)
          @m[k] = v
        end

        def update(k)
          n = yield(@m[k])
          @m[k] = n unless n.nil?
          @m[k]
        end
      end

      class NoCallKv
        def get(_k) = nil
        def update(_k) = nil
      end

      class CloseKv < RefKv
        attr_reader :closed

        def close = (@closed = true; :closed_value)
      end

      class MsgErr < StandardError
        def message = 'from-message'
      end

      module_function

      def oc(status, id: nil, result: nil, replayed: false, recorded: true, error: nil, reason: nil, authorization: nil)
        [status, id, result, replayed, recorded, error, reason, authorization]
      end

      def dig(params = { 'a' => 1 }) = AtlasPca.params_digest(AtlasPca.params_copy(params))

      def op(id: 'op-1', verb: 'v.do', resource: '/r/1', params: { 'a' => 1 }, digest: nil)
        AtlasPca::AuthorizedOperation.new(verb: verb, resource: resource, params_digest: digest || dig(params), id: id)
      end

      def operation = { 'verb' => 'v.do', 'resource' => '/r/1', 'params' => { 'a' => 1 } }

      def az(id: 'op-1', cls: 'reversible', extra: {})
        Allowed.new(true, { 'action' => { 'reversibility_class' => cls } }.merge(extra), op(id: id))
      end

      def seq(*vals)
        i = -1
        -> { i += 1; vals[[i, vals.length - 1].min] }
      end

      def pending_rec(over = {}) = { 'id' => 'op-1', 'state' => 'pending', 'verb' => 'v.do', 'resource' => '/r/1', 'params_digest' => dig, 'startedAt' => 0 }.merge(over)

      def run(authorization, store, **kw, &blk) = AtlasPca.execute_authorized(authorization, store: store, **kw, &blk)

      def raises_nie
        yield
        false
      rescue NotImplementedError
        true
      end
    end
  end

  t('c26 ops: constants and the OperationStore base protocol') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    C26.same(AtlasPca::OPERATION_STATES, %w[pending executing committed failed aborted uncertain], 'states')
    C26.same(AtlasPca::OPERATION_STATES.frozen?, true, 'states frozen')
    C26.same(AtlasPca::OPERATION_PENDING_TIMEOUT_MS, 300_000, 'default timeout')
    base = AtlasPca::OperationStore.new
    C26.same(base.scope, 'shared', 'base scope')
    C26.same(o.raises_nie { base.create({}) }, true, 'create')
    C26.same(o.raises_nie { base.get('x') }, true, 'get')
    C26.same(o.raises_nie { base.transition('x', 'a', {}) }, true, 'transition')
    true
  end

  t('c26 ops: MemoryOperationStore keeps copies, answers atomically, lists the open records') do
    next true if C26.skip?('operations.rb')

    s = AtlasPca::MemoryOperationStore.new
    C26.same(s.scope, 'process', 'scope')
    rec = { 'id' => 'a', 'state' => 'pending', 'n' => 1 }
    C26.same(s.create(rec), nil, 'first create')
    rec['n'] = 2
    C26.same(s.get('a')['n'], 1, 'create stores a copy')
    ex = s.create({ 'id' => 'a', 'state' => 'x' })
    C26.same(ex, { 'id' => 'a', 'state' => 'pending', 'n' => 1 }, 'second create returns the existing record')
    ex['state'] = 'mutated'
    C26.same(s.get('a')['state'], 'pending', 'existing record returned is a copy')
    g = s.get('a')
    g['state'] = 'mutated'
    C26.same(s.get('a')['state'], 'pending', 'get returns a copy')
    C26.same(s.get('zz'), nil, 'get missing')
    C26.same(s.transition('a', 'executing', { 'state' => 'committed' }), false, 'wrong from-state')
    C26.same(s.transition('zz', 'pending', { 'state' => 'committed' }), false, 'missing id')
    C26.same(s.get('a')['state'], 'pending', 'unchanged by refused transitions')
    nxt = { 'state' => 'executing' }
    C26.same(s.transition('a', 'pending', nxt), true, 'transition')
    C26.same(s.get('a'), { 'state' => 'executing', 'id' => 'a' }, 'the id is stamped on the new record')
    C26.same(nxt, { 'state' => 'executing' }, 'caller record not mutated')
    s.create({ 'id' => 'b', 'state' => 'committed' })
    s.create({ 'id' => 'c', 'state' => 'pending' })
    s.create({ 'id' => 'd', 'state' => 'uncertain' })
    C26.same(s.list_open.map { |r| r['id'] }.sort, %w[a c], 'open records only')
    l = s.list_open
    l.each { |r| r['state'] = 'mutated' }
    C26.same(s.get('c')['state'], 'pending', 'list_open returns copies')
    true
  end

  t('c26 ops: KvOperationStore over a reference-keeping kv') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    kv = o::RefKv.new
    st = AtlasPca::KvOperationStore.new(kv)
    C26.same(st.scope, 'shared', 'default scope')
    rec = { 'id' => 'a', 'state' => 'pending', 'n' => 1 }
    C26.same(st.create(rec), nil, 'create')
    C26.same(kv.get('pca-op:a'), { 'id' => 'a', 'state' => 'pending', 'n' => 1 }, 'default key prefix')
    rec['n'] = 2
    C26.same(kv.get('pca-op:a')['n'], 1, 'a stored copy, not the caller object')
    C26.same(st.create({ 'id' => 'a', 'state' => 'x' }), { 'id' => 'a', 'state' => 'pending', 'n' => 1 }, 'existing returned')
    C26.same(kv.get('pca-op:a')['state'], 'pending', 'existing not overwritten')
    C26.same(st.get('a'), { 'id' => 'a', 'state' => 'pending', 'n' => 1 }, 'get')
    C26.same(st.get('zz'), nil, 'get missing')
    C26.same(st.transition('a', 'executing', { 'state' => 'c' }), false, 'wrong from-state')
    C26.same(st.transition('zz', 'pending', { 'state' => 'c' }), false, 'missing')
    C26.same(kv.get('pca-op:zz'), nil, 'missing stays missing')
    nxt = { 'state' => 'executing' }
    C26.same(st.transition('a', 'pending', nxt), true, 'transition')
    C26.same(kv.get('pca-op:a'), { 'state' => 'executing', 'id' => 'a' }, 'id stamped')
    C26.same(nxt, { 'state' => 'executing' }, 'caller record untouched')
    # custom prefix and scope
    kv2 = o::RefKv.new
    st2 = AtlasPca::KvOperationStore.new(kv2, prefix: 'x:', scope: 'process')
    C26.same(st2.scope, 'process', 'explicit scope')
    st2.create({ 'id' => 'q', 'state' => 'pending' })
    C26.same(kv2.get('x:q')['id'], 'q', 'explicit prefix')
    # values under the key that are not operation records count as absent
    ['garbage', 'id state', { 'state' => 'pending' }, { 'id' => 'g' }, { 'id' => 1, 'state' => 's' }, { 'id' => 'g', 'state' => 1 }, [], nil].each_with_index do |bad, i|
      k = o::RefKv.new
      s3 = AtlasPca::KvOperationStore.new(k)
      k.put('pca-op:g', bad) unless bad.nil?
      C26.same(s3.get('g'), nil, "get over #{bad.inspect}")
      C26.same(s3.transition('g', 'pending', { 'state' => 'z' }), false, "transition over #{bad.inspect} (#{i})")
      C26.same(s3.create({ 'id' => 'g', 'state' => 'pending' }), nil, "create over #{bad.inspect}")
      C26.same(k.get('pca-op:g'), { 'id' => 'g', 'state' => 'pending' }, "create replaced #{bad.inspect}")
    end
    good = { 'id' => 'i', 'state' => 's', 'x' => 1 }
    C26.same(AtlasPca::KvOperationStore.as_record(good).equal?(good), true, 'as_record returns the same hash')
    true
  end

  t('c26 ops: KvOperationStore with a kv that never runs the update block, close, and the sqlite constructor') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    nc = AtlasPca::KvOperationStore.new(o::NoCallKv.new)
    C26.same(nc.create({ 'id' => 'a', 'state' => 'pending' }), nil, 'create without a block call')
    C26.same(nc.transition('a', 'pending', { 'state' => 'x' }), false, 'transition without a block call')
    C26.same(AtlasPca::KvOperationStore.new(o::RefKv.new).close, nil, 'close of a kv without close')
    ck = o::CloseKv.new
    C26.same(AtlasPca::KvOperationStore.new(ck).close, :closed_value, 'close delegates')
    C26.same(ck.closed, true, 'close called')
    # sqlite_operation_store builds a KvOperationStore over SqliteAtomicKv.new(path) (constant swapped for a fake)
    fake = Class.new do
      attr_reader :path

      def initialize(path)
        @path = path
        @m = {}
      end

      def get(k) = @m[k]

      def update(k)
        n = yield(@m[k])
        @m[k] = n unless n.nil?
        @m[k]
      end
    end
    orig = AtlasPca::SqliteAtomicKv
    AtlasPca.send(:remove_const, :SqliteAtomicKv)
    AtlasPca.const_set(:SqliteAtomicKv, fake)
    begin
      st = AtlasPca.sqlite_operation_store('/p/ops.db')
      C26.same(st.is_a?(AtlasPca::KvOperationStore), true, 'is a KvOperationStore')
      C26.same(st.instance_variable_get(:@kv).is_a?(fake), true, 'over the sqlite kv')
      C26.same(st.instance_variable_get(:@kv).path, '/p/ops.db', 'path passed')
      C26.same(st.create({ 'id' => 'a', 'state' => 'pending' }), nil, 'usable')
      C26.same(st.get('a'), { 'id' => 'a', 'state' => 'pending' }, 'round trip')
    ensure
      AtlasPca.send(:remove_const, :SqliteAtomicKv)
      AtlasPca.const_set(:SqliteAtomicKv, orig)
    end
    true
  end

  t('c26 ops: ExecuteOutcome defaults and the reference to_h shape') do
    next true if C26.skip?('operations.rb')

    C26.same(AtlasPca::ExecuteOutcome.new(status: 'x').to_a, ['x', nil, nil, false, true, nil, nil, nil], 'defaults')
    mk = ->(**kw) { AtlasPca::ExecuteOutcome.new(**kw).to_h }
    C26.same(mk.(status: 'committed', operation_id: 'i', result: { 'a' => 1 }, replayed: true, recorded: false),
             { 'status' => 'committed', 'operationId' => 'i', 'result' => { 'a' => 1 }, 'replayed' => true, 'recorded' => false }, 'committed')
    C26.same(mk.(status: 'committed', operation_id: 'i'), { 'status' => 'committed', 'operationId' => 'i', 'result' => nil, 'replayed' => false, 'recorded' => true }, 'committed defaults')
    C26.same(mk.(status: 'failed', operation_id: 'i', error: 'e', replayed: true), { 'status' => 'failed', 'operationId' => 'i', 'error' => 'e', 'replayed' => true }, 'failed')
    %w[aborted uncertain].each do |st|
      C26.same(mk.(status: st, operation_id: 'i', reason: 'r', replayed: true), { 'status' => st, 'operationId' => 'i', 'reason' => 'r', 'replayed' => true }, st)
    end
    C26.same(mk.(status: 'pending', operation_id: 'i'), { 'status' => 'pending', 'operationId' => 'i', 'replayed' => true }, 'pending')
    %w[refused denied].each { |st| C26.same(mk.(status: st, reason: 'r'), { 'status' => st, 'reason' => 'r' }, st) }
    h = AtlasPca::ExecutionHandle.new(idempotency_key: 'k', operation: 1, pcactn: 2, authorization: 3)
    C26.same([h.idempotency_key, h.operation, h.pcactn, h.authorization], ['k', 1, 2, 3], 'handle')
    true
  end

  t('c26 ops: op_clock is epoch milliseconds') do
    next true if C26.skip?('operations.rb')

    a = (Time.now.to_f * 1000).to_i
    v = AtlasPca.op_clock
    b = (Time.now.to_f * 1000).to_i
    C26.same(v.is_a?(Integer), true, 'integer')
    C26.same(a <= v && v <= b, true, "in range #{a} <= #{v} <= #{b}")
    true
  end

  t('c26 ops: op_store_ok? needs create, get and transition') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    full = o::Script.new
    C26.same(AtlasPca.op_store_ok?(full), true, 'full')
    C26.same(AtlasPca.op_store_ok?(nil), false, 'nil')
    C26.same(AtlasPca.op_store_ok?(5), false, 'int')
    %i[create get transition].each do |missing|
      partial = Object.new
      (%i[create get transition] - [missing]).each { |m| partial.define_singleton_method(m) { |*_a| nil } }
      C26.same(AtlasPca.op_store_ok?(partial), false, "missing #{missing}")
    end
    # nil is refused by the nil guard itself, not merely because nil has no create/get/transition
    %i[create get transition].each { |m| NilClass.send(:define_method, m) { |*_a| nil } }
    begin
      C26.same(AtlasPca.op_store_ok?(nil), false, 'nil with methods defined on NilClass')
    ensure
      %i[create get transition].each { |m| NilClass.send(:remove_method, m) }
    end
    true
  end

  t('c26 ops: op_allowed accepts exactly an allowed authorization with a string operation id') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    opn = o.op
    pc = { 'action' => {} }
    good = o::Allowed.new(true, pc, opn)
    got = AtlasPca.op_allowed(good)
    C26.same(got.length, 2, 'pair')
    C26.same(got[0].equal?(pc) && got[1].equal?(opn), true, 'identity')
    bad = [nil, Object.new, 5, o::Allowed.new(false, pc, opn), o::Allowed.new(nil, pc, opn), o::Allowed.new('yes', pc, opn),
           o::Allowed.new(1, pc, opn), o::Allowed.new(true, [], opn), o::Allowed.new(true, nil, opn), o::Allowed.new(true, 'x', opn),
           o::Allowed.new(true, pc, Object.new), o::Allowed.new(true, pc, nil), o::Allowed.new(true, pc, o.op(id: '')),
           o::Allowed.new(true, pc, o.op(id: nil)), o::Allowed.new(true, pc, o.op(id: 5)),
           Struct.new(:pcactn, :operation).new(pc, opn), Struct.new(:allow, :operation).new(true, opn), Struct.new(:allow, :pcactn).new(true, pc)]
    bad.each_with_index { |a, i| C26.same(AtlasPca.op_allowed(a), nil, "bad #{i}") }
    true
  end

  t('c26 ops: op_settle_stale ages pending from startedAt and executing from executingAt, settles once, answers from the store') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    st = o::Script.new
    c = { 'id' => 'op-1', 'state' => 'committed', 'startedAt' => 0 }
    C26.same(AtlasPca.op_settle_stale(st, c, 10**9, 1000).equal?(c), true, 'committed untouched')
    C26.same(st.calls, [], 'no store call for a settled record')
    ['weird', nil, 'failed', 'aborted'].each { |x| r = { 'id' => 'i', 'state' => x, 'startedAt' => 0 }; C26.same(AtlasPca.op_settle_stale(st, r, 10**9, 1).equal?(r), true, "state #{x.inspect}") }
    p0 = o.pending_rec
    C26.same(AtlasPca.op_settle_stale(st, p0, 1000, 1000).equal?(p0), true, 'pending at exactly the timeout is not stale')
    C26.same(st.calls, [], 'no store call when fresh')
    # stale pending: aborted, message with the timeout as a JS number (1000.0 prints as 1000)
    marker = { 'marker' => 1 }
    st = o::Script.new(get: ->(_i) { marker })
    nxt = p0.merge('state' => 'aborted', 'error' => 'not started within 1000 ms of the claim: the side effect never ran', 'finishedAt' => 1001)
    C26.same(AtlasPca.op_settle_stale(st, p0, 1001, 1000.0).equal?(marker), true, 'returns what the store holds now')
    C26.same(st.calls, [[:transition, 'op-1', 'pending', nxt], [:get, 'op-1']], 'calls')
    # the store lost the record: the settled record itself
    st = o::Script.new
    C26.same(AtlasPca.op_settle_stale(st, p0, 1001, 1000), nxt, 'falls back to the settled record')
    # pending is aged from startedAt even if an executingAt is present
    pe = o.pending_rec('executingAt' => 900)
    C26.same(AtlasPca.op_settle_stale(o::Script.new, pe, 1001, 1000)['state'], 'aborted', 'pending ignores executingAt')
    # executing: aged from executingAt (500), falling back to startedAt (0) when it is absent
    ex = o.pending_rec('state' => 'executing', 'executingAt' => 500)
    C26.same(AtlasPca.op_settle_stale(o::Script.new, ex, 1500, 1000).equal?(ex), true, 'executing 1000 old is not stale')
    st = o::Script.new
    r = AtlasPca.op_settle_stale(st, ex, 1501, 1000)
    unc = ex.merge('state' => 'uncertain', 'finishedAt' => 1501, 'error' => 'no outcome recorded within 1000 ms of the start: the side effect may or may not have happened')
    C26.same(r, unc, 'executing settles to uncertain')
    C26.same(st.calls, [[:transition, 'op-1', 'executing', unc], [:get, 'op-1']], 'executing calls')
    old = o.pending_rec('state' => 'executing')
    C26.same(AtlasPca.op_settle_stale(o::Script.new, old, 1001, 1000)['state'], 'uncertain', 'executing without executingAt uses startedAt')
    # a store that already moved on wins
    st = o::Script.new(get: ->(_i) { { 'id' => 'op-1', 'state' => 'committed', 'result' => 'done' } })
    C26.same(AtlasPca.op_settle_stale(st, p0, 5000, 1000), { 'id' => 'op-1', 'state' => 'committed', 'result' => 'done' }, 'concurrent finish wins')
    # real store
    ms = AtlasPca::MemoryOperationStore.new
    ms.create(p0)
    C26.same(AtlasPca.op_settle_stale(ms, p0, 300_001, 300_000)['state'], 'aborted', 'memory store')
    C26.same(ms.get('op-1')['state'], 'aborted', 'memory store updated')
    true
  end

  t('c26 ops: op_from_record answers every state, with defaults for a missing error') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    ms = AtlasPca::MemoryOperationStore.new
    from = ->(rec, now = 10, to = 100_000) { AtlasPca.op_from_record(ms, rec, now, to).to_a }
    C26.same(from.({ 'id' => 'i', 'state' => 'committed', 'result' => { 'k' => 1 } }), o.oc('committed', id: 'i', result: { 'k' => 1 }, replayed: true, recorded: true), 'committed')
    C26.same(from.({ 'id' => 'i', 'state' => 'committed' }), o.oc('committed', id: 'i', replayed: true), 'committed no result')
    { 'failed' => 'failed', 'aborted' => 'aborted', 'uncertain' => 'outcome unknown' }.each do |st, dflt|
      mk = ->(reason) { st == 'failed' ? o.oc(st, id: 'i', error: reason, replayed: true) : o.oc(st, id: 'i', reason: reason, replayed: true) }
      C26.same(from.({ 'id' => 'i', 'state' => st, 'error' => 'E' }), mk.('E'), "#{st} error")
      C26.same(from.({ 'id' => 'i', 'state' => st }), mk.(dflt), "#{st} no error")
      C26.same(from.({ 'id' => 'i', 'state' => st, 'error' => '' }), mk.(dflt), "#{st} empty error")
      C26.same(from.({ 'id' => 'i', 'state' => st, 'error' => nil }), mk.(dflt), "#{st} nil error")
      C26.same(from.({ 'id' => 'i', 'state' => st, 'error' => 0 }), mk.(dflt), "#{st} zero error (JS falsy)")
    end
    %w[pending executing].each do |st|
      C26.same(from.({ 'id' => 'i', 'state' => st, 'startedAt' => 0, 'executingAt' => 0 }), o.oc('pending', id: 'i', replayed: true), "#{st} fresh")
    end
    C26.same(from.({ 'id' => 'i', 'state' => 'weird' }), o.oc('uncertain', id: 'i', reason: "unknown record state 'weird'", replayed: true), 'unknown state')
    C26.same(from.({ 'id' => 'i', 'state' => nil }), o.oc('uncertain', id: 'i', reason: "unknown record state 'null'", replayed: true), 'nil state')
    # a stale open record is settled first, and the settled state is what is answered
    ms.create(o.pending_rec('id' => 'sp'))
    C26.same(from.(o.pending_rec('id' => 'sp'), 5000, 1000),
             o.oc('aborted', id: 'sp', reason: 'not started within 1000 ms of the claim: the side effect never ran', replayed: true), 'stale pending')
    ms.create(o.pending_rec('id' => 'se', 'state' => 'executing'))
    C26.same(from.(o.pending_rec('id' => 'se', 'state' => 'executing'), 5000, 1000),
             o.oc('uncertain', id: 'se', reason: 'no outcome recorded within 1000 ms of the start: the side effect may or may not have happened', replayed: true), 'stale executing')
    true
  end

  t('c26 ops: op_finish leaves executing, or uncertain when recovery settled a slow run') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    rec = { 'id' => 'i', 'state' => 'executing', 'a' => 1 }
    nxt = { 'state' => 'committed' }
    out = rec.merge(nxt)
    st = o::Script.new
    C26.same(AtlasPca.op_finish(st, rec, nxt), true, 'first transition')
    C26.same(st.calls, [[:transition, 'i', 'executing', out]], 'one call')
    seqs = ->(*answers) { i = -1; ->(*_a) { i += 1; answers[i] } }
    st = o::Script.new(transition: seqs.(false, true))
    C26.same(AtlasPca.op_finish(st, rec, nxt), true, 'second transition')
    C26.same(st.calls, [[:transition, 'i', 'executing', out], [:transition, 'i', 'uncertain', out]], 'two calls')
    st = o::Script.new(transition: seqs.(false, false))
    C26.same(AtlasPca.op_finish(st, rec, nxt), false, 'both refused')
    st = o::Script.new(transition: seqs.(false, 'yes'))
    C26.same(AtlasPca.op_finish(st, rec, nxt), false, 'only true counts')
    st = o::Script.new(transition: seqs.(nil, true))
    C26.same(AtlasPca.op_finish(st, rec, nxt), true, 'nil then true')
    pend = rec.merge('state' => 'pending')
    st = o::Script.new(transition: seqs.(false, true))
    C26.same(AtlasPca.op_finish(st, pend, nxt), false, 'a pending record gets no second try')
    C26.same(st.calls.length, 1, 'one call for pending')
    st = o::Script.new(transition: seqs.('truthy'))
    C26.same(AtlasPca.op_finish(st, pend, nxt), true, 'truthy first transition')
    true
  end

  t('c26 ops: op_answer_current answers from the stored record or reports it gone') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    st = o::Script.new
    C26.same(AtlasPca.op_answer_current(st, 'i', 10, 1000).to_a, o.oc('uncertain', id: 'i', reason: 'the operation record disappeared', replayed: true), 'gone')
    C26.same(st.calls, [[:get, 'i']], 'get call')
    st = o::Script.new(get: ->(_i) { { 'id' => 'i', 'state' => 'committed', 'result' => 7 } })
    C26.same(AtlasPca.op_answer_current(st, 'i', 10, 1000).to_a, o.oc('committed', id: 'i', result: 7, replayed: true), 'committed')
    ms = AtlasPca::MemoryOperationStore.new
    ms.create(o.pending_rec('id' => 'i'))
    C26.same(AtlasPca.op_answer_current(ms, 'i', 10, 1000).to_a, o.oc('pending', id: 'i', replayed: true), 'pending uses the integer clock')
    C26.same(AtlasPca.op_answer_current(ms, 'i', 5000, 1000).to_a, o.oc('aborted', id: 'i', reason: 'not started within 1000 ms of the claim: the side effect never ran', replayed: true), 'stale')
    true
  end

  t('c26 ops: op_bound_to? compares verb, resource and the params digest; faults are false') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    opn = o.op
    C26.same(AtlasPca.op_bound_to?(opn, o.operation), true, 'match')
    C26.same(AtlasPca.op_bound_to?(opn, { verb: 'v.do', resource: '/r/1', params: { 'a' => 1 } }), true, 'symbol keys')
    C26.same(AtlasPca.op_bound_to?(opn, o.operation.merge('verb' => 'v.other')), false, 'verb')
    C26.same(AtlasPca.op_bound_to?(opn, o.operation.merge('resource' => '/r/2')), false, 'resource')
    C26.same(AtlasPca.op_bound_to?(opn, o.operation.merge('params' => { 'a' => 2 })), false, 'params')
    C26.same(AtlasPca.op_bound_to?(o.op(digest: 'zzz'), o.operation), false, 'digest')
    ['x', 5, nil, {}, [], { 'verb' => 'v.do', 'resource' => '/r/1' }, { 'verb' => '', 'resource' => '/r/1', 'params' => {} }].each do |bad|
      C26.same(AtlasPca.op_bound_to?(opn, bad), false, "invalid operation #{bad.inspect}")
    end
    raiser = Object.new
    def raiser.verb = raise('boom')
    C26.same(AtlasPca.op_bound_to?(raiser, o.operation), false, 'fault is false')
    # with nil answering [] like a hash, the nil guard alone still refuses an invalid operation
    NilClass.send(:define_method, :[]) { |k| { 'verb' => 'v.do', 'resource' => '/r/1', 'params' => {} }[k] }
    begin
      C26.same(AtlasPca.op_bound_to?(o.op(params: {}), 'x'), false, 'nil operation with a lenient nil')
    ensure
      NilClass.send(:remove_method, :[])
    end
    true
  end

  t('c26 ops: execute_authorized refuses missing components, a mismatched operation and a missing block (nothing recorded)') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    ran = []
    blk = proc { ran << 1 }
    a = o.az
    store_msg = o.oc('refused', reason: 'executeAuthorized: missing required component: store (fail closed)')
    partial = Object.new
    def partial.create(_r) = nil
    def partial.get(_i) = nil
    [nil, partial, 5].each { |s| C26.same(AtlasPca.execute_authorized(a, store: s, &blk).to_a, store_msg, "store #{s.inspect}") }
    C26.same(AtlasPca.execute_authorized(a, &blk).to_a, store_msg, 'store omitted')
    mem = AtlasPca::MemoryOperationStore.new
    allow_msg = o.oc('refused', reason: 'executeAuthorized: the authorization did not allow an operation')
    [nil, Object.new, o::Allowed.new(false, {}, o.op), o::Allowed.new(true, [], o.op), o::Allowed.new(true, {}, Object.new),
     o::Allowed.new(true, {}, o.op(id: ''))].each_with_index { |x, i| C26.same(AtlasPca.execute_authorized(x, store: mem, &blk).to_a, allow_msg, "authorization #{i}") }
    bound = o.oc('refused', reason: 'executeAuthorized: the authorization is not for this operation (verb, resource or params differ)')
    [o.operation.merge('verb' => 'x'), o.operation.merge('resource' => '/x'), o.operation.merge('params' => { 'a' => 9 }), 'str', {}, 5].each_with_index do |x, i|
      C26.same(AtlasPca.execute_authorized(a, store: mem, operation: x, &blk).to_a, bound, "operation #{i}")
    end
    nb = o.oc('refused', reason: 'executeAuthorized: no block to execute (fail closed)')
    C26.same(AtlasPca.execute_authorized(a, store: mem).to_a, nb, 'no block')
    C26.same(AtlasPca.execute_authorized(a, store: mem, operation: o.operation).to_a, nb, 'no block with a matching operation')
    C26.same(AtlasPca.execute_authorized(a, store: mem, operation: { 'verb' => 'x' }).to_a, bound, 'binding is checked before the block')
    C26.same(mem.get('op-1'), nil, 'nothing recorded')
    C26.same(ran, [], 'block never ran')
    # a matching operation (symbol keys too) lets it run
    C26.same(AtlasPca.execute_authorized(a, store: mem, operation: o.operation) { 'R' }.status, 'committed', 'matching operation')
    C26.same(AtlasPca.execute_authorized(o.az(id: 'op-2'), store: mem, operation: { verb: 'v.do', resource: '/r/1', params: { 'a' => 1 } }) { 'R' }.status, 'committed', 'symbol keys')
    true
  end

  t('c26 ops: execute_authorized recheck requirement by effective class, exact refusal text') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    mem = AtlasPca::MemoryOperationStore.new
    ran = []
    msg = ->(cls) { o.oc('refused', reason: "executeAuthorized: a #{cls} operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)") }
    C26.same(o.run(o.az(cls: 'irreversible'), mem) { ran << 1 }.to_a, msg.('irreversible'), 'signed irreversible')
    C26.same(o.run(o.az(cls: 'reversible'), mem, reversibility_class: 'irreversible') { ran << 1 }.to_a, msg.('irreversible'), 'server irreversible')
    C26.same(o.run(o.az(cls: nil), mem) { ran << 1 }.to_a, msg.('irreversible'), 'missing signed class')
    C26.same(o.run(o.az(cls: 'bogus'), mem) { ran << 1 }.to_a, msg.('irreversible'), 'unknown signed class')
    C26.same(o.run(o.az(extra: { 'action' => [] }), mem) { ran << 1 }.to_a, msg.('irreversible'), 'action not a hash (array)')
    C26.same(o.run(o.az(extra: { 'action' => nil }), mem) { ran << 1 }.to_a, msg.('irreversible'), 'action nil')
    C26.same(o.run(o.az(extra: { 'action' => 5 }), mem) { ran << 1 }.to_a, msg.('irreversible'), 'action integer')
    C26.same(o.run(o.az(cls: 'reversible'), mem, recheck_for: 'always') { ran << 1 }.to_a, msg.('reversible'), 'always')
    C26.same(o.run(o.az(cls: 'rate_limited'), mem, recheck_for: 'always') { ran << 1 }.to_a, msg.('rate_limited'), 'always rate_limited')
    C26.same(o.run(o.az(cls: 'irreversible'), mem, recheck: 5) { ran << 1 }.to_a, msg.('irreversible'), 'recheck not callable')
    C26.same(o.run(o.az(cls: 'reversible'), mem, recheck_for: 'always', recheck: :sym) { ran << 1 }.to_a, msg.('reversible'), 'recheck symbol')
    C26.same(ran, [], 'never ran')
    C26.same(mem.get('op-1'), nil, 'nothing recorded')
    # no recheck needed for reversible / rate_limited under the default
    C26.same(o.run(o.az(id: 'r1', cls: 'reversible'), mem) { 1 }.status, 'committed', 'reversible')
    C26.same(o.run(o.az(id: 'r2', cls: 'rate_limited'), mem) { 1 }.status, 'committed', 'rate_limited')
    C26.same(o.run(o.az(id: 'r3', cls: 'reversible'), mem, recheck_for: 'irreversible') { 1 }.status, 'committed', 'explicit default')
    C26.same(o.run(o.az(id: 'r4', cls: 'reversible'), mem, recheck_for: 'never') { 1 }.status, 'committed', 'other value')
    true
  end

  t('c26 ops: execute_authorized commit path, record shape, clock order, handle, defaults') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    mem = AtlasPca::MemoryOperationStore.new
    a = o.az
    seen = []
    out = o.run(a, mem, now: o.seq(10, 20, 30, 40)) { |h| seen << h; 'R' }
    C26.same(out.to_a, o.oc('committed', id: 'op-1', result: 'R', replayed: false, recorded: true), 'outcome')
    C26.same(mem.get('op-1'), { 'id' => 'op-1', 'state' => 'committed', 'verb' => 'v.do', 'resource' => '/r/1', 'params_digest' => o.dig,
                                'reversibility' => 'reversible', 'startedAt' => 10, 'executingAt' => 20, 'result' => 'R', 'finishedAt' => 30 }, 'record')
    h = seen[0]
    C26.same(h.idempotency_key, 'op-1', 'idempotency key')
    C26.same(h.operation.equal?(a.operation) && h.pcactn.equal?(a.pcactn) && h.authorization.equal?(a), true, 'handle contents')
    # a retry is answered from the record without running again
    again = o.run(a, mem, now: o.seq(50, 60)) { seen << :again; 'R2' }
    C26.same(again.to_a, o.oc('committed', id: 'op-1', result: 'R', replayed: true, recorded: true), 'replay')
    C26.same(seen.length, 1, 'ran once')
    # defaults: no now, no operation, no reversibility_class, no timeout
    t0 = (Time.now.to_f * 1000).to_i
    d = AtlasPca.execute_authorized(o.az(id: 'op-d'), store: mem) { 'D' }
    t1 = (Time.now.to_f * 1000).to_i
    C26.same(d.to_a, o.oc('committed', id: 'op-d', result: 'D'), 'defaults outcome')
    r = mem.get('op-d')
    C26.same([r['startedAt'], r['executingAt'], r['finishedAt']].all? { |x| x.is_a?(Integer) && x >= t0 && x <= t1 }, true, 'default clock is the real clock')
    # a nil result is a result
    C26.same(o.run(o.az(id: 'op-n'), mem, now: o.seq(1, 2, 3)) { nil }.to_a, o.oc('committed', id: 'op-n', result: nil), 'nil result')
    true
  end

  t('c26 ops: open records found at create time are answered, default and explicit timeouts, never re-run') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    ran = []
    mem = AtlasPca::MemoryOperationStore.new
    mem.create(o.pending_rec('startedAt' => 50))
    C26.same(o.run(o.az, mem, now: -> { 100 }) { ran << 1 }.to_a, o.oc('pending', id: 'op-1', replayed: true), 'fresh pending (default timeout)')
    C26.same(o.run(o.az, mem, now: -> { 300_050 }) { ran << 1 }.to_a, o.oc('pending', id: 'op-1', replayed: true), 'at the default timeout')
    C26.same(o.run(o.az, mem, now: -> { 300_051 }) { ran << 1 }.to_a,
             o.oc('aborted', id: 'op-1', reason: 'not started within 300000 ms of the claim: the side effect never ran', replayed: true), 'past the default timeout')
    mem2 = AtlasPca::MemoryOperationStore.new
    mem2.create(o.pending_rec('startedAt' => 0))
    C26.same(o.run(o.az, mem2, now: -> { 1001 }, pending_timeout_ms: 1000) { ran << 1 }.to_a,
             o.oc('aborted', id: 'op-1', reason: 'not started within 1000 ms of the claim: the side effect never ran', replayed: true), 'explicit timeout')
    mem3 = AtlasPca::MemoryOperationStore.new
    mem3.create(o.pending_rec('state' => 'executing', 'executingAt' => 0))
    C26.same(o.run(o.az, mem3, now: -> { 1001 }, pending_timeout_ms: 1000) { ran << 1 }.to_a,
             o.oc('uncertain', id: 'op-1', reason: 'no outcome recorded within 1000 ms of the start: the side effect may or may not have happened', replayed: true), 'executing becomes uncertain')
    mem4 = AtlasPca::MemoryOperationStore.new
    mem4.create({ 'id' => 'op-1', 'state' => 'failed', 'error' => 'earlier' })
    C26.same(o.run(o.az, mem4, now: -> { 1 }) { ran << 1 }.to_a, o.oc('failed', id: 'op-1', error: 'earlier', replayed: true), 'failed replay')
    C26.same(ran, [], 'never ran')
    true
  end

  t('c26 ops: execute_authorized recheck path: clock order, handle, expiry, every verdict shape') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    # passing recheck: the block runs, clock order is startedAt, expiry check, executingAt, finishedAt
    mem = AtlasPca::MemoryOperationStore.new
    handles = []
    a = o.az(cls: 'irreversible', extra: { 'exp' => 5000 })
    out = o.run(a, mem, now: o.seq(10, 20, 30, 40), recheck: ->(h) { handles << h; { 'ok' => true } }) { 'R' }
    C26.same(out.to_a, o.oc('committed', id: 'op-1', result: 'R'), 'outcome')
    C26.same(mem.get('op-1'), { 'id' => 'op-1', 'state' => 'committed', 'verb' => 'v.do', 'resource' => '/r/1', 'params_digest' => o.dig,
                                'reversibility' => 'irreversible', 'startedAt' => 10, 'executingAt' => 30, 'result' => 'R', 'finishedAt' => 40 }, 'record')
    C26.same(handles.length == 1 && handles[0].idempotency_key == 'op-1' && handles[0].pcactn.equal?(a.pcactn) && handles[0].operation.equal?(a.operation), true, 'recheck handle')
    # refusals: reason shapes
    refuse = lambda do |ret, id = 'op-r'|
      m = AtlasPca::MemoryOperationStore.new
      ran = []
      r = o.run(o.az(id: id, cls: 'irreversible'), m, now: o.seq(10, 20, 30, 40), recheck: ->(_h) { ret.respond_to?(:call) ? ret.call : ret }) { ran << 1 }
      C26.same(ran, [], 'block not run')
      [r, m.get(id)]
    end
    cases = [[{ 'ok' => false, 'reason' => 'nope' }, 'recheck: nope'], [{ 'ok' => false, 'reason' => '' }, 'recheck: refused'],
             [{ 'ok' => false, 'reason' => 0 }, 'recheck: refused'], [{ 'ok' => false, 'reason' => nil }, 'recheck: refused'],
             [{ 'ok' => false }, 'recheck: refused'], [{ 'ok' => nil, 'reason' => 'r' }, 'recheck: refused'],
             [{ 'ok' => 'yes', 'reason' => 'r' }, 'recheck: refused'], [{ 'ok' => 1 }, 'recheck: refused'], [{}, 'recheck: refused'],
             [nil, 'recheck: refused'], [true, 'recheck: refused'], ['ok', 'recheck: refused'], [[], 'recheck: refused'],
             [-> { raise 'boom' }, 'recheck: recheck error (fail closed): boom'],
             [-> { raise o::MsgErr }, 'recheck: recheck error (fail closed): from-message']]
    cases.each_with_index do |(ret, want), i|
      r, rec = refuse.(ret)
      C26.same(r.to_a, o.oc('aborted', id: 'op-r', reason: want, replayed: false), "verdict #{i}")
      C26.same(rec, { 'id' => 'op-r', 'state' => 'aborted', 'verb' => 'v.do', 'resource' => '/r/1', 'params_digest' => o.dig, 'reversibility' => 'irreversible',
                      'startedAt' => 10, 'error' => want, 'finishedAt' => 30 }, "aborted record #{i}")
    end
    # PCActn expiry: strictly after exp aborts without calling recheck; Integer and Float; non-numbers are ignored
    called = []
    chk = lambda do |exp, t|
      m = AtlasPca::MemoryOperationStore.new
      o.run(o.az(cls: 'irreversible', extra: exp.nil? ? {} : { 'exp' => exp }), m, now: o.seq(10, t, 30, 40), recheck: ->(_h) { called << 1; { 'ok' => true } }) { 'R' }
    end
    called.clear
    C26.same(chk.(100, 101).to_a, o.oc('aborted', id: 'op-1', reason: 'recheck: the PCActn expired at 100', replayed: false), 'expired int')
    C26.same(called, [], 'recheck not called when expired')
    C26.same(chk.(100.5, 101).to_a, o.oc('aborted', id: 'op-1', reason: 'recheck: the PCActn expired at 100.5', replayed: false), 'expired float')
    C26.same(chk.(100.0, 101).to_a, o.oc('aborted', id: 'op-1', reason: 'recheck: the PCActn expired at 100', replayed: false), 'expired integral float prints as a JS number')
    C26.same(chk.(100, 100).status, 'committed', 'now == exp is not expired')
    C26.same(chk.(100.0, 100).status, 'committed', 'now == exp float')
    C26.same(chk.('soon', 101).status, 'committed', 'string exp ignored')
    C26.same(chk.(nil, 101).status, 'committed', 'no exp')
    C26.same(chk.([1], 101).status, 'committed', 'array exp ignored')
    true
  end

  t('c26 ops: execute_authorized when the store moves under it (scripted store, exact calls)') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    rec = { 'id' => 'op-1', 'state' => 'pending', 'verb' => 'v.do', 'resource' => '/r/1', 'params_digest' => o.dig, 'reversibility' => 'reversible', 'startedAt' => 10 }
    # pending -> executing refused (a recovery settled the claim): answered from the store, block never runs
    ran = []
    st = o::Script.new(transition: ->(*_a) { false }, get: ->(_i) { { 'id' => 'op-1', 'state' => 'committed', 'result' => 'prev' } })
    out = o.run(o.az, st, now: o.seq(10, 20, 30)) { ran << 1 }
    C26.same(out.to_a, o.oc('committed', id: 'op-1', result: 'prev', replayed: true), 'answered from the record')
    C26.same(st.calls, [[:create, rec], [:transition, 'op-1', 'pending', rec.merge('state' => 'executing', 'executingAt' => 20)], [:get, 'op-1']], 'calls')
    C26.same(ran, [], 'not run')
    st = o::Script.new(transition: ->(*_a) { false }, get: ->(_i) { { 'id' => 'op-1', 'state' => 'pending', 'startedAt' => 0 } })
    C26.same(o.run(o.az, st, now: o.seq(10, 20, 30)) { ran << 1 }.to_a, o.oc('pending', id: 'op-1', replayed: true), 'open record answered with the integer clock')
    st = o::Script.new(transition: ->(*_a) { false })
    C26.same(o.run(o.az, st, now: o.seq(10, 20, 30)) { ran << 1 }.to_a, o.oc('uncertain', id: 'op-1', reason: 'the operation record disappeared', replayed: true), 'record gone')
    # recheck refusal whose abort transition is refused: answered from the store
    st = o::Script.new(transition: ->(*_a) { false }, get: ->(_i) { { 'id' => 'op-1', 'state' => 'pending', 'startedAt' => 0 } })
    out = o.run(o.az(cls: 'irreversible'), st, now: o.seq(10, 20, 30, 40), recheck: ->(_h) { { 'ok' => false, 'reason' => 'x' } }) { ran << 1 }
    C26.same(out.to_a, o.oc('pending', id: 'op-1', replayed: true), 'abort lost the race')
    irrec = rec.merge('reversibility' => 'irreversible')
    C26.same(st.calls, [[:create, irrec], [:transition, 'op-1', 'pending', irrec.merge('state' => 'aborted', 'error' => 'recheck: x', 'finishedAt' => 30)], [:get, 'op-1']], 'abort calls')
    st = o::Script.new(transition: ->(*_a) { false }, get: ->(_i) { { 'id' => 'op-1', 'state' => 'committed', 'result' => 'z' } })
    out = o.run(o.az(cls: 'irreversible'), st, now: o.seq(10, 20, 30, 40), recheck: ->(_h) { { 'ok' => false } }) { ran << 1 }
    C26.same(out.to_a, o.oc('committed', id: 'op-1', result: 'z', replayed: true), 'abort lost the race, finished')
    C26.same(ran, [], 'never ran')
    # the final transition: refused (recorded false), raising (recorded false), accepted via uncertain (recorded true)
    fin = lambda do |tr|
      calls = []
      s2 = o::Script.new(transition: ->(id, from, nxt) { calls << [from, nxt['state']]; tr.call(id, from, nxt) })
      [o.run(o.az, s2, now: o.seq(10, 20, 30)) { 'R' }, calls]
    end
    out, calls = fin.(->(_i, _f, nxt) { nxt['state'] != 'committed' })
    C26.same(out.to_a, o.oc('committed', id: 'op-1', result: 'R', recorded: false), 'commit not recorded')
    C26.same(calls, [%w[pending executing], %w[executing committed], %w[uncertain committed]], 'commit tried twice')
    out, = fin.(->(_i, _f, nxt) { raise 'down' if nxt['state'] == 'committed'; true })
    C26.same(out.to_a, o.oc('committed', id: 'op-1', result: 'R', recorded: false), 'commit raised')
    out, = fin.(->(_i, from, _n) { from != 'executing' })
    C26.same(out.to_a, o.oc('committed', id: 'op-1', result: 'R', recorded: true), 'commit recorded through uncertain')
    true
  end

  t('c26 ops: execute_authorized records a failing block as failed and returns the error') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    mem = AtlasPca::MemoryOperationStore.new
    out = o.run(o.az, mem, now: o.seq(10, 20, 30)) { raise 'kaboom' }
    C26.same(out.to_a, o.oc('failed', id: 'op-1', error: 'kaboom'), 'outcome')
    C26.same(mem.get('op-1'), { 'id' => 'op-1', 'state' => 'failed', 'verb' => 'v.do', 'resource' => '/r/1', 'params_digest' => o.dig, 'reversibility' => 'reversible',
                                'startedAt' => 10, 'executingAt' => 20, 'error' => 'kaboom', 'finishedAt' => 30 }, 'record')
    again = o.run(o.az, mem, now: o.seq(40)) { 'never' }
    C26.same(again.to_a, o.oc('failed', id: 'op-1', error: 'kaboom', replayed: true), 'replay of the failure')
    C26.same(o.run(o.az(id: 'op-m'), AtlasPca::MemoryOperationStore.new) { raise o::MsgErr }.error, 'from-message', 'error text is the exception message')
    # even if recording the failure raises, the failure is still returned
    st = o::Script.new(transition: ->(_i, _f, nxt) { raise 'down' if nxt['state'] == 'failed'; true })
    C26.same(o.run(o.az, st, now: o.seq(10, 20, 30)) { raise 'kaboom' }.to_a, o.oc('failed', id: 'op-1', error: 'kaboom'), 'record fault swallowed')
    true
  end

  t('c26 ops: recover_operation / recover_operations settle stale open records, return what changed') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    mk = lambda do
      m = AtlasPca::MemoryOperationStore.new
      m.create(o.pending_rec('id' => 'A', 'startedAt' => 0))
      m.create(o.pending_rec('id' => 'B', 'state' => 'executing', 'executingAt' => 0))
      m.create(o.pending_rec('id' => 'C', 'startedAt' => 900_000))
      m.create({ 'id' => 'D', 'state' => 'committed', 'result' => 1 })
      m
    end
    m = mk.()
    got = AtlasPca.recover_operations(m, now: -> { 1_000_000 })
    C26.same(got.map { |r| [r['id'], r['state']] }.sort, [%w[A aborted], %w[B uncertain]], 'default timeout settles A and B')
    C26.same(got.all? { |r| r == m.get(r['id']) }, true, 'returns the stored records')
    C26.same(m.get('C')['state'], 'pending', 'C is fresh')
    C26.same(AtlasPca.recover_operations(m, now: -> { 1_000_000 }), [], 'second run: nothing changed')
    m = mk.()
    C26.same(AtlasPca.recover_operations(m, older_than_ms: 50_000, now: -> { 1_000_000 }).map { |r| r['id'] }.sort, %w[A B C], 'explicit timeout also settles C')
    m = AtlasPca::MemoryOperationStore.new
    m.create(o.pending_rec('id' => 'E', 'startedAt' => 700_000))
    C26.same(AtlasPca.recover_operations(m, now: -> { 1_000_000 }), [], 'exactly the default timeout is not stale')
    C26.same(AtlasPca.recover_operations(m, now: -> { 1_000_001 }).map { |r| r['id'] }, ['E'], 'one more ms is')
    # recover_operation by id
    m = mk.()
    C26.same(AtlasPca.recover_operation(m, 'nope', now: -> { 1 }), nil, 'unknown id')
    C26.same(AtlasPca.recover_operation(m, 'A', now: -> { 1_000_000 })['state'], 'aborted', 'by id')
    C26.same(AtlasPca.recover_operation(m, 'C', now: -> { 1_000_000 })['state'], 'pending', 'fresh by id (default timeout)')
    C26.same(AtlasPca.recover_operation(m, 'C', older_than_ms: 1000, now: -> { 1_000_000 })['state'], 'aborted', 'explicit timeout by id')
    # real clock: a record started at the epoch is long stale
    C26.same(AtlasPca.recover_operation(mk.(), 'A')['state'], 'aborted', 'default clock (by id)')
    C26.same(AtlasPca.recover_operations(mk.()).map { |r| r['id'] }.sort, %w[A B C], 'default clock (all)')
    # a record that vanished between list_open and get is skipped
    st = o::ScriptOpen.new([{ 'id' => 'gone', 'state' => 'pending', 'startedAt' => 0 }])
    C26.same(AtlasPca.recover_operations(st, now: -> { 1_000_000 }), [], 'vanished record')
    # no list_open
    msg = 'recover_operations: the store has no list_open (recover by id with recover_operation)'
    err = begin
      AtlasPca.recover_operations(o::Script.new)
      nil
    rescue TypeError => e
      e.message
    end
    C26.same(err, msg, 'TypeError text')
    true
  end

  t('c26 ops: resolve_operation settles only an uncertain record, with the reconciled outcome') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    unc = ->(extra = {}) { { 'id' => 'u', 'state' => 'uncertain', 'verb' => 'v', 'startedAt' => 0, 'error' => 'e0' }.merge(extra) }
    mk = ->(rec = unc.()) { m = AtlasPca::MemoryOperationStore.new; m.create(rec); m }
    m = mk.()
    C26.same(AtlasPca.resolve_operation(m, 'u', { 'state' => 'committed', 'result' => { 'x' => 1 } }, now: -> { 50 }), true, 'committed')
    C26.same(m.get('u'), unc.().merge('state' => 'committed', 'finishedAt' => 50, 'result' => { 'x' => 1 }), 'committed record')
    m = mk.()
    AtlasPca.resolve_operation(m, 'u', { 'state' => 'committed' }, now: -> { 50 })
    C26.same(m.get('u').key?('result'), false, 'no result key invented')
    m = mk.(unc.('result' => 'old'))
    AtlasPca.resolve_operation(m, 'u', { 'state' => 'committed' }, now: -> { 50 })
    C26.same(m.get('u')['result'], 'old', 'existing result kept')
    m = mk.()
    AtlasPca.resolve_operation(m, 'u', { 'state' => 'committed', 'result' => nil }, now: -> { 50 })
    C26.same(m.get('u').key?('result') && m.get('u')['result'].nil?, true, 'explicit nil result')
    m = mk.()
    C26.same(AtlasPca.resolve_operation(m, 'u', { 'state' => 'failed', 'error' => 'bad' }, now: -> { 60 }), true, 'failed')
    C26.same(m.get('u'), unc.().merge('state' => 'failed', 'error' => 'bad', 'finishedAt' => 60), 'failed record')
    m = mk.()
    AtlasPca.resolve_operation(m, 'u', { 'state' => 'whatever' }, now: -> { 60 })
    C26.same(m.get('u').merge('x' => 1), unc.().merge('state' => 'failed', 'error' => nil, 'finishedAt' => 60, 'x' => 1), 'anything but committed is failed')
    C26.same(AtlasPca.resolve_operation(m, 'u', { 'state' => 'committed' }, now: -> { 70 }), false, 'already settled')
    C26.same(AtlasPca.resolve_operation(mk.(), 'nope', { 'state' => 'committed' }, now: -> { 1 }), false, 'unknown id')
    # a non-uncertain record is refused WITHOUT asking the store to transition, even if the store would say yes
    st = o::Script.new(get: ->(_i) { { 'id' => 'c', 'state' => 'committed' } })
    C26.same(AtlasPca.resolve_operation(st, 'c', { 'state' => 'committed' }, now: -> { 1 }), false, 'committed record')
    C26.same(st.calls, [[:get, 'c']], 'no transition attempted')
    st = o::Script.new(get: ->(_i) { unc.() }, transition: ->(*_a) { 'yes' })
    C26.same(AtlasPca.resolve_operation(st, 'u', { 'state' => 'committed' }, now: -> { 5 }), false, 'only true counts')
    C26.same(st.calls[1], [:transition, 'u', 'uncertain', unc.().merge('state' => 'committed', 'finishedAt' => 5)], 'transition args')
    st = o::Script.new(get: ->(_i) { unc.() }, transition: ->(*_a) { false })
    C26.same(AtlasPca.resolve_operation(st, 'u', { 'state' => 'committed' }, now: -> { 5 }), false, 'lost the race')
    # default clock
    m = mk.()
    t0 = (Time.now.to_f * 1000).to_i
    AtlasPca.resolve_operation(m, 'u', { 'state' => 'committed' })
    t1 = (Time.now.to_f * 1000).to_i
    f = m.get('u')['finishedAt']
    C26.same(f.is_a?(Integer) && f >= t0 && f <= t1, true, 'default clock')
    true
  end

  # ------------------------------------------------------------------------------------------------------------------
  # the Executor
  # ------------------------------------------------------------------------------------------------------------------
  t('c26 ops: Executor passes every option and call argument to authorize, nil when absent') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    last = Object.new
    def last.last(_k) = nil
    def last.pin(_k) = nil
    def last.raise_pin(_k, _v) = nil
    opts = AtlasPca::AuthorizeOptions.new(state_store: last, is_revoked: :isrev, plan: :plan, context: :ctx, require: :req, escalation_principals: [:ep],
                                          revocation_staleness: :rs, plans: :plans, require_assurance: :ra, k1: :k1opt, uses_store: :us, provenance: :provopt, undo: :undo)
    ops = AtlasPca::MemoryOperationStore.new
    ex = AtlasPca.create_executor(operations: ops, options: opts, audience: :aud, resolve_grant: :resolve, now: -> { 777 })
    got = []
    denied = AtlasPca::AuthorizeResult.new(allow: false, status: 401, checks: {}, reason: 'R')
    C26.seam(AtlasPca, authorize: ->(pc, **kw) { got << [pc, kw]; denied }) do
      r = ex.call(:pc, :opn, intent_policy: :ip, intent_v2: :iv2, escalation_answer: :ea, k1: :k1arg, fresh_at: :fa, workflow: :wf, workflow_call: :wfc,
                            provenance: :provarg, provenance_bundle: :pb) { 1 }
      C26.same(r.to_a, o.oc('denied', reason: 'R', authorization: denied), 'denied outcome')
      ex.call(:pc2, :opn2) { 1 }
    end
    want = { operation: :opn, audience: :aud, resolve_grant: :resolve, state_store: last, is_revoked: :isrev, now: 777, plan: :plan, context: :ctx,
             intent_policy: :ip, intent_v2: :iv2, require: :req, escalation_principals: [:ep], escalation_answer: :ea, revocation_staleness: :rs,
             plans: :plans, require_assurance: :ra, k1: :k1arg, uses_store: :us, fresh_at: :fa, workflow: :wf, workflow_call: :wfc,
             provenance: :provarg, provenance_bundle: :pb, undo: :undo }
    C26.same(got[0][0], :pc, 'pcactn argument')
    # the 0.5 options the executor forwards untouched: unset on this options object, so each arrives as nil
    extra = %i[multi_instance risk threshold_hook pq_pins require_risk_inputs resolve_principal require_verified_principal require_passport passport enforce_freshness
               adaptive seed_budget enforce_taint beacon require_linked_template forbid contracts]
    C26.same(got[0][1].keys.sort, (want.keys + extra).sort, 'the forwarded keys')
    C26.same(got[0][1].slice(*want.keys), want, 'all arguments passed')
    C26.same(got[0][1][:multi_instance], AtlasPca.store_shared?(last), 'multi_instance follows the store scope')
    C26.same(got[0][1].slice(*(extra - %i[multi_instance])).values.compact, [], 'the other new options are nil when absent')
    C26.same(got[1][0], :pc2, 'second pcactn')
    C26.same(got[1][1].slice(*want.keys), want.merge(operation: :opn2, intent_policy: nil, intent_v2: nil, escalation_answer: nil, k1: :k1opt, fresh_at: nil,
                                   workflow: nil, workflow_call: nil, provenance: :provopt, provenance_bundle: nil), 'absent arguments are nil, k1 / provenance fall back to the options')
    true
  end

  t('c26 ops: Executor refuses without a store; on allow hands execute_authorized exactly its configuration') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    opts = AtlasPca::AuthorizeOptions.new(is_revoked: ->(_p, _g) { false })
    partial = Object.new
    def partial.create(_r) = nil
    called = []
    C26.seam(AtlasPca, authorize: ->(*_a, **_k) { called << 1; nil }) do
      [nil, partial].each do |bad|
        ex = AtlasPca.create_executor(operations: bad, options: opts, audience: 'a', resolve_grant: ->(_r) { {} })
        C26.same(ex.call({}, o.operation) { 1 }.to_a, o.oc('refused', reason: 'createExecutor: missing required component: operations (fail closed)'), "ops #{bad.inspect}")
      end
    end
    C26.same(called, [], 'authorize never reached')
    ops = AtlasPca::MemoryOperationStore.new
    opn = o.op
    allow = AtlasPca::AuthorizeResult.new(allow: true, status: 200, pcactn: { 'action' => {} }, operation: opn)
    cap = []
    blk = proc { 1 }
    run = lambda do |operation, **kw|
      ex = AtlasPca.create_executor(operations: ops, options: opts, audience: 'a', resolve_grant: ->(_r) { {} }, **kw)
      C26.seam(AtlasPca, authorize: ->(*_a, **_k) { allow }, execute_authorized: ->(r, **k, &b) { cap << [r, k, b]; :done }) do
        [ex, ex.call({}, operation, &blk)]
      end
    end
    ex, res = run.(o.operation, now: -> { 42 })
    C26.same(res, :done, 'returns execute_authorized result')
    r, k, b = cap[0]
    C26.same(r.equal?(allow) && b.equal?(blk), true, 'result and block passed through')
    C26.same(k.keys.sort, %i[now operation pending_timeout_ms recheck recheck_for reversibility_class store], 'keyword set')
    C26.same(k[:store].equal?(ops), true, 'store')
    C26.same(k[:operation], o.operation, 'operation')
    C26.same(k[:recheck_for], 'irreversible', 'default recheck_for')
    C26.same(k[:reversibility_class], nil, 'no class catalog')
    C26.same(k[:pending_timeout_ms], 300_000, 'default timeout')
    C26.same(k[:now].call, 42, 'clock passed')
    C26.same(k[:recheck].receiver.equal?(ex) && k[:recheck].name == :recheck, true, 'recheck is the executor method')
    # explicit configuration
    seen = []
    run.(o.operation, recheck_for: 'always', reversibility_class_of: ->(opn2) { seen << opn2; 'rate_limited' }, pending_timeout_ms: 1234, now: -> { 1 })
    k = cap[1][1]
    C26.same([k[:recheck_for], k[:reversibility_class], k[:pending_timeout_ms], seen], ['always', 'rate_limited', 1234, [o.operation]], 'explicit configuration')
    # a catalog is not consulted for a non-hash operation
    seen.clear
    run.('str', reversibility_class_of: ->(opn2) { seen << opn2; 'x' })
    C26.same([cap[2][1][:reversibility_class], seen], [nil, []], 'non-hash operation')
    # default clock is the real clock
    run.(o.operation)
    t = cap[3][1][:now].call
    C26.same(t.is_a?(Integer) && (t - (Time.now.to_f * 1000).to_i).abs < 5000, true, 'default clock')
    true
  end

  t('c26 ops: Executor denial vs replay: only a lone replay failure at 403 is answered from the record') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    pcactn = { 'action' => { 'verb' => 'v.do' }, 'n' => 1 }
    id = AtlasPca.hash_canonical(pcactn)
    mkres = ->(status, checks) { AtlasPca::AuthorizeResult.new(allow: false, status: status, checks: checks, reason: 'R') }
    rec = { 'id' => id, 'state' => 'committed', 'verb' => 'v.do', 'resource' => '/r/1', 'params_digest' => o.dig, 'result' => 'RES' }
    build = lambda do |ops, result, pc, operation|
      opts = AtlasPca::AuthorizeOptions.new(is_revoked: ->(_p, _g) { false })
      ex = AtlasPca.create_executor(operations: ops, options: opts, audience: 'a', resolve_grant: ->(_r) { {} }, now: -> { 5 })
      C26.seam(AtlasPca, authorize: ->(*_a, **_k) { result }) { ex.call(pc, operation) { raise 'must not run' } }
    end
    replay = { 'replay' => 'fail', 'sig' => 'pass' }
    ops = AtlasPca::MemoryOperationStore.new
    ops.create(rec)
    answered = o.oc('committed', id: id, result: 'RES', replayed: true)
    C26.same(build.(ops, mkres.(403, replay), pcactn, o.operation).to_a, answered, 'replay answered')
    C26.same(build.(ops, mkres.(403, replay), pcactn, { verb: 'v.do', resource: '/r/1', params: { 'a' => 1 } }).to_a, answered, 'symbol-key operation')
    C26.same(build.(ops, mkres.(403, replay), JSON.generate(pcactn), o.operation).to_a, answered, 'JSON text pcactn')
    # not a lone replay failure at 403: denied with the authorize result and its reason
    [[401, replay], [403, { 'replay' => 'fail', 'sig' => 'fail' }], [403, { 'sig' => 'fail' }], [403, {}], [500, replay], [200, replay]].each_with_index do |(status, checks), i|
      res = mkres.(status, checks)
      got = build.(ops, res, pcactn, o.operation)
      C26.same(got.to_a, o.oc('denied', reason: 'R', authorization: res), "denied #{i}")
    end
    # a lone replay failure but no usable record: denied
    res = mkres.(403, replay)
    no_rec = AtlasPca::MemoryOperationStore.new
    C26.same(build.(no_rec, res, pcactn, o.operation).to_a, o.oc('denied', reason: 'R', authorization: res), 'no record')
    C26.same(build.(ops, res, 'garbage', o.operation).to_a, o.oc('denied', reason: 'R', authorization: res), 'undecodable pcactn')
    C26.same(build.(ops, res, nil, o.operation).to_a, o.oc('denied', reason: 'R', authorization: res), 'absent pcactn')
    [o.operation.merge('verb' => 'other'), o.operation.merge('resource' => '/other'), o.operation.merge('params' => { 'a' => 2 })].each_with_index do |opn, i|
      C26.same(build.(ops, res, pcactn, opn).to_a, o.oc('denied', reason: 'R', authorization: res), "operation mismatch #{i}")
    end
    # each recorded field is compared on its own
    { 'verb' => 'x', 'resource' => 'x', 'params_digest' => 'x' }.each do |k, v|
      m = AtlasPca::MemoryOperationStore.new
      m.create(rec.merge(k => v))
      C26.same(build.(m, res, pcactn, o.operation).to_a, o.oc('denied', reason: 'R', authorization: res), "record #{k} differs")
    end
    # an invalid operation matches a record that carries no verb / resource / digest (all nil on both sides)
    bare = AtlasPca::MemoryOperationStore.new
    bare.create({ 'id' => id, 'state' => 'committed', 'result' => 'RES' })
    [nil, {}, 'x'].each do |opn|
      C26.same(build.(bare, res, pcactn, opn).to_a, answered, "bare record with operation #{opn.inspect}")
    end
    # an open record is settled against the executor clock (5) and timeout
    open_ops = AtlasPca::MemoryOperationStore.new
    open_ops.create(rec.merge('state' => 'pending', 'startedAt' => 0).reject { |k, _| k == 'result' })
    C26.same(build.(open_ops, res, pcactn, o.operation).to_a, o.oc('pending', id: id, replayed: true), 'open record answered')
    true
  end

  t('c26 ops: Executor#recheck: grant, revocation verdicts, registered plan, caller extra') do
    next true if C26.skip?('operations.rb')

    o = C26::Ops
    pcactn = { 'grant_ref' => 'g1', 'plan' => { 'root' => 'R1', 'node_id' => 'n1' } }
    handle = ->(pc = pcactn) { AtlasPca::ExecutionHandle.new(idempotency_key: 'i', operation: nil, pcactn: pc, authorization: nil) }
    plans_cls = Class.new do
      attr_reader :log

      def initialize(get, check)
        @get = get
        @check = check
        @log = []
      end

      def get(g, r) = (@log << [:get, g, r]; @get)
      def check(g, r, node_id:, now:) = (@log << [:check, g, r, node_id, now]; @check)
    end
    mk = lambda do |revoked: ->(_p, _g) { false }, resolve: ->(_r) { {} }, plans: nil, **kw|
      opts = AtlasPca::AuthorizeOptions.new(is_revoked: revoked, plans: plans)
      AtlasPca.create_executor(operations: AtlasPca::MemoryOperationStore.new, options: opts, audience: 'a', resolve_grant: resolve, now: -> { 555 }, **kw)
    end
    ok = { 'ok' => true }
    C26.same(mk.().recheck(handle.()), ok, 'all clear, no extra')
    # the grant is looked up by the PCActn's grant_ref
    asked = []
    unknown = { 'ok' => false, 'reason' => 'the grant is no longer known' }
    C26.same(mk.(resolve: ->(r) { asked << r; nil }).recheck(handle.()), unknown, 'grant unknown (nil)')
    C26.same(asked, ['g1'], 'resolve called with grant_ref')
    [5, 'g', [], false].each { |g| C26.same(mk.(resolve: ->(_r) { g }).recheck(handle.()), unknown, "grant #{g.inspect}") }
    # revocation: called with (pcactn, grant)
    args = []
    grant = { 'id' => 'G' }
    C26.same(mk.(resolve: ->(_r) { grant }, revoked: ->(p, g) { args << [p, g]; false }).recheck(handle.()), ok, 'not revoked')
    C26.same(args.length == 1 && args[0][0].equal?(pcactn) && args[0][1].equal?(grant), true, 'revocation args')
    C26.same(mk.(revoked: ->(_p, _g) { true }).recheck(handle.()), { 'ok' => false, 'reason' => 'the grant has been revoked' }, 'revoked')
    undecided = { 'ok' => false, 'reason' => 'revocation could not be checked' }
    [nil, 'false', 0, :x].each { |v| C26.same(mk.(revoked: ->(_p, _g) { v }).recheck(handle.()), undecided, "verdict #{v.inspect}") }
    C26.same(mk.(revoked: ->(_p, _g) { raise 'down' }).recheck(handle.()), undecided, 'revocation check raised')
    # registered plan
    gone = plans_cls.new(nil, { 'executable' => false, 'state' => 'revoked' })
    C26.same(mk.(plans: gone).recheck(handle.()), ok, 'plan not registered: skipped')
    C26.same(gone.log, [[:get, 'g1', 'R1']], 'only get is asked')
    good = plans_cls.new({ 'id' => 'x' }, { 'executable' => true })
    C26.same(mk.(plans: good).recheck(handle.()), ok, 'plan executable')
    C26.same(good.log, [[:get, 'g1', 'R1'], [:check, 'g1', 'R1', 'n1', 555]], 'plan check arguments (node id, executor clock)')
    bad = lambda do |ps|
      mk.(plans: plans_cls.new({ 'id' => 'x' }, ps)).recheck(handle.())
    end
    C26.same(bad.({ 'executable' => false, 'reason' => 'withdrawn' }), { 'ok' => false, 'reason' => 'withdrawn' }, 'plan reason')
    C26.same(bad.({ 'executable' => false, 'reason' => '', 'state' => 'revoked' }), { 'ok' => false, 'reason' => 'plan is revoked' }, 'empty reason -> state')
    C26.same(bad.({ 'executable' => false, 'reason' => nil, 'state' => 'expired' }), { 'ok' => false, 'reason' => 'plan is expired' }, 'nil reason -> state')
    C26.same(bad.({ 'executable' => false, 'reason' => 0, 'state' => 'draft' }), { 'ok' => false, 'reason' => 'plan is draft' }, 'zero reason -> state')
    C26.same(bad.({ 'state' => 'revoked' }), { 'ok' => false, 'reason' => 'plan is revoked' }, 'executable absent')
    C26.same(bad.({ 'executable' => nil, 'state' => 'revoked' }), { 'ok' => false, 'reason' => 'plan is revoked' }, 'executable nil')
    # a PCActn without a usable plan root never reaches the registry
    always = plans_cls.new({ 'id' => 'x' }, { 'executable' => false, 'state' => 'revoked' })
    [{ 'grant_ref' => 'g1' }, { 'grant_ref' => 'g1', 'plan' => [] }, { 'grant_ref' => 'g1', 'plan' => nil }, { 'grant_ref' => 'g1', 'plan' => 'root' },
     { 'grant_ref' => 'g1', 'plan' => { 'root' => 5 } }, { 'grant_ref' => 'g1', 'plan' => { 'root' => nil } }].each_with_index do |pc, i|
      C26.same(mk.(plans: always).recheck(handle.(pc)), ok, "no root #{i}")
    end
    C26.same(always.log, [], 'registry never asked')
    # the caller's extra re-check runs last, with the handle, and its verdict is returned as is
    got = []
    h = handle.()
    extra = ->(hh) { got << hh; { 'ok' => false, 'reason' => 'extra says no' } }
    C26.same(mk.(recheck: extra).recheck(h), { 'ok' => false, 'reason' => 'extra says no' }, 'extra verdict')
    C26.same(got.length == 1 && got[0].equal?(h), true, 'extra gets the handle')
    C26.same(mk.(recheck: ->(_h) { ok }, revoked: ->(_p, _g) { true }).recheck(h), { 'ok' => false, 'reason' => 'the grant has been revoked' }, 'extra not reached after a revocation')
    true
  end
end
