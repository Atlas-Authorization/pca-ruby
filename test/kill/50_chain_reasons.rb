# frozen_string_literal: true

# verify_chain returns [reason, ok]; the reason is part of the API (the reference returns the same texts). Pinned exactly
# over the TS-generated chain_pin fixtures and hand-made malformed chains, plus the chain helpers (kills surviving mutants of
# tools/pca-audit/ruby-mutate).
module MutationKill
  module K
    module_function

    def pin(name) = Corpus.core['primitives']['chain_pin'].find { |v| v['name'] == name }
    def root = pin('chainpin-ed25519-root-no-pin-needed')['chain'][0]
    def iss = pin('chainpin-ed25519-root-no-pin-needed')['expected_root_issuer']
    def vc(chain, iss = K.iss, have = true, al = nil, pins = nil, tr = nil) = AtlasPca.verify_chain(chain, iss, have, al, pins, tr)
    def bad_sig = 'hop 0: bad signature (not signed by expected key)'
  end

  t('verify_chain: shape reasons') do
    [nil, [], 'x', {}].all? { |c| K.vc(c) == ['empty chain', false] } &&
      K.vc([5] * 17) == ['chain longer than 16 capabilities', false] &&
      K.vc([{ 'caveats' => Array.new(257) { { 'type' => 'x' } } }]) == [AtlasPca::CAVEAT_LIMIT_REASON, false] &&
      K.vc([5]) == ['hop 0: malformed capability', false] &&
      K.vc([K.root.merge('parent' => 'x')]) == ['hop 0: root must not have a parent', false]
  end
  t('verify_chain: root issuer, suite, digest and signature reasons') do
    r = K.root
    other_sig = AtlasPca.b64e("\x01".b * 64)
    K.vc([r]) == ['', true] && K.vc([r], 'someone-else') == ['hop 0: root issuer is not the expected principal', false] &&
      K.vc([r], 'someone-else', false) == ['', true] &&
      K.vc([r.merge('alg' => 'rsa')]) == ["hop 0: unknown signature alg 'rsa'", false] &&
      K.vc([r.merge('caveats' => r['caveats'] + [{ 'type' => 'x' }])]) == ['hop 0: body digest mismatch', false] &&
      K.vc([r.merge('id' => 'x')]) == ['hop 0: body digest mismatch', false] &&
      K.vc([r.merge('sig' => other_sig)]) == [K.bad_sig, false] &&
      K.vc([r], K.iss, true, []) == ["hop 0: signature suite 'ed25519' is not allowed by this verifier's suite policy", false] &&
      K.vc([r], K.iss, true, ['ed25519']) == ['', true]
  end
  t('verify_chain: stored grant AND a pin must agree (0.4.2, fail closed)') do
    v = K.pin('chainpin-pure-pq-root-trusted-root')
    wrong = K.pin('chainpin-hybrid-root-wrong-pin')['pq_pins']
    right = K.pin('chainpin-pure-pq-root-pinned')['pq_pins']
    eri = v['expected_root_issuer']
    want = ["hop 0: root suite 'ml-dsa-65': the server-side PQ pin for the root issuer (policy.pqPins) does not match the stored grant's pq_pk (fail closed)", false]
    refused = K.vc(v['chain'], eri, true, nil, wrong, v['trusted_root']) == want &&
              K.vc(v['chain'], eri, true, nil, { eri => 'not-the-key' }, v['trusted_root']) == want
    # agreeing pin / pin for another issuer: the stored grant still authorises (needs a runtime that verifies ML-DSA-65)
    agree = !AtlasPca.supported_suites.include?('ml-dsa-65') ||
            (K.vc(v['chain'], eri, true, nil, right, v['trusted_root']) == ['', true] &&
             K.vc(v['chain'], eri, true, nil, { 'someone-else' => 'k' }, v['trusted_root']) == ['', true])
    refused && agree
  end
  t('verify_chain: two-hop reasons', needs: 'ml-dsa-65') do
    v = K.pin('chainpin-mixed-ed25519-root-bound-pq-hop')
    r, h = v['chain']
    ok = K.vc(v['chain'], v['expected_root_issuer'])
    ok == ['', true] &&
      K.vc([r, 5], v['expected_root_issuer']) == ['hop 1: malformed capability', false] &&
      K.vc([r, h.merge('parent' => 'x')], v['expected_root_issuer']) == ['hop 1: broken parent link', false] &&
      K.vc([r, h.merge('issuer' => 'x')], v['expected_root_issuer']) == ["hop 1: issuer is not the parent's bound holder", false] &&
      K.vc([r, h], v['expected_root_issuer'], true, ['ed25519']) == ["hop 1: signature suite 'ml-dsa-65' is not allowed by this verifier's suite policy", false]
  end
  t('verify_chain: an internal fault is reported by class name') do
    deep = []
    40.times { deep = [deep] }
    r = K.root.merge('caveats' => [{ 'type' => 'deep', 'v' => deep }])
    K.vc([r]) == ['malformed capability chain: AtlasPca::Malformed', false]
  end

  t('caveat_limit_exceeded? counts only Array caveats of Hash hops; strictly false when within') do
    c = ->(x) { AtlasPca.caveat_limit_exceeded?(x) }
    c.call([]).equal?(false) && c.call([5, 'x', nil]).equal?(false) && c.call([{ 'caveats' => 'x' * 300 }]).equal?(false) &&
      c.call(Array.new(1025) { 5 }).equal?(false) && c.call(Array.new(1025) { { 'caveats' => 'y' } }).equal?(false) &&
      c.call([{ 'caveats' => Array.new(257) { 1 } }]) == true
  end
  t('suite_policy_error exact') do
    s = ->(*a) { AtlasPca.suite_policy_error(*a) }
    s.call(nil, 'L', nil).nil? && s.call('ml-dsa-65', 'L', nil).nil? && s.call(nil, 'L', ['ed25519']).nil? &&
      s.call('ml-dsa-65', 'L', ['ed25519']) == "L: signature suite 'ml-dsa-65' is not allowed by this verifier's suite policy" &&
      s.call(nil, 'L', []) == "L: signature suite 'ed25519' is not allowed by this verifier's suite policy" &&
      s.call(5, 'L', [5]) == "L: signature suite '5' is not allowed by this verifier's suite policy"
  end
  t('pq_binding_error exact') do
    b = ->(*a) { AtlasPca.pq_binding_error(*a) }
    c = AtlasPca.holder_pq_commitment('P')
    need = "L: suite 'ml-dsa-65' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)"
    mism = "L: pq_pk does not match the signer's committed holder_pq (F-2)"
    b.call(nil, 'P', nil, 'L').nil? && b.call('ed25519', 'P', nil, 'L').nil? && b.call('rsa', 'P', nil, 'L').nil? && b.call(5, 'P', nil, 'L').nil? &&
      b.call('ml-dsa-65', 'P', nil, 'L') == need && b.call('ml-dsa-65', 'P', 5, 'L') == need &&
      b.call('ml-dsa-65', 'P', c, 'L').nil? && b.call('ml-dsa-65', 'Q', c, 'L') == mism && b.call('ml-dsa-65', nil, c, 'L') == mism &&
      b.call('hybrid-ed25519-ml-dsa-65', 'P', c, 'L').nil? && b.call('hybrid-ed25519-ml-dsa-65', 5, c, 'L') ==
        "L: pq_pk does not match the signer's committed holder_pq (F-2)"
  end
  t('signable_hop_body exact', needs: 'ml-dsa-65') do
    s = ->(c) { AtlasPca.signable_hop_body(c) }
    base = { 'issuer' => 'I', 'holder' => 'H', 'caveats' => [], 'parent' => 'P' }
    body = base.dup
    s.call(base.merge('alg' => 'rsa')) == [nil, "unknown signature alg 'rsa'"] &&
      s.call(base) == [body, nil] && s.call(base.merge('alg' => 'ed25519', 'pq_pk' => 'X')) == [body, nil] &&
      s.call(base.merge('alg' => 'ml-dsa-65', 'pq_pk' => 'X')) == [body.merge('alg' => 'ml-dsa-65', 'pq_pk' => 'X'), nil] &&
      s.call(base.merge('alg' => 'ml-dsa-65', 'pq_pk' => 5)) == [body.merge('alg' => 'ml-dsa-65'), nil] &&
      s.call(base.merge('alg' => 'hybrid-ed25519-ml-dsa-65', 'pq_pk' => 'X', 'holder_pq' => 'C')) ==
        [body.merge('holder_pq' => 'C', 'alg' => 'hybrid-ed25519-ml-dsa-65', 'pq_pk' => 'X'), nil]
  end
  t('resolve_root_pq exact') do
    v = K.pin('chainpin-pure-pq-root-pinned')
    r = v['chain'][0]
    reason = format(AtlasPca::ROOT_PQ_PIN_REASON, 'ml-dsa-65')
    a = AtlasPca.resolve_root_pq(K.root, nil, nil)
    b = AtlasPca.resolve_root_pq(r, v['pq_pins'], nil)
    c = AtlasPca.resolve_root_pq(r, nil, r)
    a == [nil, nil] && AtlasPca.resolve_root_pq({ 'alg' => 'rsa' }, nil, nil) == [nil, nil] &&
      b[0].is_a?(AtlasPca::PinnedPq) && b[0].source == 'pin' && b[1].nil? &&
      c[0].is_a?(AtlasPca::PinnedPq) && c[0].source == 'trusted' && c[1].nil? &&
      AtlasPca.resolve_root_pq(r, nil, nil) == [nil, reason] &&
      AtlasPca.resolve_root_pq(r, nil, K.root) == [nil, reason] &&
      AtlasPca.resolve_root_pq(r.merge('pq_pk' => 5), nil, r.merge('pq_pk' => 5)) == [nil, reason] &&
      AtlasPca.resolve_root_pq(r, nil, Object.new) == [nil, reason]
  end
end
