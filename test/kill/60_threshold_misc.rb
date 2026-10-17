# frozen_string_literal: true

# Threshold-share edges, signer registry, PQ artifacts, Merkle root and params digest, pinned exactly (kills surviving
# mutants of tools/pca-audit/ruby-mutate). Fixtures are the TS-generated corpus entries, never built by the code under test.
module MutationKill
  module T
    module_function

    def ts = Corpus.core['primitives']['threshold_share']
    def tset = Corpus.core['primitives']['threshold_set']
    def valid_ed(t = 1) = ts.find { |s| s['valid'] != false && s['t'] == t && !s['share'].key?('alg') }
    def valid_hybrid = tset.find { |e| e['valid'] && e['share']['alg'] == 'hybrid-ed25519-ml-dsa-65' }
    def sf(v) = v.equal?(false)
  end

  t('verify_threshold_share: t as an integral float is t (JS number semantics)') do
    e = T.valid_ed
    AtlasPca.verify_threshold_share(e) == true && AtlasPca.verify_threshold_share(e.merge('t' => 1.0)) == true &&
      [1.5, Float::INFINITY, Float::NAN, '1', nil, 0, 4].all? { |t| T.sf(AtlasPca.verify_threshold_share(e.merge('t' => t))) }
  end
  t('verify_threshold_share: strictly false for an unregistered role, a null pq_pk on a share, a non-Hash entry') do
    e = T.valid_ed
    set = e['signer_set'].reject { |m| m['role'] == 'guardian' }
    g = e.merge('role' => 'guardian', 'share' => e['share'].merge('role' => 'guardian'), 'signer_set' => set)
    T.sf(AtlasPca.verify_threshold_share(g)) && T.sf(AtlasPca.verify_threshold_share(5)) && T.sf(AtlasPca.verify_threshold_share(nil)) &&
      T.sf(AtlasPca.verify_threshold_share(e.merge('share' => e['share'].merge('pq_pk' => nil)))) &&
      T.sf(AtlasPca.verify_threshold_share(e.merge('share' => e['share'].merge('sig' => AtlasPca.b64e("\x01".b * 64)))))
  end
  t('verify_threshold_share: a hybrid share needs BOTH halves', needs: 'ml-dsa-65') do
    h = T.valid_hybrid
    h.nil? || (AtlasPca.verify_threshold_share(h) == true &&
      T.sf(AtlasPca.verify_threshold_share(h.merge('share' => h['share'].merge('sig' => AtlasPca.b64e("\x01".b * 64))))))
  end
  t('signer_registry: every registered PQ key length, nothing else; nil (never false / a raise) on malformed sets') do
    ok = { 'role' => 'agent', 'publicKey' => T.valid_ed['signer_set'].find { |m| m['role'] == 'agent' }['publicKey'] }
    pq = ->(n) { AtlasPca.b64e("\x00".b * n) }
    AtlasPca::PQ_PK_LENGTHS.all? { |n| AtlasPca.signer_registry([ok.merge('pq_pk' => pq.call(n))]) == { 'agent' => [ok['publicKey'], pq.call(n)] } } &&
      AtlasPca::PQ_PK_LENGTHS.flat_map { |n| [n - 1, n + 1] }.reject { |n| AtlasPca::PQ_PK_LENGTHS.include?(n) }.all? { |n| AtlasPca.signer_registry([ok.merge('pq_pk' => pq.call(n))]).nil? } &&
      [nil, 5, 'x', [5], [ok.merge('role' => 5)], [ok.merge('role' => 'nobody')], [ok.merge('publicKey' => 5)], [ok.merge('publicKey' => 'AA')],
       [ok.merge('pq_pk' => 5)], [ok.merge('pq_pk' => nil)], [ok.merge('pq_pk' => 'AA')],
       [ok, ok.merge('publicKey' => AtlasPca.b64e("\x02".b * 32))], [ok, ok.merge('role' => 'guardian')]].all? { |s| AtlasPca.signer_registry(s).nil? } &&
      AtlasPca.signer_registry([ok, ok]) == { 'agent' => [ok['publicKey'], nil] } && AtlasPca.signer_registry([]) == {}
  end
  t('signer_set_hash: a non-String role or key is nil, not a raise') do
    AtlasPca.signer_set_hash([{ 'role' => 5, 'publicKey' => 'K' }]).nil? && AtlasPca.signer_set_hash([{ 'role' => 'agent', 'publicKey' => 5 }]).nil?
  end
  t('verify_pq_artifact: strictly false on a bad entry, message or key', needs: 'ml-dsa-65') do
    a = Corpus.core['primitives']['pq_artifact'].find { |x| x['alg'] == 'hybrid-ed25519-ml-dsa-65' && x['valid'] != false }
    AtlasPca.verify_pq_artifact(a) == true &&
      [5, nil, 'x', {}, a.merge('message' => 'AA'), a.merge('message' => 5), a.merge('ed_pub' => 'AA'), a.merge('ed_pub' => 5),
       a.merge('sig' => 'AA'), a.merge('pq_pk' => 'AA'), a.merge('pq_sig' => 'AA')].all? { |e| T.sf(AtlasPca.verify_pq_artifact(e)) }
  end
  t('merkle_root: empty set is Malformed; params_digest hashes its argument') do
    msg = begin
      AtlasPca.merkle_root([])
      nil
    rescue AtlasPca::Malformed => e
      e.message
    end
    msg == 'empty leaf set' && AtlasPca.params_digest({ 'a' => 1 }) == AtlasPca.hash_canonical({ 'a' => 1 }) &&
      AtlasPca.params_digest({ 'a' => 1 }) != AtlasPca.params_digest(nil)
  end
  t('b64d: non-canonical trailing bits, padding, foreign alphabet, len % 4 == 1') do
    %w[AB AAB AA== A+A_ AAAAA A/AA].all? { |s| AtlasPca.b64d(s).nil? } && AtlasPca.b64d('AQ') == "\x01".b && AtlasPca.b64d('', 0) == ''.b
  end
end
