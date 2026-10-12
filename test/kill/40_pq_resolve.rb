# frozen_string_literal: true

# The R3-01 PQ-key choke point and its neighbours, pinned exactly (kills surviving mutants of tools/pca-audit/ruby-mutate):
# which authority mints a key (trusted > own pin > holder commitment), refusal is nil (never false, never a raise).
module MutationKill
  module Q
    module_function

    def r(*a, **k) = AtlasPca.resolve_pq_key(*a, **k)
    def minted?(x, key, src) = x.is_a?(AtlasPca::PinnedPq) && x.key == key && x.source == src
  end

  t('resolve_pq_key: trusted key') do
    Q.minted?(Q.r(nil, nil, trusted_pk: 'T'), 'T', 'trusted') && Q.minted?(Q.r('id', 'A', trusted_pk: 'T', pq_pins: { 'id' => 'X' }), 'T', 'trusted') &&
      Q.r(nil, nil, trusted_pk: '').nil? && Q.r(nil, nil, trusted_pk: 5).nil? && Q.r(nil, nil, trusted_pk: false).nil?
  end
  t('resolve_pq_key: artifact key must be a non-empty string') do
    Q.r('id', '', pq_pins: { 'id' => '' }).nil? && Q.r('id', 5, pq_pins: { 'id' => 5 }).nil? && Q.r('id', nil).nil?
  end
  t('resolve_pq_key: own pin decides (match mints, mismatch refuses even with a holder commitment)') do
    c = AtlasPca.holder_pq_commitment('A')
    Q.minted?(Q.r('id', 'A', pq_pins: { 'id' => 'A' }), 'A', 'pin') &&
      Q.r('id', 'A', pq_pins: { 'id' => 'B' }, holder_pq: c).nil? &&
      Q.minted?(Q.r('id', 'A', pq_pins: { 'other' => 'B' }, holder_pq: c), 'A', 'holder-commitment') &&
      Q.r(5, 'A', pq_pins: { 5 => 'A' }).nil? && Q.r('id', 'A', pq_pins: 'x').nil? && Q.r('id', 'A', pq_pins: ['id']).nil? &&
      Q.minted?(Q.r(5, 'A', pq_pins: { 5 => 'B' }, holder_pq: c), 'A', 'holder-commitment')
  end
  t('resolve_pq_key: holder commitment must match') do
    c = AtlasPca.holder_pq_commitment('A')
    Q.minted?(Q.r('id', 'A', holder_pq: c), 'A', 'holder-commitment') && Q.r('id', 'A', holder_pq: AtlasPca.holder_pq_commitment('B')).nil? &&
      Q.r('id', 'A', holder_pq: 'x').nil? && Q.r('id', 'A', holder_pq: 5).nil?
  end
  t('mldsa65_verify_pinned: strictly false for anything but a PinnedPq') do
    ['key', nil, 5, Object.new].all? { |k| AtlasPca.mldsa65_verify_pinned(k, 'm', 'AA').equal?(false) } &&
      AtlasPca.mldsa65_verify_pinned(AtlasPca::PinnedPq.mint('AA', 'pin'), 'm', 'AA').equal?(false)
  end
  t('verify_suite / verify_share_suite: strictly false on an unknown suite') do
    AtlasPca.verify_suite({ 'alg' => 'rsa', 'sig' => 'AA' }, 'AA', 'm', nil).equal?(false) &&
      AtlasPca.verify_suite({ 'alg' => 5 }, 'AA', 'm', nil).equal?(false) &&
      AtlasPca.verify_share_suite({ 'alg' => 'rsa', 'sig' => 'AA', 'publicKey' => 'AA' }, 'm').equal?(false)
  end
  t('signer_set_hash: nil for anything that is not a non-empty list of {role,publicKey} strings') do
    ok = { 'role' => 'agent', 'publicKey' => 'K' }
    [nil, [], 'x', {}, [5], [ok, 5], [ok.merge('publicKey' => 5)], [ok.merge('role' => nil)], [{ 'role' => 'agent' }]].all? { |s| AtlasPca.signer_set_hash(s).nil? } &&
      AtlasPca.signer_set_hash([ok]).is_a?(String) && AtlasPca.signer_set_hash([ok]).bytesize == 32 &&
      AtlasPca.signer_set_hash([ok]) == AtlasPca.sha(AtlasPca::SIGNERSET_DOMAIN + '[{"publicKey":"K","role":"agent"}]'.b) &&
      AtlasPca.signer_set_hash([ok.merge('pq_pk' => '')]) == AtlasPca.sha(AtlasPca::SIGNERSET_DOMAIN + '[{"pq_pk":"","publicKey":"K","role":"agent"}]'.b) &&
      AtlasPca.signer_set_hash([ok.merge('pq_pk' => 5)]) == AtlasPca.signer_set_hash([ok]) &&
      AtlasPca.signer_set_hash([ok.merge('role' => 'b', 'publicKey' => 'A'), ok.merge('role' => 'a', 'publicKey' => 'B')]) ==
        AtlasPca.sha(AtlasPca::SIGNERSET_DOMAIN + '[{"publicKey":"B","role":"a"},{"publicKey":"A","role":"b"}]'.b) &&
      AtlasPca.signer_set_hash([ok.merge('publicKey' => 'B'), ok.merge('publicKey' => 'A')]) ==
        AtlasPca.sha(AtlasPca::SIGNERSET_DOMAIN + '[{"publicKey":"A","role":"agent"},{"publicKey":"B","role":"agent"}]'.b)
  end
end
