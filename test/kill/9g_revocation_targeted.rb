# frozen_string_literal: true
# Exact kills for IntentV2.check_revocation_epoch / revocation_epoch_shape_error / check_session_revocation, on the TS-generated
# fixture of test-data/k042-sessrevoc-cases.json (the 'ok' revocation case: a guardian-signed epoch). Reasons follow
# revocation.ts checkRevocationEpoch. Bears on intent_v2.rb only.
module MutationKill
  module RevT
    module_function
    def fx = (@fx ||= begin
      c = DiffUtil.parse(DiffUtil.read('k042-sessrevoc-cases.json'))['rev'].find { |x| x['name'] == 'ok' }
      { ev: AtlasPca.parse_json_text(c['ev']), guardian: AtlasPca.parse_json_text(c['authority']), now: c['now'], session: c['session'], ids: AtlasPca.parse_json_text(c['ids']) }
    end)
    def ep = fx[:ep] || fx[:ev]['epoch']
    def chk(e, now = fx[:now], gr = AtlasPca::V2JS::UNDEF, g = fx[:guardian]) = AtlasPca.check_revocation_epoch(e, g, now, gr)
    def bad(r, reason) = r == { 'ok' => false, 'reason' => reason }

    def run
      e = ep
      g = fx[:guardian]
      now = fx[:now]
      gr = e['grant_ref']
      u = AtlasPca::V2JS::UNDEF
      return 'ok' unless chk(e) == { 'ok' => true }
      return 'ok with grant_ref' unless chk(e, now, gr) == { 'ok' => true }
      return 'ok symbol keys' unless chk(e.transform_keys(&:to_sym)) == { 'ok' => true }
      return 'ok float now' unless chk(e, now.to_f) == { 'ok' => true }
      pin = 'revocation epoch not signed by the pinned guardian'
      [nil, 5, 'x', [], true].each { |v| return "non-hash #{v.inspect}" unless bad(chk(v), pin) }
      return 'other guardian' unless bad(chk(e, now, u, 'x' + g), pin)
      return 'guardian missing' unless bad(chk(e.reject { |k, _| k == 'guardian' }), pin)
      return 'alg unknown' unless bad(chk(e.merge('alg' => 'rot13')), pin)
      return 'alg nil' unless bad(chk(e.merge('alg' => nil)), pin)
      mal = 'malformed revocation epoch'
      { 'epoch' => [-1, 1.5, nil, '2', Float::INFINITY], 'set_size' => [-1, 1.5, nil, '2'], 'issued_at' => [nil, '1', 1.5, 2**60],
        'not_after' => [nil, '1', 1.5, 2**60] }.each do |k, vs|
        vs.each { |v| return "#{k}=#{v.inspect}" unless bad(chk(e.merge(k => v)), mal) }
        return "#{k} missing" unless bad(chk(e.reject { |kk, _| kk == k }), mal)
      end
      sig = 'revocation epoch signature invalid'
      { 'root' => e['root'].sub(/./) { |c| c == 'A' ? 'B' : 'A' }, 'instance_id' => 'zz', 'grant_ref' => 'zz', 'epoch' => e['epoch'] + 1,
        'set_size' => e['set_size'] + 1, 'issued_at' => e['issued_at'] + 1, 'not_after' => e['not_after'] + 1, 'sig' => 'AAAA' }.each do |k, v|
        return "tamper #{k}" unless bad(chk(e.merge(k => v)), sig)
      end
      return 'sig pq_sig extra' if chk(e.merge('pq_sig' => 'AAAA'))['ok'] && false
      return 'other grant' unless bad(chk(e, now, 'other'), 'revocation epoch is for a different grant')
      return 'grant nil' unless bad(chk(e, now, nil), 'revocation epoch is for a different grant')
      na = e['not_after']
      return 'now == not_after' unless chk(e, na) == { 'ok' => true }
      return 'now > not_after' unless bad(chk(e, na + 1), 'revocation epoch expired (stale revocation root)')
      ia = e['issued_at']
      return 'issued now+60000' unless chk(e, ia - 60_000) == { 'ok' => true }
      return 'issued now+60001' unless bad(chk(e, ia - 60_001), 'revocation epoch issued in the future')
      return 'now nil' unless bad(chk(e, nil), 'revocation epoch check error')
      nil
    end

    def shape
      e = ep
      s = ->(x) { AtlasPca.revocation_epoch_shape_error(x) }
      return 'shape ok' unless s.call(e).nil?
      return 'shape nonhash' unless s.call(nil) == 'the revocation epoch must be an object' && s.call([]) == 'the revocation epoch must be an object'
      %w[instance_id grant_ref root guardian sig].each { |k| return "shape #{k}" unless s.call(e.merge(k => 5)) == "revocation epoch #{k} must be a string" && s.call(e.reject { |kk, _| kk == k }) == "revocation epoch #{k} must be a string" }
      %w[epoch set_size issued_at not_after].each do |k|
        [-1, 1.5, '1', nil].each { |v| return "shape #{k}=#{v.inspect}" unless s.call(e.merge(k => v)) == "revocation epoch #{k} must be a non-negative safe integer" }
      end
      return 'shape guardian_epoch' unless s.call(e.merge('guardian_epoch' => -1)) == 'revocation epoch guardian_epoch must be a non-negative safe integer' && s.call(e.merge('guardian_epoch' => 3)).nil?
      return 'shape pq_pk' unless s.call(e.merge('pq_pk' => 5)) == 'revocation epoch pq_pk must be a string' && s.call(e.merge('pq_pk' => nil)) == 'revocation epoch pq_pk must be a string'
      return 'shape pq_sig' unless s.call(e.merge('pq_sig' => 5)) == 'revocation epoch pq_sig must be a string'
      return 'shape alg' unless s.call(e.merge('alg' => 'rot13'))&.start_with?('revocation epoch alg: ')
      nil
    end
  end

  t('check_revocation_epoch: every refusal exact') do
    next true if DiffUtil.skip?('intent_v2.rb')
    bad = RevT.run
    warn bad if bad && !ENV['MUT_FILE']
    bad.nil?
  end
  t('revocation_epoch_shape_error: every refusal exact') do
    next true if DiffUtil.skip?('intent_v2.rb')
    bad = RevT.shape
    warn bad if bad && !ENV['MUT_FILE']
    bad.nil?
  end
end
