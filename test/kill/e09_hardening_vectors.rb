# frozen_string_literal: true

# e09: the shared hardening vectors (packages/pca/conformance): budget-alloc-vectors.json, plan-root-vectors.json,
# pq-pin-vectors.json. Each Ruby result is compared with the reference's `expect` exactly. AtlasPca is resolved at call time.

module MutationKill
  module E09
    module_function

    CONF = File.expand_path('../../conformance', __dir__)

    def read_vec(name) = AtlasPca.parse_json(File.read(File.join(CONF, name), encoding: 'UTF-8'), loose: true)
    def core = (@core ||= read_vec('vectors.json')['vectors'])
    def vector(name) = core.find { |v| v['name'] == name } || raise("no core vector #{name}")
    def gate?(*files) = (f = ENV['MUT_FILE']).nil? || f.empty? || files.include?(f)

    def ck(label, got, want)
      got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
    end
  end

  t('e09 vectors: budget_alloc monotonicity over the flattened caveat list') do
    next true unless E09.gate?('atlas_pca.rb')

    rows = E09.read_vec('budget-alloc-vectors.json')['budget_alloc']
    raise "rows: #{rows.length}" unless rows.length >= 24

    rows.all? do |c|
      want = c['expect']['ok'] ? nil : c['expect']['reason']
      E09.ck(c['name'], AtlasPca.allocations_monotone_error(c['caveats']), want)
    end
  end

  t('e09 vectors: the core plan_root_authorized check with authorizedPlanRoots / insecureSkipPlanRootCheck') do
    next true unless E09.gate?('atlas_pca.rb')

    rows = E09.read_vec('plan-root-vectors.json')['plan_root_authorized']
    raise "rows: #{rows.length}" unless rows.length >= 9

    rows.all? do |c|
      v = E09.vector(c['vector'])
      root = v['pcactn']['plan']['root']
      o = c['options']
      kw = { now: v['context']['now'], audience: v['context']['aud'], insecure_skip_plan_root_check: o['insecureSkipPlanRootCheck'] == true }
      kw[:authorized_plan_roots] = o['authorizedPlanRoots'].map { |x| x == '$plan_root' ? root : x } if o.key?('authorizedPlanRoots')
      r = AtlasPca.verify_pcactn(v['pcactn'], v['grant'], **kw)
      got = r.checks.key?('plan_root_authorized') ? (r.checks['plan_root_authorized'] ? 'pass' : 'fail') : 'not-enforced'
      E09.ck("#{c['name']} check", got, c['expect']['check']) && E09.ck("#{c['name']} allow", r.allow, c['expect']['allow']) &&
        (c['expect']['allow'] || E09.ck("#{c['name']} reason", r.reason, c['expect']['reason']))
    end
  end

  t('e09 vectors: server-side PQ pins (the pq_pin check of authorize)') do
    next true unless E09.gate?('authorize.rb', 'atlas_pca.rb')

    rows = E09.read_vec('pq-pin-vectors.json')['pq_pin']
    raise "rows: #{rows.length}" unless rows.length >= 8

    rows.all? do |c|
      v = E09.vector(c['vector'])
      g = v['grant']
      alg = g['alg'] || 'ed25519'
      next true unless AtlasPca.supported_suites.include?(alg) # a runtime without the suite cannot read the grant at all

      subst = lambda do |x|
        x = x.sub('$grant.issuer', g['issuer'].to_s).sub('$grant.pq_pk[0:20]', g['pq_pk'].to_s[0, 20]).sub('$grant.pq_pk', g['pq_pk'].to_s)
        x
      end
      pins = c['pq_pins'].nil? ? nil : c['pq_pins'].to_h { |k, x| [subst.call(k), x.is_a?(String) ? subst.call(x) : x] }
      pa = v['pcactn']['action']
      r = AtlasPca.authorize(v['pcactn'], operation: { 'verb' => pa['verb'], 'resource' => pa['resource'], 'params' => {} }, audience: v['context']['aud'],
                                          resolve_grant: ->(_ref) { g }, state_store: AtlasPca::MemoryStateStore.new, is_revoked: ->(_p, _g) { false },
                                          now: v['context']['now'], plan: 'single-step', pq_pins: pins)
      status = r.checks.key?('pq_pin') ? r.checks['pq_pin'] : 'absent'
      E09.ck("#{c['name']} check", status, c['expect']['check']) &&
        (c['expect']['reason'].nil? || E09.ck("#{c['name']} reason", r.reasons.include?(c['expect']['reason']), true))
    end
  end

  t('e09 vectors: authorize-pq-pin-fixtures.json end to end (a classical grant from a pinned issuer is refused)') do
    next true unless E09.gate?('authorize.rb', 'atlas_pca.rb')

    d = E09.read_vec('authorize-pq-pin-fixtures.json')
    raise 'format' unless d['format'] == 'pca-authorize-pq-pin-fixtures/1' && d['cases'].length >= 9
    ran = 0
    d['cases'].each do |c|
      alg = c['grant']['alg'] || 'ed25519'
      next unless AtlasPca.supported_suites.include?(alg) # a runtime without the suite cannot read the grant (the fixtures call for unsupported_suite)

      ran += 1
      op = d['operation']
      r = AtlasPca.authorize(c['pcactn'], operation: op, audience: d['audience'], resolve_grant: ->(_ref) { c['grant'] }, state_store: AtlasPca::MemoryStateStore.new,
                                          is_revoked: ->(_p, _g) { false }, now: d['now'], plan: 'single-step', risk: ProvHarness::RISK, pq_pins: c['pq_pins'])
      e = c['expect']
      failing = r.checks.select { |_k, v| v == 'fail' }.keys
      E09.ck("#{c['name']} allow", [r.allow, r.decision, r.status], [e['allow'], e['decision'], e['status']])
      E09.ck("#{c['name']} pq_pin", r.checks.key?('pq_pin') ? r.checks['pq_pin'] : 'absent', e['checks']['pq_pin'])
      E09.ck("#{c['name']} failed", (e['failed_includes'] - failing), [])
      E09.ck("#{c['name']} reason", r.reasons.any? { |x| x.include?(e['reason']) }, true) unless e['reason'].nil?
    end
    raise 'no case ran' if ran.zero?

    true
  end

  t('e09 core verify_pcactn: a classical root whose issuer is pinned is refused after the chain check (once, in authorize too)') do
    next true unless E09.gate?('atlas_pca.rb', 'authorize.rb')

    d = E09.read_vec('authorize-pq-pin-fixtures.json')
    c = d['cases'].find { |x| x['name'] == 'classical-grant-from-a-pinned-issuer-is-refused' } || raise('no case')
    msg = 'the grant issuer is pinned to a post-quantum key; a classical grant is refused'
    core = ->(pins) { AtlasPca.verify_pcactn(c['pcactn'], c['grant'], now: d['now'], audience: d['audience'], insecure_skip_plan_root_check: true, pq_pins: pins) }
    pinned = core.call(c['pq_pins'])
    E09.ck('refused', [pinned.allow, pinned.checks['pq_pin'], pinned.checks['chain'], pinned.reason], [false, false, true, "pq_pin: #{msg}"])
    other = core.call({ 'someone-else' => 'x' })
    E09.ck('an unrelated pin changes nothing', [other.allow, other.checks.key?('pq_pin')], [true, false])
    E09.ck('empty pins change nothing', [core.call({}).allow, core.call({}).checks.key?('pq_pin')], [true, false])
    E09.ck('no pins change nothing', [core.call(nil).allow, core.call(nil).checks.key?('pq_pin')], [true, false])
    r = AtlasPca.authorize(c['pcactn'], operation: d['operation'], audience: d['audience'], resolve_grant: ->(_ref) { c['grant'] }, state_store: AtlasPca::MemoryStateStore.new,
                                        is_revoked: ->(_p, _g) { false }, now: d['now'], plan: 'single-step', risk: ProvHarness::RISK, pq_pins: c['pq_pins'])
    E09.ck('authorize lists it once', [r.allow, r.status, r.reasons.count { |x| x.include?(msg) }], [false, 401, 1])
    true
  end

  t('e09 verify_chain: a leaf whose caveats member is missing, null, {}, "x" or 5 is refused (budget_alloc rule input), [] passes') do
    next true unless E09.gate?('atlas_pca.rb')

    pr = AtlasPca::KeyPair.new("\x41".b * 32)
    ho = AtlasPca::KeyPair.new("\x42".b * 32)
    body = { 'issuer' => pr.public, 'holder' => ho.public, 'parent' => nil } # hand-signed: no caveats member at all
    digest = AtlasPca.hash_canonical(body)
    missing = { 'id' => digest, 'issuer' => pr.public, 'holder' => ho.public, 'body_digest' => digest, 'sig' => AtlasPca.b64e(pr.sign(AtlasPca::CAP_DOMAIN + AtlasPca.b64d(digest, 32))) }
    bad = [['missing', missing]] + [nil, {}, 'x', 5].map { |c| [c.inspect, AtlasPca.mint_root(pr, ho.public, c)] }
    bad.each { |n, cap| E09.ck("#{n} refused", AtlasPca.verify_chain([cap], pr.public, true), ['hop 0: malformed capability', false]) }
    E09.ck('the [] control passes', AtlasPca.verify_chain([AtlasPca.mint_root(pr, ho.public, [])], pr.public, true), ['', true])
    # the rule itself, on the same inputs (a hop that reached it would be refused with exactly this reason)
    [nil, {}, 'x', 5].each { |c| E09.ck("rule #{c.inspect}", AtlasPca.allocations_monotone_error(c), 'malformed caveats') }
    true
  end

  t('e09 O3: BasicConstraints cA must be a DER BOOLEAN (0x00 or 0xFF)') do
    next true unless E09.gate?('der.rb', 'cert.rb')

    der = AtlasPca::Attest::Der
    mk = lambda do |byte|
      bc = OpenSSL::X509::Extension.new('2.5.29.19', ["30030101#{byte}"].pack('H*'), true)
      der.read_cert_role_info(C13.cert("O3 #{byte}", 'O3 root', [bc]).to_der)
    end
    E09.ck('0xff is a CA', mk.call('ff')['ca'], true) && E09.ck('0x00 is not', mk.call('00')['ca'], false) &&
      %w[01 80 fe].all? do |b|
        err = begin
          mk.call(b)
          nil
        rescue AtlasPca::Attest::DerError => e
          e.message
        end
        E09.ck("0x#{b}", err, 'BasicConstraints cA is not a DER BOOLEAN')
      end
  end
end
