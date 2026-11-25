# frozen_string_literal: true

# Replays the TS-reference oracle of the sandbox policy logic (test-data/ref-sandbox.json.gz): policy compile, OS profile
# generators, runtime-claim signing / verification, receipt hash chains, the capability handle table, the egress admission policy,
# the private-address check and the reference tools.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/sandbox'
require 'minitest/autorun'
require 'digest'

class TestRefSandbox < Minitest::Test
  S = AtlasPca::Sandbox
  BY_FN = Ref.load('sandbox')

  def self.seed(label) = Digest::SHA256.digest("atlas-pca-conformance/#{label}")

  def self.res(allow, bind)
    r = { 'allow' => allow }
    if bind
      r['operation'] = { 'verb' => bind['verb'], 'resource' => bind['resource'], 'params_digest' => AtlasPca.hash_canonical(bind['params']),
                         'id' => bind['id'].nil? ? 'op' : bind['id'] }
    end
    r
  end

  def self.receipt_log(spec)
    t = 0
    log = S::ReceiptLog.new(now: -> { t }, sign: spec['sign'] ? ->(d) { "sig:#{d}" } : nil)
    spec['appends'].map do |a|
      t = a['t']
      log.append(a['rc'], a['body'])
    rescue StandardError
      { '$err' => true }
    end
  end

  def self.compile(spec)
    items = spec['items'].map { |it| { 'result' => res(it['allow'], it['bind']), 'operation' => it['operation'] } }
    S.compile_policy(items, ->(op) { spec['needs']["#{op['verb']} #{op['resource']}"] }, spec['proxyPort'])
  end

  def self.sign_rc(key, pub, c)
    sk = key.is_a?(String) ? seed(key) : "\0".b * key['short']
    pk = AtlasPca.b64d(AtlasPca::KeyPair.new(seed(pub.is_a?(String) ? pub : 'x')).public)
    S.sign_runtime_claim(sk, pk, c)
  end

  def self.egress(spec)
    t = 0
    p = S::EgressPolicy.new(-> { t })
    spec['steps'].map do |st|
      case st['op']
      when 'now'
        t = st['t']
        nil
      when 'admit'
        p.admit(res(st['allow'], st['bind']), st['operation'], ->(_op) { st['template'] }, Ref.snake(st['opts'] || {}))
        'ok'
      else
        req = { 'method' => st['req']['method'] }
        req['url'] = st['req']['url'] if st['req'].key?('url')
        req['body'] = st['req']['body'] if st['req'].key?('body')
        p.claim(req)
      end
    rescue StandardError
      { '$err' => true }
    end
  end

  EXEC = {
    'fs.read' => ->(_op) { [1, 2, 3].pack('C*') },
    'fs.echo' => ->(op) { AtlasPca::Js.json(op).b },
    'fs.throw' => ->(_op) { raise 'boom' },
    'fs.notbytes' => ->(_op) { 'nope' }
  }.freeze

  def self.handles(spec)
    t = 0
    log = S::ReceiptLog.new(now: -> { t })
    table = S::HandleTable.new(spec['cls'], log, EXEC, -> { t })
    outs = spec['steps'].map do |st|
      case st['op']
      when 'now'
        t = st['t']
        nil
      when 'mint'
        bind = st.key?('bind') ? st['bind'] : st['operation'].merge('id' => st.fetch('id', 'op-h'))
        table.mint(res(st.fetch('allow', true), bind), st['operation'], Ref.snake(st['opts'] || {}))
      when 'attenuate' then table.attenuate(st['index'], Ref.snake(st['narrower'] || {}))
      when 'revoke'
        table.revoke(st['index'])
        nil
      when 'use' then table.use(st['index'])
      when 'verbOf' then table.verb_of(st['index'])
      when 'size' then table.size
      end
    rescue StandardError
      { '$err' => true }
    end
    { 'outs' => outs, 'log' => log.entries }
  end

  CONSTS = lambda do
    { 'IMPORT_MODULE' => S::IMPORT_MODULE, 'ALLOWED_IMPORTS' => S::ALLOWED_IMPORTS, 'USE_ERR' => S::USE_ERR, 'GENESIS' => S::GENESIS,
      'RUNTIME_CLASSES' => S::RUNTIME_CLASSES, 'DOMAIN' => S::RUNTIME_CLAIM_DOMAIN }
  end

  MAP = {
    'moduleConsts' => CONSTS,
    'satisfiesRuntimeClass' => ->(a, r) { S.satisfies_runtime_class(a, r) },
    'receiptLog' => ->(spec) { receipt_log(spec) },
    'verifyReceiptChain' => ->(rs, mode) { S.verify_receipt_chain(rs, mode == 'tag' ? ->(d, s) { s == "sig:#{d}" } : nil) },
    'policyFromNeeds' => ->(needs, port = nil) { S.policy_from_needs(needs, port) },
    'compilePolicy' => ->(spec) { compile(spec) },
    'seccompProfile' => ->(p) { S.seccomp_profile(p) },
    'landlockRuleset' => ->(p) { S.landlock_ruleset(p) },
    'macosProfile' => ->(p) { S.macos_profile(p) },
    'confineArgs' => ->(p) { S.confine_args(p) },
    'isPrivateAddress' => ->(ip) { S.private_address?(ip) },
    'egress' => ->(spec) { egress(spec) },
    'handles' => ->(spec) { handles(spec) },
    'signRuntimeClaim' => ->(k, p, c) { sign_rc(k, p, c) },
    'verifiedRuntimeClass' => ->(c, t) { S.verified_runtime_class(c, t) },
    'passportDigest' => ->(sp) { S.passport_digest(sp) },
    'evidenceDigest' => ->(d) { S.evidence_digest(d) },
    'buildTool' => ->(spec) { S.build_tool(Ref.snake(spec)) },
    'buildProbeTool' => ->(cap = 64) { S.build_probe_tool(cap) },
    'referenceComponentWat' => ->(o = nil) { S.reference_component_wat(o.nil? ? nil : Ref.snake(o)) }
  }.freeze

  # bytes (binary Strings) are the oracle's {"$bytes"}
  def self.tag(v)
    case v
    when Hash then v.transform_values { |x| tag(x) }
    when Array then v.map { |x| tag(x) }
    when String then v.encoding == Encoding::BINARY ? { '$bytes' => Ref.b64e(v) } : v
    else v
    end
  end

  # These vectors predate the address check that classifies the parsed address: they read these loopback / unspecified / v4-mapped /
  # zoned / reserved (outside 2000::/3) spellings as public, and a non-string as a throw. The native check, like the current
  # reference, calls all of them private.
  STRICTER_PRIVATE = %w[0:0:0:0:0:0:0:1 0:0:0:0:0:0:0:0 ::ffff:7f00:1 ::ffff:0:0 ::1%eth0 ::127.0.0.1 ::ffff:1.2.3.4%x ::2 fec0::1
                        1:2:3:4:5:6:7:8 1:2:3:4:5:6:1.2.3.4 f::].freeze

  CMP = lambda do |got, out, c|
    if c['fn'] == 'isPrivateAddress' && c['args'][0].is_a?(String) && STRICTER_PRIVATE.include?(c['args'][0])
      out == false && got == true
    else
      Ref.canon(tag(got)) == Ref.canon(out)
    end
  end

  REFUSED = ->(got, c) { c['fn'] == 'isPrivateAddress' && !c['args'][0].is_a?(String) && got == true }

  def test_corpus_is_the_full_oracle
    assert_equal [], BY_FN.keys - MAP.keys
    assert_equal [], MAP.keys - BY_FN.keys
  end

  def test_stricter_private_set_is_exactly_the_reference_misses
    misses = BY_FN['isPrivateAddress'].select { |c| c['out'] == false && S.private_address?(c['args'][0]) }.map { |c| c['args'][0] }
    assert_equal STRICTER_PRIVATE.sort, misses.uniq.sort
  end

  MAP.each_key do |fn|
    define_method("test_matches_the_reference_#{fn}") do
      Ref.run(self, BY_FN[fn], MAP[fn], compare: CMP, refused: REFUSED)
    end
  end

  # Negative times and empty or over-long digests are none even when correctly signed and trusted.
  def test_runtime_claim_strict_form
    sk = self.class.seed('strict-attestor')
    pub = AtlasPca.b64d(AtlasPca::KeyPair.new(sk).public)
    run_one = lambda do |over, t_over|
      c = S.sign_runtime_claim(sk, pub, { 'class' => 'os_confined', 'passport_digest' => 'pd', 'evidence_digest' => 'ev', 'iat' => 0, 'exp' => 100 }.merge(over))
      t = { 'pinnedAttestors' => [c['attestor']], 'passportDigest' => c['passport_digest'], 'verifiedEvidenceDigests' => [c['evidence_digest']],
            'now' => 50 }.merge(t_over)
      S.verified_runtime_class(c, t)
    end
    assert_equal 'os_confined', run_one.call({}, {})
    [[{ 'iat' => -5 }, {}], [{ 'iat' => -10, 'exp' => -1 }, { 'now' => -5 }], [{ 'iat' => -10 }, { 'now' => -1 }],
     [{ 'evidence_digest' => '' }, {}], [{ 'passport_digest' => '' }, {}], [{ 'evidence_digest' => 'd' * 129 }, {}],
     [{ 'passport_digest' => 'd' * 129 }, {}], [{}, { 'now' => 2**53 }]].each do |over, t_over|
      assert_equal 'none', run_one.call(over, t_over), [over, t_over].inspect
    end
    assert_equal 'os_confined', run_one.call({ 'evidence_digest' => 'd' * 128, 'passport_digest' => 'p' * 128 }, {})
  end

  def test_private_address_classifies_the_parsed_address
    ['0:0:0:0:0:0:0:1', '0::1', '::ffff:7f00:1', '::FFFF:7F00:0001', '::127.0.0.1', '::7f00:1', '64:ff9b::7f00:1', '64:ff9b::10.0.0.1',
     '::1%eth0', 'fe80::1%25eth0', '2606:4700::1111%eth0', 'FE80::1', 'fc::1', 'fec0::1', '1fff::1', '4000::1', '1::2::3', '::00001',
     '::01.2.3.4', '[::1]', ' ::1', nil, 1].each { |ip| assert S.private_address?(ip), ip.inspect }
    ['2606:4700:0:0:0:0:0:1111', '2001:DB8::1', '::ffff:808:808', '::ffff:8.8.8.8', '64:ff9b::8.8.8.8', '2000::', '3fff::1', '8.8.8.8'].each do |ip|
      refute S.private_address?(ip), ip
    end
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1604, BY_FN.values.sum(&:length), 'sandbox'
  end

end
