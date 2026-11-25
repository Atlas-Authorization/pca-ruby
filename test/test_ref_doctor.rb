# frozen_string_literal: true

# Replays the TS-reference oracle of the deployment doctor (scrubbing, the clock / proxy / suites / root-caveat / enforcement
# checks, result formatting, configuration, the CLI and the full run; test-data/ref-doctor.json.gz). Network, clock and the
# deployed library are replayed from the named fakes the reference used.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/doctor'
require 'minitest/autorun'

class TestRefDoctor < Minitest::Test
  D = AtlasPca::Doctor
  CE = AtlasPca::ControlEvals
  CASES = Ref.load('doctor')
  URL1 = 'https://api.example.com'

  class Resp
    def initialize(rsp) = @rsp = rsp
    def status = 200
    def headers = self

    def get(name)
      case name
      when 'date' then @rsp['date']
      when 'ratelimit-remaining' then @rsp['rl']
      end
    end

    def read = ''
  end

  # A fake network and clock: every fetch pops the next entry of its url (the last one repeats), advances the clock by `rtt`
  # BEFORE answering and raises when the entry says so.
  class Env
    attr_reader :t

    def initialize(spec)
      @t = spec['now']
      @spec = spec
      @idx = {}
    end

    def now = -> { @t }

    def fetch
      lambda do |url, method: 'GET', headers: nil, timeout_ms: nil| # rubocop:disable Lint/UnusedBlockArgument
        lst = @spec['responses'][url]
        raise "no route #{url}" if lst.nil?

        i = @idx.fetch(url, 0)
        @idx[url] = i + 1
        rsp = lst[[i, lst.length - 1].min]
        @t += rsp['rtt'] || 0
        raise rsp['throw'] if D.truthy?(rsp['throw'])

        Resp.new(rsp)
      end
    end
  end

  # The reference's named fake library: it decides a payment under the root caveat the way each behaviour says.
  def self.fake_pca(spec)
    behavior = spec['behavior']
    lambda do |cav, amount|
      raise 'boom' if behavior == 'throws'
      next({ 'allowed' => true, 'reasons' => [] }) if behavior == 'allow-all'
      next({ 'allowed' => false, 'reasons' => ['denied', 7] }) if behavior == 'deny-all'
      next({ 'allowed' => false, 'reasons' => 'x' }) if behavior == 'nonarray-reasons'

      if cav['type'] == 'max_spend'
        next({ 'allowed' => true, 'reasons' => [] }) if behavior == 'ignore-max'

        next amount <= cav['usd'] ? { 'allowed' => true, 'reasons' => [] } : { 'allowed' => false, 'reasons' => ['over max_spend'] }
      end
      next({ 'allowed' => true, 'reasons' => [] }) if behavior == 'ignore-unknown'

      { 'allowed' => false, 'reasons' => ['unknown caveat type'] }
    end
  end

  def self.loader(spec)
    lambda do |_dir|
      raise spec['throws'] if spec['throws']

      D::LoadedPca.new(spec['version'], spec['path'], fake_pca(spec))
    end
  end

  def self.consts
    { 'USAGE' => D::USAGE, 'CHECK_GROUPS' => D::CHECK_GROUPS, 'DEFAULT_REQUIRED' => D::DEFAULT_REQUIRED,
      'ROOT_CAVEAT_MIN_VERSION' => D::ROOT_CAVEAT_MIN_VERSION, 'DEFAULT_REFERENCE_URL' => D::DEFAULT_REFERENCE_URL,
      'SUITES_REMEDIATION' => D::SUITES_REMEDIATION, 'PQ_REMEDIATION' => D::PQ_REMEDIATION, 'CLOCK_REMEDIATION' => D::CLOCK_REMEDIATION,
      'PROXY_REMEDIATION' => D::PROXY_REMEDIATION, 'ATOMICITY_REMEDIATION' => D::ATOMICITY_REMEDIATION,
      'DURABILITY_REMEDIATION' => D::DURABILITY_REMEDIATION, 'CAVEAT_REMEDIATION' => D::CAVEAT_REMEDIATION }
  end

  def self.cli(argv, env)
    out = []
    err = []
    code = D.main(argv, env, ->(s) { out << s }, ->(s) { err << s })
    { 'code' => code, 'out' => out, 'err' => err }
  end

  def self.run_doctor(cfg, only, spec, caveat)
    e = Env.new(spec)
    D.run_doctor(cfg, only, fetch: e.fetch, now: e.now, load: loader(caveat))
  end

  MAP = {
    'consts' => -> { consts },
    'scrubText' => ->(t) { D.scrub_text(t) },
    'scrubDeep' => ->(v) { D.scrub_deep(v) },
    'checkAllowedSuites' => ->(c) { D.check_allowed_suites(c) },
    'checkPqBinding' => ->(c) { D.check_pq_binding(c) },
    'checkProxyConfig' => ->(c) { D.check_proxy_config(c) },
    'testNetIp' => ->(seed) { D.test_net_ip(CE.mulberry32(seed)) },
    'forgedHeaders' => ->(seed) { D.forged_headers(CE.mulberry32(seed)) },
    'checkClock' => ->(cfg, spec) { e = Env.new(spec); D.check_clock(cfg, e.fetch, e.now) },
    'readDate' => ->(_u, spec) { e = Env.new(spec); D.read_date(URL1, e.fetch, e.now, 1000) },
    'checkProxyProbe' => ->(cfg, spec) { D.check_proxy_probe(cfg, Env.new(spec).fetch, CE.mulberry32(7)) },
    'compareVersion' => ->(a, b) { D.compare_version(a, b) },
    'checkRootCaveats' => ->(cfg, spec) { D.check_root_caveats(cfg, loader(spec)) },
    'checkEnforcement' => ->(c) { D.check_enforcement(c) },
    'configProblems' => ->(c) { D.config_problems(c) },
    'verdictOf' => ->(*a) { D.verdict_of(*a) },
    'formatResults' => ->(rs, target, strict) { D.format_results(rs, target, strict) },
    'configFromEnv' => ->(e) { D.config_from_env(e) },
    'mergeConfig' => ->(*a) { D.merge_config(*a) },
    'parseDoctorArgs' => ->(a) { D.parse_doctor_args(a) },
    'main' => ->(argv, env) { cli(argv, env) },
    'runDoctor' => ->(cfg, only, spec, caveat) { run_doctor(cfg, only, spec, caveat) }
  }.freeze

  # lone-surrogate safe canonical comparison
  CMP = ->(g, o, _c) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(g))) == AtlasPca::Js.json(Ref.sort_keys(Ref.norm(o))) }

  def test_corpus_is_the_full_oracle
    assert_equal [], CASES.keys - MAP.keys
    assert_equal [], MAP.keys - CASES.keys
  end

  MAP.each do |fn, call|
    define_method("test_matches_the_reference_#{fn}") { Ref.run(self, CASES[fn], call, compare: CMP) }
  end

  def test_runtime_check_reports_the_registered_suites
    r = D.check_runtime({ 'verifier' => { 'allowedSuites' => ['ed25519'] } })
    assert_equal 'suites.runtime', r['id']
    assert_equal 'pass', r['status']
    assert_includes r['observed']['available'], 'ed25519'
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  # a skew limit or warning fraction that is not a number never reads as a passing clock
  def test_a_non_numeric_clock_limit_never_passes
    now = Time.utc(2026, 11, 21, 12).to_f * 1000
    spec = { 'now' => now, 'responses' => { URL1 => [{ 'date' => 'Sat, 21 Nov 2026 12:00:00 GMT' }] } }
    ok = D.check_clock({ 'url' => URL1, 'clock' => { 'referenceUrl' => 'local' } }, Env.new(spec).fetch, Env.new(spec).now)
    assert_equal 'pass', ok['status']
    [Float::NAN, 'x'].each do |bad|
      [{ 'maxSkewMs' => bad }, { 'warnFraction' => bad }].each do |c|
        r = D.check_clock({ 'url' => URL1, 'clock' => c.merge('referenceUrl' => 'local') }, Env.new(spec).fetch, Env.new(spec).now)
        refute_equal 'pass', r['status'], c.inspect
      end
    end
  end

  def test_the_corpus_total_is_pinned
    assert_equal 1597, CASES.values.sum(&:length), 'doctor'
  end

end
