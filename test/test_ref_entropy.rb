# frozen_string_literal: true

# Replays the TS-reference oracle of the entropy module (test-data/ref-entropy.json.gz, 562 cases): the QRNG sources, the SP 800-90B
# continuous health tests, the HKDF combiner, secure_seed and the Ed25519 key pair helper. Every fn of the corpus has a handler.
# Nothing here touches a network or needs the platform CSPRNG to be a given value: each case INJECTS
#   the source      {name?, kind: bytes (the value, whatever n is) | reject | throwSync (raise) | nonbytes (answers a non-string)}
#   the local CSPRNG {kind: fixed (the value, whatever n is) | throw | nonbytes}
#   the hook        none | collect | throw (records, then raises: must be swallowed)
#   the transport   {kind: json | text | jsonThrows | textThrows | throw | hang (never answers: cut off by the timeout) | none}
# and the result lists what was asked of them (requests, localRequested, the hook's arguments as {cls, message, code?}).
# A reference refusal is a native raise; its message is compared exactly when it starts with QRNG, HttpQrngSource, mixEntropy or
# secureSeed (the rest is JavaScript runtime text). Skipped, with a reason: the cases whose argument is a JavaScript type confusion
# a Ruby caller cannot produce (a text string where bytes are expected, a bare string raised instead of an error), and, when the
# Ada URL library is not available, the HTTP cases whose URL only Ada serialises (userinfo; they fail instead when PCA_ADA_REQUIRED
# is 1). The pure URL path is also checked on its own against every request URL of the corpus, whether Ada is there or not.
require_relative 'support/ref_oracle'
require 'bigdecimal/math'
require 'minitest/autorun'

class TestRefEntropy < Minitest::Test
  E = AtlasPca::Entropy
  BY_FN = Ref.load('entropy')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  EXACT = /\A(QRNG|HttpQrngSource|mixEntropy|secureSeed)/

  def self.dnum(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| dnum(x) }
    when Array then v.map { |x| dnum(x) }
    else v
    end
  end

  def self.bx(bytes) = { '$bytes' => Ref.b64e(bytes) }
  def self.sym(opts, map) = (opts || {}).each_with_object({}) { |(k, v), h| h[map.fetch(k)] = v }

  def self.cls(e)
    case e
    when E::EntropyError then 'EntropyError'
    when TypeError then 'TypeError'
    when RangeError then 'RangeError'
    else 'Error'
    end
  end

  def self.err_rec(e)
    rec = { 'cls' => cls(e), 'message' => e.message }
    rec['code'] = e.code if e.respond_to?(:code) && e.code.is_a?(String)
    rec
  end

  def self.thrown(e, extra = {}) = { '$throws' => e.message }.merge(err_rec(e).reject { |k, _| k == 'message' }).merge(extra)

  # equal as JSON values; a refusal whose reference message is JavaScript runtime text is compared without message and class
  def self.same?(got, out)
    return false unless got.is_a?(Hash) && got.key?('$throws') == out.key?('$throws')

    g = Ref.norm(got)
    o = out
    if o.key?('$throws') && !o['$throws'].match?(EXACT)
      g = g.reject { |k, _| %w[$throws cls].include?(k) }
      o = o.reject { |k, _| %w[$throws cls].include?(k) }
    end
    Ref.canon(g) == Ref.canon(o)
  end

  Source = Struct.new(:name, :spec, :log) do
    def fetch(n)
      log << n
      case spec['kind']
      when 'bytes' then spec['value']
      when 'reject', 'throwSync' then raise spec['message']
      when 'nonbytes' then :not_bytes
      else raise "bad source spec #{spec['kind']}"
      end
    end
  end

  def self.local(spec, log)
    lambda do |n|
      log << n
      case spec['kind']
      when 'fixed' then spec['value']
      when 'throw' then raise spec['message']
      else :nonbytes
      end
    end
  end

  SEED_OPTS = { 'length' => :length, 'quantumBytes' => :quantum_bytes, 'localBytes' => :local_bytes, 'context' => :context,
                'requireQuantum' => :require_quantum, 'healthTest' => :health_test }.freeze

  def self.seed_run(opts, keypair)
    reqs = []
    locals = []
    errs = []
    kw = sym(opts.slice(*SEED_OPTS.keys), SEED_OPTS)
    kw[:source] = Source.new(opts['source']['name'] || 'test-src', opts['source'], reqs) if opts['source']
    kw[:random_bytes] = local(opts['local'], locals) if opts['local']
    hook = opts['hook'] || 'none'
    unless hook == 'none'
      kw[:on_qrng_error] = lambda do |e|
        errs << err_rec(e)
        raise 'hook boom' if hook == 'throw'
      end
    end
    seen = -> { { 'qrngErrors' => errs, 'localRequested' => locals[0], 'requests' => reqs } }
    begin
      if keypair
        r = E.generate_key_pair_with_entropy(**kw)
        { 'publicKey' => bx(r.public_key), 'secretKeySha256' => Digest::SHA256.hexdigest(r.secret_key), 'usedQuantum' => r.used_quantum }.merge(seen.call)
      else
        r = E.secure_seed(**kw)
        { 'seed' => bx(r.seed), 'usedQuantum' => r.used_quantum, 'quantumByteCount' => r.quantum_byte_count, 'source' => r.source }.merge(seen.call)
      end
    rescue StandardError => e
      thrown(e, seen.call)
    end
  end

  Response = Struct.new(:ok, :status, :json_fn, :text_fn) do
    def json = json_fn.call
    def text = text_fn.call
  end

  def self.transport(spec, log)
    lambda do |url, headers:, redirect:, timeout_ms:|
      log << { 'url' => url, 'headers' => headers, 'redirect' => redirect, 'signal' => !timeout_ms.nil? }
      status = spec['status'] || 200
      ok = spec['ok'].nil? ? (200..299).cover?(status) : spec['ok']
      case spec['kind']
      when 'json' then Response.new(ok, status, -> { spec['body'] }, -> { raise 'text unused' })
      when 'text' then Response.new(ok, status, -> { raise 'json unused' }, -> { spec['text'] })
      when 'jsonThrows' then Response.new(ok, status, -> { raise 'bad json' }, -> { '' })
      when 'textThrows' then Response.new(ok, status, -> { {} }, -> { raise 'read failed' })
      when 'throw' then raise spec['message']
      when 'hang' then sleep
      else raise "bad transport spec #{spec['kind']}"
      end
    end
  end

  HTTP_OPTS = { 'url' => :url, 'apiKey' => :api_key, 'apiKeyHeader' => :api_key_header, 'format' => :format, 'timeoutMs' => :timeout_ms,
                'maxBytes' => :max_bytes, 'lengthParam' => :length_param, 'extraParams' => :extra_params,
                'allowInsecureLoopback' => :allow_insecure_loopback }.freeze

  def self.http_run(cfg, n, tr)
    log = []
    kw = sym(cfg.slice(*HTTP_OPTS.keys), HTTP_OPTS)
    kw[:url] = nil unless kw.key?(:url)
    kw[:build_url] = ->(base, k) { "#{base}/#{k}#{cfg['buildUrl']['suffix']}" } if cfg['buildUrl']
    kw[:transport] = transport(tr, log) unless tr['kind'] == 'none'
    src = begin
      E::HttpQrngSource.new(**kw)
    rescue StandardError => e
      return thrown(e)
    end
    begin
      { 'name' => src.name, 'bytes' => bx(src.fetch(n)), 'requests' => log }
    rescue StandardError => e
      key = cfg['apiKey']
      thrown(e, 'name' => src.name, 'requests' => log, 'leaksKey' => key.is_a?(String) && !key.empty? && e.message.include?(key))
    end
  end

  def self.unavailable(src, n)
    src.fetch(n)
    { 'name' => src.name, 'ok' => true }
  rescue StandardError => e
    { 'name' => src.name, '$throws' => e.message }
  end

  CONSTANTS = %w[MAX_HKDF_OUTPUT MIN_LOCAL_BYTES DEFAULT_SEED_BYTES DEFAULT_MAX_QRNG_BYTES DEFAULT_TIMEOUT_MS].freeze
  HEALTH = { 'h' => :h, 'window' => :window }.freeze
  MIX = { 'length' => :length, 'context' => :context }.freeze

  # fn => handler; a handler that answers a Hash with its own "$throws" is compared with same?
  HANDLERS = {
    'constants' => -> { CONSTANTS.to_h { |n| [n, E.const_get(n)] } },
    'repetitionCutoff' => ->(h) { E.repetition_cutoff(h) },
    'proportionCutoff' => ->(h, w) { E.proportion_cutoff(h, w) },
    'healthTestBytes' => ->(bytes, opts = nil) { E.health_test_bytes(bytes, **sym(opts, HEALTH)) },
    'parseAnuUint8' => ->(json) { bx(E.parse_anu_uint8(json)) },
    'parseHex' => ->(text) { bx(E.parse_hex(text)) },
    'parseBase64' => ->(text) { bx(E.parse_base64(text)) },
    'mixEntropy' => ->(local, quantum, opts = nil) { bx(E.mix_entropy(local, quantum, **sym(opts, MIX))) },
    'secureSeed' => ->(opts) { seed_run(opts, false) },
    'generateKeyPairWithEntropy' => ->(opts) { seed_run(opts, true) },
    'httpQrng' => ->(cfg, n, tr) { http_run(cfg, n, tr) },
    'nullQrng' => ->(reason, n) { unavailable(reason.nil? ? E::NullQrngSource.new : E::NullQrngSource.new(reason), n) },
    'unavailableSource' => ->(reason, n) { unavailable(reason.nil? ? E.unavailable_source : E.unavailable_source(reason), n) },
    'entropyError' => lambda do |code, message|
      e = E::EntropyError.new(code, message)
      { 'name' => e.name, 'code' => e.code, 'message' => e.message, 'isError' => e.is_a?(StandardError) }
    end
  }.freeze
  OWN_REFUSAL = %w[secureSeed generateKeyPairWithEntropy httpQrng nullQrng unavailableSource].freeze

  # a JSON text string where the reference takes bytes: a Ruby String is bytes, so the type confusion cannot be expressed
  def self.text_for_bytes?(c)
    case c['fn']
    when 'mixEntropy' then c['args'][0, 2].any? { |a| a.is_a?(String) }
    when 'healthTestBytes' then c['args'][0].is_a?(String)
    else false
    end
  end

  # JSON null where the reference tells null from undefined (a Ruby nil is both: the omitted option)
  def self.null_not_undefined?(c)
    %w[healthTestBytes/null-opts mixEntropy/ctx-null].include?(c['name'])
  end

  # a bare string raised instead of an error
  def self.bare_string?(c)
    (c['fn'] == 'httpQrng' && c['args'][2]['kind'] == 'throwString') ||
      (%w[secureSeed generateKeyPairWithEntropy].include?(c['fn']) && c['args'][0]['source'].is_a?(Hash) && c['args'][0]['source']['kind'] == 'rejectString')
  end

  # an HTTP case that builds its request URL through the Ada URL library
  def self.builds_url?(c)
    c['fn'] == 'httpQrng' && !c['args'][0].key?('buildUrl') && c['args'][2]['kind'] != 'none' && c['out'].key?('name') &&
      c['args'][0]['url'].to_s.include?('@')
  end

  # the pure serialiser gives the reference's URL for every request of the corpus, or refuses (only the userinfo shape)
  def test_pure_url_path_matches_every_request_url_of_the_corpus
    made = 0
    refused = []
    BY_FN.fetch('httpQrng').each do |c|
      cfg = c['args'][0]
      want = c['out']['requests']&.first&.fetch('url')
      next if cfg.key?('buildUrl') || want.nil?

      pairs = [[cfg['lengthParam'] || 'length', c['args'][1].to_s], *(cfg['extraParams'] || {}).to_a]
      begin
        assert_equal want, E::Url.pure_with_params(cfg['url'], pairs), c['name']
        made += 1
      rescue ArgumentError
        refused << c['name']
      end
    end
    assert_equal 60, made
    assert_equal ['httpQrng/ok-userinfo'], refused
    assert_raises(TypeError) { E::Url.pure_with_params('not a url', []) }
    assert_raises(TypeError) { E::Url.pure_with_params('/api', []) }
    assert_raises(TypeError) { E::Url.pure_with_params(nil, []) }
  end

  def test_fdlibm_pow
    f = AtlasPca::FdLibm
    assert_equal [1.0, 0.00390625, 1024.0, 0.125, 9.0, 3.0, 0.5, 2.0], [f.pow(7.0, 0), f.pow(2.0, -8), f.pow(2, 10), f.pow(0.5, 3), f.pow(-3.0, 2), f.pow(9.0, 0.5), f.pow(2.0, -1), f.pow(2.0, 1)]
    assert_equal [-8.0, Float::INFINITY, 0.0, 0.0, Float::INFINITY, 1.0], [f.pow(-2.0, 3), f.pow(2.0, 2000), f.pow(2.0, -2000), f.pow(0.5, Float::INFINITY), f.pow(0.0, -1), f.pow(1.0, 1e300)]
    [f.pow(Float::NAN, 1), f.pow(2.0, Float::NAN), f.pow(1.0, Float::INFINITY), f.pow(-1.0, -Float::INFINITY), f.pow(-8.0, 1.0 / 3), f.pow(-4.0, 0.5)].each { |v| assert v.nan? }
    assert_equal 9.5367431640625e-07, f.pow(2.0, -20)
    assert_equal 4.9e-324, f.pow(2.0, -1074)
    # within one unit in the last place of the exactly rounded value (a platform pow is not always that accurate: mingw's is off by 1e-13 here)
    [[0.99609375, 512], [0.9375, 64], [0.5, 100], [1.5, 2.5], [10.0, -3], [0.7071067811865476, 1024], [3.0, 40], [1.0000001, 1e7]].each do |x, y|
      mine = f.pow(x, y)
      theirs = BigMath.exp(BigDecimal(y.to_r, 60) * BigMath.log(BigDecimal(x.to_r, 60), 60), 60).to_f
      assert_operator (mine - theirs).abs, :<=, [theirs.abs * Float::EPSILON, Float::MIN].max, "pow(#{x}, #{y})"
    end
  end

  def test_every_fn_of_the_corpus_has_a_handler
    assert_empty BY_FN.keys - HANDLERS.keys
    assert_empty HANDLERS.keys - BY_FN.keys
    assert_equal 562, BY_FN.values.sum(&:length)
  end

  def test_the_skipped_cases_are_the_few_a_ruby_caller_cannot_express
    all = BY_FN.values.flatten(1)
    assert_operator all.count { |c| self.class.text_for_bytes?(c) }, :<=, 6
    assert_operator all.count { |c| self.class.bare_string?(c) }, :<=, 4
    assert_equal 2, all.count { |c| self.class.null_not_undefined?(c) }
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      ada = E::Url.available?
      flunk 'the Ada URL library is required here (PCA_ADA_REQUIRED) and is not available' if fn == 'httpQrng' && !ada && ENV['PCA_ADA_REQUIRED'] == '1'
      k = self.class
      skip_case = ->(c) { k.text_for_bytes?(c) || k.bare_string?(c) || k.null_not_undefined?(c) || (!ada && k.builds_url?(c)) }
      call = ->(*args) { handler.call(*args.map { |a| k.dnum(a) }) }
      if OWN_REFUSAL.include?(fn)
        Ref.run(self, BY_FN.fetch(fn), call, skip: skip_case, compare: ->(got, out, _c) { k.same?(got, out) }, refused: ->(got, c) { k.same?(got, c['out']) })
      else
        Ref.run(self, BY_FN.fetch(fn), call, skip: skip_case)
      end
    end
  end

  # ---- without injected randomness ------------------------------------------------------------------------------------

  def test_secure_seed_from_the_platform_csprng
    r = E.secure_seed
    assert_equal [32, false, 0, nil], [r.seed.bytesize, r.used_quantum, r.quantum_byte_count, r.source]
    refute_equal r.seed, E.secure_seed.seed
    assert_equal 64, E.secure_seed(length: 64).seed.bytesize
    seen = []
    fallback = E.secure_seed(source: E.unavailable_source('offline'), on_qrng_error: ->(e) { seen << e.message })
    assert_equal [false, 0, 'null-qrng'], [fallback.used_quantum, fallback.quantum_byte_count, fallback.source]
    assert_equal ['QRNG unavailable: offline'], seen
    e = assert_raises(E::EntropyError) { E.secure_seed(source: E::NullQrngSource.new, require_quantum: true) }
    assert_equal 'quantum_required', e.code
    e = assert_raises(E::EntropyError) { E.secure_seed(require_quantum: true) }
    assert_equal 'quantum_required', e.code
  end

  def test_generated_key_pair_is_the_ed25519_key_of_the_seed
    kp = E.generate_key_pair_with_entropy
    assert_equal [32, 32, false], [kp.secret_key.bytesize, kp.public_key.bytesize, kp.used_quantum]
    assert_equal AtlasPca::KeyPair.new(kp.secret_key).public, AtlasPca.b64e(kp.public_key)
  end

  def test_the_http_source_never_prints_its_key
    src = E::HttpQrngSource.new(url: 'https://qrng.example/api', api_key: 'sekret-1', build_url: ->(base, n) { "#{base}/#{n}" })
    assert_equal 'http-qrng(qrng.example)', src.name
    refute_includes src.inspect, 'sekret-1'
  end
end
