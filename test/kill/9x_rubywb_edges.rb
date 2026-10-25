# frozen_string_literal: true
require 'stringio'
require 'tmpdir'
require 'fileutils'
require 'fiddle'
# r11 kills for rack_middleware.rb, intent_layers.rb and less_ffi.rb (survivors of mutation run 39902549441):
#  - rack: a PCActn minted HERE with iat/exp around the wall clock (the corpus vectors are all in the past, so the wall-clock
#    default of `now:` and current_now's arithmetic were never observable), the default kwargs, the intent_policy hand-off, a
#    binary / frozen request body (Rack's rack.input is binary), forbidden's fallback reason, a non-String audience;
#  - layers: exact reasons of malformed vs outside-ceiling layers, a Hash with a default value (an absent member is absent),
#    a non-Array `denied` / `task` that would iterate as empty, and the fail-closed rescue of both entry points;
#  - LESS: verify's rescue on a non-String key, Fiddle missing (LoadError), and a library named by a bare soname that is not
#    a file (the loader opens only real files, never through the dynamic loader's search / already-loaded list).
# Names start with `rubywb` (MUT_QUICK). AtlasPca is resolved at CALL time (the oracle replaces the module per mutant).
module MutationKill
  module RubyWb
    module_function

    def ed(label) = OpenSSL::PKey.new_raw_private_key('ED25519', Digest::SHA256.digest("ruby-kill-wb/#{label}"))
    def pub(k) = AtlasPca.b64e(k.raw_public_key)
    def wire(x) = AtlasPca.parse_json(AtlasPca.canonicalize(x))

    def sign_hop(body, key)
      d = AtlasPca.hash_canonical(body)
      sig = key.sign(nil, AtlasPca::CAP_DOMAIN + AtlasPca.b64d(d, 32))
      body.reject { |k, v| k == 'parent' && v.nil? }.merge('id' => d, 'body_digest' => d, 'sig' => AtlasPca.b64e(sig))
    end

    VEC = Corpus.core['vectors'].find do |v|
      v['expect']['allow'] == true && (v['requires'].nil? || v['requires'].empty?) && v['pcactn'].is_a?(Hash) &&
        !v['pcactn'].key?('intent') && !v['pcactn'].key?('intent_session') && !v['pcactn'].key?('threshold')
    end

    # [pcactn, grant] valid at the wall clock: principal -> agent (root) -> leaf, the corpus vector's action / plan
    def fresh(t = (Time.now.to_f * 1000).to_i)
      p, a, l = ed('principal'), ed('agent'), ed('leaf')
      root = sign_hop({ 'issuer' => pub(p), 'holder' => pub(a), 'caveats' => [], 'parent' => nil }, p)
      hop = sign_hop({ 'issuer' => pub(a), 'holder' => pub(l), 'caveats' => [], 'parent' => AtlasPca.cap_hash(root) }, a)
      x = Marshal.load(Marshal.dump(VEC['pcactn'])).reject { |k, _| %w[alg pq_pk pq_sig].include?(k) }
      x['cap_chain'] = [root, hop]
      x['grant_ref'] = root['id']
      x['iat'] = t - 60_000
      x['exp'] = t + 240_000
      x['sig'] = AtlasPca.b64e(l.sign(nil, AtlasPca.threshold_message(x)))
      [wire(x), wire(root)]
    end

    def mw = AtlasPca::RackMiddleware

    def rack
      pa, grant = fresh
      aud = pa['aud']
      res = ->(r) { r == pa['grant_ref'] ? grant : nil }
      hdr = AtlasPca.b64e(AtlasPca.canon_bytes(pa))
      app = ->(_env) { [200, {}, ['ok']] }
      env = ->(h = hdr) { { 'HTTP_PCA_ACTION' => h, 'rack.input' => StringIO.new('') } }
      # sanity: the minted PCActn verifies at the wall clock
      v = AtlasPca.verify_pcactn(pa, grant, now: (Time.now.to_f * 1000).to_i, audience: aud)
      return "minted pcactn denied: #{v.reason}" unless v.allow == true
      # every optional kwarg left at its default (now: wall clock, no intent policy, no intent_v2)
      return 'defaults' unless mw.new(app, audience: aud, resolve_grant: res).call(env.call)[0] == 200
      return 'now: nil' unless mw.new(app, audience: aud, resolve_grant: res, now: nil).call(env.call)[0] == 200
      return 'now: -> nil' unless mw.new(app, audience: aud, resolve_grant: res, now: -> {}).call(env.call)[0] == 200
      m = mw.new(app, audience: aud, resolve_grant: res)
      t0 = (Time.now.to_f * 1000).to_i
      n = m.send(:current_now)
      t1 = (Time.now.to_f * 1000).to_i
      return "current_now #{n.inspect}" unless n.is_a?(Integer) && n.between?(t0, t1)
      return 'current_now explicit' unless mw.new(app, audience: aud, resolve_grant: res, now: 7).send(:current_now) == 7
      # intent_policy is handed to the verifier: an active policy denies a PCActn without a bound intent
      r = mw.new(app, audience: aud, resolve_grant: res, intent_policy: { 'require' => true }).call(env.call)
      return "intent_policy #{r[0]} #{r[2].inspect}" unless r[0] == 403 && JSON.parse(r[2][0])['failed_checks'] == ['intent']
      # a non-String audience is stringified for the presence check only
      begin
        mw.new(app, audience: 5, resolve_grant: res)
      rescue StandardError => e
        return "audience 5 refused: #{e.class}"
      end
      # a binary (Rack) body with non-ASCII UTF-8 text, returned FROZEN by the input: decoded as UTF-8, never mutated
      body = %({"note":"café","pcactn":#{AtlasPca.canon_bytes(pa)}}).b.freeze
      frozen_in = Class.new { def initialize(s) = @s = s; def read = @s; def rewind = nil }.new(body)
      r = mw.new(app, audience: aud, resolve_grant: res).call('rack.input' => frozen_in)
      return "frozen binary body #{r[0]} #{r[2].inspect}" unless r[0] == 200
      mut = +body.dup
      same_in = Class.new { def initialize(s) = @s = s; def read = @s; def rewind = nil }.new(mut)
      r = mw.new(app, audience: aud, resolve_grant: res).call('rack.input' => same_in)
      return "binary body #{r[0]}" unless r[0] == 200 && mut.encoding == Encoding::BINARY
      nil
    end

    def forbidden
      m = mw.new(->(_) {}, audience: 'a', resolve_grant: ->(_) {})
      want = lambda do |desc, failed|
        [403, { 'WWW-Authenticate' => 'PCA realm="pca", error="access_denied"', 'content-type' => 'application/json' },
         [%({"error":"access_denied","error_description":"#{desc}","failed_checks":#{JSON.generate(failed)}})]]
      end
      v = ->(reason) { AtlasPca::Verdict.new(false, { 'wire' => true, 'chain' => false, 'x' => false }, reason) }
      return 'nil reason' unless m.send(:forbidden, v.call(nil)) == want.call('policy denied the action', %w[chain x])
      return 'empty reason' unless m.send(:forbidden, v.call('')) == want.call('policy denied the action', %w[chain x])
      return 'reason kept' unless m.send(:forbidden, v.call('chain: bad')) == want.call('chain: bad', %w[chain x])
      nil
    end

    # ---- intent_layers.rb ----
    class OddError < StandardError
      def message = 'the message'
      def to_s = 'not the message'
    end

    def layers
      lp = ->(l) { AtlasPca.is_layer_policy(l) }
      return 'layer_policy predicates:5' unless lp.call({ 'predicates' => 5 }) == false
      return 'layer_policy extra member' unless lp.call({ 'predicates' => [], 'x' => 1 }) == false
      return 'layer_policy default-valued Hash' unless lp.call(Hash.new([])) == false
      return 'layer_policy ok' unless lp.call({ 'predicates' => [] }) == true
      ctx = {}
      mal = ->(k) { { 'status' => 'fail', 'layer' => k, 'reason' => "layers: the #{k} ceiling is malformed (null or not {predicates: [...]})" } }
      %w[org site std].each do |k|
        [{ 'predicates' => 5 }, { 'predicates' => [], 'x' => 1 }, nil, Hash.new([])].each do |bad|
          got = AtlasPca.decide_layer_ceilings({ k => bad }, ctx)
          return "ceiling #{k} #{bad.inspect}: #{got.inspect}" unless got == mal.call(k)
        end
      end
      # a raising layers object: fail closed, the exception's #message (not #to_s)
      boom = {}
      boom.define_singleton_method(:key?) { |_k| raise OddError }
      err = { 'status' => 'fail', 'layer' => 'org', 'reason' => 'layers: evaluation error (fail closed): the message' }
      return "ceilings rescue #{AtlasPca.decide_layer_ceilings(boom, ctx).inspect}" unless AtlasPca.decide_layer_ceilings(boom, ctx) == err
      # decide_layers: `task` is required (a default value of the Hash is not a member), `denied` / `task` must be Arrays
      dl = ->(g) { AtlasPca.decide_layers(g, ctx) }
      deny = { 'decision' => 'intent_denied' }
      g = Hash.new([{ 'predicates' => [] }])
      return "absent task with a Hash default #{dl.call(g).inspect}" unless dl.call(g) == deny
      g = Hash.new([])
      g['task'] = [{ 'predicates' => [] }]
      return "absent denied with a Hash default #{dl.call(g).inspect}" unless dl.call(g) == { 'decision' => 'intent_required' }
      return "denied {} #{dl.call({ 'denied' => {}, 'task' => [{ 'predicates' => [] }] }).inspect}" unless dl.call({ 'denied' => {}, 'task' => [{ 'predicates' => [] }] }) == deny
      return "task {} #{dl.call({ 'task' => {} }).inspect}" unless dl.call({ 'task' => {} }) == deny
      return 'task 5' unless dl.call({ 'task' => 5 }) == deny
      return 'denied 5' unless dl.call({ 'denied' => 5, 'task' => [] }) == deny
      return 'no task' unless dl.call({}) == deny
      # a malformed entry is refused before any evaluation (it would otherwise just fail to admit)
      return 'task entry with an extra member' unless dl.call({ 'task' => [{ 'predicates' => [], 'x' => 1 }] }) == deny
      return 'denied entry with an extra member' unless dl.call({ 'denied' => [{ 'predicates' => [], 'x' => 1 }], 'task' => [] }) == deny
      return 'plain' unless dl.call({ 'denied' => [], 'task' => [] }) == { 'decision' => 'intent_required' }
      raising = { 'task' => [{ 'predicates' => [] }] }
      raising.define_singleton_method(:key?) { |k| k == 'denied' ? raise('boom') : super(k) }
      return "decide_layers rescue #{dl.call(raising).inspect}" unless dl.call(raising) == deny
      nil
    end

    # ---- less_ffi.rb ----
    def ffi = AtlasPca::LessFfi

    def with_binding_reset
      had = ffi.instance_variable_defined?(:@binding)
      saved = had ? ffi.instance_variable_get(:@binding) : nil
      ffi.send(:remove_instance_variable, :@binding) if had
      yield
    ensure
      ffi.send(:remove_instance_variable, :@binding) if ffi.instance_variable_defined?(:@binding)
      ffi.instance_variable_set(:@binding, saved) if had
    end

    DIR = Dir.mktmpdir('rubywb-less')
    at_exit { FileUtils.rm_rf(DIR) }
    SONAME = 'libatlasrubywbstub.so'
    STUB = begin
      c = File.join(DIR, 'stub.c')
      so = File.join(DIR, 'stub.so')
      File.write(c, "unsigned long atlas_less_cat1_public_key_bytes(void){return 97484UL;}\n" \
                    "unsigned long atlas_less_cat1_signature_min_bytes(void){return 1153UL;}\n" \
                    "unsigned long atlas_less_cat1_signature_max_bytes(void){return 1329UL;}\n" \
                    "int atlas_less_cat1_verify(const void*a,unsigned long b,const void*c,unsigned long d,const void*e,unsigned long f){return 7;}\n")
      ok = system('cc', '-shared', '-fPIC', "-Wl,-soname,#{SONAME}", '-o', so, c, out: File::NULL, err: File::NULL)
      # keep it mapped for the whole process (forks inherit it): a bare soname then resolves through the loader's list
      ok ? [so, Fiddle.dlopen(so)['atlas_less_cat1_verify']] : nil
    end

    def less
      return 'verify(nil key)' unless ffi.verify(nil, 'm', 's' * 1329).equal?(false)
      return 'verify(nil sig)' unless ffi.verify('k' * 97_484, 'm', nil).equal?(false)
      # Fiddle missing: `require 'fiddle'` raises LoadError -> no binding (nil), LESS unavailable
      with_binding_reset do
        ffi.define_singleton_method(:require) { |name| name == 'fiddle' ? raise(LoadError, 'no fiddle') : super(name) }
        begin
          return 'no fiddle: load_binding' unless ffi.load_binding.nil? && ffi.binding.nil? && ffi.available?.equal?(false)
        ensure
          ffi.singleton_class.send(:remove_method, :require)
        end
      end
      if STUB
        old = ENV['ATLAS_PCA_LIBLESS']
        begin
          ENV['ATLAS_PCA_LIBLESS'] = SONAME # not a file (relative, not in the cwd), but already mapped under that soname
          return 'bare soname is a file?' if File.file?(SONAME)

          f = ffi.load_binding
          return 'a bare soname was opened through the dynamic loader' if !f.nil? && f.ptr == STUB[1].to_i
          ENV['ATLAS_PCA_LIBLESS'] = STUB[0]
          f = ffi.load_binding
          return 'the stub by path' unless !f.nil? && f.ptr == STUB[1].to_i
        ensure
          old.nil? ? ENV.delete('ATLAS_PCA_LIBLESS') : ENV['ATLAS_PCA_LIBLESS'] = old
        end
      end
      nil
    end
  end

  [%w[rack rack_middleware.rb], %w[forbidden rack_middleware.rb], %w[layers intent_layers.rb], %w[less less_ffi.rb]].each do |k, file|
    t("rubywb #{k}") do
      next true if DiffUtil.skip?(file)

      bad = RubyWb.send(k)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
