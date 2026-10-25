# frozen_string_literal: true
require 'openssl'
# r11 kills for lib/atlas_pca.rb (survivors of mutation run 39902549441): the raw-JSON-text number / surrogate / depth model,
# b64?, the PQ capability memo, the exact-length guards of pq_verify (a spy on the backends: an out-of-contract key or
# signature length never reaches OpenSSL or the LESS library), the fail-closed rescues of every "never raises" verifier
# entry point (an input object that raises), the PinnedPq choke point of verify_suite, the nested-hybrid message bytes,
# resolve_root_pq's pin/grant agreement, wire_unsupported_suite on threshold shares, the intent threshold / goal helpers,
# and verify_pcactn's fallback reason of a v2 check that carries none. Names start with `rubywb` (MUT_QUICK).
module MutationKill
  module RubyWbCore
    module_function

    def a = AtlasPca
    def ed(label) = OpenSSL::PKey.new_raw_private_key('ED25519', Digest::SHA256.digest("ruby-kill-wbc/#{label}"))
    def mldsa = (@mldsa ||= OpenSSL::PKey.generate_key('ML-DSA-65'))
    def b64e(x) = AtlasPca.b64e(x)

    # A Hash whose element reads raise (an input "of any shape": the fail-closed rescues must turn it into false).
    class RaisingHash < Hash
      def [](_k) = raise(ArgumentError, 'boom')
    end

    class OddError < StandardError
      def message = 'the message'
      def to_s = 'not the message'
    end

    # Object whose #hash raises (Hash#[] on it raises).
    class BadKey
      def hash = raise(ArgumentError, 'boom')
    end

    # Backend spy: counts OpenSSL::PKey.new_raw_public_key calls while on (prepended once, in the parent).
    module PkeySpy
      STATE = { on: false, n: 0 }
      def new_raw_public_key(*args)
        STATE[:n] += 1 if STATE[:on]
        super
      end
    end
    OpenSSL::PKey.singleton_class.prepend(PkeySpy)

    module LessSpy
      STATE = { on: false, n: 0 }
      def verify(*args)
        LessSpy::STATE[:n] += 1 if LessSpy::STATE[:on]
        super
      end
    end

    def spied
      AtlasPca::LessFfi.singleton_class.prepend(LessSpy) unless AtlasPca::LessFfi.singleton_class.include?(LessSpy)
      PkeySpy::STATE.merge!(on: true, n: 0)
      LessSpy::STATE.merge!(on: true, n: 0)
      r = yield
      [r, PkeySpy::STATE[:n] + LessSpy::STATE[:n]]
    ensure
      PkeySpy::STATE[:on] = false
      LessSpy::STATE[:on] = false
    end

    def json
      t = ->(s) { a.parse_json_text(s) }
      v = t.call('-9007199254740993')
      return "big negative #{v.inspect}" unless v.is_a?(Float) && v == -9_007_199_254_740_992.0
      return 'big positive' unless t.call('9007199254740993').is_a?(Float)
      return 'safe negative' unless t.call('-9007199254740991').eql?(-9_007_199_254_740_991)
      return '-1.5' unless t.call('-1.5').eql?(-1.5)
      return '-2e0' unless t.call('-2e0').eql?(-2.0)
      z = t.call('-0.0')
      return '-0.0' unless z.is_a?(Float) && z.zero? && (1.0 / z).negative?
      s = t.call('"\\ud800"')
      return 'lone surrogate' unless s.is_a?(String) && !s.valid_encoding?
      d = AtlasPca::MAX_JSON_DEPTH + 3
      return 'deep json text' unless t.call(('[' * d) + (']' * d)).is_a?(Array)
      begin
        t.call(('[' * 300_000) + (']' * 300_000))
        return 'no stack overflow at 300k'
      rescue AtlasPca::Malformed => e
        return "overflow message #{e.message.inspect}" unless e.message == 'nesting too deep'
      end
      nil
    end

    def b64q
      return 'b64? 64' unless a.b64?(b64e("\x01".b * 64)) == true
      return 'b64? 63' unless a.b64?(b64e("\x01".b * 63)) == false
      return 'b64? 65' unless a.b64?(b64e("\x01".b * 65)) == false
      return 'b64? nil' unless a.b64?(nil) == false && a.b64?('a=') == false
      nil
    end

    def caps
      memo = AtlasPca::PQ_PRIM_AVAILABLE
      full = a.supported_suites
      return 'needs ml-dsa-87' unless full.include?('ml-dsa-87')
      saved = memo.dup
      begin
        memo['ML-DSA-87'] = false
        got = a.supported_suites
        return "memo ignored #{got.inspect}" unless got == full - %w[ml-dsa-87 hybrid-ed25519-ml-dsa-87]
        return 'pq_prim_available? memo' unless a.pq_prim_available?('ML-DSA-87') == false
      ensure
        memo.replace(saved)
      end
      ffi = AtlasPca::LessFfi
      had = ffi.instance_variable_defined?(:@binding)
      old = had ? ffi.instance_variable_get(:@binding) : nil
      begin
        memo.delete('LESS-cat1')
        ffi.instance_variable_set(:@binding, nil)
        return 'LESS without a library' unless a.pq_prim_available?('LESS-cat1') == false && !a.supported_suites.include?('less-cat1')
      ensure
        memo.replace(saved)
        had ? ffi.instance_variable_set(:@binding, old) : ffi.send(:remove_instance_variable, :@binding)
      end
      nil
    end

    def guards
      k = ed('g')
      m = 'msg'
      esig = k.sign(nil, m)
      cases = {
        'ml-dsa pk -1' => ['ML-DSA-65', "\x00".b * 1951, "\x00".b * 3309],
        'ml-dsa pk +1' => ['ML-DSA-65', "\x00".b * 1953, "\x00".b * 3309],
        'ml-dsa sig -1' => ['ML-DSA-65', "\x00".b * 1952, "\x00".b * 3308],
        'slh sig +1' => ['SLH-DSA-SHA2-128f', "\x00".b * 32, "\x00".b * 17_089],
        'less pk -1' => ['LESS-cat1', "\x00".b * 97_483, "\x00".b * 1329],
        'less off-step sig' => ['LESS-cat1', "\x00".b * 97_484, "\x00".b * 1154],
        'ed25519 is no pq prim' => ['ED25519', k.raw_public_key, esig]
      }
      cases.each do |name, (prim, pk, sig)|
        r, n = spied { a.pq_verify(prim, pk, m, sig) }
        return "#{name}: #{r.inspect}, #{n} backend call(s)" unless r.equal?(false) && n.zero?
      end
      # pq_verify_b64u: exactly false (never nil) for an unknown primitive, and false (rescued) when the lookup raises
      return 'b64u unknown prim' unless a.pq_verify_b64u('nope', 'AA', 'm', 'AA').equal?(false)
      return 'b64u raising prim' unless a.pq_verify_b64u(BadKey.new, 'AA', 'm', 'AA').equal?(false)
      nil
    end

    def pinned
      m = "pinned é"
      pk = b64e(mldsa.raw_public_key)
      sig = b64e(mldsa.sign(nil, m))
      pq = AtlasPca::PinnedPq.mint(pk, 'trusted')
      return 'mldsa65_verify_pinned valid' unless a.mldsa65_verify_pinned(pq, m, sig) == true
      return 'mldsa65_verify_pinned raw' unless a.mldsa65_verify_pinned(pk, m, sig).equal?(false)
      p = { 'alg' => 'ml-dsa-65', 'sig' => sig }
      return 'verify_suite pinned' unless a.verify_suite(p, nil, m, pq) == true
      # the choke point: only a PinnedPq (or nil) is a PQ key; a look-alike carrying a valid key is refused, exactly false
      fake = Struct.new(:key, :source).new(pk, 'trusted')
      return 'verify_suite look-alike' unless a.verify_suite(p, nil, m, fake).equal?(false)
      return 'verify_suite string key' unless a.verify_suite(p, nil, m, pk).equal?(false)
      # suite_dispatch: a PQ suite without a PQ key is exactly false
      return 'dispatch pq nil' unless a.suite_dispatch(p, nil, m, nil).equal?(false)
      # nested hybrid over a non-ASCII UTF-8 message: the PQ half signs msg.b + ed_sig (binary concatenation)
      e = ed('nested')
      esig = e.sign(nil, m)
      hp = { 'alg' => 'hybrid-nested-ed25519-ml-dsa-65', 'sig' => b64e(esig), 'pq_sig' => b64e(mldsa.sign(nil, m.b + esig)) }
      return 'nested hybrid utf-8' unless a.suite_dispatch(hp, b64e(e.raw_public_key), m, pk) == true
      nil
    end

    def dispatch
      k = ed('d')
      m = 'dispatch'
      sig = b64e(k.sign(nil, m))
      pub = b64e(k.raw_public_key)
      return 'ed25519 baseline' unless a.suite_dispatch({ 'sig' => sig }, pub, m, nil) == true
      return 'unknown alg with a valid ed25519 sig' unless a.suite_dispatch({ 'alg' => 'x-unknown', 'sig' => sig }, pub, m, nil).equal?(false)
      bad = RaisingHash.new
      bad.define_singleton_method(:key?) { |_k| raise ArgumentError, 'boom' }
      return 'dispatch raising' unless a.suite_dispatch(bad, pub, m, nil).equal?(false)
      return 'verify_b64u nil' unless a.verify_b64u(nil, m, sig).equal?(false)
      return 'verify_b64u bad msg' unless a.verify_b64u(pub, BadKey.new, sig).equal?(false)
      return 'verify_threshold_share raising' unless a.verify_threshold_share(RaisingHash.new).equal?(false)
      return 'verify_pq_artifact raising' unless a.verify_pq_artifact(RaisingHash.new).equal?(false)
      w = RaisingHash.new
      RubyWb::VEC['pcactn'].each { |kk, v| w.store(kk, v) }
      return 'wire_ok? raising' unless a.wire_ok?(w).equal?(false)
      nil
    end

    def root_pq
      pk = b64e("\x07".b * 1952)
      root = { 'alg' => 'ml-dsa-65', 'pq_pk' => pk, 'issuer' => 'iss', 'holder' => 'h', 'caveats' => [] }
      r = ->(rt, pins, tr) { a.resolve_root_pq(rt, pins, tr) }
      ok = ->(x) { x.is_a?(Array) && x[0].is_a?(AtlasPca::PinnedPq) && x[0].key == pk && x[1].nil? }
      return 'trusted only' unless ok.call(r.call(root, nil, root))
      return 'trusted + no pin entry' unless ok.call(r.call(root, {}, root))
      return 'trusted + equal pin' unless ok.call(r.call(root, { 'iss' => pk }, root))
      return 'trusted + pins not a Hash' unless ok.call(r.call(root, [], root))
      mism = format(AtlasPca::ROOT_PQ_PIN_MISMATCH_REASON, 'ml-dsa-65')
      return 'trusted + other pin' unless r.call(root, { 'iss' => 'other' }, root) == [nil, mism]
      r5 = root.merge('issuer' => 5)
      return 'non-String issuer' unless ok.call(r.call(r5, { 5 => 'other' }, r5))
      return 'unregistered alg' unless r.call(root.merge('alg' => 'x-unknown'), nil, nil) == [nil, nil]
      # an absent alg is ed25519, whatever the Hash's default value
      d = Hash.new('ml-dsa-65')
      root.reject { |k, _| k == 'alg' }.each { |k, v| d[k] = v }
      return 'absent alg with a Hash default' unless r.call(d, nil, nil) == [nil, nil]
      nil
    end

    def wire
      p = RubyWb::VEC['pcactn']
      return 'vec wire' unless a.wire_ok?(p) == true
      { 'nonce' => '', 'caution' => 2, 'rationale_commitment' => 'x', 'tool_binding' => 'x', 'intent' => 5,
        'intent_session' => 5, 'threshold' => 5 }.each do |k, v|
        got = a.wire_ok?(p.merge(k => v))
        return "wire_ok? #{k}: #{got.inspect}" unless got.equal?(false)
      end
      return 'threshold shares' unless a.wire_ok?(p.merge('threshold' => { 'shares' => 5 })).equal?(false)
      return 'wire_unsupported_suite non-Hash' unless a.wire_unsupported_suite(5).nil? && a.wire_unsupported_suite('x').nil?
      return 'wire_unsupported_suite plain' unless a.wire_unsupported_suite(p).nil?
      sh = { 'role' => 'r', 'alg' => 'fn-dsa-512', 'sig' => 'AA' }
      got = a.wire_unsupported_suite(p.merge('threshold' => { 'shares' => [5, sh] }))
      return "share suite #{got.inspect}" unless got == "#{AtlasPca::UNSUPPORTED_SUITE}: fn-dsa-512"
      v = a.verify_pcactn(5, {}, now: 0, audience: 'a')
      return "verify non-Hash #{v.inspect}" unless v.allow == false && v.reason == 'wire: malformed PCActn'
      nil
    end

    def intent
      gc = ->(*x) { a.intent_goal_commit(*x) }
      return 'goal default session' unless gc.call('r', 'm', 's') == gc.call('r', 'm', 's', nil, nil) && gc.call('r', 'm', 's') != gc.call('r', 'm', 's', 'x')
      th = ->(x) { a.intent_threshold(x) }
      return 'threshold 2^60' unless th.call(2.0**60).nil?
      return 'threshold 2.5' unless th.call(2.5).nil?
      return 'threshold 5.0' unless th.call(5.0).eql?(5)
      return 'root_goal_commit caveats String' unless a.root_goal_commit({ 'caveats' => 'x' }).nil?
      commit = gc.call('r', 'm', 's')
      grant = { 'caveats' => [{ 'type' => 'envelope', 'goal_commit' => commit }] }
      it = { 'ref' => 'r', 'map_digest' => 'm', 'goal_salt' => 's', 'fidelity_ppm' => 1, 'residual_risk_ppm' => 1 }
      return 'binding defaults' unless a.decide_intent_binding(it, grant) == [:pass, nil]
      odd = it.dup
      odd.define_singleton_method(:[]) { |_k| raise OddError }
      return 'binding error message' unless a.decide_intent_binding(odd, grant) == [:fail, 'intent binding error (fail closed): the message']
      nil
    end

    # verify_pcactn: a v2 check that fails without a reason is reported as "<name>: rejected"
    module V2Stub
      STATE = { on: false }
      def decide_intent_v2(*args)
        return { 'checks' => [{ 'name' => 'schema', 'ok' => false }] } if V2Stub::STATE[:on]

        super
      end
    end

    def v2_reason
      AtlasPca.singleton_class.prepend(V2Stub) unless AtlasPca.singleton_class.include?(V2Stub)
      v = RubyWb::VEC
      V2Stub::STATE[:on] = true
      got = a.verify_pcactn(v['pcactn'], v['grant'], now: v['context']['now'], audience: v['context']['aud'])
      return "v2 fallback reason #{got.reason.inspect}" unless got.allow == false && got.reason == 'schema: rejected'
      base = a.verify_pcactn(v['pcactn'], v['grant'], now: v['context']['now'], audience: v['context']['aud'], allowed_suites: nil, intent_policy: nil, intent_v2: nil)
      V2Stub::STATE[:on] = false
      return 'defaults' unless a.verify_pcactn(v['pcactn'], v['grant'], now: v['context']['now'], audience: v['context']['aud']).to_a == a.verify_pcactn(v['pcactn'], v['grant'], now: v['context']['now'], audience: v['context']['aud'], allowed_suites: nil, intent_policy: nil, intent_v2: nil).to_a
      return 'stub reached the explicit-nil call' unless base.allow == false
      nil
    ensure
      V2Stub::STATE[:on] = false
    end
  end

  [%w[json], %w[b64q], %w[caps ml-dsa-87], %w[guards ml-dsa-65], %w[pinned ml-dsa-65], %w[dispatch], %w[root_pq], %w[wire],
   %w[intent], %w[v2_reason]].each do |k, needs|
    t("rubywb core #{k}", needs: needs) do
      next true if DiffUtil.skip?('atlas_pca.rb')

      bad = RubyWbCore.send(k)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
