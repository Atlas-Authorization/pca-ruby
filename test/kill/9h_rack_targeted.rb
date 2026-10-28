# frozen_string_literal: true
require 'stringio'
# Exact kills for lib/atlas_pca/rack_middleware.rb: constructor validation, header / body extraction, every 401 / 403 body and
# header, the host callbacks (resolver, intent_v2, now) and the JSON emitter, on a genuinely signed vector of the conformance
# corpus. AtlasPca is resolved at CALL time (the mutation oracle replaces the module per mutant). Bears on rack_middleware.rb.
module MutationKill
  module RackT
    module_function
    SigOnly = Class.new(AtlasPca::RackMiddleware) do
      def initialize(app, **o) = super(app, signature_only: true, **o)
    end
    def mw = SigOnly
    def vec = (@vec ||= Corpus.core['vectors'].find { |v| v['expect']['allow'] == true && (v['requires'].nil? || v['requires'].empty? || v['requires'] == 'ed25519') && v.key?('pcactn') })
    def pa = vec['pcactn']
    def grant = vec['grant']
    def aud = vec['context']['aud']
    def now = vec['context']['now']
    def b64 = AtlasPca.b64e(AtlasPca.canon_bytes(pa))
    def resolver = ->(r) { r == pa['grant_ref'] ? grant : nil }
    def build(**o) = mw.new(->(env) { (@seen = env['pca']) && [200, {}, ['ok']] }, **{ audience: aud, resolve_grant: resolver, now: now }.merge(o))
    def seen = @seen
    def env(h = nil, body = nil) = { 'rack.input' => StringIO.new(body || '') }.merge(h ? { 'HTTP_PCA_ACTION' => h } : {})
    # every 401 / 403 body ends with `doc` (the refusals page, anchored at the refusing check when the reason names one)
    DOC = 'https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md'
    def err(status, code, desc, extra = '', anchor = '')
      [status, { 'WWW-Authenticate' => %(PCA realm="pca", error="#{code}"), 'content-type' => 'application/json' },
       [%({"error":"#{code}","error_description":#{desc}#{extra},"doc":"#{DOC}#{anchor}"})]]
    end
    def q(s) = s.inspect # simple ASCII strings only

    def ctor
      raise_msg = ->(msg, &b) { begin; b.call; false; rescue ArgumentError => e; e.message == msg; end }
      ok = [raise_msg.call('audience: is required') { mw.new(nil, audience: nil, resolve_grant: resolver) },
            raise_msg.call('audience: is required') { mw.new(nil, audience: '', resolve_grant: resolver) },
            raise_msg.call('resolve_grant: must respond to #call') { mw.new(nil, audience: 'a', resolve_grant: 5) },
            raise_msg.call('intent_v2: must be a Hash or respond to #call') { mw.new(nil, audience: 'a', resolve_grant: resolver, intent_v2: 5) },
            raise_msg.call('intent_v2: must be a Hash or respond to #call') { mw.new(nil, audience: 'a', resolve_grant: resolver, intent_v2: 'x') }]
      return 'ctor refusals' unless ok.all?
      mw.new(nil, audience: :sym, resolve_grant: resolver)
      mw.new(nil, audience: 'a', resolve_grant: resolver, intent_v2: {})
      mw.new(nil, audience: 'a', resolve_grant: resolver, intent_v2: ->(_) { {} })
      mw.new(nil, audience: 'a', resolve_grant: resolver, intent_v2: nil)
      nil
    end

    def run
      m = build
      s, _, b = m.call(env(b64))
      return "valid header #{s} #{b.inspect}" unless s == 200 && b == ['ok']
      return 'env pca' unless seen['verdict'].allow == true && seen['pcactn'] == pa
      # body path (and the body is rewound for the app)
      e = env(nil, %({"pcactn":#{AtlasPca.canon_bytes(pa)}}))
      return 'body path' unless build.call(e)[0] == 200 && e['rack.input'].read == %({"pcactn":#{AtlasPca.canon_bytes(pa)}})
      e = env('', %({"pcactn":#{AtlasPca.canon_bytes(pa)}}))
      return 'empty header falls to body' unless build.call(e)[0] == 200
      e = env(b64, %({"pcactn":5}))
      return 'header wins over body' unless build.call(e)[0] == 200
      # no PCActn
      none = err(401, 'invalid_pcactn', '"no PCActn presented"')
      [{}, { 'rack.input' => nil }, { 'rack.input' => StringIO.new('') }, { 'rack.input' => StringIO.new('{}') }, { 'rack.input' => StringIO.new('{"pcactn":null}') },
       { 'HTTP_PCA_ACTION' => '', 'rack.input' => StringIO.new('') }].each_with_index do |ev, i|
        r = build.call(ev)
        return "none ##{i} #{r.inspect}" unless r == none
      end
      # input without #rewind, and a read that returns nil
      noread = Class.new { def read = nil }.new
      return 'read nil' unless build.call('rack.input' => noread) == none
      once = Class.new { def initialize(s) = @s = s; def read = @s }.new(%({"pcactn":#{AtlasPca.canon_bytes(pa)}}))
      return 'no rewind' unless build.call('rack.input' => once)[0] == 200
      # decode errors
      bad = lambda do |ev, code, desc_prefix|
        r = build.call(ev)
        r[0] == code && r[1] == err(code, 'invalid_pcactn', '')[1] && JSON.parse(r[2][0])['error_description'].start_with?(desc_prefix) &&
          JSON.parse(r[2][0]).keys == %w[error error_description doc]
      end
      return 'header not b64' unless bad.call(env('not base64!'), 401, 'PCActn header is not canonical base64url')
      return 'header padded' unless bad.call(env(b64 + '='), 401, 'PCActn header is not canonical base64url')
      return 'header not object' unless bad.call(env(AtlasPca.b64e('[1]'.b)), 401, 'PCActn failed the strict JSON profile: ')
      return 'header bad json' unless bad.call(env(AtlasPca.b64e('{"a":'.b)), 401, 'PCActn failed the strict JSON profile: ')
      return 'body bad json' unless bad.call(env(nil, 'x'), 401, 'request body is not valid JSON: ')
      return 'body array' unless bad.call(env(nil, '[1]'), 401, 'request body is not valid JSON: ')
      return 'body pcactn not obj' unless build.call(env(nil, '{"pcactn":5}')) == err(401, 'invalid_pcactn', '"body \"pcactn\" is not an object"')
      return 'body pcactn array' unless build.call(env(nil, '{"pcactn":[]}')) == err(401, 'invalid_pcactn', '"body \"pcactn\" is not an object"')
      # custom header key
      return 'custom header' unless build(header: 'HTTP_X_P').call({ 'HTTP_X_P' => b64, 'rack.input' => StringIO.new('') })[0] == 200
      return 'custom header ignores default' unless build(header: 'HTTP_X_P').call(env(b64)) == none
      # grant_ref
      called = 0
      cnt = ->(_r) { called += 1; grant }
      mal = err(401, 'invalid_pcactn', '"malformed PCActn"', '', '#malformed')
      [nil, 5, [], {}, true].each do |v|
        p2 = pa.merge('grant_ref' => v)
        return "grant_ref #{v.inspect}" unless build(resolve_grant: cnt).call(env(AtlasPca.b64e(AtlasPca.canon_bytes(p2)))) == mal
      end
      p3 = pa.reject { |k, _| k == 'grant_ref' }
      return 'grant_ref absent' unless build(resolve_grant: cnt).call(env(AtlasPca.b64e(AtlasPca.canon_bytes(p3)))) == mal && called.zero?
      return 'unknown grant' unless build(resolve_grant: ->(_) { nil }).call(env(b64)) == err(401, 'invalid_pcactn', '"unknown grant"')
      raised = [403, { 'WWW-Authenticate' => 'PCA realm="pca", error="access_denied"', 'content-type' => 'application/json' },
                [%({"error":"access_denied","error_description":"grant resolution failed (fail closed)","doc":"#{DOC}"})]]
      return 'resolver raises' unless build(resolve_grant: ->(_) { raise 'boom' }).call(env(b64)) == raised
      return 'resolver gets the ref' unless (g = nil; build(resolve_grant: ->(r) { g = r; grant }).call(env(b64)); g == pa['grant_ref'])
      # intent_v2: a Hash goes straight in, a callable gets the pcactn, a raising callable is a 403
      v2err = [403, { 'WWW-Authenticate' => 'PCA realm="pca", error="intent_v2_context_error"', 'content-type' => 'application/json' },
               [%({"error":"intent_v2_context_error","error_description":"intent v2 verifier state unavailable (fail closed)","doc":"#{DOC}"})]]
      return 'v2 raises' unless build(intent_v2: ->(_) { raise 'boom' }).call(env(b64)) == v2err
      got = nil
      build(intent_v2: ->(x) { got = x; nil }).call(env(b64))
      return 'v2 callable arg' unless got == pa
      called_v2 = false
      hash_v2 = {}
      hash_v2.define_singleton_method(:call) { |*| called_v2 = true; {} }
      build(intent_v2: hash_v2).call(env(b64))
      return 'v2 hash not called' if called_v2
      # verdict denied: audience mismatch -> 403 with the failed checks
      r = build(audience: 'other').call(env(b64))
      j = JSON.parse(r[2][0])
      return "denied #{r.inspect}" unless r[0] == 403 && r[1] == raised[1] && j['error'] == 'access_denied' && j['failed_checks'] == ['audience'] &&
                                         j['error_description'] == 'audience: audience mismatch' && j.keys == %w[error error_description failed_checks doc] && j['doc'] == "#{DOC}#audience"
      return 'denied app not run' unless (seen_before = @seen; @seen = :untouched; build(audience: 'other').call(env(b64)); r2 = @seen; @seen = seen_before; r2 == :untouched)
      # now: callable, nil -> wall clock
      return 'now callable' unless build(now: -> { now }).call(env(b64))[0] == 200
      wall = build(now: nil).call(env(b64))
      return 'now nil is wall clock' unless wall[0] == 403 && JSON.parse(wall[2][0])['failed_checks'].include?('validity')
      return 'now callable nil is wall clock' unless build(now: -> {}).call(env(b64))[0] == 403
      return 'now int' unless build(now: now).call(env(b64))[0] == 200
      nil
    end

    def emit
      m = build
      j = ->(s) { m.send(:jstr, s) }
      want = { 'a' => '"a"', '"' => '"\\""', '\\' => '"\\\\"', "\b" => '"\\b"', "\f" => '"\\f"', "\n" => '"\\n"', "\r" => '"\\r"', "\t" => '"\\t"',
               "\u0001" => '"\\u0001"', "\u001f" => '"\\u001f"', ' ' => '" "', 'é' => '"é"', '' => '""', 5 => '"5"', nil => '""', "\u007f" => "\"\u007f\"",
               "a\"b\\c\nd" => '"a\\"b\\\\c\\nd"' }
      want.each { |s, w| return "jstr #{s.inspect}: #{j.call(s)}" unless j.call(s) == w }
      tj = m.send(:to_json, { 'error' => 'e', 'n' => ['a', 'b"'], 'z' => [] })
      return "to_json #{tj}" unless tj == '{"error":"e","n":["a","b\\""],"z":[]}'
      return 'to_json empty' unless m.send(:to_json, {}) == '{}'
      return 'www' unless m.send(:www_authenticate, 'x') == 'PCA realm="pca", error="x"'
      return 'realm' unless mw::REALM == 'pca' && mw::DEFAULT_HEADER == 'HTTP_PCA_ACTION'
      r = m.send(:json_response, 418, 'e', 'd', 'k' => ['v'])
      return 'json_response' unless r == [418, { 'content-type' => 'application/json' }, ['{"error":"e","error_description":"d","k":["v"]}']]
      [401, 403].each do |st|
        c = m.send(:json_response, st, 'e', 'd')
        return "challenge #{st}" unless c == [st, { 'WWW-Authenticate' => 'PCA realm="pca", error="e"', 'content-type' => 'application/json' }, [%({"error":"e","error_description":"d","doc":"#{DOC}"})]]
      end
      nil
    end
  end

  %w[ctor run emit].each do |k|
    t("rack middleware: #{k}") do
      next true if DiffUtil.skip?('rack_middleware.rb')
      bad = RackT.send(k)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
