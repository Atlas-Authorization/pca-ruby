# frozen_string_literal: true
# Rule 13 (the intent_session wire, the grant caveat, the signed session root) targeted differential kills: test-data/
# killSession.json.gz (gzip of the Kotlin file) = tools/pca-audit/kotlin-mutate/killSession-oracle-gen.mjs (the Kotlin KillSessionTest's golden file; the
# `ts` / `shape` / `verify` members are the TS reference's exact reasons, null = accepted; `kt_*` members pin Kotlin's own text and
# do not apply here). Only intent_v2.rb bears on it.
module MutationKill
  module KillSession
    module_function
    def data = (@data ||= DiffUtil.load('killSession.json.gz'))
    def n(x) = AtlasPca::V2JS.jsnorm(x)
    def absent = AtlasPca::V2JS::UNDEF
    def iv2 = AtlasPca::IntentV2

    # the strict canonicalizer's own message is language specific: compare up to the "...: canonicalize: " prefix
    def same(want, got)
      return got.is_a?(String) && got.start_with?(want[/\A.*?: (?=canonicalize: )/]) if want.is_a?(String) && want.include?(': canonicalize: ')

      want == got
    end

    def check(kind, c)
      a = c['arg']
      case kind
      when 'wire' then same(c['ts'], iv2.validate_intent_session_wire(n(a)))
      when 'caveat' then same(c['ts'], iv2.intent_session_caveat_error(n(a)))
      when 'shape' then same(c['shape'], iv2.session_root_shape_error(n(a)))
      when 'verify'
        r = iv2.verify_session_root(n(a), c.key?('pins') ? n(c['pins']) : nil)
        same(c['verify'], r['ok'] ? nil : r['reason'])
      when 'grant'
        na = n(a)
        g = iv2.grant_session_caveat(na)
        c['want_index'].nil? ? g.nil? : g.equal?(na['caveats'][c['want_index']])
      end
    end

    # the same case through the PUBLIC wrapper (94a_pub_twin.rb): the arguments it normalizes as their twins, an absent
    # optional argument omitted (the wrapper's default)
    def pub(kind, c)
      a = c['arg']
      x = AtlasPca
      tw = ->(v) { PubTwin.twin(v) }
      case kind
      when 'wire' then same(c['ts'], x.validate_intent_session_wire(n(a)))
      when 'caveat' then same(c['ts'], x.intent_session_caveat_error(n(a)))
      when 'shape' then same(c['shape'], x.session_root_shape_error(tw.call(n(a))))
      when 'verify'
        r = c.key?('pins') ? x.verify_session_root(tw.call(n(a)), tw.call(n(c['pins']))) : x.verify_session_root(tw.call(n(a)))
        same(c['verify'], r['ok'] ? nil : r['reason'])
      when 'grant'
        na = n(a)
        g = x.grant_session_caveat(na)
        c['want_index'].nil? ? g.nil? : g.equal?(na['caveats'][c['want_index']])
      end
    end

    SECTION = { 'wire' => 'wire', 'caveat' => 'caveat', 'shape' => 'root', 'verify' => 'root', 'grant' => 'grant' }.freeze

    def first_bad(kind)
      data[SECTION[kind]].each do |c|
        ok = begin
          check(kind, c) && (pub(kind, c) || 'public twin differs')
        rescue StandardError, SystemStackError => e
          "raised #{e.class}"
        end
        next if ok == true
        next if DiffUtil.pq_case?(c['arg'])

        return "#{kind} #{c['name']}: #{ok.inspect}"
      end
      nil
    end
  end

  %w[wire caveat shape verify grant].each do |kind|
    t("kill session differential (TS oracle): #{kind}") do
      next true if DiffUtil.skip?('intent_v2.rb')
      bad = KillSession.first_bad(kind)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
