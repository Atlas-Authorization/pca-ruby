# frozen_string_literal: true
# Rule 13 (the intent_session wire member, the grant caveat, the signed session root, revocation by a dedicated authority)
# differential kills against the TS reference: test-data/k042-sessrevoc-cases.json = tools/pca-audit/java-mutate/
# k042-sessrevoc-oracle.mts (the Java suite runs the same file; every value is raw JSON TEXT). Exact reasons; a reason ending in
# "(fail closed): " is compared up to that prefix (the internal-error text is language specific). Only intent_v2.rb bears on it.
module MutationKill
  module SessRevocDiff
    module_function
    FAIL_CLOSED = '(fail closed): '
    def data = (@data ||= DiffUtil.parse(DiffUtil.read('k042-sessrevoc-cases.json')))
    def j(t) = AtlasPca.parse_json_text(t)
    def absent = AtlasPca::V2JS::UNDEF

    def same(want, got)
      return got.is_a?(String) && got.start_with?(want) if want.is_a?(String) && want.end_with?(FAIL_CLOSED)
      # the strict canonicalizer's own message is language specific: compare up to the "malformed ...: " prefix
      return got.is_a?(String) && got.start_with?(want[/\A.*?: (?=canonicalize: )/]) if want.is_a?(String) && want.include?(': canonicalize: ')
      want == got
    end

    def reason(r) = r['ok'] ? nil : r['reason']

    def check(kind, c)
      case kind
      when 'wire' then [same(c['reason'], AtlasPca.validate_intent_session_wire(j(c['v']))), c['name']]
      when 'caveat' then [same(c['reason'], AtlasPca.intent_session_caveat_error(j(c['c']))), c['name']]
      when 'root'
        s = j(c['s'])
        pins = c.key?('pq_pins') && !c['pq_pins'].nil? ? j(c['pq_pins']) : nil
        a = same(c['shape'], AtlasPca.session_root_shape_error(s))
        v = AtlasPca.verify_session_root(s, pins)
        [a && same(c['verify'], reason(v)), c['name']]
      when 'rev'
        ev = c['ev'].nil? ? nil : j(c['ev'])
        ids = c['ids'].nil? ? nil : j(c['ids'])
        last = c['last'].nil? ? absent : j(c['last'])
        scope = c['scope'].nil? ? absent : c['scope']
        r = AtlasPca.check_session_revocation(ev, session: c['session'], authority: j(c['authority']), ids: ids, now: c['now'],
                                                  max_age_ms: c['maxAge'], scope: scope, last: last)
        [same(c['reason'], reason(r)), c['name']]
      when 'prim'
        r = AtlasPca.intent_revocation_primitive(j(c['text']))
        [same(c['reason'], reason(r)) && (c['reason'].nil? == (r['ok'] == true)), c['name']]
      end
    end

    def first_bad(kind)
      data[kind].each do |c|
        ok, name = begin
          check(kind, c)
        rescue StandardError, SystemStackError => e
          [false, "#{c['name']} (raised #{e.class})"]
        end
        # a case naming a PQ suite this host lacks refuses with unsupported_suite: by design, not a difference
        next if !ok && DiffUtil.pq_case?(c.reject { |k, _| %w[name reason shape verify].include?(k) })

        return "#{kind} #{name}" unless ok
      end
      nil
    end
  end

  %w[wire caveat root rev prim].each do |kind|
    t("session / revocation differential (TS oracle): #{kind}") do
      next true if DiffUtil.skip?('intent_v2.rb')
      bad = SessRevocDiff.first_bad(kind)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
