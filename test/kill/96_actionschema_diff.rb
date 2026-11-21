# frozen_string_literal: true
require 'json'
# Rule 14 (signed action schemas, closed-world conformance) differential kills against the TS reference:
# test-data/k042-actionschema.json (tools/pca-audit/java-mutate/k042-actionschema-oracle.mts; the Java suite runs the same
# file). Every input is raw JSON text. Reasons are compared exactly. Only intent_v2.rb bears on these rules, so under the
# mutation oracle (MUT_FILE exported by mutate.rb) every other file skips them. AtlasPca is resolved at CALL time.
module MutationKill
  module ActionSchemaDiff
    module_function
    FILE = File.expand_path('../../test-data/k042-actionschema.json', __dir__)
    def data = (@data ||= JSON.parse(File.read(FILE, encoding: 'UTF-8')))
    def j(t) = AtlasPca.parse_json_text(t)
    def skip? = (f = ENV['MUT_FILE']) && !f.empty? && f != 'intent_v2.rb'

    # the strict canonicalizer's own message is language-specific: compare the shape-level prefix
    MALFORMED = 'malformed schema: '

    # every case of a kind -> the first mismatch (a description) or nil
    def first_bad(kind)
      data[kind].each do |c|
        r = begin
          check(kind, c)
        rescue StandardError, SystemStackError => e
          "#{c['name']}: raised #{e.class} #{e.message[0, 80]}"
        end
        return r if r
      end
      nil
    end

    def check(kind, c)
      case kind
      when 'shape'
        want = c['expect']
        got = AtlasPca.action_schema_shape_error(j(c['doc']))
        return nil if got.is_a?(String) && got.include?('unsupported_suite')
        return nil if want.is_a?(String) && want.start_with?(MALFORMED) && got.is_a?(String) && got.start_with?(MALFORMED)
        want == got ? nil : "#{c['name']}: want #{want.inspect} got #{got.inspect}"
      when 'verify'
        want = c['expect']
        got = AtlasPca.verify_action_schema(j(c['doc']), j(c['keys']))
        got = got['ok'] == true ? nil : got['reason']
        return nil if got.is_a?(String) && got.include?('unsupported_suite') # a PQ suite this host lacks: by design
        want == got ? nil : "#{c['name']}: want #{want.inspect} got #{got.inspect}"
      when 'pvv'
        e = c['expect']
        got = AtlasPca.param_value_violation(j(c['d']), j(c['x']))
        gotn = got.nil? ? nil : { 'code' => got['code'], 'reason' => got['reason'] }
        e == gotn ? nil : "#{c['name']}: want #{e.inspect} got #{got.inspect}"
      when 'conform'
        e = c['expect']
        r = AtlasPca.conform_action(j(c['doc']), c['verb'], j(c['params']))
        got = r.is_a?(Hash) ? r : { 'ok' => r }
        if e['ok'] == true
          got['ok'] == true ? nil : "#{c['name']}: want ok got #{got.inspect}"
        else
          ok = got['ok'] == false && got['code'] == e['code'] && got['path'] == e['path'] && got['reason'] == e['reason']
          ok ? nil : "#{c['name']}: want #{e.inspect} got #{got.inspect}"
        end
      when 'acc'
        got = AtlasPca.accumulation_params(j(c['v']), c['unit'])
        got = got.to_a
        c['expect'] == got ? nil : "#{c['name']}: want #{c['expect'].inspect} got #{got.inspect}"
      when 'canon'
        e = c['expect']
        got = begin
          AtlasPca.canon_projection(j(c['doc']), c['verb'], j(c['params']))
        rescue StandardError
          :threw
        end
        want = e['ok'] == true ? e['out'] : :threw
        want == got ? nil : "#{c['name']}: want #{want.inspect} got #{got.inspect}"
      end
    end
  end

  %w[shape verify pvv conform acc canon].each do |kind|
    t("action schema differential (TS oracle): #{kind}") do
      next true if ActionSchemaDiff.skip?
      bad = ActionSchemaDiff.first_bad(kind)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end

  # v2 verb `confirmation` shape (confirmationShapeError of action-schema.ts): exact members, canonical digests / sig, sorted trait ids.
  t('action schema: confirmation shape') do
    next true if ActionSchemaDiff.skip?
    d = 'A' * 43
    c = { 'def_digest' => d, 'traits_digest' => d, 'facts_digest' => d, 'final_traits' => %w[pca.bulk pca.irreversible], 'dismissed' => [{ 'trait' => 'pca.bulk', 'reason' => 'x' }],
          'reviewer_kid' => 'k', 'ts' => 0, 'sig' => 'A' * 86 }
    e = ->(x) { AtlasPca::IntentV2.send(:confirmation_shape_error, x) }
    e.(c).nil? && e.(c.merge('x' => 1)) == "confirmation: unknown member 'x'" && !e.(c.merge('sig' => 'A' * 85)).nil? &&
      e.(c.merge('final_traits' => %w[pca.irreversible pca.bulk])) == 'confirmation: final_traits must be sorted and distinct' &&
      !e.(c.merge('dismissed' => [{ 'trait' => 'pca.bulk', 'reason' => '' }])).nil? && !e.(c.merge('ts' => -1)).nil? && !e.([]).nil?
  end
end
