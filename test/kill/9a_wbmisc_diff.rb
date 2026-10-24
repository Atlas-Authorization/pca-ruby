# frozen_string_literal: true
# The W-B unit (rules 16-18 composed, intent_wb.rb decide_intent_wb / intent_wb_context_error) differential kills against the
# TS reference decideIntentWB: test-data/k042-wbmisc.json.gz = tools/pca-audit/java-mutate/k042-wbmisc-oracle.mjs (the Java
# suite runs the same file). Compared in full: outcome, checks IN ORDER, exact reason, friction, world / prov / class env
# members and single_source (all cleared on a deny, the contract the other natives share).
module MutationKill
  module WbMiscDiff
    module_function
    def cases = (@cases ||= DiffUtil.load('k042-wbmisc.json.gz')['cases'])
    GROUPS = { 'context shape' => %w[ctx/ wb/ctx-], 'unit cases' => %w[wb/], 'lifted world' => %w[lift/world/],
               'lifted provenance' => %w[lift/prov/], 'lifted classifiers' => %w[lift/cls/], 'dropped members' => %w[drop- other-],
               'deny clears earlier env' => %w[then-] }.freeze

    def shape(r)
      env = r['env'] || {}
      { 'outcome' => r['outcome'], 'checks' => r['checks'].to_a.map { |k, v| [k, v] }, 'reason' => r['reason'], 'friction' => r['friction'],
        'world' => env['world'], 'prov' => env['prov'], 'class' => env['class'],
        'single_source' => r['single_source'] }
    end

    def mine(prefixes) = cases.select { |c| prefixes.any? { |p| c['name'].start_with?(p) } }

    def first_bad(prefixes)
      mine(prefixes).each do |c|
        got = begin
          shape(AtlasPca.decide_intent_wb(c['input']))
        rescue StandardError, SystemStackError => e
          "THREW #{e.class}"
        end
        want = c['expect']
        next if DiffUtil.norm(got) == DiffUtil.norm(want)
        next if DiffUtil.pq_case?(c['name'])
        return "#{c['name']}: want #{want.inspect} got #{got.inspect}"
      end
      nil
    end
  end

  WbMiscDiff::GROUPS.each do |g, prefixes|
    t("W-B unit differential (TS oracle): #{g}") do
      next true if DiffUtil.skip?('intent_wb.rb')
      bad = WbMiscDiff.first_bad(prefixes)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
