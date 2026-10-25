# frozen_string_literal: true
require 'zlib'
require 'json'
# Intent Layer v2 differential kills: AtlasPca.decide_intent_v2 / intent_v2_active? against the TS reference decideIntentV2.
# test-data/k042-intentv2-cases.json.gz is the shared oracle (tools/pca-audit/java-mutate/k042-intentv2-oracle.mts; the Java,
# Python, PHP, .NET and Kotlin suites run the same file): each case pins the EXACT check list (name, ok, reason, in order),
# the canonical env and `active`. One registry test per case group. A thrown-internal-error reason is compared up to its
# prefix "<check> error (fail closed): ". In the Ruby API a nil v2 context IS the absent one (documented); a JSON-null
# context (malformed in TS) has no separate spelling, so those cases are skipped. Every AtlasPca constant / helper is
# resolved at CALL time (the oracle replaces the module per mutant).
module MutationKill
  module IntentV2Diff
    module_function
    FILE = File.expand_path('../../test-data/k042-intentv2-cases.json.gz', __dir__)
    FAIL_CLOSED = '(fail closed): '
    def cases = (@cases ||= JSON.parse(Zlib::GzipReader.open(FILE, &:read).force_encoding('UTF-8'))['cases'])
    def j(t) = AtlasPca.parse_json_text(t)

    # nil when the case agrees (or cannot run here), else a one-line description of the difference
    def mismatch(cs)
      p = j(cs['p'])
      grant = j(cs['grant'])
      ctx = cs.key?('ctx') ? j(cs['ctx']) : nil
      return nil if cs.key?('ctx') && ctx.nil?
      ctx = ctx.merge('params' => j(cs['wp'])) if cs.key?('wp') && ctx.is_a?(Hash)
      out = AtlasPca.decide_intent_v2(p, grant, ctx, cs['now'])
      want = cs['checks']
      got = out['checks'].each_with_index.map do |c, i|
        r = c['reason']
        return nil if r.is_a?(String) && r.include?('unsupported_suite') # a PQ suite this host lacks: by design
        w = want[i]
        if r.is_a?(String) && w.is_a?(Hash) && w['prefix'] == true && (k = r.index(FAIL_CLOSED))
          r = r[0, k + FAIL_CLOSED.length]
        end
        [c['name'], c['ok'], r]
      end
      w = want.map { |x| [x['name'], x['ok'], x['reason']] }
      env = AtlasPca.canonicalize(out['env'] || {})
      active = AtlasPca.intent_v2_active?(p, ctx)
      return nil if got == w && env == (cs['env'] || '{}') && active == [true, 'true'].include?(cs['active'])

      "#{cs['name']}: want #{w.inspect} got #{got.inspect} env #{env} active #{active}"
    end

    def group_names = cases.map { |c| c['name'].split('/').first }.uniq

    # ~19 ms a case (strict Ed25519 in Ruby): under the mutation oracle only the Intent Layer v2 files pay for it
    BEARS_ON = %w[intent_v2.rb intent_wb.rb intent_map.rb intent_layers.rb].freeze
    def skip? = (f = ENV['MUT_FILE']) && !f.empty? && !BEARS_ON.include?(f)
  end

  IntentV2Diff.group_names.each do |g|
    t("intent v2 differential (TS oracle): group #{g}") do
      next true if IntentV2Diff.skip?

      # first mismatch ends the group (a killed mutant should cost as little as possible)
      bad = IntentV2Diff.cases.lazy.select { |c| c['name'].split('/').first == g }.map { |c| IntentV2Diff.mismatch(c) }.find(&:itself)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
