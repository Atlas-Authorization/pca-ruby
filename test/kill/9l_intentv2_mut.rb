# frozen_string_literal: true
# Intent Layer v2 MUTATION-STYLE differential kills (the Java/Kotlin K042IntentV2MutTest, ported): test-data/
# k042-intentv2-mut.json.gz = tools/pca-audit/java-mutate/k042-intentv2-mut-oracle.mts replaces every structural path of the
# k042-intentv2-cases corpus (verifier context, PCActn, grant) by null / booleans / numbers / strings / containers, deletes
# it or adds an unknown sibling, and records the reference decideIntentV2 answer. Same case format and comparison as
# 95_intent_v2_diff.rb (IntentV2Diff.mismatch). The 14k cases are cut into groups by the member they edit, so a mutant dies on
# the first mismatch of the first group that reaches it. Bears on the Intent Layer v2 files only (~19 ms a case).
module MutationKill
  module IntentV2Mut
    module_function
    FILE = File.expand_path('../../test-data/k042-intentv2-mut.json.gz', __dir__)
    CHUNK = 600
    def cases = (@cases ||= JSON.parse(Zlib::GzipReader.open(FILE, &:read).force_encoding('UTF-8'))['cases'])

    # Not reachable through the verifier: a PCActn that fails the wire check or a grant that is not an object is refused BEFORE
    # IntentV2 runs, so IntentV2's own (still fail-closed) wording for such a direct call is not pinned. Decided ONCE, at registry
    # load, by the unmutated library (the cases are fixed; a mutant of wire_ok? must not shrink the set it is judged on).
    def reachable
      @reachable ||= cases.each_index.select do |i|
        c = cases[i]
        g = AtlasPca.parse_json_text(c['grant'])
        g.is_a?(Hash) && (AtlasPca.wire_ok?(AtlasPca.parse_json_text(c['p'])) ? true : false) &&
          # principled skip: with the epoch's pq_pk deleted the reference THROWS while binding the suite fields; this verifier
          # answers "revocation epoch signature invalid". Both refuse.
          c['name'] != 'mut/ctx/session.revocation.epoch.pq_pk/15'
      rescue StandardError
        false
      end
    end

    def group_of(c)
      parts = c['name'].split('/')
      "#{parts[1]}/#{parts[2].to_s.split('.').first}"
    end

    # [[group-name, [case index...]]...], big groups cut into CHUNK-sized parts
    def groups
      @groups ||= reachable.group_by { |i| group_of(cases[i]) }.flat_map do |g, idx|
        idx.each_slice(CHUNK).each_with_index.map { |part, k| ["#{g}##{k + 1}", part] }
      end
    end

    FILES = %w[intent_v2.rb intent_wb.rb intent_map.rb intent_layers.rb].freeze
    def skip? = (f = ENV['MUT_FILE']) && !f.empty? && !FILES.include?(f)
  end

  IntentV2Mut.groups.each do |g, idx|
    t("intent v2 mutation differential (TS oracle): #{g}") do
      next true if IntentV2Mut.skip?

      bad = idx.lazy.map { |i| IntentV2Diff.mismatch(IntentV2Mut.cases[i]) }.find(&:itself)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
