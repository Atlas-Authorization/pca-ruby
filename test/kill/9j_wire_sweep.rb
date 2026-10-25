# frozen_string_literal: true
# PCActn wire validation (atlas_pca.rb wire_ok? and its helpers hop_wire_ok? / plan_wire_ok? / optional_wire_ok? / aux_wire_ok?
# / b64? / number?) against the TS reference validateWireV2: test-data/k042-wire-sweep.json.gz = tools/pca-audit/ruby-mutate/
# wire-sweep-oracle.mjs, every single-member perturbation (deleted, or replaced by 18 wrongly typed / out-of-range values) of 14
# wire-valid conformance PCActns, each with the reference verdict. A case the host cannot judge for lack of a PQ suite is
# skipped. First mismatch ends the group. Bears on atlas_pca.rb.
module MutationKill
  module WireSweep
    module_function
    def cases = (@cases ||= DiffUtil.load('k042-wire-sweep.json.gz')['cases'])
    GROUPS = 4

    def first_bad(g)
      cases.each_with_index do |(text, want), i|
        next unless i % GROUPS == g
        p = AtlasPca.parse_json_text(text)
        got = begin
          AtlasPca.wire_ok?(p) ? true : false
        rescue StandardError
          :raised
        end
        next if got == want
        next if !got && AtlasPca.wire_unsupported_suite(p)

        return "case #{i}: want #{want} got #{got.inspect}: #{text[0, 200]}"
      end
      nil
    end
  end

  WireSweep::GROUPS.times do |g|
    t("wire sweep vs TS validateWireV2: part #{g + 1}") do
      next true if DiffUtil.skip?('atlas_pca.rb')
      bad = WireSweep.first_bad(g)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
