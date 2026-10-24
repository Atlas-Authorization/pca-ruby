# frozen_string_literal: true
# Intent Layer v2 targeted differential kills (revocation primitive, epoch shape, JS truthiness / text, v2 activation):
# test-data/killV2.json.gz = tools/pca-audit/kotlin-mutate/killV2-oracle-gen.mjs (the Kotlin KillV2Test's golden file: exact TS
# reasons). The file's `decide` section (823 whole-decision cases, ~20 ms each) is NOT replayed: it repeats the vectors
# 95_intent_v2_diff.rb / 9l_intentv2_mut.rb already replay from the larger shared corpora. Only intent_v2.rb bears on it.
module MutationKill
  module KillV2
    module_function
    def data = (@data ||= DiffUtil.load('killV2.json.gz'))
    def n(x) = AtlasPca::V2JS.jsnorm(x)
    FAIL_CLOSED = 'error (fail closed): '

    # a thrown-internal-error reason is compared up to its prefix (the message is the language's own)
    def same(want, got)
      return true if want == got
      return false unless want.is_a?(String) && got.is_a?(String) && (i = want.index(FAIL_CLOSED))

      got.start_with?(want[0, i + FAIL_CLOSED.length])
    end

    # `tw`: the input as its public twin (94a_pub_twin.rb: Symbol keys, integral Floats), which the public entry normalizes
    def rev(c, tw)
      want = c['reason'] == 'NOT-OBJECT' ? 'session revocation check error (fail closed)' : c['reason']
      i = n(c['input'])
      r = AtlasPca.intent_revocation_primitive(tw ? PubTwin.twin(i) : i)
      same(want, r['ok'] ? nil : r['reason']) && (r['ok'] == true) == want.nil?
    end

    def check(section, c)
      case section
      when 'rev' then rev(c, false) && rev(c, true)
      when 'shape'
        ep = n(c['ep'])
        AtlasPca.revocation_epoch_shape_error(ep) == c['want'] && AtlasPca.revocation_epoch_shape_error(PubTwin.twin(ep)) == c['want']
      when 'truthy' then AtlasPca::V2JS.truthy?(n(c['v'])) == c['want']
      when 'jstext' then AtlasPca::V2JS.js_str(n(c['v'])) == c['want']
      when 'active'
        ctx = c.key?('ctx') ? n(c['ctx']) : nil
        # a JSON-null context has no spelling apart from the absent one in this API (documented in 95_intent_v2_diff.rb)
        c.key?('ctx') && ctx.nil? ? true : AtlasPca.intent_v2_active?(n(c['p']), ctx) == c['want']
      end
    end

    def first_bad(section)
      data[section].each do |c|
        ok = begin
          check(section, c)
        rescue StandardError, SystemStackError => e
          "raised #{e.class}"
        end
        next if ok == true
        next if DiffUtil.pq_case?(c['input'] || c['p'])

        return "#{section} #{c['name']}: #{ok.inspect}"
      end
      nil
    end
  end

  %w[rev shape truthy jstext active].each do |section|
    t("kill v2 differential (TS oracle): #{section}") do
      next true if DiffUtil.skip?('intent_v2.rb')
      bad = KillV2.first_bad(section)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
