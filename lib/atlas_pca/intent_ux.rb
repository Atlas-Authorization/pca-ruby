# frozen_string_literal: true

require_relative 'intent_omega'
require_relative 'intent_render'
require_relative 'intent_v2'

# Question cards for human studies: a deterministic, structured form of a cell question, and the parser that turns card input into
# the learner's answer. Native port of the TypeScript reference (@atlasauth/pca-intent).
module AtlasPca
  module IntentUx
    UNDEF = V2JS::UNDEF
    FIELD_RE = /\A(?:action\.params\.[a-z_][a-z0-9_]*|action\.resource)\z/

    module_function

    def js(v) = V2JS.js_str(v)

    def fact_of(d, i)
      label = IntentRender.label_of(d['path'])
      if d['kind'] == 'num'
        c = IntentOmega.at(IntentOmega.num_cells(d), i)
        text = c['lo'] == c['hi'] ? "exactly #{js(c['lo'])}" : "any value from #{js(c['lo'])} to #{js(c['hi'])} (for example #{js(IntentOmega.rep_value(d, i))})"
        return { 'path' => d['path'], 'label' => label, 'text' => text }
      end
      v = IntentOmega.at(d['values'], i)
      text = if v['kind'] == 'exact' then "\"#{v['value']}\""
             elsif v['kind'] == 'prefix' then "anything under \"#{v['value']}\" not named elsewhere"
             else 'any value not named anywhere in the grant or your request'
             end
      { 'path' => d['path'], 'label' => label, 'text' => text }
    end

    def question_card(omega, q, catalog = nil)
      vs = omega['verbs'].find { |v| v['verb'] == q['verb'] }
      raise ArgumentError, "questionCard: no verb #{q['verb']}" if vs.nil?

      facts = vs['dims'].each_with_index.map { |d, k| fact_of(d, q['cell'][k]) }
      partial = vs['dims'].each_with_index.map do |d, k|
        if d['kind'] == 'num'
          c = IntentOmega.at(IntentOmega.num_cells(d), q['cell'][k])
          { 'path' => d['path'], 'kind' => 'num', 'lo' => c['lo'], 'hi' => c['hi'] }
        else
          { 'path' => d['path'], 'kind' => 'cat', 'options' => d['values'].select { |v| v['kind'] == 'exact' }.map { |v| v['value'] } }
        end
      end
      body = { 'v' => 1, 'verb' => q['verb'], 'cell' => q['cell'].dup, 'sentence' => IntentRender.render_question(vs, q['cell'], catalog), 'facts' => facts,
               'reversibility' => vs['reversibility'], 'answers' => %w[yes no partly], 'partial' => partial }
      body.merge('digest' => AtlasPca.hash_canonical({ 'd' => 'atlas-pca/intent-card/v1', 'c' => body }))
    end

    # [...new Set(x.filter(nonempty string))]: x must be an array (the reference throws on anything else).
    def strings(x)
      raise TypeError, 'input.notFor.filter is not a function' unless x.is_a?(Array)

      out = []
      x.each { |v| out << v if v.is_a?(String) && !v.empty? && !out.include?(v) }
      out
    end

    def int_not_neg0?(x)
      return true if x.is_a?(Integer)

      x.is_a?(Float) && x.finite? && x == x.floor && !(x.zero? && (1.0 / x).negative?)
    end

    # [...new Set(x)]: null/undefined give the empty set, a string its characters, an array its items; else a TypeError.
    def set_of(x)
      return [] if x.nil? || x.equal?(UNDEF)

      x = x.chars if x.is_a?(String)
      raise TypeError, 'object is not iterable' unless x.is_a?(Array)

      out = []
      x.each { |v| out << v unless out.include?(v) }
      out
    end

    def parse_card_answer(card, inp)
      ans = inp.key?('answer') ? inp['answer'] : UNDEF
      return { 'ok' => true, 'answer' => ans == 'yes' ? 1 : 0 } if ans != 'partly'

      if inp.key?('newField')
        nf = inp['newField']
        return { 'ok' => false, 'error' => "unknown field #{js(nf)}" } unless nf.is_a?(String) && FIELD_RE.match?(nf)
        return { 'ok' => false, 'error' => "#{nf} is already on the card; answer partly for it directly" } if card['partial'].any? { |s| s['path'] == nf }

        vals = strings(inp.key?('notFor') ? inp['notFor'] : UNDEF)
        return { 'ok' => false, 'error' => 'name at least one value' } if vals.empty?

        return { 'ok' => true, 'answer' => { 'kind' => 'partial', 'path' => nf,
                                             'newDim' => { 'kind' => 'cat', 'path' => nf, 'values' => vals.map { |v| { 'kind' => 'exact', 'value' => v } } + [{ 'kind' => 'other', 'value' => '⊥' }] },
                                             'parts' => [{ 'values' => vals, 'y' => 0 }, { 'other' => true, 'y' => 1 }] } }
      end
      path = inp.key?('path') ? inp['path'] : UNDEF
      slot = card['partial'].find { |s| s['path'] == path }
      return { 'ok' => false, 'error' => "the card has no field #{js(path)}" } if slot.nil?

      if slot['kind'] == 'num'
        lo = slot['lo']
        hi = slot['hi']
        in_range = ->(x) { int_not_neg0?(x) && x >= lo && x <= hi }
        if inp.key?('upTo')
          x = inp['upTo']
          return { 'ok' => false, 'error' => "upTo must be an integer in [#{js(lo)}, #{js(hi - 1)}]" } if !in_range.call(x) || x == hi

          return { 'ok' => true, 'answer' => { 'kind' => 'partial', 'path' => slot['path'], 'cuts' => [x],
                                               'parts' => [{ 'lo' => lo, 'hi' => x, 'y' => 1 }, { 'lo' => x + 1, 'hi' => hi, 'y' => 0 }] } }
        end
        if inp.key?('from')
          x = inp['from']
          return { 'ok' => false, 'error' => "from must be an integer in [#{js(lo + 1)}, #{js(hi)}]" } if !in_range.call(x) || x == lo

          return { 'ok' => true, 'answer' => { 'kind' => 'partial', 'path' => slot['path'], 'cuts' => [x],
                                               'parts' => [{ 'lo' => lo, 'hi' => x - 1, 'y' => 0 }, { 'lo' => x, 'hi' => hi, 'y' => 1 }] } }
        end
        if inp.key?('except')
          ex = set_of(inp['except'])
          ex = ex.sort if ex.all? { |v| int_not_neg0?(v) }
          return { 'ok' => false, 'error' => "except values must be integers in [#{js(lo)}, #{js(hi)}]" } if ex.empty? || !ex.all? { |v| in_range.call(v) }

          return { 'ok' => true, 'answer' => { 'kind' => 'partial', 'path' => slot['path'], 'cuts' => ex,
                                               'parts' => ex.map { |x| { 'lo' => x, 'hi' => x, 'y' => 0 } } + [{ 'lo' => lo, 'hi' => hi, 'y' => 1 }] } }
        end
        return { 'ok' => false, 'error' => 'a numeric partly answer needs upTo, from or except' }
      end
      return { 'ok' => false, 'error' => 'a categorical partly answer needs notFor' } unless inp.key?('notFor')

      vals = strings(inp['notFor'])
      return { 'ok' => false, 'error' => 'name at least one value' } if vals.empty?

      { 'ok' => true, 'answer' => { 'kind' => 'partial', 'path' => slot['path'], 'values' => vals, 'parts' => [{ 'values' => vals, 'y' => 0 }, { 'other' => true, 'y' => 1 }] } }
    end
  end
end
