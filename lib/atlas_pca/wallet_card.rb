# frozen_string_literal: true

require 'set'
require_relative 'wallet'
require_relative 'siem'
require_relative 'facade'
require_relative 'intent_render'

# The trusted question card and agent-initiated clarification of the wallet (the PCA Intent Layer v2): a deterministic render from
# the wallet's own outcome space, the cell coordinates, the verified site identity, the principal's own signed statement and a
# closed-enum reason (no field for agent-authored text), its digest, the "Partly..." and typed-value checks, and the structured
# clarification request with max-information cell selection. Native port of the TypeScript reference (@atlasauth/pca-wallet).
# The input is a String-keyed Hash with the reference's member names (omega, verb, coords, site, statementText, reversibility,
# units, action, friction, kind, reason, locale, catalog).
module AtlasPca
  module WalletCard
    W = Wallet
    O = IntentOmega
    UNDEF = Wallet::UNDEF
    U16 = Siem::U16

    CARD_DOMAIN = 'atlas-pca/intent-card/v2'
    CLARIFY_REASONS = %w[ambiguous_parameter multiple_options price_changed constraint_conflict missing_value other].freeze
    REASON_LABELS = {
      'ambiguous_parameter' => 'Your agent found a detail your request did not settle.',
      'multiple_options' => 'Your agent found several options that match.',
      'price_changed' => 'Your agent found that a price changed.',
      'constraint_conflict' => 'Your agent found that two parts of your request conflict.',
      'missing_value' => 'Your agent needs a value your request did not give.',
      'other' => 'Your agent needs a decision before it continues.'
    }.freeze
    MAX_CANDIDATES = 8
    MAX_VALUES = 64
    MAX_STRING = 256
    PATH_RE = /\A[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_]+)*\z/

    # JavaScript's \s and String.prototype.trim whitespace set
    WS = "\t\n\u000b\u000c\r    -     　﻿"
    CTRL = /[\u0000-\u001f\u007f-\u009f​-‏ -‮⁦-⁩]/
    WS_RUN = /[#{WS}]+/
    WS_EDGE = /\A[#{WS}]+|[#{WS}]+\z/
    TYPED_STRIP = /[#{WS},$€£¥]/
    CURRENCY_SYMBOL = { 'USD' => '$', 'EUR' => '€', 'GBP' => '£', 'JPY' => '¥' }.freeze
    ACC_RE = /\Aenv\.acc\.([A-Za-z0-9_.-]+)\.post\z/
    WORLD_RE = /\Aenv\.world\.([A-Za-z0-9_.-]+)\z/
    MON_RE = /\Aenv\.mon\.([A-Za-z0-9_.-]+)\.state\z/
    ANSWERS = {
      'tap' => [{ 'id' => 'no', 'label' => 'No' }, { 'id' => 'partly', 'label' => 'Partly…' }, { 'id' => 'yes', 'label' => 'Yes' }],
      'hold' => [{ 'id' => 'no', 'label' => 'No' }, { 'id' => 'partly', 'label' => 'Partly…' }, { 'id' => 'yes', 'label' => 'Press and hold to allow' }],
      'typed' => [{ 'id' => 'no', 'label' => 'No' }, { 'id' => 'partly', 'label' => 'Partly…' }, { 'id' => 'yes', 'label' => 'Yes, type the value to confirm' }],
      'device' => [{ 'id' => 'no', 'label' => 'No' }, { 'id' => 'partly', 'label' => 'Partly…' }, { 'id' => 'yes', 'label' => 'Yes, confirm with your security key' }]
    }.freeze
    REV_TEXT = { 'reversible' => 'that can be undone', 'rate_limited' => 'that is rate-limited', 'irreversible' => 'that cannot be undone' }.freeze

    module_function

    def js_str(v) = W.js_str(v)
    def g(o, k) = W.g(o, k)
    def truthy?(v) = W.truthy?(v)

    # Strip control characters, collapse whitespace, cap length (for the principal's own words and the site's name).
    def clean_text(s, mx)
      raise TypeError, 's.replace is not a function' unless s.is_a?(String)

      t = U16.to_pua(s).gsub(CTRL, ' ').gsub(WS_RUN, ' ').gsub(WS_EDGE, '')
      units = U16.units(t)
      units.length <= mx ? U16.from_pua(t) : U16.from_pua(U16.from_units(units[0...(mx - 1)])) + '…'
    end

    # The last four letters/digits of a string (all a card ever shows of a string the outcome space does not name).
    def last4(s)
      raise TypeError, 's.replace is not a function' unless s.is_a?(String)

      t = U16.to_pua(s).gsub(/[^A-Za-z0-9]/, '')
      (t.length > 4 ? t[-4..] : t).upcase
    end

    def group(n) = n.to_s.gsub(/\B(?=(\d{3})+(?!\d))/, ',')

    # JavaScript ToNumber for the values a JSON document can hold (undefined is NaN).
    def to_number(v)
      return Float::NAN if v.equal?(UNDEF)
      return 0.0 if v.nil? || v == false
      return 1.0 if v == true
      return v.to_f if W.number?(v)

      if v.is_a?(String)
        t = U16.to_pua(v).gsub(WS_EDGE, '')
        return 0.0 if t.empty?

        return t.match?(/\A[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?\z/) ? t.to_f : Float::NAN
      end
      return to_number(js_str(v)) if v.is_a?(Array)

      Float::NAN
    end

    def exponent(unit)
      e = to_number(g(unit, 'exponent'))
      raise ArgumentError, 'NaN exponent' if e.nan?
      return e.positive? ? 6 : 0 if e.infinite?

      [0, [6, e.floor].min].max
    end

    def money?(unit) = unit.is_a?(Hash) && unit['kind'] == 'money'

    def symbol_of(unit)
      cur = g(unit, 'currency')
      (cur.is_a?(String) ? CURRENCY_SYMBOL[cur] : nil) || "#{js_str(cur)} "
    end

    # Thousands grouping with commas, independent of any locale data (cards render identically anywhere).
    def format_number(x, unit = nil)
      raise TypeError, 'not a number' unless W.number?(x)

      if money?(unit)
        begin
          e = exponent(unit)
        rescue ArgumentError
          # an exponent that is not a number: the reference computes with NaN, rendering "NaN" for the whole part and no fraction
          return "#{x.negative? ? '-' : ''}#{symbol_of(unit)}NaN"
        end
        a = x.to_i.abs
        div = 10**e
        frac = e.positive? ? ".#{(a % div).to_s.rjust(e, '0')}" : ''
        return "#{x.negative? ? '-' : ''}#{symbol_of(unit)}#{group(a.div(div))}#{frac}"
      end
      "#{x.negative? ? '-' : ''}#{group(x.to_i.abs)}"
    end

    def dim_label(path)
      if (m = ACC_RE.match(path)) then return "#{m[1].tr('_.', '  ')} (running total for this task)" end
      if (m = WORLD_RE.match(path)) then return "#{m[1].tr('_.', '  ')} (from a signed fact)" end
      if (m = MON_RE.match(path)) then return "state of #{m[1].tr('_.', '  ')}" end

      IntentRender.label_of(path)
    end

    def prov_path?(p) = p.start_with?('env.prov.')

    def num_fact(d, ids, unit, action_value)
      cells = O.num_cells(d)
      lo = cells[ids[0]]['lo']
      hi = cells[ids[-1]]['hi']
      rng = if lo == hi then "exactly #{format_number(lo, unit)}"
            elsif lo == d['lo'] && hi == d['hi'] then 'any value'
            elsif hi == d['hi'] then "#{format_number(lo, unit)} or more"
            elsif lo == d['lo'] then "up to #{format_number(hi, unit)}"
            else "#{format_number(lo, unit)} – #{format_number(hi, unit)}"
            end
      ex = W.finite_number?(action_value) ? " (this action: #{format_number(action_value, unit)})" : ''
      rng + ex
    end

    def cat_value_text(d, i)
      v = d['values'][i]
      return "\"#{clean_text(v['value'], 64)}\"" if v['kind'] == 'exact'
      return "anything starting with \"#{clean_text(v['value'], 64)}\"" if v['kind'] == 'prefix'

      'a value not named in your request'
    end

    def cat_fact(d, ids, action_value)
      parts = ids.map { |i| cat_value_text(d, i) }
      st = parts.length == 1 ? parts[0] : "#{parts[0...-1].join(', ')} or #{parts.empty? ? 'undefined' : parts[-1]}"
      return st unless action_value.is_a?(String)

      named = d['values'].any? { |v| v['kind'] == 'exact' && v['value'] == action_value }
      "#{st} (this action: #{named ? "\"#{clean_text(action_value, 64)}\"" : "a value ending in \"#{last4(action_value)}\""})"
    end

    def banner_for(path, levels)
      w = W.worst_provenance(levels)
      label = dim_label(path)
      case w
      when 'web' then "This #{label} was suggested by content on a web page, not by you."
      when 'tool' then "This #{label} came from a tool result, not from you."
      when 'agent' then "This #{label} was chosen by your agent, not taken from your request or from the site."
      end
    end

    def prov_levels(d, ids) = ids.flat_map { |i| W.cat_label(d, i).split(/[|,]/, -1) }

    # action.values[path] for a value that may be any JSON: a missing or null `values` throws, a non-object has no members.
    def vget(values, path)
      raise TypeError, 'Cannot read properties of undefined' if values.nil? || values.equal?(UNDEF)

      values.is_a?(Hash) ? values[path] : nil
    end

    def typed_target(vs, action, units)
      return nil unless truthy?(action)

      values = g(action, 'values')
      dims = vs['dims'].reject { |d| prov_path?(d['path']) }
      nums = dims.select { |d| d['kind'] == 'num' && W.number?(vget(values, d['path'])) }
      money = nums.find { |d| money?(units.is_a?(Hash) ? g(units, d['path']) : nil) }
      pick = money || nums[0]
      return { 'path' => pick['path'], 'mode' => 'number', 'prompt' => "To allow it, type the #{dim_label(pick['path'])} of this action shown above." } if pick

      cat = dims.find { |d| d['kind'] == 'cat' && vget(values, d['path']).is_a?(String) && last4(vget(values, d['path'])).length == 4 }
      if cat
        return { 'path' => cat['path'], 'mode' => 'last4', 'prompt' => "To allow it, type the last 4 letters or digits of the #{dim_label(cat['path'])}." }
      end

      nil
    end

    # ANSWERS[friction]: a property key, so a one-element array of a tier name selects that tier too
    def answers_of(friction)
      key = if friction.is_a?(String) then friction
            elsif friction.is_a?(Array) && friction.length == 1 && friction[0].is_a?(String) then friction[0]
            end
      key.nil? ? nil : ANSWERS[key]
    end

    def lower_first(s) = s.empty? || "\n\r  ".include?(s[0]) ? s : s[0].downcase + s[1..]

    # Render the trusted question card: {ok: true, card} or {ok: false, reason}.
    def render_card(inp)
      loc = g(inp, 'locale')
      loc = 'en' if loc.equal?(UNDEF) || loc.nil?
      return { 'ok' => false, 'reason' => "unsupported locale #{js_str(g(inp, 'locale'))}" } if loc != 'en'

      kind = g(inp, 'kind')
      reason = g(inp, 'reason')
      return { 'ok' => false, 'reason' => 'a clarification card needs a reason' } if kind == 'clarification' && reason.equal?(UNDEF)
      return { 'ok' => false, 'reason' => 'unknown clarification reason' } if !reason.equal?(UNDEF) && !(reason.is_a?(String) && CLARIFY_REASONS.include?(reason))

      verb = g(inp, 'verb')
      r = W.resolve_coords(inp['omega'], verb, g(inp, 'coords'))
      return r unless r['ok']

      vs = r['vs']
      box = r['box']
      action = g(inp, 'action')
      return { 'ok' => false, 'reason' => 'the action is for another verb' } if truthy?(action) && g(action, 'verb') != verb

      cat = inp['catalog']
      catalog = cat.nil? ? AtlasPca.facade_catalog(nil) : cat
      site = inp['site']
      site_name = clean_text(site['name'], 64)
      site_name = clean_text(site['origin'], 64) if site_name.empty?
      said = inp.key?('statementText') ? clean_text(inp['statementText'], 280) : ''
      header = if kind == 'clarification'
                 said.empty? ? 'Your agent needs a decision' : "Your agent needs a decision for your request \"#{said}\""
               else
                 said.empty? ? "#{site_name} asks for your confirmation" : "#{site_name} asks on behalf of your request \"#{said}\""
               end
      spec = catalog.get(verb)
      what = if truthy?(spec)
               lower_first(spec['description'].sub(/\.\z/, ''))
             else
               "the action \"#{clean_text(verb, 64)}\" on #{site_name}"
             end
      rev = inp['reversibility']
      rev = vs['reversibility'] if rev.nil?
      sentence = "Allow #{what}, #{rev.is_a?(String) ? REV_TEXT.fetch(rev, 'undefined') : 'undefined'}, with:"
      units = inp['units']
      facts = []
      banners = []
      partial = []
      vs['dims'].each_with_index do |d, k|
        ids = box[k]
        if prov_path?(d['path'])
          next unless d['kind'] == 'cat'

          b = banner_for(d['path']['env.prov.'.length..], prov_levels(d, ids))
          banners << b if b
          next
        end
        av = nil
        av = vget(g(action, 'values'), d['path']) if !action.nil? && !action.equal?(UNDEF)
        unit = units.is_a?(Hash) ? g(units, d['path']) : nil
        unit = nil if unit.equal?(UNDEF)
        if d['kind'] == 'num'
          facts << { 'key' => d['path'], 'label' => dim_label(d['path']), 'text' => num_fact(d, ids, unit, av) }
          cells = O.num_cells(d)
          partial << { 'path' => d['path'], 'kind' => 'num', 'lo' => cells[ids[0]]['lo'], 'hi' => cells[ids[-1]]['hi'] }
        else
          facts << { 'key' => d['path'], 'label' => dim_label(d['path']), 'text' => cat_fact(d, ids, av) }
          options = ids.select { |i| d['values'][i]['kind'] == 'exact' }.map { |i| d['values'][i]['value'] }
          partial << { 'path' => d['path'], 'kind' => 'cat', 'options' => options } if options.length > 1
        end
      end
      friction = g(inp, 'friction')
      typed = W.friction_rank(friction) >= W.friction_rank('typed') ? typed_target(vs, action, units) : nil
      body = {
        'v' => 2, 'verb' => verb, 'coords' => W.plain(inp['coords']), 'locale' => 'en',
        'site' => { 'origin' => clean_text(site['origin'], 256), 'name' => site_name },
        'header' => header
      }
      body['kind'] = kind unless kind.equal?(UNDEF)
      body['reason_label'] = REASON_LABELS[reason] unless reason.equal?(UNDEF)
      body['sentence'] = sentence
      body['facts'] = facts
      body['banners'] = banners
      body['friction'] = friction unless friction.equal?(UNDEF)
      answers = answers_of(friction)
      body['answers'] = answers unless answers.nil?
      body['typed'] = typed if truthy?(typed)
      body['partial'] = partial
      { 'ok' => true, 'card' => body.merge('rendered_digest' => card_digest(body)) }
    end

    # The content address of a card body (everything but rendered_digest).
    def card_digest(body) = AtlasPca.hash_canonical({ 'd' => CARD_DOMAIN, 'c' => W.plain(body) })

    # Recompute a card's digest and compare: an auditor's check that the stored card is the one that was hashed.
    def card_digest_matches(card)
      body = card.reject { |k, _| k == 'rendered_digest' }
      card.key?('rendered_digest') && card_digest(body) == card['rendered_digest']
    end

    # The plain text of a card, line by line (what a screen reader or a text channel shows).
    def card_text(card)
      lines = [card['header']]
      lines << card['reason_label'] if truthy?(card['reason_label'])
      lines << card['sentence']
      card['facts'].each { |f| lines << "- #{f['label']}: #{f['text']}" }
      lines.concat(card['banners'])
      lines << card['typed']['prompt'] if truthy?(card['typed'])
      lines << card['answers'].map { |a| "[#{a['label']}]" }.join(' ')
      lines.join("\n")
    end

    # Validate a "Partly..." answer against the card: a structured restriction of the shown ranges and values only.
    def partial_error(card, p)
      raise TypeError, "'p' is not an object" unless p.is_a?(Hash)

      slot = card['partial'].find { |s| s['path'] == p['path'] }
      return "the card has no field #{js_str(p.key?('path') ? p['path'] : UNDEF)}" if slot.nil?

      if slot['kind'] == 'num'
        lo = slot['lo']
        hi = slot['hi']
        in_range = lambda do |x|
          W.number?(x) && W.integral?(x) && !W.neg_zero?(x) && x >= lo && x <= hi
        end
        if p.key?('upTo')
          return in_range.call(p['upTo']) && p['upTo'] < hi ? nil : "upTo must be an integer in [#{js_str(lo)}, #{js_str(hi - 1)}]"
        end
        if p.key?('from')
          return in_range.call(p['from']) && p['from'] > lo ? nil : "from must be an integer in [#{js_str(lo + 1)}, #{js_str(hi)}]"
        end
        if p.key?('except')
          ex = W.iterate(p['except'])
          return !ex.empty? && ex.all? { |x| in_range.call(x) } ? nil : "except values must be integers in [#{js_str(lo)}, #{js_str(hi)}]"
        end
        return 'a numeric partly answer needs upTo, from or except'
      end
      return 'a categorical partly answer needs notFor' unless p.key?('notFor')

      vals = W.iterate(p['notFor']).uniq
      return 'notFor must name values shown on the card' if vals.empty? || !vals.all? { |v| slot['options'].include?(v) }
      return 'excluding every value is a "No"' if vals.length == slot['options'].length

      nil
    end

    # Normalize what the human typed for comparison with the action value (digits for numbers, minor units for money).
    def normalize_typed(inp, mode, unit = nil)
      raise TypeError, 'inp.replace is not a function' unless inp.is_a?(String)

      if mode == 'last4'
        t = U16.to_pua(inp).gsub(/[^A-Za-z0-9]/, '').upcase
        return t.length == 4 ? t : nil
      end
      t = U16.to_pua(inp).gsub(TYPED_STRIP, '').sub(/\A[A-Za-z]{3}/, '')
      m = /\A(-?)([0-9]+)(?:\.([0-9]+))?\z/.match(t)
      return nil unless m

      e = money?(unit) ? exponent(unit) : 0
      frac = m[3] || ''
      return nil if frac.length > e

      minor = (m[2].to_i * (10**e)) + (frac.empty? ? 0 : frac.ljust(e, '0').to_i)
      "#{m[1] == '-' && minor != 0 ? '-' : ''}#{minor}"
    end

    # The normalized value the human must type for this card and action (what a site or auditor recomputes).
    def expected_typed(card, action)
      return nil unless truthy?(card['typed'])

      v = vget(action.key?('values') ? action['values'] : UNDEF, card['typed']['path'])
      return (v.is_a?(String) && last4(v).length == 4 ? last4(v) : nil) if card['typed']['mode'] == 'last4'

      W.number?(v) && W.safe_int?(v) && !W.neg_zero?(v) ? v.to_i.to_s : nil
    end

    # ---- agent-initiated clarification (clarify.ts) ---------------------------------------------------------------------------

    # Strict parse of a clarification body: {ok: true, request} or {ok: false, error}. Never raises.
    def parse_clarify_request(body)
      return { 'ok' => false, 'error' => 'body must be an object' } unless W.obj?(body)

      body.each_key { |k| return { 'ok' => false, 'error' => "unknown member \"#{k}\" (clarifications carry no text)" } if k != 'candidates' && k != 'reason' }
      return { 'ok' => false, 'error' => "reason must be one of #{CLARIFY_REASONS.join(', ')}" } if !body['reason'].is_a?(String) || !CLARIFY_REASONS.include?(body['reason'])

      cands = body['candidates']
      return { 'ok' => false, 'error' => "candidates must be 1..#{MAX_CANDIDATES} structured actions" } if !cands.is_a?(Array) || cands.empty? || cands.length > MAX_CANDIDATES

      out = []
      cands.each_with_index do |c, i|
        return { 'ok' => false, 'error' => "candidates[#{i}] must be an object" } unless W.obj?(c)

        c.each_key { |k| return { 'ok' => false, 'error' => "candidates[#{i}] has an unknown member \"#{k}\"" } if k != 'verb' && k != 'values' }
        verb = c['verb']
        return { 'ok' => false, 'error' => "candidates[#{i}].verb must be a non-empty string" } if !verb.is_a?(String) || verb.empty? || IntentOmega.u16len(verb) > 128
        return { 'ok' => false, 'error' => "candidates[#{i}].values must be an object" } unless W.obj?(c['values'])

        entries = W.entries(c['values'])
        return { 'ok' => false, 'error' => "candidates[#{i}] has too many values" } if entries.length > MAX_VALUES

        values = {}
        entries.each do |p, v|
          return { 'ok' => false, 'error' => "candidates[#{i}] has a malformed path" } unless PATH_RE.match?(U16.to_pua(p))
          unless p == 'action.resource' || p.start_with?('action.params.')
            return { 'ok' => false, 'error' => "candidates[#{i}].values may only name action.params.* or action.resource" }
          end

          if W.number?(v)
            return { 'ok' => false, 'error' => "candidates[#{i}].values.#{p} must be a safe integer" } if !W.safe_int?(v) || W.neg_zero?(v)
          elsif !v.is_a?(String) || IntentOmega.u16len(v) > MAX_STRING
            return { 'ok' => false, 'error' => "candidates[#{i}].values.#{p} must be a string (≤ #{MAX_STRING}) or an integer" }
          end
          values[p] = v
        end
        out << { 'verb' => verb, 'values' => values }
      end
      { 'ok' => true, 'request' => { 'candidates' => out, 'reason' => body['reason'] } }
    end

    # Expected information gain of asking a cell with acceptance p under asymmetric noise (bits).
    def information_gain(p, eta_pos, eta_neg)
      py = (p * (1 - eta_neg)) + ((1 - p) * eta_pos)
      W.bin_ent(py) - ((p * W.bin_ent(eta_neg)) + ((1 - p) * W.bin_ent(eta_pos)))
    end

    # Dry-run verdicts for each candidate and the one cell worth asking, if any. inp carries omega, view (a Hash of callables p,
    # vetoed and outsideCeiling over (verb, idx)), candidates, an optional lift callable, asked (a Set of `verb|i,j,..` keys),
    # etaPos, etaNeg and an optional harm model.
    def plan_clarification(inp)
      omega = inp['omega']
      view = inp['view']
      lift = inp['lift']
      harm = inp['harm'] || O::DEFAULT_HARM
      verdicts = []
      best = nil
      seen = Set.new
      inp['candidates'].each_with_index do |cand, index|
        at = W.cell_of_action(omega, lift ? lift.call(cand) : cand)
        if at.nil?
          verdicts << { 'index' => index, 'verdict' => 'outside' }
          next
        end
        vs = at['vs']
        idx = at['idx']
        if view['outsideCeiling'].call(vs['verb'], idx) || view['vetoed'].call(vs['verb'], idx)
          verdicts << { 'index' => index, 'verdict' => 'denied' }
          next
        end
        p = view['p'].call(vs['verb'], idx)
        if p <= 0
          verdicts << { 'index' => index, 'verdict' => 'denied' }
          next
        end
        if p >= 1
          verdicts << { 'index' => index, 'verdict' => 'admitted' }
          next
        end
        key = W.cell_key(vs['verb'], idx)
        if inp['asked'].include?(key)
          verdicts << { 'index' => index, 'verdict' => 'asked' }
          next
        end
        verdicts << { 'index' => index, 'verdict' => 'uncertain' }
        next if seen.include?(key)

        seen << key
        ig = information_gain(p, inp['etaPos'], inp['etaNeg'])
        s = O.cell_stats(vs, idx, harm)
        c2 = { 'index' => index, 'verb' => vs['verb'], 'idx' => idx, 'p' => p, 'ig' => ig, 'weight' => s['mass'] * s['harm'], 'flat' => W.flat_index(vs, idx) }
        if best.nil? || c2['ig'] > best['ig'] + 1e-12 ||
           ((c2['ig'] - best['ig']).abs <= 1e-12 && (c2['weight'] > best['weight'] || (c2['weight'] == best['weight'] && c2['flat'] < best['flat'])))
          best = c2
        end
      end
      ask = best.nil? ? nil : { 'index' => best['index'], 'verb' => best['verb'], 'idx' => best['idx'], 'p' => best['p'], 'ig' => best['ig'] }
      { 'verdicts' => verdicts, 'ask' => ask }
    end
  end
end
