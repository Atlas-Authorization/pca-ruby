# frozen_string_literal: true

# The hosted action registry of one instance: the publish gate and the verifier's view of the active versions (native port of
# hosted.ts of the TypeScript reference @atlasauth/pca-actions). Pure: storage, keys and time are the caller's. Fail closed everywhere:
# an action the view does not know, that no pinned reviewer key confirmed, or that is deprecated gets the top of the trait registry,
# no provenance facts, is irreversible and never undoable.
require 'set'
require_relative 'actions'
require_relative 'actions_build'
require_relative 'actions_diff'
require_relative 'actions_effective'
require_relative 'actions_registry'
require_relative 'actions_review'
require_relative 'actions_rules'
require_relative 'actions_render'
require_relative 'actions_undo'
require_relative 'authorize'

module AtlasPca
  module ActionsHosted
    A = AtlasPca::Actions
    E = AtlasPca::ActionsEffective
    RU = AtlasPca::ActionsRules
    RULES_DOC_KIND = 'pca-action-rules'
    HOSTED_VERSION_DOMAIN = 'atlas-pca/hosted-action-version/v1'
    PLAIN_SEMVER = /\A[0-9]+\.[0-9]+\.[0-9]+\z/
    EFFECTIVE_DIMS = %w[confirmation effective.traits effective.profile].freeze
    SERVER_CLASS = { 'reversible' => 'reversible', 'rate_limited' => 'costly', 'irreversible' => 'irreversible' }.freeze

    module_function

    def u16key(s) = A.u16key(s)
    def js(v) = RU.js_str(v)

    # The trait registry of a version: core plus its custom traits. Raises for custom traits that do not extend their implies.
    def registry_of_traits(traits) = traits.empty? ? A::CORE_REGISTRY : A.extend_registry(A::CORE_REGISTRY, traits)

    # The confirmation verifier of an instance: a signature by a pinned reviewer key (no pins: nothing is confirmed).
    def review_opts_of(pins, reg) = pins.nil? ? nil : ActionsReview.attestation_verifier(reg, pins)

    # nil iff `x` is a rules document for `ns` whose every verb is in `defs` and whose rules lint without errors.
    def rules_doc_error(x, ns, defs)
      return 'rules must be a pca-action-rules document' unless x.is_a?(Hash)

      x.each_key { |k| return "rules: unknown member '#{k}'" unless %w[v kind ns rules reviews].include?(k) }
      return "rules: not a #{RULES_DOC_KIND} v1 document" if x['v'] != 1 || x['v'] == true || x['kind'] != RULES_DOC_KIND
      return "rules: ns '#{js(x.key?('ns') ? x['ns'] : nil)}' is not the pack's '#{ns}'" if x['ns'] != ns
      return 'rules.rules must map verbs to rules blocks' unless x['rules'].is_a?(Hash)
      return 'rules.reviews must map verbs to rules reviews' if x.key?('reviews') && !x['reviews'].is_a?(Hash)

      by_verb = defs.to_h { |d| [d['verb'], d] }
      x['rules'].each do |verb, block|
        d = by_verb[verb]
        return "rules: '#{verb}' is not an action of the pack" if d.nil?

        errs = RU.lint_business_rules(d, block).select { |f| f['severity'] == 'error' }
        return "rules for '#{verb}': #{errs.map { |f| f['message'] }.join('; ')}" unless errs.empty?
      end
      (x['reviews'] || {}).each_key { |verb| return "rules.reviews: '#{verb}' is not an action of the pack" unless by_verb.key?(verb) }
      nil
    end

    def hosted_version_digest(v)
      AtlasPca.hash_canonical({ 'd' => HOSTED_VERSION_DOMAIN, 'pack' => v['pack'], 'rules' => v['rules'], 'traits' => v['traits'],
                                'deprecated' => v['deprecated'].sort_by { |s| u16key(s) } })
    end

    def fail_v(code, reason, verbs = nil)
      out = { 'ok' => false, 'code' => code, 'reason' => reason }
      out['verbs'] = verbs if verbs && !verbs.empty?
      out
    end

    def safe_confirmed(d, review)
      E.confirmed?(d, review)
    rescue StandardError
      false
    end

    # diff_defs, but each side under its own registry and review (a trait registry change shows up in the effective dimensions).
    def diff_defs_across(o, n, o_reg, n_reg, o_rev, n_rev)
      base = ActionsDiff.diff_defs(o, n, n_reg, n_rev)
      return base if o_reg.equal?(n_reg)

      eo = E.effective_with(o, o_reg, o_rev)['eff']
      en = E.effective_with(n, n_reg, n_rev)['eff']
      rel = A.leq(eo, en) ? (A.leq(en, eo) ? nil : 'narrow') : (A.leq(en, eo) ? 'widen' : 'incomparable')
      return base if rel.nil?

      reasons = (base['reasons'].reject { |r| r.start_with?('effective.profile') } + ["effective.profile: #{rel}"]).sort_by { |s| u16key(s) }
      bc = base['class']
      cls = if rel == 'incomparable' || bc == 'incomparable' || (rel == 'widen' && bc == 'narrow') || (rel == 'narrow' && bc == 'widen') then 'incomparable'
            elsif rel == 'widen' || bc == 'widen' then 'widen'
            else 'narrow'
            end
      { 'class' => cls, 'reasons' => reasons }
    end

    # Decide whether a version may become the active one of its namespace and compute what it changes. i: {current?, pack, rules?, traits?,
    # publisherKeys, pins, pin?}. Refused: bad_pack, bad_traits, bad_rules, ns_mismatch, bad_version / not_newer, widen_unreviewed.
    def publish_gate(i)
      traits = []
      if i.key?('traits')
        return fail_v('bad_traits', 'traits must be a list of trait definitions') unless i['traits'].is_a?(Array)

        traits = i['traits']
      end
      reg = begin
        registry_of_traits(traits)
      rescue StandardError => e
        return fail_v('bad_traits', e.message)
      end
      pv = ActionsBuild.verify_signed_pack(i['pack'], i['publisherKeys'], reg)
      return fail_v('bad_pack', pv['reason']) unless pv['ok']

      pack = i['pack']
      return fail_v('bad_version', "version '#{pack['version']}' must be MAJOR.MINOR.PATCH") unless PLAIN_SEMVER.match?(pack['version'])

      cur = i['current']
      return fail_v('ns_mismatch', "the active namespace is '#{cur['ns']}', the pack is '#{pack['ns']}'") if cur && cur['ns'] != pack['ns']
      if cur && !i['pin'] && ActionsRegistry.compare_versions(pack['version'], cur['version']) <= 0
        return fail_v('not_newer', "version #{pack['version']} is not above the active #{cur['version']}")
      end

      rules = i.key?('rules') ? i['rules'] : { 'v' => 1, 'kind' => RULES_DOC_KIND, 'ns' => pack['ns'], 'rules' => {} }
      re_ = rules_doc_error(rules, pack['ns'], pack['defs'])
      return fail_v('bad_rules', re_) if re_

      pins = i['pins']
      review = review_opts_of(pins, reg)
      prev_reg = reg
      if cur
        prev_reg = begin
          registry_of_traits(cur['traits'])
        rescue StandardError
          reg
        end
      end
      prev_review = review_opts_of(pins, prev_reg)
      changes = []
      blocked = []
      reasons = []
      old_defs = (cur ? cur['pack']['defs'] : []).to_h { |d| [d['verb'], d] }
      old_dep = cur ? Set.new(cur['deprecated']) : Set.new
      new_verbs = Set.new(pack['defs'].map { |d| d['verb'] })
      pack['defs'].each do |n|
        o = old_defs[n['verb']]
        new_rules = rules['rules'][n['verb']]
        confirmed = safe_confirmed(n, review)
        if o.nil? || old_dep.include?(n['verb'])
          change = { 'verb' => n['verb'], 'class' => 'added', 'reasons' => [] }
          change['reviewed'] = true if confirmed
        else
          d = diff_defs_across(o, n, prev_reg, reg, prev_review, review)
          change = { 'verb' => n['verb'], 'class' => d['class'], 'reasons' => d['reasons'] }
          if d['reasons'].any? { |r| EFFECTIVE_DIMS.any? { |dim| r.start_with?("#{dim}: widen") || r.start_with?("#{dim}: incomparable") } }
            if confirmed
              change['reviewed'] = true
            else
              blocked << n['verb']
              reasons << "#{n['verb']}: its effective authority widens without a valid confirmation of the new definition"
            end
          end
        end
        old_rules = !o.nil? && !old_dep.include?(n['verb']) ? cur['rules']['rules'][n['verb']] : nil
        if !old_rules.nil? || !new_rules.nil?
          rd = begin
            RU.diff_business_rules(n, old_rules, new_rules)
          rescue StandardError => e
            { 'class' => 'incomparable', 'reasons' => ["rules: #{e.message}"] }
          end
          change['rules'] = rd if rd['class'] != 'equal'
          if %w[widen incomparable].include?(rd['class'])
            err = RU.rules_review_error((rules['reviews'] || {})[n['verb']], n, new_rules.nil? ? {} : new_rules, pins)
            if err.nil?
              change['reviewed'] = true
            else
              blocked << n['verb']
              reasons << "#{n['verb']}: its business rules widen (#{rd['reasons'].join(', ')}) without a valid rules review: #{err}"
            end
          end
        end
        changes << change if change['class'] != 'equal' || change['rules']
      end
      deprecated = Set.new(old_dep.reject { |v| new_verbs.include?(v) })
      old_defs.each_key do |v|
        next if new_verbs.include?(v) || old_dep.include?(v)

        deprecated << v
        changes << { 'verb' => v, 'class' => 'deprecated', 'reasons' => ['removed from the namespace: treated as unknown'] }
      end
      changes.sort_by! { |c| u16key(c['verb']) }
      unless blocked.empty?
        out = fail_v('widen_unreviewed', reasons.join("\n"), blocked.uniq.sort_by { |s| u16key(s) })
        out['changes'] = changes
        return out
      end
      body = { 'pack' => pack, 'rules' => rules, 'traits' => traits, 'deprecated' => deprecated.to_a.sort_by { |s| u16key(s) } }
      { 'ok' => true, 'version' => { 'ns' => pack['ns'], 'version' => pack['version'], 'digest' => hosted_version_digest(body), 'prev' => cur ? cur['digest'] : nil,
                                     **body, 'changes' => changes } }
    end

    # ---- the verifier's view
    # Grant facts for rule 22 from a stored grant: envelope caveat types plus the pin block's caveats and escalation tiers.
    def grant_facts_of(grant)
      env = AtlasPca.read_envelope(grant)
      a = env.is_a?(Hash) ? env['actions'] : nil
      a = {} unless a.is_a?(Hash)
      tier = ->(v, d) { v.is_a?(Integer) && v >= 0 && v <= 3 ? v : d }
      caveats = ((env.is_a?(Hash) ? env['caveats'] : nil) || []).map { |c| c.is_a?(Hash) ? c['type'] : nil }
      caveats += a['caveats'] if a['caveats'].is_a?(Array)
      { 'caveats' => caveats.select { |t| t.is_a?(String) }, 'max_esc' => tier.call(a['max_esc'], 3), 'preauth_esc' => tier.call(a['preauth_esc'], 0) }
    end

    # A rules block that no longer compiles denies every call of its action (its tightening must not silently disappear).
    def broken_rules(verb)
      { 'v' => 1, 'verb' => verb, 'rules_digest' => '', 'def_digest' => '',
        'tighten' => [{ 'id' => 'rules_broken', 'when' => { 'field' => 'action.verb', 'op' => 'eq', 'value' => verb }, 'signal' => 'deny',
                        'reason' => 'the business rules of this action no longer compile' }], 'accumulators' => [] }
    end

    # The verifier's view: lookup(verb), provenance(op), undo_plan(op), floor(verb, grant, call_context).
    class HostedView
      attr_reader :versions, :pins, :deprecated, :top

      def initialize(versions, pins)
        h = ActionsHosted
        @pins = pins
        @by_verb = {}
        @deprecated = Set.new
        regs = []
        @versions = []
        @broken = Set.new
        versions.each do |v|
          @versions << "#{v['ns']}@#{v['version']}"
          begin
            reg = h.registry_of_traits(v['traits'])
          rescue StandardError
            ((v['pack'] || {})['defs'] || []).each { |d| @broken << d['verb'] if d.is_a?(Hash) && d['verb'].is_a?(String) }
            next
          end
          regs << reg
          review = h.review_opts_of(pins, reg)
          v['pack']['defs'].each do |d|
            next if @by_verb.key?(d['verb'])

            e = { 'def' => d, 'reg' => reg, 'review' => review }
            e['rules'] = v['rules']['rules'][d['verb']] if v['rules']['rules'][d['verb']]
            @by_verb[d['verb']] = e
          end
          @deprecated.merge(v['deprecated'])
        end
        (@deprecated | @broken).each { |x| @by_verb.delete(x) }
        @top = if regs.empty?
                 A.floor_of(A::CORE_REGISTRY, A.top_traits(A::CORE_REGISTRY))
               else
                 tops = regs.map { |r| A.floor_of(r, A.top_traits(r)) }
                 tops[1..].reduce(tops[0]) { |acc, b| A.leq(acc, b) ? b : A.leq(b, acc) ? acc : A.join(acc, b) }
               end
        @top_trait_ids = (regs.empty? ? [A::CORE_REGISTRY] : regs).flat_map { |r| A.top_traits(r) }.uniq.sort_by { |s| h.u16key(s) }
        @cache = {}
        @prov = {}
        @by_verb.each do |verb, e|
          @prov[verb] = ActionsRender.provenance_info_of(e['def'], e['reg'], e['review']) if h.safe_confirmed(e['def'], e['review'])
        rescue StandardError
          nil # unknown: sensitive
        end
        groups = {}
        @by_verb.each_value { |e| (groups[e['reg'].object_id] ||= { 'reg' => e['reg'], 'defs' => [] })['defs'] << e['def'] }
        @undo = groups.transform_values { |g| ActionsUndo.undo_engine(g['defs'], pins, g['reg']) }
      end

      def lookup(verb)
        hit = @cache[verb]
        return hit unless hit.nil?

        e = @by_verb[verb]
        out = { 'verb' => verb, 'confirmed' => false, 'known' => !e.nil?, 'deprecated' => @deprecated.include?(verb), 'profile' => @top,
                'traits' => @top_trait_ids, 'serverClass' => 'irreversible' }
        out = out.merge('known' => true, 'rules' => ActionsHosted.broken_rules(verb)) if e.nil? && @broken.include?(verb) && !@deprecated.include?(verb)
        unless e.nil?
          begin
            eff = ActionsEffective.effective_with(e['def'], e['reg'], e['review'])
            confirmed = eff['confirmed'] == true
            idem = (e['def']['idempotency'] || {})['mode'] == 'key_param' ? e['def']['idempotency']['param'] : nil
            nxt = out.merge('def_digest' => A.def_digest(e['def']), 'confirmed' => confirmed)
            nxt['idempotency_param'] = idem unless idem.nil?
            nxt.merge!('profile' => eff['eff'], 'traits' => eff['traits'], 'serverClass' => SERVER_CLASS.fetch(eff['eff']['rev'])) if confirmed
            nxt['rules'] = RU.compile_business_rules(e['def'], e['rules']) if e['rules']
            out = nxt
          rescue StandardError
            out = out.merge('confirmed' => false, 'profile' => @top, 'traits' => @top_trait_ids, 'serverClass' => 'irreversible', 'rules' => ActionsHosted.broken_rules(verb))
          end
        end
        @cache[verb] = out
      end

      def provenance(op) = @prov[op['verb']]

      def undo_plan(op)
        e = @by_verb[op['verb']]
        e.nil? ? nil : @undo[e['reg'].object_id].call(op)
      end

      def floor(verb, grant, call_context)
        kinds = grant['caveats'].select { |c| A::CAVEAT_KINDS.include?(c) }
        A.floor_decision({ 'caveats' => kinds, 'max_esc' => grant['max_esc'], 'preauth_esc' => grant['preauth_esc'] }, { 'context' => call_context }, lookup(verb)['profile'])
      rescue StandardError
        'deny'
      end
    end

    def hosted_view(versions, pins) = HostedView.new(versions, pins)

    # The context keys the hosted server itself establishes for a call: fresh revocation always; an idempotency key when one is present.
    def hosted_call_context(l, params)
      out = ['fresh_revocation']
      k = (l || {})['idempotency_param']
      raise TypeError, "Cannot read properties of null (reading '#{k}')" if !k.nil? && params.nil?

      out << 'idempotency' if !k.nil? && params[k].is_a?(String) && !params[k].empty?
      out
    end

    # The event keys of a rules block's rate limits: verb, window and scope id (never a rule index or the rules digest).
    def rate_keys_of(c, who)
      c['accumulators'].map do |a|
        scope = a['scope'] == 'org' ? 'org' : 'principal'
        i = scope == 'org' ? who['org'] : who['principal']
        ms = a['win']['kind'] == 'task' ? 0 : a['win']['ms']
        e = { 'id' => a['id'], 'ms' => ms }
        e['key'] = "#{c['verb']}|#{ms}|#{scope}:#{i}" if i.is_a?(String) && !i.empty? && ms.positive?
        e
      end
    end
  end
end
