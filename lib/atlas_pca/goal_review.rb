# frozen_string_literal: true

require_relative 'goal_js'
require_relative 'goal_card'
require_relative 'goal_codec'
require_relative 'goal_digests'
require_relative 'goal_examples'
require_relative 'goal_sign'

module AtlasPca
  # Principal review and signing for a Goal IR (the TypeScript reference is @atlasauth/pca-goal `review`).
  #
  # PolicyCard: a deterministic, template-only rendering of the WHOLE Goal from the same phrase table as the plain text card, with
  # exact numbers. Lossless-or-refuse: a clause that cannot be rendered and digested makes the card fail; the card is never
  # truncated. The reviewer-fatigue limits (REVIEW_LIMITS) are hard caps that REFUSE a goal or diff that is too large to read;
  # callers may only tighten them. Semantic diff: clause-level, widenings first; anything not PROVEN narrower counts as a widening.
  # GoalApproval: a pinned reviewer signs the digests of goal, compiled policy, card, ontology, tests, instruction and model set;
  # `load_approved_goal` trusts nothing the submission claims about itself (recomputes every digest, recompiles, re-renders,
  # re-runs the confirmed examples) and never raises.
  #
  # The compiler is injected as a ReviewKernel: `compile(goal, ont)`, `policy_digest(policy)`, and optionally `analyze(policy)`,
  # `decide(goal, ont, act, hist)` and `newly_allowed(prev, next, ont, limit)`; each a callable (GoalCompiler.proved_kernel is the
  # proved one).
  module GoalReview
    J = GoalJs
    ReviewKernel = Struct.new(:compile, :policy_digest, :analyze, :decide, :newly_allowed)
    REVIEW_LIMITS = { 'max_grants' => 32, 'max_prohibits' => 64, 'max_bounds' => 32, 'max_escalate_on' => 32, 'max_examples' => 40, 'max_card_lines' => 200,
                      'max_card_bytes' => 24_576, 'max_diff_changes' => 60, 'max_diff_widenings' => 12, 'max_witnesses' => 20 }.freeze
    D_CARD = 'atlas-pca/policy-card/v1'
    D_CLAUSE = 'atlas-pca/goal-clause/v1'
    GOAL_APPROVAL_KIND = 'goal-approval'
    MAX_GOAL_APPROVAL_TTL_MS = 24 * 3_600_000
    DEFAULT_TTL_MS = 3_600_000
    GOAL_APPROVAL_SIGNED_FIELDS = %w[v goal_digest policy_digest card_digest ontology_digest tests_digest nl_digest model_set_digest reviewer approved_at expires_at].freeze
    FIELD_REASON = [%w[goal_digest goal_digest_mismatch], %w[policy_digest policy_digest_mismatch], %w[ontology_digest ontology_mismatch],
                    %w[tests_digest tests_digest_mismatch], %w[nl_digest nl_digest_mismatch], %w[model_set_digest model_set_digest_mismatch],
                    %w[card_digest card_digest_mismatch]].freeze

    class ReviewError < StandardError
      attr_reader :code

      def initialize(code, detail)
        super("goal review: #{code}: #{detail}")
        @code = code
      end
    end

    module_function

    # Caller overrides may only TIGHTEN a limit (a larger number is ignored).
    def effective_limits(o = nil)
      out = REVIEW_LIMITS.dup
      if J.truthy(o)
        out.each_key do |k|
          v = o.is_a?(Hash) ? o[k] : nil
          out[k] = v.to_i if GoalCodec.safe_int?(v) && v >= 0 && v < out[k]
        end
      end
      out
    end

    def json_of(v)
      AtlasPca.canonicalize(v)
    rescue StandardError
      raise ReviewError.new('unrenderable', 'a clause has no canonical form (float, undefined or cycle)')
    end

    def line(id, kind, text, clause, severity = 'info')
      { 'id' => id, 'kind' => kind, 'severity' => severity, 'text' => text, 'clause_digest' => AtlasPca.hash_canonical({ 'd' => D_CLAUSE, 'kind' => kind, 'clause' => clause }) }
    end

    # Clause text through the shared phrase table; an unknown clause shape is shown as its canonical JSON, never dropped.
    def safe_text(clause)
      t = yield
      raise ArgumentError, 'unknown clause shape' if t.include?('undefined')

      t
    rescue StandardError
      json_of(clause)
    end

    def go(goal)
      GoalDigests.goal_digest(goal)
    rescue StandardError
      raise ReviewError.new('unrenderable', 'the Goal has no canonical form (float, undefined or cycle)')
    end

    # Render the card. Deterministic, no model, no locale. Raises ReviewError: `holes` (a draft is not reviewable for signing),
    # `wildcard_unacknowledged`, `card_too_large` (a fatigue cap), `unrenderable`. `opts['allowHoles']` renders a DRAFT for display.
    def render_policy_card(goal, tests = nil, opts = nil)
      tests = [] if tests.nil?
      opts ||= {}
      lim = effective_limits(opts['limits'])
      big = lambda do |what, n, mx|
        raise ReviewError.new('card_too_large', "#{n} #{what} exceed the cap of #{mx}: split the goal into smaller goals") if n > mx
      end
      unless goal.is_a?(Hash) && %w[grants prohibits bounds escalateOn holes].all? { |k| goal[k].is_a?(Array) } && goal['validity'].is_a?(Hash) && goal['deleg'].is_a?(Hash)
        raise ReviewError.new('unrenderable', 'not a Goal IR')
      end

      big.call('grants', goal['grants'].length, lim['max_grants'])
      big.call('prohibitions', goal['prohibits'].length, lim['max_prohibits'])
      big.call('bounds', goal['bounds'].length, lim['max_bounds'])
      big.call('escalation triggers', goal['escalateOn'].length, lim['max_escalate_on'])
      big.call('boundary examples', tests.length, lim['max_examples'])
      big.call('card lines', 4 + goal['grants'].length + goal['prohibits'].length + goal['bounds'].length + goal['escalateOn'].length + goal['holes'].length + tests.length,
               lim['max_card_lines'])
      raise ReviewError.new('holes', "#{goal['holes'].length} unresolved question(s): a goal with holes is a draft and cannot be signed") if goal['holes'].length.positive? && !J.truthy(opts['allowHoles'])

      wa = goal['wildcardAck']
      ack = wa.is_a?(Array) ? wa : []
      principal = goal.key?('principal') ? goal['principal'] : J::UNDEF
      lines = []
      lines << line('principal', 'meta', "Acting for principal #{json_of(principal)}. Nothing outside this card is allowed (default deny).", principal)
      goal['grants'].each do |g|
        res = J.jget(g, 'res')
        wild = !res.nil? && !J.undef?(res) ? J.jget(res, 'k') == 'any' : false
        raise ReviewError.new('wildcard_unacknowledged', "grant #{json_of(J.jget(g, 'gid'))} allows ANY resource without a wildcard acknowledgement") if wild && !J.includes(ack, J.jget(g, 'gid'))

        lines << line(J.jget(g, 'gid'), 'grant', safe_text(g) { "#{GoalCard.grant_line(g)}.#{wild ? ' WILDCARD acknowledged by the principal.' : ''}" }, g, wild ? 'red' : 'info')
      end
      goal['prohibits'].each do |p|
        pr = J.jget(p, 'res')
        lines << line(J.jget(p, 'pid'), 'prohibit', safe_text(p) { "#{GoalCard.prohibit_line(p)}." }, p, !pr.nil? && !J.undef?(pr) && J.jget(pr, 'k') == 'any' ? 'red' : 'info')
      end
      goal['bounds'].each { |b| lines << line(J.jget(b, 'bid'), 'bound', safe_text(b) { "#{GoalCard.bound_line(b)}." }, b) }
      lines << line('validity', 'validity', safe_text(goal['validity']) { "#{GoalCard.validity_line(goal['validity'])}." }, goal['validity'])
      nar = goal['deleg'].key?('narrowOnly') ? goal['deleg']['narrowOnly'] : J::UNDEF
      lines << line('delegation', 'delegation', safe_text(goal['deleg']) { "#{GoalCard.delegation_line(goal['deleg'])}." }, goal['deleg'], J.truthy(nar) ? 'info' : 'red')
      goal['escalateOn'].each_with_index { |c, i| lines << line("escalate_on[#{i}]", 'escalate', safe_text(c) { "#{GoalCard.escalate_line(c)}." }, c) }
      goal['holes'].each_with_index { |h, i| lines << line("hole[#{i}]", 'hole', safe_text(h) { "#{GoalCard.hole_line(h)}. Everything depending on it is dropped." }, h, 'red') }
      tests.each do |t|
        act = J.jget(t, 'act')
        n = J.jget(J.jget(t, 'hist'), 'adms').length
        ans = J.jget(t, 'answer')
        lines << line("example:#{J.js_str(J.jget(t, 'id'))}", 'example',
                      "EXAMPLE you confirmed: #{json_of(J.jget(act, 'verb'))} on #{json_of(J.jget(act, 'res'))} with #{json_of(J.jget(act, 'params'))}" \
                      "#{n.positive? ? " after #{n} earlier admitted action(s)" : ''} must be #{ans == 'ask' ? 'ASKED about' : (ans == 'allow' ? 'ALLOWED' : 'DENIED')}.", t)
      end
      big.call('card lines', lines.length, lim['max_card_lines'])
      card = { 'v' => 1, 'goal_digest' => go(goal), 'ontology_digest' => goal.key?('ontDigest') ? goal['ontDigest'] : J::UNDEF,
               'nl_digest' => goal.key?('nlDigest') ? goal['nlDigest'] : J::UNDEF, 'principal' => principal, 'lines' => lines }
      card = card.reject { |_, v| J.undef?(v) }
      big.call('bytes of card', AtlasPca.canon_bytes(card).bytesize, lim['max_card_bytes'])
      card
    end

    def card_digest(card) = AtlasPca.hash_canonical({ 'd' => D_CARD, 'card' => card })

    # Plain-text form of a card for any console or terminal. Red lines are prefixed `!!`.
    def card_to_text(card) = card['lines'].map { |l| "#{l['severity'] == 'red' ? '!! ' : '   '}#{l['text']}" }.join("\n")

    # ---- semantic diff
    def same?(a, b) = json_of(a) == json_of(b)

    def conjuncts(c)
      k = J.jget(c, 'k')
      k == 'and' ? conjuncts(J.jget(c, 'a')) + conjuncts(J.jget(c, 'b')) : (k == 'true' ? [] : [c])
    end

    def where_no_wider?(old_w, new_w)
      have = conjuncts(new_w).map { |c| json_of(c) }
      conjuncts(old_w).all? { |c| have.include?(json_of(c)) }
    end

    def grant_dir(o, n)
      return 'neutral' if same?(o, n)

      J.strict_eq(J.jget(o, 'verb'), J.jget(n, 'verb')) && same?(J.jget(o, 'res'), J.jget(n, 'res')) && where_no_wider?(J.jget(o, 'cond'), J.jget(n, 'cond')) ? 'narrow' : 'unknown'
    end

    # A prohibition that triggers on MORE (old.cond is a conjunction containing new.cond) is a narrowing of the allow set.
    def prohibit_dir(o, n)
      return 'neutral' if same?(o, n)

      same?(J.jget(o, 'target'), J.jget(n, 'target')) && same?(J.jget(o, 'res'), J.jget(n, 'res')) && where_no_wider?(J.jget(n, 'cond'), J.jget(o, 'cond')) ? 'narrow' : 'unknown'
    end

    def bound_dir(o, n)
      return 'neutral' if same?(o, n)

      rest = ->(b) { b.merge('cap' => nil) }
      return 'unknown' if !same?(rest.call(o), rest.call(n)) || !same?(J.jget(J.jget(o, 'cap'), 'u'), J.jget(J.jget(n, 'cap'), 'u'))

      on = J.jget(J.jget(o, 'cap'), 'n')
      nn = J.jget(J.jget(n, 'cap'), 'n')
      nn < on ? 'narrow' : (nn > on ? 'widen' : 'neutral')
    end

    def idle(x) = x == 0 ? Float::INFINITY : x

    def validity_dir(o, n)
      return 'neutral' if same?(o, n)

      nb = J.jget(n, 'notBefore')
      na = J.jget(n, 'notAfter')
      ni = idle(J.jget(n, 'maxIdle'))
      ob = J.jget(o, 'notBefore')
      oa = J.jget(o, 'notAfter')
      oi = idle(J.jget(o, 'maxIdle'))
      nar = nb >= ob && na <= oa && ni <= oi
      wid = nb <= ob && na >= oa && ni >= oi
      nar ? 'narrow' : (wid ? 'widen' : 'unknown')
    end

    def delegation_dir(o, n)
      return 'neutral' if same?(o, n)

      touch_o = J.req_list(J.jget(o, 'mayTouch')).dup
      touch_n = J.req_list(J.jget(n, 'mayTouch')).dup
      sub = touch_n.all? { |x| J.includes(touch_o, x) }
      sup = touch_o.all? { |x| J.includes(touch_n, x) }
      on = J.truthy(J.jget(o, 'narrowOnly'))
      nn = J.truthy(J.jget(n, 'narrowOnly'))
      nar = J.jget(n, 'maxDepth') <= J.jget(o, 'maxDepth') && sub && (nn || !on)
      wid = J.jget(n, 'maxDepth') >= J.jget(o, 'maxDepth') && sup && (on || !nn)
      nar ? 'narrow' : (wid ? 'widen' : 'unknown')
    end

    def pairs(prev, nxt, kind, added, removed, changed, text)
      out = []
      pm = {}
      prev.each { |k, v| pm[k] = v }
      nm = nxt.map(&:first)
      nxt.each do |id, v|
        if !pm.key?(id)
          out << { 'change' => 'added', 'kind' => kind, 'id' => id, 'direction' => added, 'text' => "ADDED #{text.call(id, v)}" }
        elsif !same?(pm[id], v)
          out << { 'change' => 'changed', 'kind' => kind, 'id' => id, 'direction' => changed.call(pm[id], v), 'text' => "CHANGED #{text.call(id, v)} (was: #{text.call(id, pm[id])})" }
        end
      end
      prev.each { |id, v| out << { 'change' => 'removed', 'kind' => kind, 'id' => id, 'direction' => removed, 'text' => "REMOVED #{text.call(id, v)}" } unless nm.include?(id) }
      out
    end

    # Clause-level semantic diff between the goal a principal approved before and the one now proposed. Widenings first. Raises
    # ReviewError `diff_too_large` / `too_many_widenings` past the fatigue caps: a diff a human cannot read is not offered as one.
    def diff_goals(prev, nxt, kernel = nil, opts = nil)
      opts ||= {}
      lim = effective_limits(opts['limits'])
      gl = ->(id, g) { "grant #{json_of(id)}: #{json_of(J.jget(g, 'verb'))} on #{GoalCard.res(J.jget(g, 'res'))} when #{GoalCard.cond(J.jget(g, 'cond'))}" }
      pl = lambda do |id, p|
        t = J.jget(p, 'target')
        tgt = J.jget(t, 'k') == 'verb' ? json_of(J.jget(t, 'verb')) : "effect class #{json_of(J.jget(t, 'cls'))}"
        "prohibition #{json_of(id)}: #{tgt} on #{GoalCard.res(J.jget(p, 'res'))} when #{GoalCard.cond(J.jget(p, 'cond'))}"
      end
      keyed = ->(xs, key) { J.req_list(xs).map { |x| [J.jget(x, key), x] } }
      changes = pairs(keyed.call(J.jget(prev, 'grants'), 'gid'), keyed.call(J.jget(nxt, 'grants'), 'gid'), 'grant', 'widen', 'narrow', method(:grant_dir), gl) +
                pairs(keyed.call(J.jget(prev, 'prohibits'), 'pid'), keyed.call(J.jget(nxt, 'prohibits'), 'pid'), 'prohibit', 'narrow', 'widen', method(:prohibit_dir), pl) +
                pairs(keyed.call(J.jget(prev, 'bounds'), 'bid'), keyed.call(J.jget(nxt, 'bounds'), 'bid'), 'bound', 'narrow', 'widen', method(:bound_dir),
                      ->(id, b) { "bound #{json_of(id)}: #{GoalCard.bound_line(b)} (#{GoalCard.quantity(J.jget(b, 'cap'))})" }) +
                pairs(J.req_list(J.jget(prev, 'escalateOn')).map { |c| [json_of(c), c] }, J.req_list(J.jget(nxt, 'escalateOn')).map { |c| [json_of(c), c] }, 'escalate', 'narrow', 'widen',
                      ->(_a, _b) { 'unknown' }, ->(_id, c) { "escalation when #{GoalCard.cond(c)}" })
      pv = J.jget(prev, 'validity')
      nv = J.jget(nxt, 'validity')
      unless same?(pv, nv)
        changes << { 'change' => 'changed', 'kind' => 'validity', 'id' => 'validity', 'direction' => validity_dir(pv, nv), 'text' => "CHANGED validity: #{json_of(nv)} (was: #{json_of(pv)})" }
      end
      pd = J.jget(prev, 'deleg')
      nd = J.jget(nxt, 'deleg')
      unless same?(pd, nd)
        changes << { 'change' => 'changed', 'kind' => 'delegation', 'id' => 'delegation', 'direction' => delegation_dir(pd, nd), 'text' => "CHANGED delegation: #{json_of(nd)} (was: #{json_of(pd)})" }
      end
      # Identity of the actor, the vocabulary and the wildcard acknowledgements are never "neutral": a swap can widen.
      unless J.strict_eq(J.jget(prev, 'principal'), J.jget(nxt, 'principal'))
        changes << { 'change' => 'changed', 'kind' => 'meta', 'id' => 'principal', 'direction' => 'unknown',
                     'text' => "CHANGED principal: #{json_of(J.jget(nxt, 'principal'))} (was: #{json_of(J.jget(prev, 'principal'))})" }
      end
      unless J.strict_eq(J.jget(prev, 'ontDigest'), J.jget(nxt, 'ontDigest'))
        changes << { 'change' => 'changed', 'kind' => 'meta', 'id' => 'ontology', 'direction' => 'unknown',
                     'text' => "CHANGED ontology: every term now means what the new vocabulary says (was #{json_of(J.jget(prev, 'ontDigest'))}, now #{json_of(J.jget(nxt, 'ontDigest'))})" }
      end
      unless same?(J.jget(prev, 'wildcardAck'), J.jget(nxt, 'wildcardAck'))
        changes << { 'change' => 'changed', 'kind' => 'meta', 'id' => 'wildcard_ack', 'direction' => 'unknown',
                     'text' => "CHANGED wildcard acknowledgements: #{json_of(J.jget(nxt, 'wildcardAck'))} (was: #{json_of(J.jget(prev, 'wildcardAck'))})" }
      end
      unless J.strict_eq(J.jget(prev, 'nlDigest'), J.jget(nxt, 'nlDigest'))
        changes << { 'change' => 'changed', 'kind' => 'meta', 'id' => 'instruction', 'direction' => 'neutral', 'text' => 'CHANGED the instruction text the goal was interpreted from' }
      end
      wide = ->(c) { %w[widen unknown].include?(c['direction']) }
      widenings = changes.count(&wide)
      raise ReviewError.new('diff_too_large', "#{changes.length} changes exceed the cap of #{lim['max_diff_changes']}: review the new goal as a whole instead") if changes.length > lim['max_diff_changes']
      raise ReviewError.new('too_many_widenings', "#{widenings} widenings exceed the cap of #{lim['max_diff_widenings']} per review") if widenings > lim['max_diff_widenings']

      na = nil
      ont = opts['ontology']
      na = kernel.newly_allowed.call(prev, nxt, ont, lim['max_witnesses']) if J.truthy(ont) && !kernel.nil? && !kernel.newly_allowed.nil?
      { 'v' => 1, 'from_goal_digest' => go(prev), 'to_goal_digest' => go(nxt),
        'newly_allowed' => na ? na['witnesses'].first(lim['max_witnesses']) : [],
        'newly_allowed_complete' => na ? (J.truthy(na['complete']) && na['witnesses'].length <= lim['max_witnesses']) : false,
        'changes' => changes.select(&wide) + changes.reject(&wide), 'widenings' => widenings }
    end

    def diff_to_text(d)
      head = d['newly_allowed'].map { |w| "!! NEWLY ALLOWED: #{json_of(w['verb'])} on #{json_of(w['res'])} with #{json_of(w['params'])}" }
      head << '!! The list of newly allowed actions is incomplete or unavailable: read every widening below.' unless d['newly_allowed_complete']
      (head + d['changes'].map { |c| "#{%w[widen unknown].include?(c['direction']) ? '!! ' : '   '}#{c['text']}" }).join("\n")
    end

    # ---- GoalApproval
    def derive(sub, kernel, limits)
      bad = ->(reason) { { 'ok' => false, 'reason' => reason } }
      if !sub.is_a?(Hash) || !sub['goal'].is_a?(Hash) || !sub['ontology'].is_a?(Hash) || !sub['instruction'].is_a?(String) || !sub['model_set'].is_a?(Array) ||
         sub['model_set'].any? { |m| !m.is_a?(String) } || (sub.key?('tests') && !sub['tests'].is_a?(Array))
        return bad.call('malformed_submission')
      end

      tests = sub.key?('tests') ? sub['tests'] : []
      begin
        card = render_policy_card(sub['goal'], tests, limits.nil? ? {} : { 'limits' => limits })
      rescue ReviewError => e
        return bad.call(e.code)
      rescue StandardError
        return bad.call('malformed_goal')
      end
      begin
        gd = GoalDigests.goal_digest(sub['goal'])
        nl = GoalDigests.nl_digest(sub['instruction'])
        ts = GoalExamples.tests_digest(tests)
        ms = GoalDigests.model_set_digest(sub['model_set'])
      rescue StandardError
        return bad.call('malformed_goal')
      end
      return bad.call('instruction_mismatch') if !sub['goal']['nlDigest'].is_a?(String) || nl != sub['goal']['nlDigest']

      begin
        compiled = kernel.compile.call(sub['goal'], sub['ontology'])
      rescue StandardError
        return bad.call('compile_error')
      end
      return bad.call('compile_error') unless compiled['ok']

      begin
        found = kernel.analyze.nil? ? [] : kernel.analyze.call(compiled['policy'])
        return bad.call('analyzer_error') if (found.nil? ? [] : found).length.positive?

        pd = kernel.policy_digest.call(compiled['policy'])
      rescue StandardError
        return bad.call('analyzer_error')
      end
      if tests.length.positive?
        return bad.call('tests_unverifiable') if kernel.decide.nil?

        # Regression pin: the principal's confirmed examples must be reproduced by the policy we just compiled.
        tests.each do |t|
          got = begin
            kernel.decide.call(sub['goal'], J.truthy(J.jget(t, 'rels')) ? sub['ontology'].merge('rels' => t['rels']) : sub['ontology'], t['act'], t['hist'])
          rescue StandardError
            return bad.call('tests_unverifiable')
          end
          return bad.call('tests_contradicted') if got != GoalExamples.expected_decision(t['answer'])
        end
      end
      { 'ok' => true, 'policy' => compiled['policy'], 'digests' => {
        'goal_digest' => gd, 'policy_digest' => pd, 'card_digest' => card_digest(card), 'ontology_digest' => sub['goal']['ontDigest'],
        'tests_digest' => ts, 'nl_digest' => nl, 'model_set_digest' => ms
      } }
    end

    def now_ms = (Time.now.to_f * 1000).to_i

    # The human step: sign the exact goal. Re-derives everything the loader will; raises when the goal is not signable (holes,
    # wildcard without ack, card or diff over the fatigue caps, compile or analyzer failure, a test the compiled policy contradicts,
    # an instruction that does not match `nlDigest`). `opts`: kernel (required), now, ttlMs, limits, base, alg, pq.
    def approve_goal(sub, reviewer_secret, opts = nil)
      opts ||= {}
      now = opts['now']
      now = now_ms if now.nil?
      ttl = opts['ttlMs']
      ttl = DEFAULT_TTL_MS if ttl.nil?
      raise ArgumentError, 'approveGoal: invalid time or ttl' if !GoalCodec.safe_int?(now) || !GoalCodec.safe_int?(ttl) || ttl <= 0 || ttl > MAX_GOAL_APPROVAL_TTL_MS

      kernel = opts['kernel']
      raise ArgumentError, 'approveGoal: a review kernel is required' if kernel.nil?

      d = derive(sub, kernel, opts['limits'])
      raise ArgumentError, "approveGoal: #{d['reason']}" unless d['ok']

      diff_goals(opts['base'], sub['goal'], nil, { 'limits' => opts['limits'] }) unless opts['base'].nil?
      body = d['digests'].merge('v' => 1, 'reviewer' => GoalSign.signer_id(reviewer_secret), 'approved_at' => now.to_i, 'expires_at' => now.to_i + ttl.to_i)
      GoalSign.sign_goal_artifact(GOAL_APPROVAL_KIND, body, reviewer_secret, alg: opts['alg'], pq: opts['pq'])
    end

    def fail_with(reason) = { 'ok' => false, 'reason' => reason }

    # The only door from a submitted goal to an enforceable one. Recomputes the goal digest, recompiles the policy, re-renders the
    # card and re-derives the tests, instruction and model-set digests from the submission; trusts nothing the submission or the
    # approval says about itself. Never raises. `opts`: kernel (required), reviewers (pinned), ontology_digest, now, limits.
    def load_approved_goal(sub, approval, opts)
      now = opts['now']
      now = now_ms if now.nil?
      reviewers = opts['reviewers']
      return fail_with('no_reviewers_pinned') if !reviewers.is_a?(Array) || reviewers.empty?

      a = approval
      if !a.is_a?(Hash) || !(GoalCodec.safe_int?(a['v']) && a['v'] == 1) || !a['sig'].is_a?(String) || !a['reviewer'].is_a?(String) ||
         !GoalCodec.safe_int?(a['approved_at']) || !GoalCodec.safe_int?(a['expires_at']) || FIELD_REASON.any? { |f, _| !a[f].is_a?(String) }
        return fail_with('malformed_approval')
      end
      kernel = opts['kernel']
      return fail_with('malformed_approval') if kernel.nil?

      d = derive(sub, kernel, opts['limits'])
      return d unless d['ok']

      od = opts['ontology_digest']
      return fail_with('ontology_mismatch') if !od.nil? && !J.strict_eq(sub['goal']['ontDigest'], od)

      FIELD_REASON.each { |f, reason| return fail_with(reason) if a[f] != d['digests'][f] }
      return fail_with('reviewer_not_pinned') unless reviewers.any? { |p| (p.is_a?(String) ? p : J.jget(p, 'pk')) == a['reviewer'] }
      return fail_with('ttl_too_long') if a['expires_at'] - a['approved_at'] <= 0 || a['expires_at'] - a['approved_at'] > MAX_GOAL_APPROVAL_TTL_MS
      return fail_with('not_yet_valid') unless Js.num?(now) && now.to_f.finite? && a['approved_at'] <= now
      return fail_with('expired') unless Js.num?(now) && now.to_f.finite? && now < a['expires_at']
      return fail_with('bad_signature') unless GoalSign.verify_goal_artifact(GOAL_APPROVAL_KIND, a, 'reviewer', reviewers)

      ref = { 'goal_digest' => d['digests']['goal_digest'], 'policy_digest' => d['digests']['policy_digest'] }
      { 'ok' => true, 'approved' => { 'goal' => sub['goal'], 'ontology' => sub['ontology'], 'policy' => d['policy'], 'ref' => ref, 'goal_string' => AtlasPca.intent_goal_v3(ref),
                                      'intent_policy' => { 'approved_goal' => ref }, 'instruction' => sub['instruction'], 'reviewer' => a['reviewer'], 'expires_at' => a['expires_at'] } }
    rescue StandardError
      fail_with('malformed_approval')
    end
  end
end
