# frozen_string_literal: true

require_relative 'goal_error'

module AtlasPca
  # The goal kernel (the TypeScript reference is @atlasauth/pca-verified-core `goalCall` over the proved goal compiler):
  # typecheck / compile / decide (reference semantics and compiled policy with its witness) / render over TOKEN TAPES.
  # A tape is an Array of ['k', keyword] | ['i', integer] | ['s', string] tokens. First output token: i0 ok, i1 rejected
  # with reasons, i9 malformed input. A hand port checked against the reference's tape corpus, not the extracted code.
  module GoalKernel
    IrError = AtlasPca::Goal::IrError
    MAX_SAFE = 9_007_199_254_740_991
    OPS = %w[typecheck compile decideg decidep render].freeze

    Q = Struct.new(:u, :n)
    Grant = Struct.new(:gid, :verb, :res, :cond)
    Prohibit = Struct.new(:pid, :target, :res, :cond)
    BCore = Struct.new(:agg, :value, :key, :window, :scope, :cap, :on_exceed)
    Bound = Struct.new(:bid, :sel, :core)
    Validity = Struct.new(:not_before, :not_after, :max_idle)
    Delegation = Struct.new(:max_depth, :narrow_only, :may_touch)
    Hole = Struct.new(:hid, :q, :domain, :affects, :global)
    Goal = Struct.new(:v, :principal, :ont_digest, :nl_digest, :sources, :grants, :prohibits, :bounds, :validity, :deleg,
                      :escalate_on, :wildcard_ack, :holes)
    ParamDecl = Struct.new(:path, :ty)
    VerbDecl = Struct.new(:verb, :cls, :params)
    RelDecl = Struct.new(:rel, :anchor, :members)
    Ontology = Struct.new(:verbs, :rels)
    Act = Struct.new(:verb, :res, :params, :t, :sess, :prin, :org, :agent, :depth)
    Adm = Struct.new(:gid, :act)
    Hist = Struct.new(:adms, :last, :aggs)
    LSel = Struct.new(:gids, :verbs)
    LPred = Struct.new(:gid, :verb, :res, :cond)
    LProh = Struct.new(:pid, :verbs, :res, :cond)
    LCeil = Struct.new(:bid, :sel, :core)
    Pol = Struct.new(:preds, :prohs, :ceils, :escs, :validity, :deleg)

    # Terms: [:param, path, ty] [:lit, v] [:hist_agg, bid, unit]. Units: [:money, ccy] [:count] [:duration] [:instant] [:bytes]
    # [:ratio]. Values: [:vq, q] [:vs, s] [:vset, atoms]; atoms [:aq, q] [:as, s]. Types: [:tyq, unit] [:tys].
    # Conditions: [:ctrue] [:cmp, op, l, r] [:and, a, b] [:or, a, b] [:not, c]. Resource selectors: [:exact, id] [:oneof, ids]
    # [:related, rel, anchor] [:anyres, reason] [:allof, parts]; parts [:pexact, id] [:poneof, ids] [:prelated, rel, anchor].
    # Patterns: [:pstar] [:pset, ids]. Windows: [:wtask] [:wsliding, ms] [:wperiod, ms, t0] [:wlifetime]. Scopes: [:ssession]
    # [:sprincipal] [:sorg] [:sfleet, agents]. Normal-form conditions: [:ntrue] [:nfalse] [:natom, op, l, r] [:nand, a, b] [:nor, a, b].

    DENY = 0
    ESCALATE = 1
    ALLOW = 2
    OPS_BY_KW = %i[eq ne lt lte gt gte in nin].freeze
    AGGS = %i[count sum max distinct].freeze

    module_function

    # ---- Kleene truth and decisions (false < unknown < true; Deny < Escalate < Allow)
    def b2t(b) = b ? 2 : 0
    def and_k(a, b) = a <= b ? a : b
    def or_k(a, b) = a >= b ? a : b
    def not_k(a) = 2 - a

    # ---- values, terms and conditions
    def atom_v(a) = a[0] == :aq ? [:vq, a[1]] : [:vs, a[1]]

    def type_of_v(v)
      case v[0]
      when :vq then [:tyq, v[1].u]
      when :vs then [:tys]
      end
    end

    def eq_t(x, y)
      case x[0]
      when :vq then y[0] == :vq && x[1].u == y[1].u ? b2t(x[1].n == y[1].n) : 1
      when :vs then y[0] == :vs ? b2t(x[1] == y[1]) : 1
      else 1
      end
    end

    def lt_t(x, y) = x[0] == :vq && y[0] == :vq && x[1].u == y[1].u ? b2t(x[1].n < y[1].n) : 1
    def in_t(x, items) = items.map { |i| eq_t(x, atom_v(i)) }.max || 0

    def cmp_t(op, x, y)
      return 1 if x.nil? || y.nil?

      case op
      when :eq then eq_t(x, y)
      when :ne then not_k(eq_t(x, y))
      when :lt then lt_t(x, y)
      when :gte then not_k(lt_t(x, y))
      when :gt then lt_t(y, x)
      when :lte then not_k(lt_t(y, x))
      when :in then y[0] == :vset ? in_t(x, y[1]) : 1
      when :nin then not_k(y[0] == :vset ? in_t(x, y[1]) : 1)
      end
    end

    def neg_op(op) = { eq: :ne, ne: :eq, lt: :gte, gte: :lt, gt: :lte, lte: :gt, in: :nin, nin: :in }.fetch(op)

    def eval_t(t, a, h)
      case t[0]
      when :param then a.params[t[1]]
      when :lit then t[1]
      when :hist_agg then h.aggs.key?(t[1]) ? [:vq, h.aggs[t[1]]] : nil
      end
    end

    def eval_c(c, a, h)
      case c[0]
      when :ctrue then 2
      when :cmp then cmp_t(c[1], eval_t(c[2], a, h), eval_t(c[3], a, h))
      when :and then and_k(eval_c(c[1], a, h), eval_c(c[2], a, h))
      when :or then or_k(eval_c(c[1], a, h), eval_c(c[2], a, h))
      when :not then not_k(eval_c(c[1], a, h))
      end
    end

    def eval_n(c, a, h)
      case c[0]
      when :ntrue then 2
      when :nfalse then 0
      when :natom then cmp_t(c[1], eval_t(c[2], a, h), eval_t(c[3], a, h))
      when :nand then and_k(eval_n(c[1], a, h), eval_n(c[2], a, h))
      when :nor then or_k(eval_n(c[1], a, h), eval_n(c[2], a, h))
      end
    end

    # pos = the polarity: nnf(c, false) is the normal form of `not c`
    def nnf(c, pos)
      case c[0]
      when :ctrue then pos ? [:ntrue] : [:nfalse]
      when :cmp then [:natom, pos ? c[1] : neg_op(c[1]), c[2], c[3]]
      when :and then pos ? [:nand, nnf(c[1], true), nnf(c[2], true)] : [:nor, nnf(c[1], false), nnf(c[2], false)]
      when :or then pos ? [:nor, nnf(c[1], true), nnf(c[2], true)] : [:nand, nnf(c[1], false), nnf(c[2], false)]
      when :not then nnf(c[1], !pos)
      end
    end

    # ---- resource patterns
    def res_ok(p, r) = p[0] == :pstar || p[1].include?(r)

    def rel_members(rels, rel, anchor) = rels.find { |x| x.rel == rel && x.anchor == anchor }&.members || []

    def inter_pat(x, y)
      return y if x[0] == :pstar
      return x if y[0] == :pstar

      [:pset, x[1].select { |s| y[1].include?(s) }]
    end

    def resolve_part(ont, p)
      case p[0]
      when :pexact then [:pset, [p[1]]]
      when :poneof then [:pset, p[1]]
      when :prelated then [:pset, rel_members(ont.rels, p[1], p[2])]
      end
    end

    def resolve_sel(ont, s)
      case s[0]
      when :exact then [:pset, [s[1]]]
      when :oneof then [:pset, s[1]]
      when :related then [:pset, rel_members(ont.rels, s[1], s[2])]
      when :anyres then [:pstar]
      when :allof then s[1].reverse.reduce([:pstar]) { |acc, p| inter_pat(resolve_part(ont, p), acc) }
      end
    end

    def verbs_of_class(vs, cls) = vs.select { |v| v.cls == cls }.map(&:verb)
    def resolve_bsel(ont, s) = s[0] == :sel_gids ? LSel.new(s[1], []) : LSel.new([], verbs_of_class(ont.verbs, s[1]))
    def proh_verbs(ont, t) = t[0] == :pverb ? [t[1]] : verbs_of_class(ont.verbs, t[1])

    # ---- bounds
    def applies_l(s, gid, verb) = s.gids.include?(gid) || s.verbs.include?(verb)

    def in_scope(sc, a, x)
      case sc[0]
      when :ssession then a.sess == x.sess
      when :sprincipal then a.prin == x.prin
      when :sorg then a.org == x.org
      when :sfleet then sc[1].include?(a.agent) && sc[1].include?(x.agent)
      end
    end

    def in_window(w, a, x)
      case w[0]
      when :wtask, :wlifetime then true
      when :wsliding then x.t > a.t - w[1] && x.t <= a.t
      when :wperiod then w[1] > 0 && (a.t - w[2]).div(w[1]) == (x.t - w[2]).div(w[1])
      end
    end

    # the admitted actions this bound counts, followed by the candidate itself
    def sel_items(core, s, adms, a)
      adms.select { |m| applies_l(s, m.gid, m.act.verb) && in_scope(core.scope, a, m.act) && in_window(core.window, a, m.act) }
          .map(&:act) + [a]
    end

    def item_vals(core, items, h)
      items.map do |it|
        v = eval_t(core.value, it, h)
        return nil unless v && v[0] == :vq && v[1].u == core.cap.u

        v[1].n
      end
    end

    def key_vals(core, items)
      items.map do |it|
        return nil unless it.params.key?(core.key)

        it.params[core.key]
      end
    end

    # true / unknown / false = exceeded / unreadable / within
    def exceeded(core, items, h)
      case core.agg
      when :count then b2t(items.length > core.cap.n)
      when :sum then (xs = item_vals(core, items, h)) ? b2t(xs.sum > core.cap.n) : 1
      when :max
        xs = item_vals(core, items, h)
        xs.nil? || xs.empty? ? 1 : b2t(xs.max > core.cap.n)
      when :distinct then (vs = key_vals(core, items)) ? b2t(vs.uniq.length > core.cap.n) : 1
      end
    end

    def bound_stat(core, s, a, h)
      e = exceeded(core, sel_items(core, s, h.adms, a), h)
      return core.on_exceed == :on_deny ? DENY : ESCALATE if e == 2

      e == 1 ? ESCALATE : ALLOW
    end

    # ---- the decision D_G
    def validity_dec(v, dg, a, h)
      return DENY if a.t < v.not_before || a.t > v.not_after
      return DENY if v.max_idle > 0 && h.last >= 0 && a.t - h.last > v.max_idle
      return DENY if a.depth < 0 || a.depth > dg.max_depth

      ALLOW
    end

    def deleg_ok(dg, gid, a) = a.depth == 0 || dg.may_touch.include?(gid)
    def esc_one(m) = m == 0 ? ALLOW : ESCALATE

    def proh_one(verbs, res, ce, a, h)
      m = and_k(b2t(verbs.include?(a.verb)), and_k(b2t(res_ok(res, a.res)), ce))
      m == 2 ? DENY : m == 1 ? ESCALATE : ALLOW
    end

    def proh_dec_g(ont, ps, a, h)
      ps.map { |p| proh_one(proh_verbs(ont, p.target), resolve_sel(ont, p.res), eval_c(p.cond, a, h), a, h) }.min || ALLOW
    end

    def esc_dec_g(cs, a, h) = cs.map { |c| esc_one(eval_c(c, a, h)) }.min || ALLOW

    def bounds_dec_g(ont, bs, gid, a, h)
      bs.map do |b|
        s = resolve_bsel(ont, b.sel)
        applies_l(s, gid, a.verb) ? bound_stat(b.core, s, a, h) : ALLOW
      end.min || ALLOW
    end

    def grant_dec_g(ont, g, gr, a, h)
      m = and_k(b2t(a.verb == gr.verb && deleg_ok(g.deleg, gr.gid, a)),
                and_k(b2t(res_ok(resolve_sel(ont, gr.res), a.res)), eval_c(gr.cond, a, h)))
      [m, bounds_dec_g(ont, g.bounds, gr.gid, a, h)].min
    end

    def dg(ont, g, a, h)
      [validity_dec(g.validity, g.deleg, a, h), proh_dec_g(ont, g.prohibits, a, h), esc_dec_g(g.escalate_on, a, h),
       g.grants.map { |gr| grant_dec_g(ont, g, gr, a, h) }.max || DENY].min
    end

    # ---- the lowered policy and its decision D_P
    def proh_dec_p(ps, a, h)
      ps.map { |p| proh_one(p.verbs, p.res, eval_n(p.cond, a, h), a, h) }.min || ALLOW
    end

    def esc_dec_p(cs, a, h) = cs.map { |c| esc_one(eval_n(c, a, h)) }.min || ALLOW
    def ceils_dec_p(cs, gid, a, h) = cs.map { |c| applies_l(c.sel, gid, a.verb) ? bound_stat(c.core, c.sel, a, h) : ALLOW }.min || ALLOW

    def pred_dec(p, ceils, dg, a, h)
      m = and_k(b2t(a.verb == p.verb && deleg_ok(dg, p.gid, a)), and_k(b2t(res_ok(p.res, a.res)), eval_n(p.cond, a, h)))
      [m, ceils_dec_p(ceils, p.gid, a, h)].min
    end

    def dp(p, a, h)
      [validity_dec(p.validity, p.deleg, a, h), proh_dec_p(p.prohs, a, h), esc_dec_p(p.escs, a, h),
       p.preds.map { |x| pred_dec(x, p.ceils, p.deleg, a, h) }.max || DENY].min
    end

    # ---- typing
    def str_lt(a, b) = (a.b <=> b.b) < 0

    def strictly_sorted?(xs) = xs.each_cons(2).all? { |a, b| str_lt(a, b) }
    def unit_ok?(u) = u[0] != :money || !u[1].empty?
    def ty_ok?(t) = t[0] == :tys || unit_ok?(t[1])

    def v_ok?(v)
      case v[0]
      when :vq then unit_ok?(v[1].u)
      when :vs then true
      when :vset then v[1].all? { |i| i[0] == :as || unit_ok?(i[1].u) }
      end
    end

    def type_of_term(t)
      case t[0]
      when :param then t[2]
      when :lit then type_of_v(t[1])
      when :hist_agg then [:tyq, t[2]]
      end
    end

    def term_ok?(t)
      case t[0]
      when :param then !t[1].empty? && ty_ok?(t[2])
      when :lit then v_ok?(t[1])
      when :hist_agg then !t[1].empty? && unit_ok?(t[2])
      end
    end

    def cmp_typed?(op, l, r)
      return false unless term_ok?(l) && term_ok?(r) && (lt = type_of_term(l))

      case op
      when :eq, :ne then lt == type_of_term(r)
      when :lt, :lte, :gt, :gte then lt == type_of_term(r) && lt[0] == :tyq
      when :in, :nin then r[0] == :lit && r[1][0] == :vset && r[1][1].all? { |i| type_of_v(atom_v(i)) == lt }
      end
    end

    def cond_typed?(c, ok)
      case c[0]
      when :ctrue then true
      when :cmp then cmp_typed?(c[1], c[2], c[3]) && params_ok?(c[2], ok) && params_ok?(c[3], ok)
      when :and, :or then cond_typed?(c[1], ok) && cond_typed?(c[2], ok)
      when :not then cond_typed?(c[1], ok)
      end
    end

    def params_ok?(t, ok) = t[0] != :param || ok.call(t[1], t[2])
    def find_decl(vs, verb) = vs.find { |d| d.verb == verb }

    def declared_for?(ont, verbs, p, ty)
      verbs.all? { |v| (d = find_decl(ont.verbs, v)) && d.params.include?(ParamDecl.new(p, ty)) }
    end

    def no_conflict?(vs, p, ty) = vs.all? { |d| d.params.all? { |x| x.path != p || x.ty == ty } }
    def rel_declared?(ont, rel, anchor) = ont.rels.any? { |r| r.rel == rel && r.anchor == anchor }

    def part_ok?(ont, p)
      case p[0]
      when :pexact then !p[1].empty?
      when :poneof then !p[1].empty?
      when :prelated then rel_declared?(ont, p[1], p[2])
      end
    end

    def res_sel_ok?(ont, s)
      case s[0]
      when :exact, :oneof then !s[1].empty?
      when :related then rel_declared?(ont, s[1], s[2])
      when :anyres then true
      when :allof then s[1].length >= 2 && s[1].all? { |p| part_ok?(ont, p) }
      end
    end

    def grant_ok?(ont, g, gr)
      !gr.gid.empty? && find_decl(ont.verbs, gr.verb) && res_sel_ok?(ont, gr.res) &&
        (gr.res[0] != :anyres || g.wildcard_ack.include?(gr.gid)) &&
        cond_typed?(gr.cond, ->(p, ty) { declared_for?(ont, [gr.verb], p, ty) })
    end

    def prohibit_ok?(ont, p)
      return false unless !p.pid.empty? && res_sel_ok?(ont, p.res)

      tgt = p.target[0] == :pverb ? find_decl(ont.verbs, p.target[1]) : (!p.target[1].empty? && !verbs_of_class(ont.verbs, p.target[1]).empty?)
      tgt && cond_typed?(p.cond, ->(q, ty) { declared_for?(ont, proh_verbs(ont, p.target), q, ty) })
    end

    def window_ok?(w) = %i[wsliding wperiod].include?(w[0]) ? w[1] > 0 : true
    def scope_ok?(s) = s[0] != :sfleet || !s[1].empty?
    def gid_in?(g, id) = g.grants.any? { |x| x.gid == id }

    def bound_ok?(_ont, g, b)
      c = b.core
      return false unless !b.bid.empty? && term_ok?(c.value) && unit_ok?(c.cap.u) && c.cap.n >= 0 && window_ok?(c.window) && scope_ok?(c.scope)

      sel = b.sel[0] == :sel_gids ? (!b.sel[1].empty? && b.sel[1].all? { |id| gid_in?(g, id) }) : !b.sel[1].empty?
      return false unless sel

      case c.agg
      when :count then c.cap.u == [:count]
      when :sum, :max then type_of_term(c.value) == [:tyq, c.cap.u]
      when :distinct then c.cap.u == [:count] && !c.key.empty?
      end
    end

    def validity_ok?(v, dg, g)
      v.not_before <= v.not_after && v.max_idle >= 0 && dg.max_depth.between?(0, 16) && dg.narrow_only &&
        dg.may_touch.all? { |id| gid_in?(g, id) }
    end

    def hole_ok?(g, h) = !h.hid.empty? && h.affects.all? { |id| gid_in?(g, id) }
    def escs_typed?(ont, g) = g.escalate_on.all? { |c| cond_typed?(c, ->(p, ty) { no_conflict?(ont.verbs, p, ty) }) }

    def sorted4?(g)
      strictly_sorted?(g.grants.map(&:gid)) && strictly_sorted?(g.prohibits.map(&:pid)) &&
        strictly_sorted?(g.bounds.map(&:bid)) && strictly_sorted?(g.holes.map(&:hid))
    end

    def type_reasons(ont, g)
      r = []
      r << 'not_canonical_order' unless sorted4?(g)
      r << 'ill_typed_grant' unless g.grants.all? { |x| grant_ok?(ont, g, x) }
      r << 'ill_typed_prohibit' unless g.prohibits.all? { |x| prohibit_ok?(ont, x) }
      r << 'ill_typed_bound' unless g.bounds.all? { |x| bound_ok?(ont, g, x) }
      r << 'ill_typed_escalation' unless escs_typed?(ont, g)
      r << 'bad_validity_or_delegation' unless validity_ok?(g.validity, g.deleg, g)
      r << 'bad_hole' unless g.holes.all? { |x| hole_ok?(g, x) }
      r
    end

    # ---- compile: strip the grants a hole touches, then lower
    def depends_on?(hs, gid) = hs.any? { |h| h.global || h.affects.include?(gid) }

    def strip(g)
      g2 = g.dup
      g2.grants = g.grants.reject { |gr| depends_on?(g.holes, gr.gid) }
      g2.holes = []
      g2
    end

    def lower(ont, g)
      Pol.new(g.grants.map { |x| LPred.new(x.gid, x.verb, resolve_sel(ont, x.res), nnf(x.cond, true)) },
              g.prohibits.map { |x| LProh.new(x.pid, proh_verbs(ont, x.target), resolve_sel(ont, x.res), nnf(x.cond, true)) },
              g.bounds.map { |x| LCeil.new(x.bid, resolve_bsel(ont, x.sel), x.core) },
              g.escalate_on.map { |c| nnf(c, true) }, g.validity, g.deleg)
    end

    # [:compiled, pol] | [:escalate, reasons]
    def compile(ont, g)
      rs = type_reasons(ont, g)
      rs.empty? ? [:compiled, lower(ont, strip(g))] : [:escalate, rs]
    end

    # ---- witness
    def applicable(cs, gid, verb) = cs.select { |c| applies_l(c.sel, gid, verb) }.map(&:bid)

    # [decision, gid, bids]
    def decide_w(p, a, h)
      d = dp(p, a, h)
      return [d, '', []] unless d == ALLOW

      pr = p.preds.find { |x| pred_dec(x, p.ceils, p.deleg, a, h) == ALLOW }
      pr ? [ALLOW, pr.gid, applicable(p.ceils, pr.gid, a.verb)] : [DENY, '', []]
    end

    def verify_witness(p, a, h, gid, bids)
      validity_dec(p.validity, p.deleg, a, h) == ALLOW && proh_dec_p(p.prohs, a, h) == ALLOW && esc_dec_p(p.escs, a, h) == ALLOW &&
        p.preds.any? { |x| x.gid == gid && pred_dec(x, p.ceils, p.deleg, a, h) == ALLOW } && bids == applicable(p.ceils, gid, a.verb)
    end

    # ---- tape decoding (a fixed-order cursor; any mismatch throws :goal_fail, the reference's Fail)
    class Reader
      def initialize(ts)
        @ts = ts
        @i = 0
      end

      def fail! = throw(:goal_fail)
      def rest = @ts.length - @i
      def done? = @i >= @ts.length

      def tok
        t = @ts[@i] or fail!
        @i += 1
        t
      end

      def str = (t = tok)[0] == 's' ? t[1] : fail!
      def int = (t = tok)[0] == 'i' ? t[1] : fail!
      def kw = (t = tok)[0] == 'k' ? t[1] : fail!
      def expect(k) = kw == k || fail!
      def bool = (v = int) == 0 || v == 1 ? v == 1 : fail!

      def list
        n = int
        fail! if n.negative?
        out = []
        n.times { out << yield }
        out
      end

      def strs = list { str }

      def unit
        case kw
        when 300 then [:money, str]
        when 301 then [:count]
        when 302 then [:duration]
        when 303 then [:instant]
        when 304 then [:bytes]
        when 305 then [:ratio]
        else fail!
        end
      end

      def q = Q.new(unit, int)

      def ty
        case kw
        when 310 then [:tyq, unit]
        when 311 then [:tys]
        else fail!
        end
      end

      def atom
        case kw
        when 320 then [:aq, q]
        when 321 then [:as, str]
        else fail!
        end
      end

      def val
        case kw
        when 330 then [:vq, q]
        when 331 then [:vs, str]
        when 332 then [:vset, list { atom }]
        else fail!
        end
      end

      def term
        case kw
        when 340 then [:param, str, ty]
        when 341 then [:lit, val]
        when 342 then [:hist_agg, str, unit]
        else fail!
        end
      end

      def op = (k = kw) >= 350 && k <= 357 ? OPS_BY_KW[k - 350] : fail!

      def cond(fuel)
        fail! if fuel.zero?
        case kw
        when 360 then [:ctrue]
        when 361 then [:cmp, op, term, term]
        when 362 then (x = cond(fuel - 1)
                       [:and, x, cond(fuel - 1)])
        when 363 then (x = cond(fuel - 1)
                       [:or, x, cond(fuel - 1)])
        when 364 then [:not, cond(fuel - 1)]
        else fail!
        end
      end

      def cond_top = cond(rest)

      def part
        case kw
        when 375 then [:pexact, str]
        when 376 then [:poneof, strs]
        when 377 then [:prelated, str, str]
        else fail!
        end
      end

      def res_sel
        case kw
        when 370 then [:exact, str]
        when 371 then [:oneof, strs]
        when 372 then [:related, str, str]
        when 373 then [:anyres, str]
        when 374 then [:allof, list { part }]
        else fail!
        end
      end

      def grant = (expect(380)
                   Grant.new(str, str, res_sel, cond_top))

      def proh_target
        case kw
        when 390 then [:pverb, str]
        when 391 then [:peffect, str]
        else fail!
        end
      end

      def prohibit = (expect(392)
                      Prohibit.new(str, proh_target, res_sel, cond_top))

      def sel
        case kw
        when 410 then [:sel_gids, strs]
        when 411 then [:sel_effect, str]
        else fail!
        end
      end

      def window
        case kw
        when 420 then [:wtask]
        when 421 then [:wsliding, int]
        when 422 then (ms = int
                       [:wperiod, ms, int])
        when 423 then [:wlifetime]
        else fail!
        end
      end

      def scope
        case kw
        when 430 then [:ssession]
        when 431 then [:sprincipal]
        when 432 then [:sorg]
        when 433 then [:sfleet, strs]
        else fail!
        end
      end

      def on_exceed
        case kw
        when 440 then :on_deny
        when 441 then :on_escalate
        else fail!
        end
      end

      def bcore = (expect(450)
                   BCore.new(agg, term, str, window, scope, q, on_exceed))

      def agg = (k = kw) >= 400 && k <= 403 ? AGGS[k - 400] : fail!
      def bound = (expect(451)
                   Bound.new(str, sel, bcore))
      def validity = (expect(460)
                      Validity.new(int, int, int))
      def deleg = (expect(461)
                   Delegation.new(int, bool, strs))
      def hole = (expect(470)
                  Hole.new(str, str, strs, strs, bool))

      def goal
        fail! if rest < 5
        expect(480)
        v = int
        principal = str
        ont_d = str
        nl_d = str
        Goal.new(v, principal, ont_d, nl_d, strs, list { grant }, list { prohibit }, list { bound }, validity, deleg,
                 list { cond_top }, strs, list { hole })
      end

      def param_decl = (expect(500)
                        ParamDecl.new(str, ty))
      def verb_decl = (expect(501)
                       VerbDecl.new(str, str, list { param_decl }))
      def rel_decl = (expect(502)
                      RelDecl.new(str, str, strs))
      def ontology = (expect(510)
                      Ontology.new(list { verb_decl }, list { rel_decl }))

      # the first entry of a key wins (the reference applies the head over the decoded tail)
      def keyed(kwn)
        out = {}
        list { (expect(kwn)
                [str, yield]) }.each { |k, v| out[k] = v unless out.key?(k) }
        out
      end

      def act
        expect(530)
        verb = str
        res = str
        params = keyed(520) { val }
        Act.new(verb, res, params, int, str, str, str, str, int)
      end

      def adm = (expect(531)
                 Adm.new(str, act))
      def hist = (expect(541)
                  Hist.new(list { adm }, int, nil).tap { |h| h.aggs = keyed(540) { q } })
    end

    # parse a whole tape with `m` (a Reader method); nil when it does not parse or leaves tokens over
    def whole(ts, m)
      r = Reader.new(ts)
      v = catch(:goal_fail) { r.send(m) }
      v.nil? || !r.done? ? nil : v
    end

    # ---- tape encoding (the compiled policy)
    def tk(n) = ['k', n]
    def ti(n) = ['i', n]
    def ts_(s) = ['s', s]
    def enc_strs(xs) = [ti(xs.length)] + xs.map { |s| ts_(s) }

    def enc_unit(u)
      case u[0]
      when :money then [tk(300), ts_(u[1])]
      else [tk(301 + %i[count duration instant bytes ratio].index(u[0]))]
      end
    end

    def enc_q(q) = enc_unit(q.u) + [ti(q.n)]

    def enc_ty(t) = t[0] == :tyq ? [tk(310)] + enc_unit(t[1]) : [tk(311)]

    def enc_atom(a) = a[0] == :aq ? [tk(320)] + enc_q(a[1]) : [tk(321), ts_(a[1])]

    def enc_v(v)
      case v[0]
      when :vq then [tk(330)] + enc_q(v[1])
      when :vs then [tk(331), ts_(v[1])]
      when :vset then [tk(332), ti(v[1].length)] + v[1].flat_map { |a| enc_atom(a) }
      end
    end

    def enc_term(t)
      case t[0]
      when :param then [tk(340), ts_(t[1])] + enc_ty(t[2])
      when :lit then [tk(341)] + enc_v(t[1])
      when :hist_agg then [tk(342), ts_(t[1])] + enc_unit(t[2])
      end
    end

    def enc_op(op) = [tk(350 + OPS_BY_KW.index(op))]
    def enc_res_pat(p) = p[0] == :pstar ? [tk(630)] : [tk(631)] + enc_strs(p[1])

    def enc_nc(c)
      case c[0]
      when :ntrue then [tk(600)]
      when :nfalse then [tk(601)]
      when :natom then [tk(602)] + enc_op(c[1]) + enc_term(c[2]) + enc_term(c[3])
      when :nand then [tk(603)] + enc_nc(c[1]) + enc_nc(c[2])
      when :nor then [tk(604)] + enc_nc(c[1]) + enc_nc(c[2])
      end
    end

    def enc_window(w)
      case w[0]
      when :wtask then [tk(420)]
      when :wsliding then [tk(421), ti(w[1])]
      when :wperiod then [tk(422), ti(w[1]), ti(w[2])]
      when :wlifetime then [tk(423)]
      end
    end

    def enc_scope(s)
      case s[0]
      when :ssession then [tk(430)]
      when :sprincipal then [tk(431)]
      when :sorg then [tk(432)]
      when :sfleet then [tk(433)] + enc_strs(s[1])
      end
    end

    def enc_bcore(b)
      [tk(450), tk(400 + AGGS.index(b.agg))] + enc_term(b.value) + [ts_(b.key)] + enc_window(b.window) + enc_scope(b.scope) +
        enc_q(b.cap) + [tk(b.on_exceed == :on_deny ? 440 : 441)]
    end

    def enc_pred(p) = [tk(620), ts_(p.gid), ts_(p.verb)] + enc_res_pat(p.res) + enc_nc(p.cond)
    def enc_proh(p) = [tk(640), ts_(p.pid)] + enc_strs(p.verbs) + enc_res_pat(p.res) + enc_nc(p.cond)
    def enc_ceil(c) = [tk(610), ts_(c.bid)] + enc_strs(c.sel.gids) + enc_strs(c.sel.verbs) + enc_bcore(c.core)
    def enc_list(xs, &f) = [ti(xs.length)] + xs.flat_map(&f)

    def enc_pol(p)
      [tk(650)] + enc_list(p.preds) { |x| enc_pred(x) } + enc_list(p.prohs) { |x| enc_proh(x) } + enc_list(p.ceils) { |x| enc_ceil(x) } +
        enc_list(p.escs) { |x| enc_nc(x) } + [tk(460), ti(p.validity.not_before), ti(p.validity.not_after), ti(p.validity.max_idle)] +
        [tk(461), ti(p.deleg.max_depth), ti(p.deleg.narrow_only ? 1 : 0)] + enc_strs(p.deleg.may_touch)
    end

    # ---- tape encoding (the goal: Render)
    def enc_cond(c)
      case c[0]
      when :ctrue then [tk(360)]
      when :cmp then [tk(361)] + enc_op(c[1]) + enc_term(c[2]) + enc_term(c[3])
      when :and then [tk(362)] + enc_cond(c[1]) + enc_cond(c[2])
      when :or then [tk(363)] + enc_cond(c[1]) + enc_cond(c[2])
      when :not then [tk(364)] + enc_cond(c[1])
      end
    end

    def enc_part(p)
      case p[0]
      when :pexact then [tk(375), ts_(p[1])]
      when :poneof then [tk(376)] + enc_strs(p[1])
      when :prelated then [tk(377), ts_(p[1]), ts_(p[2])]
      end
    end

    def enc_res_sel(s)
      case s[0]
      when :exact then [tk(370), ts_(s[1])]
      when :oneof then [tk(371)] + enc_strs(s[1])
      when :related then [tk(372), ts_(s[1]), ts_(s[2])]
      when :anyres then [tk(373), ts_(s[1])]
      when :allof then [tk(374)] + enc_list(s[1]) { |p| enc_part(p) }
      end
    end

    def enc_grant(g) = [tk(380), ts_(g.gid), ts_(g.verb)] + enc_res_sel(g.res) + enc_cond(g.cond)

    def enc_prohibit(p)
      t = p.target[0] == :pverb ? [tk(390), ts_(p.target[1])] : [tk(391), ts_(p.target[1])]
      [tk(392), ts_(p.pid)] + t + enc_res_sel(p.res) + enc_cond(p.cond)
    end

    def enc_sel(s) = s[0] == :sel_gids ? [tk(410)] + enc_strs(s[1]) : [tk(411), ts_(s[1])]
    def enc_bound(b) = [tk(451), ts_(b.bid)] + enc_sel(b.sel) + enc_bcore(b.core)
    def enc_hole(h) = [tk(470), ts_(h.hid), ts_(h.q)] + enc_strs(h.domain) + enc_strs(h.affects) + [ti(h.global ? 1 : 0)]

    def render(g)
      [tk(480), ti(g.v), ts_(g.principal), ts_(g.ont_digest), ts_(g.nl_digest)] + enc_strs(g.sources) +
        enc_list(g.grants) { |x| enc_grant(x) } + enc_list(g.prohibits) { |x| enc_prohibit(x) } + enc_list(g.bounds) { |x| enc_bound(x) } +
        [tk(460), ti(g.validity.not_before), ti(g.validity.not_after), ti(g.validity.max_idle)] +
        [tk(461), ti(g.deleg.max_depth), ti(g.deleg.narrow_only ? 1 : 0)] + enc_strs(g.deleg.may_touch) +
        enc_list(g.escalate_on) { |c| enc_cond(c) } + enc_strs(g.wildcard_ack) + enc_list(g.holes) { |x| enc_hole(x) }
    end

    # ---- entry points
    BAD = [['i', 9]].freeze

    def ival(v)
      v = v.to_i if v.is_a?(Float) && v.finite? && v == v.floor
      raise IrError, "goal tape: #{v.inspect} is not a safe integer" unless v.is_a?(Integer) && v.abs <= MAX_SAFE

      v
    end

    # Validate a caller tape (each token a [tag, value] pair) and normalize it to ['k'|'i'|'s', value].
    def check_tape(tape)
      raise IrError, 'goal tape: an Array of tokens expected' unless tape.is_a?(Array)

      tape.map do |t|
        raise IrError, 'goal tape: token expected' unless t.is_a?(Array) && t.length == 2

        tag, v = t
        case tag.to_s
        when 'k', 'i' then [tag.to_s, ival(v)]
        when 's'
          raise IrError, 'goal tape: string token expected' unless v.is_a?(String)

          ['s', v]
        else raise IrError, "goal tape: unknown token tag #{tag.inspect}"
        end
      end
    end

    # One proved entry point over token tapes (op in typecheck compile decideg decidep render).
    def kernel_call(op, goal, ont = nil, act = nil, hist = nil)
      raise ArgumentError, "goal kernel: unknown op #{op.inspect}" unless OPS.include?(op.to_s)

      gt = check_tape(goal)
      return render_t(gt) if op.to_s == 'render'

      g = whole(gt, :goal)
      o = whole(check_tape(ont || []), :ontology)
      return BAD unless g && o

      case op.to_s
      when 'typecheck' then (rs = type_reasons(o, g)).empty? ? [ti(0)] : [ti(1)] + enc_strs(rs)
      when 'compile'
        kind, x = compile(o, g)
        kind == :compiled ? [ti(0)] + enc_pol(x) : [ti(1)] + enc_strs(x)
      else
        a = whole(check_tape(act || []), :act)
        h = whole(check_tape(hist || []), :hist)
        return BAD unless a && h

        op.to_s == 'decideg' ? [ti(0), ti(dg(o, g, a, h))] : decide_p(o, g, a, h)
      end
    end

    def decide_p(o, g, a, h)
      kind, x = compile(o, g)
      return [ti(1)] + enc_strs(x) if kind == :escalate

      d, gid, bids = decide_w(x, a, h)
      [ti(0), ti(d), ts_(gid)] + enc_strs(bids) + [ti(d == ALLOW && verify_witness(x, a, h, gid, bids) ? 1 : 0)]
    end

    def render_t(gt)
      g = whole(gt, :goal)
      g ? [ti(0)] + render(g) : BAD
    end

    # ---- tape text (the corpus syntax): kN, iN, s<hex>.<hex>..., a bare s is the empty string
    def tape_to_text(tape)
      tape.map { |tag, v| tag == 's' ? "s#{v.codepoints.map { |c| c.to_s(16) }.join('.')}" : "#{tag}#{v}" }.join(' ')
    end

    def tape_from_text(s)
      s.split(' ').map do |x|
        b = x[1..]
        case x[0]
        when 'k', 'i' then [x[0], Integer(b, 10)]
        when 's' then ['s', b.empty? ? +'' : b.split('.').map { |h| Integer(h, 16) }.pack('U*')]
        else raise IrError, "goal tape text: bad token #{x.inspect}"
        end
      end
    end
  end
end
