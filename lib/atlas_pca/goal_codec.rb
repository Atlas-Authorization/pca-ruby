# frozen_string_literal: true

require_relative 'goal_error'
require_relative 'goal_js'

module AtlasPca
  # Token-tape form of the Goal IR (the TypeScript reference is @atlasauth/pca-goal `codec`). A tape is an Array of
  # [tag, value] tokens, tag 'k' (keyword number) | 'i' (integer) | 's' (string). Encoding is STRICT: anything that is not
  # exactly an IR value raises IrError (or the TypeError a JavaScript property read of null would). IR values are the JSON
  # trees of the reference (String-keyed Hashes with a 'k' discriminant).
  module GoalCodec
    IrError = Goal::IrError
    J = GoalJs
    MAX_SAFE = 9_007_199_254_740_991
    OPS = %w[eq ne lt lte gt gte in nin].freeze
    AGGS = %w[count sum max distinct].freeze
    UNITS = { 'count' => 301, 'duration' => 302, 'instant' => 303, 'bytes' => 304, 'ratio' => 305 }.freeze
    UNIT_TAGS = UNITS.invert.freeze

    module_function

    def kk(n) = ['k', n]

    def safe_int?(n)
      return n.abs <= MAX_SAFE if n.is_a?(Integer)

      n.is_a?(Float) && n.finite? && n == n.floor && n.abs <= MAX_SAFE && !(n.zero? && (1.0 / n).negative?)
    end

    def ii(n)
      raise IrError, "#{n.inspect} is not a safe integer" unless safe_int?(n)

      ['i', n.to_i]
    end

    def ss(s)
      raise IrError, 'string expected' unless s.is_a?(String)

      ['s', s]
    end

    def bad(what, v) = raise(IrError, "unknown #{what}: #{v.inspect}")

    def list(xs, &f)
      raise IrError, 'array expected' unless xs.is_a?(Array)

      [ii(xs.length)] + xs.flat_map(&f)
    end

    def strs(xs) = list(xs) { |s| [ss(s)] }

    def enc_unit(u)
      k = J.jget(u, 'k')
      return [kk(300), ss(J.jget(u, 'ccy'))] if k == 'money'
      return [kk(UNITS[k])] if k.is_a?(String) && UNITS.key?(k)

      bad('unit', u)
    end

    def enc_q(q) = enc_unit(J.jget(q, 'u')) + [ii(J.jget(q, 'n'))]

    def enc_ty(t)
      k = J.jget(t, 'k')
      return [kk(310)] + enc_unit(J.jget(t, 'u')) if k == 'q'

      k == 's' ? [kk(311)] : bad('type', t)
    end

    def enc_atom(a)
      k = J.jget(a, 'k')
      return [kk(320)] + enc_q(J.jget(a, 'q')) if k == 'q'
      return [kk(321), ss(J.jget(a, 's'))] if k == 's'

      bad('set member (sets hold quantities and strings only)', a)
    end

    def enc_v(v)
      k = J.jget(v, 'k')
      return [kk(330)] + enc_q(J.jget(v, 'q')) if k == 'q'
      return [kk(331), ss(J.jget(v, 's'))] if k == 's'
      return [kk(332)] + list(J.jget(v, 'items')) { |a| enc_atom(a) } if k == 'set'

      bad('value', v)
    end

    def enc_term(t)
      k = J.jget(t, 'k')
      return [kk(340), ss(J.jget(t, 'path'))] + enc_ty(J.jget(t, 'ty')) if k == 'param'
      return [kk(341)] + enc_v(J.jget(t, 'v')) if k == 'lit'
      return [kk(342), ss(J.jget(t, 'bid'))] + enc_unit(J.jget(t, 'u')) if k == 'hist'

      bad('term', t)
    end

    def enc_op(op) = op.is_a?(String) && OPS.include?(op) ? [kk(350 + OPS.index(op))] : bad('operator', op)

    def enc_cond(c)
      k = J.jget(c, 'k')
      case k
      when 'true' then [kk(360)]
      when 'cmp' then [kk(361)] + enc_op(J.jget(c, 'op')) + enc_term(J.jget(c, 'l')) + enc_term(J.jget(c, 'r'))
      when 'and' then [kk(362)] + enc_cond(J.jget(c, 'a')) + enc_cond(J.jget(c, 'b'))
      when 'or' then [kk(363)] + enc_cond(J.jget(c, 'a')) + enc_cond(J.jget(c, 'b'))
      when 'not' then [kk(364)] + enc_cond(J.jget(c, 'c'))
      else bad('condition', c)
      end
    end

    def enc_part(s)
      k = J.jget(s, 'k')
      return [kk(375), ss(J.jget(s, 'id'))] if k == 'exact'
      return [kk(376)] + strs(J.jget(s, 'ids')) if k == 'oneof'
      return [kk(377), ss(J.jget(s, 'rel')), ss(J.jget(s, 'anchor'))] if k == 'related'

      bad('resource part', s)
    end

    def enc_res(s)
      k = J.jget(s, 'k')
      case k
      when 'exact' then [kk(370), ss(J.jget(s, 'id'))]
      when 'oneof' then [kk(371)] + strs(J.jget(s, 'ids'))
      when 'related' then [kk(372), ss(J.jget(s, 'rel')), ss(J.jget(s, 'anchor'))]
      when 'any' then [kk(373), ss(J.jget(s, 'reason'))]
      when 'all_of' then [kk(374)] + list(J.jget(s, 'parts')) { |p| enc_part(p) }
      else bad('resource selector', s)
      end
    end

    def enc_grant(g) = [kk(380), ss(J.jget(g, 'gid')), ss(J.jget(g, 'verb'))] + enc_res(J.jget(g, 'res')) + enc_cond(J.jget(g, 'cond'))

    def enc_target(t)
      k = J.jget(t, 'k')
      return [kk(390), ss(J.jget(t, 'verb'))] if k == 'verb'

      k == 'effect' ? [kk(391), ss(J.jget(t, 'cls'))] : bad('prohibit target', t)
    end

    def enc_prohibit(p)
      [kk(392), ss(J.jget(p, 'pid'))] + enc_target(J.jget(p, 'target')) + enc_res(J.jget(p, 'res')) + enc_cond(J.jget(p, 'cond'))
    end

    def enc_sel(s)
      k = J.jget(s, 'k')
      return [kk(410)] + strs(J.jget(s, 'gids')) if k == 'gids'

      k == 'effect' ? [kk(411), ss(J.jget(s, 'cls'))] : bad('selection', s)
    end

    def enc_window(w)
      k = J.jget(w, 'k')
      case k
      when 'task' then [kk(420)]
      when 'sliding' then [kk(421), ii(J.jget(w, 'ms'))]
      when 'period' then [kk(422), ii(J.jget(w, 'ms')), ii(J.jget(w, 't0'))]
      when 'lifetime' then [kk(423)]
      else bad('window', w)
      end
    end

    def enc_scope(s)
      k = J.jget(s, 'k')
      case k
      when 'session' then [kk(430)]
      when 'principal' then [kk(431)]
      when 'org' then [kk(432)]
      when 'fleet' then [kk(433)] + strs(J.jget(s, 'agents'))
      else bad('scope', s)
      end
    end

    def enc_on_exceed(o)
      return [kk(440)] if o == 'deny'

      o == 'escalate' ? [kk(441)] : bad('on_exceed', o)
    end

    def enc_bcore(b)
      agg = J.jget(b, 'agg')
      bad('aggregate', agg) unless agg.is_a?(String) && AGGS.include?(agg)
      [kk(450), kk(400 + AGGS.index(agg))] + enc_term(J.jget(b, 'value')) + [ss(J.jget(b, 'key'))] + enc_window(J.jget(b, 'window')) +
        enc_scope(J.jget(b, 'scope')) + enc_q(J.jget(b, 'cap')) + enc_on_exceed(J.jget(b, 'onExceed'))
    end

    def enc_bound(b) = [kk(451), ss(J.jget(b, 'bid'))] + enc_sel(J.jget(b, 'sel')) + enc_bcore(b)

    def enc_validity(v) = [kk(460), ii(J.jget(v, 'notBefore')), ii(J.jget(v, 'notAfter')), ii(J.jget(v, 'maxIdle'))]

    def enc_deleg(d)
      [kk(461), ii(J.jget(d, 'maxDepth')), ii(J.truthy(J.jget(d, 'narrowOnly')) ? 1 : 0)] + strs(J.jget(d, 'mayTouch'))
    end

    def enc_hole(h)
      [kk(470), ss(J.jget(h, 'hid')), ss(J.jget(h, 'q'))] + strs(J.jget(h, 'domain')) + strs(J.jget(h, 'affects')) +
        [ii(J.truthy(J.jget(h, 'global')) ? 1 : 0)]
    end

    # The goal as a token tape.
    def encode_goal(g)
      [kk(480), ii(J.jget(g, 'v')), ss(J.jget(g, 'principal')), ss(J.jget(g, 'ontDigest')), ss(J.jget(g, 'nlDigest'))] +
        strs(J.jget(g, 'sources')) + list(J.jget(g, 'grants')) { |x| enc_grant(x) } + list(J.jget(g, 'prohibits')) { |x| enc_prohibit(x) } +
        list(J.jget(g, 'bounds')) { |x| enc_bound(x) } + enc_validity(J.jget(g, 'validity')) + enc_deleg(J.jget(g, 'deleg')) +
        list(J.jget(g, 'escalateOn')) { |x| enc_cond(x) } + strs(J.jget(g, 'wildcardAck')) + list(J.jget(g, 'holes')) { |x| enc_hole(x) }
    end

    def enc_param_decl(p) = [kk(500), ss(J.jget(p, 'path'))] + enc_ty(J.jget(p, 'ty'))

    def enc_verb_decl(v)
      [kk(501), ss(J.jget(v, 'verb')), ss(J.jget(v, 'cls'))] + list(J.jget(v, 'params')) { |p| enc_param_decl(p) }
    end

    def enc_rel_decl(r) = [kk(502), ss(J.jget(r, 'rel')), ss(J.jget(r, 'anchor'))] + strs(J.jget(r, 'members'))

    def encode_ontology(o)
      [kk(510)] + list(J.jget(o, 'verbs')) { |v| enc_verb_decl(v) } + list(J.jget(o, 'rels')) { |r| enc_rel_decl(r) }
    end

    def enc_act(a)
      params = J.jget(a, 'params')
      keys = J.okeys(params).sort_by { |k| J.u16key(k) }
      [kk(530), ss(J.jget(a, 'verb')), ss(J.jget(a, 'res'))] + list(keys) { |k| [kk(520), ss(k)] + enc_v(J.kget(params, k)) } +
        [ii(J.jget(a, 't')), ss(J.jget(a, 'sess')), ss(J.jget(a, 'prin')), ss(J.jget(a, 'org')), ss(J.jget(a, 'agent')), ii(J.jget(a, 'depth'))]
    end

    def encode_act(a) = enc_act(a)
    def enc_adm(a) = [kk(531), ss(J.jget(a, 'gid'))] + enc_act(J.jget(a, 'act'))

    def encode_hist(h)
      aggs = J.jget(h, 'aggs')
      keys = J.okeys(aggs).sort_by { |k| J.u16key(k) }
      [kk(541)] + list(J.jget(h, 'adms')) { |a| enc_adm(a) } + [ii(J.jget(h, 'last'))] +
        list(keys) { |k| [kk(540), ss(k)] + enc_q(J.kget(aggs, k)) }
    end

    # ---- decoding
    class TapeReader
      def initialize(t)
        @t = t
        @i = 0
      end

      def next_tok
        raise IrError, 'truncated tape' if !@t.is_a?(Array) || @i >= @t.length

        x = @t[@i]
        @i += 1
        raise IrError, 'malformed token' if !x.is_a?(Array) || x.length < 2

        x
      end

      def k
        x = next_tok
        raise IrError, 'keyword expected' unless x[0] == 'k' && GoalCodec.safe_int?(x[1])

        x[1].to_i
      end

      def int
        x = next_tok
        raise IrError, 'integer expected' unless x[0] == 'i' && GoalCodec.safe_int?(x[1])

        x[1].to_i
      end

      def str
        x = next_tok
        raise IrError, 'string expected' unless x[0] == 's' && x[1].is_a?(String)

        x[1]
      end

      def done? = @i >= @t.length

      def list
        n = int
        raise IrError, 'negative length' if n.negative?

        out = []
        n.times { out << yield }
        out
      end

      def strs = list { str }
    end

    def d_unit(r)
      k = r.k
      return { 'k' => 'money', 'ccy' => r.str } if k == 300
      raise IrError, "bad unit tag #{k}" unless UNIT_TAGS.key?(k)

      { 'k' => UNIT_TAGS[k] }
    end

    def d_q(r)
      u = d_unit(r)
      { 'u' => u, 'n' => r.int }
    end

    def d_ty(r)
      k = r.k
      return { 'k' => 'q', 'u' => d_unit(r) } if k == 310
      return { 'k' => 's' } if k == 311

      raise IrError, "bad type tag #{k}"
    end

    def d_atom(r)
      k = r.k
      return { 'k' => 'q', 'q' => d_q(r) } if k == 320
      return { 'k' => 's', 's' => r.str } if k == 321

      raise IrError, "bad atom tag #{k}"
    end

    def d_v(r)
      k = r.k
      return { 'k' => 'q', 'q' => d_q(r) } if k == 330
      return { 'k' => 's', 's' => r.str } if k == 331
      return { 'k' => 'set', 'items' => r.list { d_atom(r) } } if k == 332

      raise IrError, "bad value tag #{k}"
    end

    def d_term(r)
      k = r.k
      if k == 340
        path = r.str
        return { 'k' => 'param', 'path' => path, 'ty' => d_ty(r) }
      end
      return { 'k' => 'lit', 'v' => d_v(r) } if k == 341

      if k == 342
        bid = r.str
        return { 'k' => 'hist', 'bid' => bid, 'u' => d_unit(r) }
      end
      raise IrError, "bad term tag #{k}"
    end

    def d_op(r)
      i = r.k - 350
      return OPS[i] if i >= 0 && i < OPS.length

      raise IrError, 'bad operator'
    end

    def d_n(r)
      k = r.k
      case k
      when 600 then { 'k' => 'true' }
      when 601 then { 'k' => 'false' }
      when 602
        op = d_op(r)
        l = d_term(r)
        { 'k' => 'atom', 'op' => op, 'l' => l, 'r' => d_term(r) }
      when 603
        a = d_n(r)
        { 'k' => 'and', 'a' => a, 'b' => d_n(r) }
      when 604
        a = d_n(r)
        { 'k' => 'or', 'a' => a, 'b' => d_n(r) }
      else raise IrError, "bad condition tag #{k}"
      end
    end

    def d_res_pat(r)
      k = r.k
      return { 'k' => 'star' } if k == 630
      return { 'k' => 'set', 'ids' => r.strs } if k == 631

      raise IrError, "bad resource pattern tag #{k}"
    end

    def d_window(r)
      k = r.k
      case k
      when 420 then { 'k' => 'task' }
      when 421 then { 'k' => 'sliding', 'ms' => r.int }
      when 422
        ms = r.int
        { 'k' => 'period', 'ms' => ms, 't0' => r.int }
      when 423 then { 'k' => 'lifetime' }
      else raise IrError, "bad window tag #{k}"
      end
    end

    def d_scope(r)
      k = r.k
      case k
      when 430 then { 'k' => 'session' }
      when 431 then { 'k' => 'principal' }
      when 432 then { 'k' => 'org' }
      when 433 then { 'k' => 'fleet', 'agents' => r.strs }
      else raise IrError, "bad scope tag #{k}"
      end
    end

    def d_agg(r)
      i = r.k - 400
      return AGGS[i] if i >= 0 && i < AGGS.length

      raise IrError, 'bad aggregate'
    end

    def d_on_exceed(r)
      oe = r.k
      raise IrError, 'bad on_exceed' unless [440, 441].include?(oe)

      oe == 440 ? 'deny' : 'escalate'
    end

    def d_ceil(r)
      raise IrError, 'ceiling expected' unless r.k == 610

      bid = r.str
      sel_gids = r.strs
      sel_verbs = r.strs
      raise IrError, 'bound core expected' unless r.k == 450

      agg = d_agg(r)
      value = d_term(r)
      key = r.str
      window = d_window(r)
      scope = d_scope(r)
      cap = d_q(r)
      { 'bid' => bid, 'selGids' => sel_gids, 'selVerbs' => sel_verbs, 'agg' => agg, 'value' => value, 'key' => key, 'window' => window,
        'scope' => scope, 'cap' => cap, 'onExceed' => d_on_exceed(r) }
    end

    # Decode the compiler's policy tape (after its leading status token); raises IrError unless the whole tape is one policy.
    def decode_policy(t)
      r = TapeReader.new(t)
      raise IrError, 'policy expected' unless r.k == 650

      preds = r.list do
        raise IrError, 'pred' unless r.k == 620

        gid = r.str
        verb = r.str
        res = d_res_pat(r)
        { 'gid' => gid, 'verb' => verb, 'res' => res, 'cond' => d_n(r) }
      end
      prohs = r.list do
        raise IrError, 'prohibition' unless r.k == 640

        pid = r.str
        verbs = r.strs
        res = d_res_pat(r)
        { 'pid' => pid, 'verbs' => verbs, 'res' => res, 'cond' => d_n(r) }
      end
      ceils = r.list { d_ceil(r) }
      escs = r.list { d_n(r) }
      raise IrError, 'validity' unless r.k == 460

      nb = r.int
      na = r.int
      validity = { 'notBefore' => nb, 'notAfter' => na, 'maxIdle' => r.int }
      raise IrError, 'delegation' unless r.k == 461

      md = r.int
      nrw = r.int == 1
      deleg = { 'maxDepth' => md, 'narrowOnly' => nrw, 'mayTouch' => r.strs }
      raise IrError, 'trailing tokens after policy' unless r.done?

      { 'preds' => preds, 'prohs' => prohs, 'ceils' => ceils, 'escs' => escs, 'validity' => validity, 'deleg' => deleg }
    end

    def d_cond(r)
      k = r.k
      case k
      when 360 then { 'k' => 'true' }
      when 361
        op = d_op(r)
        l = d_term(r)
        { 'k' => 'cmp', 'op' => op, 'l' => l, 'r' => d_term(r) }
      when 362
        a = d_cond(r)
        { 'k' => 'and', 'a' => a, 'b' => d_cond(r) }
      when 363
        a = d_cond(r)
        { 'k' => 'or', 'a' => a, 'b' => d_cond(r) }
      when 364 then { 'k' => 'not', 'c' => d_cond(r) }
      else raise IrError, "bad condition tag #{k}"
      end
    end

    def d_part(r)
      k = r.k
      return { 'k' => 'exact', 'id' => r.str } if k == 375
      return { 'k' => 'oneof', 'ids' => r.strs } if k == 376

      if k == 377
        rel = r.str
        return { 'k' => 'related', 'rel' => rel, 'anchor' => r.str }
      end
      raise IrError, "bad resource part tag #{k}"
    end

    def d_res(r)
      k = r.k
      case k
      when 370 then { 'k' => 'exact', 'id' => r.str }
      when 371 then { 'k' => 'oneof', 'ids' => r.strs }
      when 372
        rel = r.str
        { 'k' => 'related', 'rel' => rel, 'anchor' => r.str }
      when 373 then { 'k' => 'any', 'reason' => r.str }
      when 374 then { 'k' => 'all_of', 'parts' => r.list { d_part(r) } }
      else raise IrError, "bad resource selector tag #{k}"
      end
    end

    def expect(r, k, what) = r.k == k || raise(IrError, "#{what} expected")

    # Parse a goal tape; raises IrError unless the whole tape is exactly one goal.
    def decode_goal(t)
      r = TapeReader.new(t)
      expect(r, 480, 'goal')
      v = r.int
      principal = r.str
      ont_digest = r.str
      nl_digest = r.str
      sources = r.strs
      grants = r.list do
        expect(r, 380, 'grant')
        gid = r.str
        verb = r.str
        res = d_res(r)
        { 'gid' => gid, 'verb' => verb, 'res' => res, 'cond' => d_cond(r) }
      end
      prohibits = r.list do
        expect(r, 392, 'prohibit')
        pid = r.str
        tk = r.k
        if tk == 390
          target = { 'k' => 'verb', 'verb' => r.str }
        elsif tk == 391
          target = { 'k' => 'effect', 'cls' => r.str }
        else
          raise IrError, 'bad prohibit target'
        end
        res = d_res(r)
        { 'pid' => pid, 'target' => target, 'res' => res, 'cond' => d_cond(r) }
      end
      bounds = r.list do
        expect(r, 451, 'bound')
        bid = r.str
        sk = r.k
        if sk == 410
          sel = { 'k' => 'gids', 'gids' => r.strs }
        elsif sk == 411
          sel = { 'k' => 'effect', 'cls' => r.str }
        else
          raise IrError, 'bad selection'
        end
        expect(r, 450, 'bound core')
        agg = d_agg(r)
        value = d_term(r)
        key = r.str
        window = d_window(r)
        scope = d_scope(r)
        cap = d_q(r)
        { 'bid' => bid, 'sel' => sel, 'agg' => agg, 'value' => value, 'key' => key, 'window' => window, 'scope' => scope, 'cap' => cap,
          'onExceed' => d_on_exceed(r) }
      end
      expect(r, 460, 'validity')
      nb = r.int
      na = r.int
      validity = { 'notBefore' => nb, 'notAfter' => na, 'maxIdle' => r.int }
      expect(r, 461, 'delegation')
      md = r.int
      nrw = r.int == 1
      deleg = { 'maxDepth' => md, 'narrowOnly' => nrw, 'mayTouch' => r.strs }
      escalate_on = r.list { d_cond(r) }
      wildcard_ack = r.strs
      holes = r.list do
        expect(r, 470, 'hole')
        hid = r.str
        q = r.str
        domain = r.strs
        affects = r.strs
        { 'hid' => hid, 'q' => q, 'domain' => domain, 'affects' => affects, 'global' => r.int == 1 }
      end
      raise IrError, 'trailing tokens after goal' unless r.done?

      { 'v' => v, 'principal' => principal, 'ontDigest' => ont_digest, 'nlDigest' => nl_digest, 'sources' => sources, 'grants' => grants,
        'prohibits' => prohibits, 'bounds' => bounds, 'validity' => validity, 'deleg' => deleg, 'escalateOn' => escalate_on,
        'wildcardAck' => wildcard_ack, 'holes' => holes }
    end
  end
end
