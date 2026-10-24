# frozen_string_literal: true
# The Intent Layer v2 PUBLIC API layer (the AtlasPca module functions at the end of intent_v2.rb): every one is a thin wrapper
# over IntentV2 that normalizes its JSON arguments (V2JS.jsnorm: Symbol keys -> String keys, an integral Float -> the Integer it
# equals) and passes the rest through. See 94a_pub_twin.rb for why the differential oracles never saw this layer.
#
# Here, over the inputs of the shared TS oracles (k042-actionschema, k042-sessrevoc-cases, k042-intentv2-cases, killMap): the
# public call on the TWIN of every argument the wrapper normalizes (an absent optional argument omitted, i.e. the wrapper's
# default) must give exactly what IntentV2 gives on the JSON-normal arguments (the value, or the class it raised). The
# internal side is the reference the differential suites already pin to the TS answers; the public side is what a caller gets.
# Plus the re-exported constants against the TS literals, and the committed-map hash pieces against the oracle commitments.
# Only intent_v2.rb bears on it.
module MutationKill
  module PubApi
    module_function

    def iv2 = AtlasPca::IntentV2
    def tw(x) = PubTwin.twin(x)
    # JSON-normal (the shape every wrapper hands IntentV2): a value the parser keeps as an integral Float (the lexeme 1.0) is the
    # Integer it equals once a wrapper normalizes it, so the internal side gets the normalized value too
    def j(t) = AtlasPca::V2JS.jsnorm(raw(t))
    def raw(t) = AtlasPca.parse_json_text(t)
    def absent = AtlasPca::V2JS::UNDEF

    def res
      DiffUtil.norm(yield)
    rescue StandardError, SystemStackError => e
      "raised #{e.class}"
    end

    # [[label, public, internal]...] -> nil when every pair agrees, else the first difference
    def first_diff(pairs)
      pairs.each do |label, pub, int|
        a = res(&pub)
        b = res(&int)
        return "#{label}: public #{a.inspect[0, 160]} internal #{b.inspect[0, 160]}" unless a == b
      end
      nil
    end

    # ---- the action schema (k042-actionschema.json) ----
    def schema_data = (@schema_data ||= DiffUtil.load('k042-actionschema.json'))

    def schema_pairs
      d = schema_data
      out = []
      d['shape'].each do |c|
        doc = j(c['doc'])
        out << ["shape #{c['name']}", -> { AtlasPca.action_schema_shape_error(tw(doc)) }, -> { iv2.action_schema_shape_error(doc, true) }]
        out << ["shape unsigned #{c['name']}", -> { AtlasPca.action_schema_shape_error(tw(doc), signed: false) }, -> { iv2.action_schema_shape_error(doc, false) }]
        out << ["digest #{c['name']}", -> { AtlasPca.action_schema_digest(tw(doc)) }, -> { iv2.action_schema_digest(doc) }]
      end
      d['verify'].each do |c|
        doc = j(c['doc'])
        keys = j(c['keys'])
        out << ["verify #{c['name']}", -> { AtlasPca.verify_action_schema(tw(doc), tw(keys)) }, -> { iv2.verify_action_schema(doc, keys) }]
      end
      d['pvv'].each do |c|
        dd = j(c['d'])
        x = j(c['x'])
        out << ["pvv #{c['name']}", -> { AtlasPca.param_value_violation(tw(dd), tw(x)) }, -> { iv2.param_value_violation(dd, x) }]
      end
      (d['conform'] + d['canon']).each do |c|
        doc = j(c['doc'])
        params = j(c['params'])
        v = c['verb']
        out << ["conform #{c['name']}", -> { AtlasPca.conform_action(tw(doc), v, tw(params)) }, -> { iv2.conform_action(doc, v, params) }]
        out << ["verb #{c['name']}", -> { AtlasPca.schema_verb(tw(doc), v) }, -> { iv2.schema_verb(doc, v) }]
        out << ["canon #{c['name']}", -> { AtlasPca.canon_projection(tw(doc), v, tw(params)) }, -> { iv2.canon_projection(doc, v, params) }]
      end
      d['acc'].each do |c|
        v = j(c['v'])
        out << ["acc #{c['name']}", -> { AtlasPca.accumulation_params(tw(v), c['unit']) }, -> { iv2.accumulation_params(v, c['unit']) }]
      end
      out
    end

    # ---- the session root and session revocation (k042-sessrevoc-cases.json) ----
    def sess_data = (@sess_data ||= DiffUtil.parse(DiffUtil.read('k042-sessrevoc-cases.json')))

    def session_pairs
      d = sess_data
      out = []
      d['root'].each do |c|
        s = j(c['s'])
        pins = c.key?('pq_pins') && !c['pq_pins'].nil? ? j(c['pq_pins']) : nil
        out << ["root shape #{c['name']}", -> { AtlasPca.session_root_shape_error(tw(s)) }, -> { iv2.session_root_shape_error(s, true) }]
        out << ["root shape unsigned #{c['name']}", -> { AtlasPca.session_root_shape_error(tw(s), signed: false) }, -> { iv2.session_root_shape_error(s, false) }]
        out << ["root digest #{c['name']}", -> { AtlasPca.session_root_digest(tw(s)) }, -> { iv2.session_root_digest(s) }]
        out << if pins.nil?
                 ["root verify #{c['name']}", -> { AtlasPca.verify_session_root(tw(s)) }, -> { iv2.verify_session_root(s, nil) }]
               else
                 ["root verify pinned #{c['name']}", -> { AtlasPca.verify_session_root(tw(s), tw(pins)) }, -> { iv2.verify_session_root(s, pins) }]
               end
      end
      d['rev'].each do |c|
        ev = c['ev'].nil? ? nil : j(c['ev'])
        ids = c['ids'].nil? ? nil : raw(c['ids'])
        auth = raw(c['authority'])
        kw = { session: c['session'], authority: auth, ids: ids, now: c['now'], max_age_ms: c['maxAge'] }
        kw[:scope] = c['scope'] unless c['scope'].nil?
        kw[:last] = j(c['last']) unless c['last'].nil?
        pkw = kw.merge(now: tw(kw[:now]), max_age_ms: tw(kw[:max_age_ms]))
        pkw[:last] = tw(kw[:last]) if kw.key?(:last)
        out << ["revocation #{c['name']}", -> { AtlasPca.check_session_revocation(tw(ev), **pkw) },
                -> { iv2.check_session_revocation(ev, **kw) }]
        next unless ev.is_a?(Hash) && ev['epoch'].is_a?(Hash)

        ep = ev['epoch']
        now = c['now']
        out << ["epoch #{c['name']}", -> { AtlasPca.check_revocation_epoch(tw(ep), auth, tw(now)) }, -> { iv2.check_revocation_epoch(ep, auth, now, absent, nil) }]
        gr = ep['grant_ref']
        out << ["epoch grant_ref #{c['name']}", -> { AtlasPca.check_revocation_epoch(tw(ep), auth, tw(now), gr) }, -> { iv2.check_revocation_epoch(ep, auth, now, gr, nil) }]
        out << ["epoch shape #{c['name']}", -> { AtlasPca.revocation_epoch_shape_error(tw(ep)) }, -> { iv2.revocation_epoch_shape_error(ep) }]
        s = c['session']
        out << ["ids #{c['name']}", -> { [AtlasPca.session_revocation_id(s), AtlasPca.session_revocation_scope(s), AtlasPca.map_revocation_id(s), AtlasPca.delta_revocation_id(s), AtlasPca.profile_revocation_id(s, ep['epoch']), AtlasPca.profile_revocation_scope(s)] },
                -> { [iv2.session_revocation_id(s), iv2.session_revocation_scope(s), iv2.map_revocation_id(s), iv2.delta_revocation_id(s), iv2.profile_revocation_id(s, ep['epoch']), iv2.profile_revocation_scope(s)] }]
        list = ev['revoked'].is_a?(Array) && ev['revoked'].all?(String) ? ev['revoked'] : nil
        out << ["revset root #{c['name']}", -> { AtlasPca.revset_root(list) }, -> { iv2.revset_root(list) }] if list
      end
      out
    end

    # ---- the v2 verifier context (k042-intentv2-cases.json: every distinct context) ----
    def ctx_pairs
      seen = {}
      out = [['context nil', -> { AtlasPca.intent_v2_context_error(nil) }, -> { iv2.intent_v2_context_error(absent) }]]
      IntentV2Diff.cases.each do |c|
        next unless c.key?('ctx') && !seen[c['ctx']]

        seen[c['ctx']] = true
        ctx = j(c['ctx'])
        next if ctx.nil?

        out << ["context #{c['name']}", -> { AtlasPca.intent_v2_context_error(tw(ctx)) }, -> { iv2.intent_v2_context_error(ctx) }]
      end
      %w[commit x].each do |f|
        out << ["goal #{f}", -> { [AtlasPca.intent_goal_v2('s', 'd'), AtlasPca.intent_goal_v2('s', 'd', f)] }, -> { [iv2.intent_goal_v2('s', 'd', nil), iv2.intent_goal_v2('s', 'd', f)] }]
      end
      out
    end

    # ---- the whole v2 decision (k042-intentv2-cases.json): decide_intent_v2 normalizes the PCActn, grant, context and clock ----
    # The first 3 cases of every case group (a whole decision is ~20 ms; the twin only has to reach each input shape once).
    def decide_pairs
      per = Hash.new(0)
      IntentV2Diff.cases.select { |c| (per[c['name'].split('/').first] += 1) <= 3 }.filter_map do |c|
        pp = raw(c['p'])
        g = raw(c['grant'])
        ctx = c.key?('ctx') ? raw(c['ctx']) : nil
        next if c.key?('ctx') && ctx.nil?

        ctx = ctx.merge('params' => raw(c['wp'])) if c.key?('wp') && ctx.is_a?(Hash)
        now = c['now']
        pick = ->(o) { { 'checks' => o['checks'], 'env' => o['env'] } }
        ["decide #{c['name']}", -> { pick.call(AtlasPca.decide_intent_v2(tw(pp), tw(g), tw(ctx), tw(now))) },
         -> { pick.call(iv2.decide_intent_v2(pp, g, ctx, now)) }]
      end
    end

    # ---- the committed map: the commitment of each oracle leaf list, rebuilt from the PUBLIC hash pieces ----
    def map_commit_bad
      KillMap.cases.each do |c|
        next unless c['fn'] == 'commit' && c['out'].is_a?(String)

        leaves = AtlasPca::V2JS.jsnorm(c['args'][0])
        hs = leaves.map { |l| AtlasPca.map_leaf_hash(l['kind'], AtlasPca.b64d(l['salt'], 32), tw(l['leaf'])) }
        root = mth(hs)
        got = AtlasPca.map_commit_of(hs.length, root)
        return "map commit #{c['name']}: want #{c['out']} got #{got}" unless got == c['out']
        # the audit path of every leaf (RFC 9162 PATH) leads back to the same root through the public verifier
        hs.each_index do |i|
          r = AtlasPca.map_root_from_path(i, hs.length, hs[i], path(hs, i))
          return "map path #{c['name']} leaf #{i}" unless r == root
        end
      end
      nil
    end

    # RFC 9162 MTH / PATH over leaf hashes, with the public node hash
    def split(n) = 1 << ((n - 1).bit_length - 1)
    def mth(hs) = hs.length == 1 ? hs[0] : AtlasPca.map_node_hash(mth(hs[0, split(hs.length)]), mth(hs[split(hs.length)..]))

    def path(hs, m)
      return [] if hs.length == 1

      k = split(hs.length)
      m < k ? path(hs[0, k], m) + [mth(hs[k..])] : path(hs[k..], m - k) + [mth(hs[0, k])]
    end

    # ---- the re-exported constants (the TS literals) ----
    CONSTS = {
      ACTION_SCHEMA_DOMAIN: "atlas-pca/action-schema/v1\0", ACTION_SCHEMA_REF_DOMAIN: 'atlas-pca/action-schema-ref/v1',
      INTENT_SESSION_SIG_DOMAIN: "atlas-pca/intent-session/v1\0", INTENT_SESSION_REF_DOMAIN: 'atlas-pca/intent-session-ref/v1',
      ACC_RECEIPT_DOMAIN: "atlas-pca/acc-receipt/v1\0", ACC_RECEIPT_REF_DOMAIN: 'atlas-pca/acc-receipt-ref/v1',
      ACC_RESERVE_DOMAIN: 'atlas-pca/acc-reserve/v1', SEQUENCER_KEYS_DOMAIN: "atlas-pca/sequencer-keys/v1\0",
      REVEPOCH_DOMAIN: "atlas-pca/revepoch/v1\0",
      MAP_TAG_HEADER: "atlas-pca/intent-map/header/v1\0", MAP_TAG_CELL: "atlas-pca/intent-map/cell/v1\0",
      MAP_TAG_METRICS: "atlas-pca/intent-map/metrics/v1\0", MAP_TAG_LEARNER: "atlas-pca/intent-map/learner/v1\0",
      MAP_TAG_NODE: "atlas-pca/intent-map/node/v1\0", MAP_TAG_COMMIT: "atlas-pca/intent-map/commit/v1\0",
      INTENT_SESSION_FIELDS: %w[session root seq schema acc facts offer_set prov classes labels map_form]
    }.freeze

    def consts_bad
      CONSTS.each do |name, want|
        return "AtlasPca::#{name} is not defined" unless AtlasPca.const_defined?(name, false)

        got = AtlasPca.const_get(name, false)
        return "AtlasPca::#{name} = #{got.inspect}" unless got == want && got.equal?(iv2.const_get(name, false))
      end
      nil
    end
  end

  # the pairs are built ONCE at registry load (inputs parsed by the unmutated library; each lambda resolves AtlasPca at call time)
  pairs = { schema: PubApi.schema_pairs, session: PubApi.session_pairs, ctx: PubApi.ctx_pairs, decide: PubApi.decide_pairs }
  [['schema', -> { PubApi.first_diff(pairs[:schema]) }],
   ['session root / revocation', -> { PubApi.first_diff(pairs[:session]) }],
   ['verifier context / goal', -> { PubApi.first_diff(pairs[:ctx]) }],
   ['whole decision', -> { PubApi.first_diff(pairs[:decide]) }],
   ['committed map hashing', -> { PubApi.map_commit_bad }],
   ['re-exported constants', -> { PubApi.consts_bad }]].each do |label, fn|
    t("intent v2 public API twin: #{label}") do
      next true if DiffUtil.skip?('intent_v2.rb')

      bad = fn.call
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
