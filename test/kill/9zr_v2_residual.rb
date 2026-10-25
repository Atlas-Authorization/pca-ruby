# frozen_string_literal: true
require 'openssl'
# Intent Layer v2 (intent_v2.rb): exact-outcome kills for the survivors of run 39902549441 that still survived the r11 oracles
# (9t..9z). Each check pins one documented behaviour the earlier oracles never reached: the IntentV2 constants themselves,
# String ENCODINGS of equal bytes (a Ruby caller may hand over a binary String: duplicates are found by bytes), the public
# entry points on malformed input (TS reads `Array.isArray(...)` / `isObj(...)` there, never throws), the fail-closed rescues
# of the public wrappers, a hybrid PQ revocation epoch, and an accumulator key declaration without a string `semantic` (the
# accumulators check fails closed with the named reason). Fixtures are built HERE by the unmutated library at load. Only
# intent_v2.rb bears on it.
module MutationKill
  module V2Residual
    module_function

    def iv2 = AtlasPca::IntentV2
    def absent = AtlasPca::V2JS::UNDEF
    def x = AtlasPca
    def deep(o) = Marshal.load(Marshal.dump(o))

    # A key whose `is_a?` raises: jsnorm (the first thing every public wrapper does) cannot copy an input that holds it.
    RAISING_KEY = Class.new { def is_a?(*) = raise(ArgumentError, 'raising key') }.new
    # A pins Hash whose lookup raises: the signature seam must fail CLOSED on it.
    RAISING_PINS = Class.new(Hash) { def key?(*) = raise(ArgumentError, 'raising pins') }.new

    def constant_checks
      [
        ['IntentV2::UNSUPPORTED_SUITE', iv2.const_defined?(:UNSUPPORTED_SUITE, false) && iv2::UNSUPPORTED_SUITE == 'unsupported_suite'],
        ['IntentV2::INTENT_GOAL_V2_PREFIX', iv2.const_defined?(:INTENT_GOAL_V2_PREFIX, false) && iv2::INTENT_GOAL_V2_PREFIX == 'pca-intent:v2:'],
        ['IntentV2::INTENT_GOAL_V2C_PREFIX', iv2.const_defined?(:INTENT_GOAL_V2C_PREFIX, false) && iv2::INTENT_GOAL_V2C_PREFIX == 'pca-intent:v2c:']
      ]
    end

    # ---- equal bytes in another encoding are the same string (strings compare by UTF-8 bytes, as in TS) ----
    def encoding_checks
      doc = deep(V2Targeted.schema_doc).reject { |k, _| k == 'sig' }
      v0 = doc['verbs'][0]
      twice = doc.merge('verbs' => [v0.merge('verb' => 'é'), v0.merge('verb' => 'é'.b)])
      cat = ->(vals) { { 'verb' => 'v', 'first' => 0, 'cells' => vals.length, 'dims' => [{ 'kind' => 'cat', 'path' => 'action.resource', 'values' => vals }] } }
      other = { 'kind' => 'other', 'value' => iv2::MAP_OTHER }
      dup_vals = cat.call([{ 'kind' => 'exact', 'value' => 'é' }, { 'kind' => 'exact', 'value' => 'é'.b }, other])
      distinct = 'header.dims[0].values must be distinct'
      acc = { 'agg' => 'distinct' }
      [
        ['schema verb declared twice (binary twin)', x.action_schema_shape_error(twice, signed: false).to_s.b == "verb 'é' is declared twice".b],
        ['map values distinct (binary twin)', x.map_header_error(dup_vals) == distinct],
        ['map values distinct control', x.map_header_error(cat.call([{ 'kind' => 'exact', 'value' => 'é' }, { 'kind' => 'exact', 'value' => 'e' }, other])).nil?],
        # a distinct key already in the pre-state values is not new: post = |values| (+0), whatever the encodings
        ['distinct seen utf8/utf8', x.combine_acc(acc, { 'values' => ['"é"'] }, { 'key' => '"é"' }) == 1],
        ['distinct seen bin/utf8', x.combine_acc(acc, { 'values' => ['"é"'.b] }, { 'key' => '"é"' }) == 1],
        ['distinct seen utf8/bin', x.combine_acc(acc, { 'values' => ['"é"'] }, { 'key' => '"é"'.b }) == 1],
        ['distinct new', x.combine_acc(acc, { 'values' => ['"é"'] }, { 'key' => '"e"' }) == 2]
      ]
    end

    # ---- public entry points on malformed input: the documented answer, never a raise ----
    def malformed_checks
      num = { 'dims' => [{ 'kind' => 'num', 'path' => 5, 'lo' => 0, 'hi' => 9, 'cuts' => [] }] }
      cat = ->(vals) { { 'dims' => [{ 'kind' => 'cat', 'path' => 'action.resource', 'values' => vals }] } }
      other = { 'kind' => 'other', 'value' => iv2::MAP_OTHER }
      mon = begin
        x.monitor_states({ 'kind' => 'bogus' })
        'no raise'
      rescue AtlasPca::V2JS::StrictError => e
        e.message
      end
      [
        # `isObj(params) ? params[d.path.slice(14)] : undefined`: no params object -> absent, never a slice of a non-string path
        ['map cell: non-object params, odd path', [nil, 5, 'p', []].all? { |pr| x.map_cell_of(num, 'r', pr) == { 'error' => "the action's 5 lies outside the committed map's dimension" } }],
        # the FIRST exact value wins (break), a longer prefix only replaces a strictly shorter one
        ['map cell: first exact wins', x.map_cell_of(cat.call([{ 'kind' => 'exact', 'value' => 'a' }, { 'kind' => 'exact', 'value' => 'a' }, other]), 'a', {}) == { 'cell' => [0], 'flat' => 0 }],
        ['map cell: first equal prefix wins', x.map_cell_of(cat.call([{ 'kind' => 'prefix', 'value' => 'ab' }, { 'kind' => 'prefix', 'value' => 'ab' }, other]), 'abc', {}) == { 'cell' => [0], 'flat' => 0 }],
        ['map cell: longer prefix wins', x.map_cell_of(cat.call([{ 'kind' => 'prefix', 'value' => 'a' }, { 'kind' => 'prefix', 'value' => 'ab' }, other]), 'abc', {}) == { 'cell' => [1], 'flat' => 1 }],
        ['monitor states: unknown kind text', mon == 'monitorStates: unknown kind'],
        # `Array.isArray(sel.verbs) && sel.verbs.some(...)`: a non-array verbs selects nothing (no throw)
        ['acc selects: verbs not an array', [{ 'verbs' => 'air.book' }, { 'verbs' => 5 }].all? { |sel| x.acc_selects({ 'sel' => sel }, 'air.book') == false }],
        # the pre-state member set is compared as `Object.keys(s).join(',')`
        ['pre-state keys joined by comma', x.pre_state_error({ 'agg' => 'sum' }, { 'su' => 1, 'm' => 2 }) == 'pre-state of a sum accumulator is {sum}'],
        ['pre-state values keys', x.pre_state_error({ 'agg' => 'distinct' }, { 'valu' => 1, 'es' => 2 }) == 'pre-state of a distinct accumulator is {values}']
      ]
    end

    # ---- the public wrappers' rescues answer the documented fail-closed value ----
    def rescue_checks
      odd = { RAISING_KEY => 1 }
      [
        ['receipt vs holder: fresh not an object', [nil, 'x', 5].all? { |f| x.verify_receipt_against_holder({}, {}, [], 1, f) == false }],
        ['intent_v2_active? on an uncopyable context', x.intent_v2_active?({}, odd) == false],
        ['intent_revocation primitive on an uncopyable input', x.intent_revocation_primitive(odd) == { 'ok' => false, 'reason' => 'session revocation check error (fail closed)' }],
        ['intent_map primitive on an uncopyable input', x.intent_map_primitive(odd) == { 'ok' => false, 'reason' => 'malformed input' }]
      ]
    end

    # ---- non-JSON look-alikes: a number-like object is never === a number, a String subclass prints its own characters,
    # an alg that only pretends to be a suite name is no suite; numeric cells are Ruby Integers ----
    NUMLIKE = Class.new { def ==(other) = other.is_a?(Numeric) }.new
    STRLIKE = Class.new do
      def to_str = 'ed25519'
      def ==(other) = other.is_a?(String) && other == 'ed25519'
    end.new
    SUBSTR = Class.new(String) { def to_s = 'not-the-content' }
    ANYEQ = Class.new { def ==(_other) = true }.new
    TYPELIKE = Class.new do
      def to_str = 'boolean'
      def ==(other) = other.is_a?(String) && other == 'boolean'
    end.new

    def lookalike_checks
      ep = { 'guardian' => 'g', 'alg' => STRLIKE, 'instance_id' => 'i', 'grant_ref' => 'r', 'epoch' => 0, 'set_size' => 0, 'root' => 'x',
             'issued_at' => 0, 'not_after' => 10, 'sig' => 's' }
      cells = iv2.map_num_cells({ 'kind' => 'num', 'lo' => 0.0, 'hi' => 5.0, 'cuts' => [2.0] })
      [
        ['strict_eq number vs number-like', AtlasPca::V2JS.strict_eq(1, NUMLIKE) == false && AtlasPca::V2JS.strict_eq(NUMLIKE, 1) == false],
        ['strict_eq numbers', AtlasPca::V2JS.strict_eq(1, 1.0) == true],
        # an object equal to everything passes the boolean test, but is still not === a non-boolean
        ['strict_eq everything-equal vs a number', AtlasPca::V2JS.strict_eq(ANYEQ, 5) == false],
        # a declared type that is not a String is an unknown type, even when it compares equal to a type name
        ['declared type look-alike', x.param_value_violation({ 'type' => TYPELIKE }, true) == { 'code' => 'bad_type', 'reason' => 'unknown declared type' }],
        ['js_str of a String subclass', x.session_revocation_id(SUBSTR.new('s1')) == 'pca-intent:session:s1'],
        ['alg look-alike is no suite', x.check_revocation_epoch(ep, 'g', 1) == { 'ok' => false, 'reason' => 'revocation epoch not signed by the pinned guardian' }],
        ['numeric cells are Integers', cells == [[0, 1], [2, 2], [3, 5]] && cells.flatten.all?(Integer)]
      ]
    end

    # ---- a hybrid (ed25519 + ML-DSA-65) revocation epoch: the PQ half is ep.pq_sig, verified under the pinned key ----
    HYB = 'hybrid-ed25519-ml-dsa-65'
    NOW = 1_800_000_000_000

    def pq_epoch = (@pq_epoch ||= begin
      ed = V2Targeted.ed_key
      ml = OpenSSL::PKey.generate_key('ML-DSA-65')
      pq_pk = AtlasPca.b64e(ml.raw_public_key)
      body = { 'instance_id' => 'inst-1', 'grant_ref' => 'pca-intent-session:s1', 'epoch' => 0, 'set_size' => 0,
               'root' => iv2.revset_root([]), 'issued_at' => NOW - 1000, 'not_after' => NOW + 100_000 }
      msg = iv2.dmsg(iv2::REVEPOCH_DOMAIN, body.merge('alg' => HYB, 'pq_pk' => pq_pk))
      ep = body.merge('guardian' => V2Targeted.ed_pk, 'alg' => HYB, 'pq_pk' => pq_pk, 'sig' => AtlasPca.b64e(ed.sign(nil, msg)),
                      'pq_sig' => AtlasPca.b64e(ml.sign(nil, msg)))
      [ep, { V2Targeted.ed_pk => pq_pk }]
    end)

    def pq_epoch_checks
      ep, pins = pq_epoch
      g = V2Targeted.ed_pk
      invalid = { 'ok' => false, 'reason' => 'revocation epoch signature invalid' }
      [
        ['hybrid epoch verifies under the pin', x.check_revocation_epoch(ep, g, NOW, absent, pins) == { 'ok' => true }],
        ['hybrid epoch: wrong pq_sig', x.check_revocation_epoch(ep.merge('pq_sig' => ep['sig']), g, NOW, absent, pins) == invalid],
        ['hybrid epoch: no pin', x.check_revocation_epoch(ep, g, NOW, absent, nil) == invalid],
        # an exception inside the signature seam (here: the pins lookup) is a failed signature, never a pass
        ['hybrid epoch: raising pins fail closed', x.check_revocation_epoch(ep, g, NOW, absent, RAISING_PINS) == invalid]
      ]
    end

    # ---- accumulators: the k042-intentv2-cases `vec/acc-receipt` decision (a passing sequenced receipt), its session root
    # re-signed by a key of this file so accumulators can be added ----
    def acc_case = (@acc_case ||= IntentV2Diff.cases.find { |c| c['name'] == 'vec/acc-receipt' })

    def acc_run(p_edit: nil, root_edit: nil, ctx_edit: nil)
      c = acc_case
      p = AtlasPca.parse_json_text(c['p'])
      ctx = AtlasPca.parse_json_text(c['ctx'])
      s = ctx['session']['root']
      root_edit&.call(s)
      s['principals'] = [{ 'key' => V2Targeted.ed_pk }]
      s['signer'] = V2Targeted.ed_pk
      s['sig'] = V2Targeted.ed_sig(iv2.dmsg(iv2::INTENT_SESSION_SIG_DOMAIN, iv2.session_root_body(s).merge('signer' => s['signer'])))
      p['intent_session']['root'] = iv2.session_root_digest(s)
      p_edit&.call(p)
      ctx_edit&.call(ctx, p)
      out = iv2.decide_intent_v2(p, AtlasPca.parse_json_text(c['grant']), ctx, c['now'])
      out['checks'].find { |k| k['name'] == 'accumulators' }
    end

    def acc_checks
      keyed = { 'id' => 'k1', 'agg' => 'count', 'sel' => { 'verbs' => ['air.book'] }, 'win' => { 'kind' => 'task' },
                'key' => 'action.params.offer_id', 'holder' => { 'kind' => 'site_local' } }
      semantic = lambda do |val|
        lambda do |ctx, p|
          doc = deep(ctx['schema']['docs'][0])
          d = doc['verbs'].find { |v| v['verb'] == 'air.book' }['params']['action.params.offer_id']
          val.nil? ? d.delete('semantic') : d['semantic'] = val
          ctx['schema']['docs'] << doc
          ctx['acc']['state'] = { 'k1' => { 'count' => 0 } }
          p['intent_session']['schema'] = AtlasPca.action_schema_digest(doc)
        end
      end
      claim_k1 = ->(p) { p['intent_session']['acc'].unshift({ 'id' => 'k1', 'post' => 1 }) }
      [
        ['re-signed fixture passes', acc_run == { 'name' => 'accumulators', 'ok' => true }],
        # `decl.semantic.startsWith('text.')` on a declaration without a string semantic (an unverified schema doc): fail closed, named
        ['key declaration without a semantic', acc_run(root_edit: ->(s) { s['accumulators'].unshift(keyed) }, p_edit: claim_k1, ctx_edit: semantic.call(nil)) ==
          { 'name' => 'accumulators', 'ok' => false, 'reason' => 'accumulators error (fail closed): semantic is not a string' }]
      ]
    end

    def first_bad(checks)
      checks.call.each { |name, ok| return name unless ok == true }
      nil
    rescue StandardError, SystemStackError => e
      "raised #{e.class}: #{e.message[0, 120]}"
    end
  end

  # the hybrid epoch is signed here, by the unmutated library
  V2Residual.pq_epoch if AtlasPca.supported_suites.include?(V2Residual::HYB)

  [['IntentV2 constants', -> { V2Residual.constant_checks }, nil],
   ['equal bytes in another encoding', -> { V2Residual.encoding_checks }, nil],
   ['public entry points on malformed input', -> { V2Residual.malformed_checks }, nil],
   ['public wrapper rescues fail closed', -> { V2Residual.rescue_checks }, nil],
   ['non-JSON look-alikes / Integer cells', -> { V2Residual.lookalike_checks }, nil],
   ['hybrid revocation epoch', -> { V2Residual.pq_epoch_checks }, V2Residual::HYB],
   ['accumulators: key declaration semantic', -> { V2Residual.acc_checks }, nil]].each do |label, checks, needs|
    t("intent v2 residual: #{label}", needs: needs) do
      next true if DiffUtil.skip?('intent_v2.rb')

      bad = V2Residual.first_bad(checks)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
