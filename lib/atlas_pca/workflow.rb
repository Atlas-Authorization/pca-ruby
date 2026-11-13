# frozen_string_literal: true

# K5 workflow (DAG) admission: ports packages/pca/src/workflow.ts check for check. Total and pure; anything unknown, malformed,
# unsigned, out of order or unplanned DENIES. Hashes use String keys; integers only (a Float is never an integer).
# Replays packages/pca/conformance/workflow-vectors.json.
module AtlasPca
  WORKFLOW_DOMAIN = "atlas-pca/workflow/v1\x00".b.freeze
  WF_RECEIPT_DOMAIN = "atlas-pca/wf-receipt/v1\x00".b.freeze
  K5_WF_REF = 'atlas-pca/workflow-ref/v1'
  K5_WR_REF = 'atlas-pca/wf-receipt-ref/v1'
  K5_VAL = 'atlas-pca/wf-value/v1'
  WORKFLOW_LIMITS = { steps: 64, edges: 256, deps: 16, labels: 16, fields: 32, cost: 8, id: 64 }.freeze
  K5_ID_RE = /\A(?!__proto__\z)[A-Za-z0-9_.:-]{1,64}\z/
  K5_LABEL_RE = /\A(?!__proto__\z)[a-z0-9_.:-]{1,64}\z/
  K5_NAME_RE = /\A(?!__proto__\z)[A-Za-z0-9_.-]{1,64}\z/
  K5_UNIT_RE = /\A[A-Za-z0-9_.:-]{1,16}\z/
  K5_STEP_KEYS = %w[id verb resource params_digest deps sink deny_labels escalate_labels fresh_ms cost].freeze
  K5_EDGE_KEYS = %w[from to op unit deny_labels promise].freeze
  K5_BODY_KEYS = %w[v id principal goal_digest plan_root issued_at expires_at steps edges budget].freeze
  K5_OPS = %w[eq le ge lt gt].freeze
  K5_REQ_KEYS = %w[step verb resource params units goal_digest plan_root].freeze
  K5_RECEIPT_KEYS = %w[v wf step seq prev outcome params_digest outputs issued_at signer sig].freeze

  module_function

  # ---- shared strict helpers (also used by readside.rb) ----
  def k5_obj?(x) = x.is_a?(Hash)
  def k5_uint?(n) = n.is_a?(Integer) && n >= 0 && n <= MAX_SAFE
  def k5_one?(v) = v.is_a?(Integer) && v == 1
  def k5_b32?(x) = x.is_a?(String) && !b64d(x, 32).nil?
  def k5_re?(x, re) = x.is_a?(String) && x.valid_encoding? && re.match?(x)
  def k5_id?(x) = k5_re?(x, K5_ID_RE)
  def k5_name?(x) = k5_re?(x, K5_NAME_RE)
  def k5_unit?(x) = k5_re?(x, K5_UNIT_RE)
  def k5_null_or(x) = x.nil? || yield(x)
  def k5_keys?(o, keys) = o.keys.length == keys.length && keys.all? { |k| o.key?(k) }

  # Strictly ascending (bytewise; all members ASCII) with every member matching `re`.
  def k5_sorted_unique?(x, re, max)
    return false unless x.is_a?(Array) && x.length <= max

    x.each_with_index do |s, i|
      return false unless k5_re?(s, re)
      return false if i.positive? && !(x[i - 1].b < s.b)
    end
    true
  end

  def k5_scalar?(v) = v.is_a?(String) || v == true || v == false || (v.is_a?(Integer) && v.abs <= MAX_SAFE)

  def k5_scalar_map?(x)
    x.is_a?(Hash) && x.length <= WORKFLOW_LIMITS[:fields] && x.all? { |k, v| k5_name?(k) && k5_scalar?(v) }
  end

  def k5_uint_map?(x, max)
    x.is_a?(Hash) && x.length <= max && x.all? { |k, v| k5_name?(k) && k5_uint?(v) }
  end

  def k5_verify_body(domain, body, signer, sig)
    signer.is_a?(String) && k3_verify_body(domain, body, signer, sig)
  rescue StandardError
    false
  end

  def wf_value_digest(v) = hash_canonical({ 'd' => K5_VAL, 'v' => v })
  def workflow_digest(b) = hash_canonical({ 'd' => K5_WF_REF, 'w' => b })
  def wf_receipt_ref(r) = hash_canonical({ 'd' => K5_WR_REF, 'r' => r })

  # ---- validation ----
  def k5_valid_step?(s)
    return false unless s.is_a?(Hash) && k5_keys?(s, K5_STEP_KEYS)

    k5_id?(s['id']) && k3_str?(s['verb'], 128) && k3_str?(s['resource'], 512) && k5_null_or(s['params_digest']) { |x| k5_b32?(x) } &&
      k5_sorted_unique?(s['deps'], K5_ID_RE, WORKFLOW_LIMITS[:deps]) && k5_null_or(s['sink']) { |x| k5_id?(x) } &&
      k5_sorted_unique?(s['deny_labels'], K5_LABEL_RE, WORKFLOW_LIMITS[:labels]) &&
      k5_sorted_unique?(s['escalate_labels'], K5_LABEL_RE, WORKFLOW_LIMITS[:labels]) &&
      k5_null_or(s['fresh_ms']) { |x| k5_uint?(x) } && k5_uint_map?(s['cost'], WORKFLOW_LIMITS[:cost])
  end

  def k5_valid_edge?(e)
    return false unless e.is_a?(Hash) && k5_keys?(e, K5_EDGE_KEYS)

    f = e['from']
    t = e['to']
    f.is_a?(Hash) && k5_keys?(f, %w[step field]) && k5_id?(f['step']) && k5_name?(f['field']) &&
      t.is_a?(Hash) && k5_keys?(t, %w[step param]) && k5_id?(t['step']) && k5_name?(t['param']) &&
      e['op'].is_a?(String) && K5_OPS.include?(e['op']) && k5_null_or(e['unit']) { |x| k5_unit?(x) } &&
      k5_sorted_unique?(e['deny_labels'], K5_LABEL_RE, WORKFLOW_LIMITS[:labels]) && k5_null_or(e['promise']) { |x| k5_id?(x) }
  end

  # Shape of the body only (no signature, no DAG semantics).
  def valid_workflow_body?(b)
    return false unless b.is_a?(Hash) && k5_keys?(b, K5_BODY_KEYS) && k5_one?(b['v'])
    unless k5_id?(b['id']) && k5_b32?(b['principal']) && k5_null_or(b['goal_digest']) { |x| k5_b32?(x) } &&
           k5_null_or(b['plan_root']) { |x| k5_b32?(x) } && k5_uint?(b['issued_at']) && k5_uint?(b['expires_at'])
      return false
    end

    st = b['steps']
    return false unless st.is_a?(Array) && !st.empty? && st.length <= WORKFLOW_LIMITS[:steps] && st.all? { |s| k5_valid_step?(s) }

    ed = b['edges']
    return false unless ed.is_a?(Array) && ed.length <= WORKFLOW_LIMITS[:edges] && ed.all? { |e| k5_valid_edge?(e) }

    bg = b['budget']
    return false unless bg.is_a?(Hash) && k5_keys?(bg, %w[max_steps caps]) && k5_uint?(bg['max_steps']) && k5_uint_map?(bg['caps'], WORKFLOW_LIMITS[:cost])

    # every cost name must be capped: an uncapped cost is a budget that silently does not exist
    st.all? { |s| s['cost'].keys.all? { |k| bg['caps'].key?(k) } }
  rescue StandardError
    false
  end

  # step id -> Set of its transitive dependencies; nil on a cycle.
  def wf_ancestors(b)
    by_id = b['steps'].to_h { |s| [s['id'], s] }
    out = {}
    state = {}
    visit = lambda do |id|
      return true if state[id] == 2
      return false if state[id] == 1

      state[id] = 1
      set = {}
      by_id[id]['deps'].each do |d|
        return false unless visit.call(d)

        set[d] = true
        out[d].each_key { |x| set[x] = true }
      end
      out[id] = set
      state[id] = 2
      true
    end
    b['steps'].each { |s| return nil unless visit.call(s['id']) }
    out
  end

  # DAG semantics: unique ids, deps exist, acyclic, every edge runs from a (transitive) dependency. nil when fine.
  def wf_dag_error(b)
    ids = {}
    b['steps'].each do |s|
      return 'duplicate step id' if ids.key?(s['id'])

      ids[s['id']] = s
    end
    b['steps'].each { |s| s['deps'].each { |d| return 'bad dependency' if d == s['id'] || !ids.key?(d) } }
    anc = wf_ancestors(b)
    return 'cycle' if anc.nil?

    b['edges'].each do |e|
      unless ids.key?(e['from']['step']) && ids.key?(e['to']['step']) && anc[e['to']['step']].key?(e['from']['step'])
        return 'edge does not follow a dependency'
      end
    end
    nil
  end

  def k5_receipt_body(r) = %w[v wf step seq prev outcome params_digest outputs issued_at signer].to_h { |k| [k, r[k]] }

  def k5_valid_receipt_shape?(r)
    return false unless r.is_a?(Hash) && k5_keys?(r, K5_RECEIPT_KEYS) && k5_one?(r['v'])
    return false unless k5_b32?(r['wf']) && k5_id?(r['step']) && k5_uint?(r['seq']) && k5_null_or(r['prev']) { |x| k5_b32?(x) }
    return false unless r['seq'].zero? == r['prev'].nil? && %w[ok failed].include?(r['outcome'])
    return false unless k5_b32?(r['params_digest']) && k5_uint?(r['issued_at']) && k5_b32?(r['signer']) && r['sig'].is_a?(String)

    o = r['outputs']
    return false unless o.is_a?(Hash) && o.length <= WORKFLOW_LIMITS[:fields]

    o.all? do |k, v|
      k5_name?(k) && v.is_a?(Hash) && k5_keys?(v, %w[digest num unit labels]) && k5_b32?(v['digest']) && k5_null_or(v['num']) { |x| k5_uint?(x) } &&
        k5_null_or(v['unit']) { |x| k5_unit?(x) } && k5_sorted_unique?(v['labels'], K5_LABEL_RE, WORKFLOW_LIMITS[:labels])
    end
  end

  def k5_wf_res(decision, code, step, at = nil, pending = [])
    { 'decision' => decision, 'code' => code, 'step' => step, 'at' => at, 'pending' => pending }
  end

  def k5_wf_deny(code, step = nil, at = nil) = k5_wf_res('deny', code, step, at)

  def k5_valid_request?(r)
    r.is_a?(Hash) && k5_keys?(r, K5_REQ_KEYS) && k5_id?(r['step']) && k3_str?(r['verb'], 128) && k3_str?(r['resource'], 512) &&
      k5_scalar_map?(r['params']) && r['units'].is_a?(Hash) && r['units'].all? { |k, v| k5_name?(k) && k5_unit?(v) } &&
      k5_null_or(r['goal_digest']) { |x| k5_b32?(x) } && k5_null_or(r['plan_root']) { |x| k5_b32?(x) }
  end

  # Is `root` the Merkle plan root this signed, unexpired, pinned-principal workflow authorizes?
  def plan_root_authorized?(workflow, principal, now, root)
    w = workflow
    w.is_a?(Hash) && valid_workflow_body?(w['body']) && wf_dag_error(w['body']).nil? && w['body']['principal'] == principal &&
      k5_verify_body(WORKFLOW_DOMAIN, w['body'], principal, w['sig']) && now.is_a?(Integer) && now >= w['body']['issued_at'] &&
      now < w['body']['expires_at'] && w['body']['plan_root'] == root
  rescue StandardError
    false
  end

  # Index of the offending receipt, or nil.
  def k5_receipt_error(w, rs_signer, receipts, now)
    wd = workflow_digest(w)
    by_id = w['steps'].to_h { |s| [s['id'], s] }
    index = {}
    prev = nil
    receipts.each_with_index do |r, i|
      return i unless k5_valid_receipt_shape?(r) && r['signer'] == rs_signer && r['wf'] == wd && r['seq'] == i && r['issued_at'] <= now
      return i if !by_id.key?(r['step']) || index.key?(r['step'])
      return i if (prev.nil? ? !r['prev'].nil? : r['prev'] != wf_receipt_ref(prev)) || !k5_verify_body(WF_RECEIPT_DOMAIN, k5_receipt_body(r), rs_signer, r['sig'])

      # a receipt may precede one of its dependencies' receipts only when every edge from that dependency is a declared promise
      by_id[r['step']]['deps'].each do |d|
        next if index.key?(d)

        es = w['edges'].select { |e| e['from']['step'] == d && e['to']['step'] == r['step'] }
        return i if es.empty? || es.any? { |e| e['promise'].nil? }
      end
      index[r['step']] = i
      prev = r
    end
    nil
  end

  def k5_edge_ok?(op, val, num)
    case op
    when 'le' then val <= num
    when 'ge' then val >= num
    when 'lt' then val < num
    else val > num
    end
  end

  def k5_evaluate(inp, bind)
    sw = inp['workflow']
    q = inp['request']
    receipts = inp['receipts']
    unless sw.is_a?(Hash) && k5_keys?(sw, %w[body sig]) && valid_workflow_body?(sw['body']) && k5_valid_request?(q) && receipts.is_a?(Array) &&
           k5_b32?(inp['principal']) && k5_b32?(inp['rs_signer']) && k5_uint?(inp['now'])
      return k5_wf_deny('bad_workflow')
    end

    w = sw['body']
    now = inp['now']
    return k5_wf_deny('bad_dag', q['step']) unless wf_dag_error(w).nil?
    return k5_wf_deny('bad_signature', q['step']) if w['principal'] != inp['principal'] || !k5_verify_body(WORKFLOW_DOMAIN, w, inp['principal'], sw['sig'])
    return k5_wf_deny('not_yet', q['step']) if now < w['issued_at']
    return k5_wf_deny('expired', q['step']) if now >= w['expires_at']
    return k5_wf_deny('goal_mismatch', q['step']) if q['goal_digest'] != w['goal_digest']
    return k5_wf_deny('plan_root_mismatch', q['step']) if q['plan_root'] != w['plan_root']

    bad = k5_receipt_error(w, inp['rs_signer'], receipts, now)
    return k5_wf_deny('bad_receipt', q['step'], bad) unless bad.nil?

    rec = receipts.to_h { |r| [r['step'], r] }
    step = w['steps'].find { |s| s['id'] == q['step'] }
    return k5_wf_deny('unplanned_step', q['step']) if step.nil?
    return k5_wf_deny('step_mismatch', q['step']) if step['verb'] != q['verb'] || step['resource'] != q['resource']

    pd = hash_canonical(q['params'])
    return k5_wf_deny('params_mismatch', q['step']) if !step['params_digest'].nil? && step['params_digest'] != pd

    mine = rec[step['id']]
    if bind
      return k5_wf_deny('params_mismatch', q['step']) if mine.nil? || mine['params_digest'] != pd
    else
      return k5_wf_deny('already_done', q['step']) unless mine.nil?
      return k5_wf_deny('budget_exceeded', q['step']) if receipts.length + 1 > w['budget']['max_steps']

      w['budget']['caps'].each do |name, cap|
        spent = receipts.sum { |r| w['steps'].find { |s| s['id'] == r['step'] }['cost'][name] || 0 } + (step['cost'][name] || 0)
        return k5_wf_deny('budget_exceeded', q['step']) if spent > cap
      end
    end
    pending = []
    unconstrained = false
    step['deps'].each do |d|
      dr = rec[d]
      if dr.nil?
        es = w['edges'].each_with_index.select { |e, _| e['from']['step'] == d && e['to']['step'] == step['id'] }
        return k5_wf_deny('deps_unmet', q['step']) if bind || es.empty?

        unconstrained = true if es.any? { |e, _| e['promise'].nil? }
        next
      end
      return k5_wf_deny('dep_failed', q['step']) if dr['outcome'] != 'ok'
      return k5_wf_deny('stale_dep', q['step']) if !step['fresh_ms'].nil? && now - dr['issued_at'] > step['fresh_ms']
    end
    w['edges'].each_with_index do |e, i|
      next if e['to']['step'] != step['id']

      src = rec[e['from']['step']]
      if src.nil?
        pending << i
        next
      end
      out = src['outputs'][e['from']['field']]
      has_val = q['params'].key?(e['to']['param'])
      val = q['params'][e['to']['param']]
      return k5_wf_deny('edge_missing', q['step'], i) if out.nil? || !has_val
      return k5_wf_deny('edge_unit', q['step'], i) if out['unit'] != q['units'][e['to']['param']] || out['unit'] != e['unit']

      if e['op'] == 'eq'
        return k5_wf_deny('edge_digest', q['step'], i) if wf_value_digest(val) != out['digest']
      else
        return k5_wf_deny('edge_value', q['step'], i) if !val.is_a?(Integer) || out['num'].nil?
        return k5_wf_deny('edge_relation', q['step'], i) unless k5_edge_ok?(e['op'], val, out['num'])
      end
      return k5_wf_deny('taint_flow', q['step'], i) if out['labels'].any? { |l| e['deny_labels'].include?(l) }
    end
    return k5_wf_deny('deps_unmet', q['step']) if bind && !pending.empty?

    inherited = {}
    wf_ancestors(w)[step['id']].each_key do |a|
      (rec[a] ? rec[a]['outputs'] : {}).each_value { |o| o['labels'].each { |l| inherited[l] = true } }
    end
    return k5_wf_deny('taint_flow', q['step']) if step['deny_labels'].any? { |l| inherited.key?(l) }
    return k5_wf_res('escalate', 'pipeline_unconstrained', q['step']) if unconstrained
    return k5_wf_res('escalate', 'taint_escalate', q['step']) if step['escalate_labels'].any? { |l| inherited.key?(l) }

    k5_wf_res('allow', nil, q['step'], nil, pending)
  end

  # Admit ONE step of the committed workflow, or deny / escalate. `inp` (String keys): workflow, principal, rs_signer,
  # receipts, now, request. Never raises.
  def admit_step(inp)
    k5_evaluate(inp, false)
  rescue StandardError
    k5_wf_deny('bad_workflow')
  end

  # Promise binding (post hoc): the step already has its receipt; its params are re-checked against every edge.
  def bind_promises(inp)
    k5_evaluate(inp, true)
  rescue StandardError
    k5_wf_deny('bad_workflow')
  end
end
