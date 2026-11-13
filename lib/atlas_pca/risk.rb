# frozen_string_literal: true

# Risk functional, threshold map and decaying trust budget (spec section 10, L3). A port of packages/pca/src/risk.ts and of the
# numeric kernels of the policy VM (formal/dafny/PolicyVm.dfy: ReqThr, Escalate, AdmitOf, DecideCore). Pure and deterministic.
# Time is epoch milliseconds; `lambda` is budget drained PER SECOND. Non-finite inputs fail closed (treated as worst case).
#
# Shapes (string keys, as the rest of the SDK): a policy is { 'weights' => { 'alpha' .. 'zeta' }, 'theta1', 'theta2', 'kappa',
# 'lambda', 'rho', 'bMax' }; risk inputs { 'semanticDistance', 'reversibility', 'blastRadius', 'taint', 'confidence', 'age' };
# a budget { 'B', 'tau', 'asOf' }; a threshold { 't', 'proof', 'optimisticAllowed' }.
module AtlasPca
  module Risk
    module_function

    WEIGHT_KEYS = %w[alpha beta gamma delta epsilon zeta].freeze
    INPUT_KEYS = %w[semanticDistance reversibility blastRadius taint confidence age].freeze
    # the worst case of each input (a missing or non-finite value counts as this)
    WORST = { 'semanticDistance' => 1, 'reversibility' => 0, 'blastRadius' => 1, 'taint' => 1, 'confidence' => 0, 'age' => 1 }.freeze
    PROOF_FOR_T = { 1 => 'claim', 2 => 'standard', 3 => 'strong' }.freeze
    PROOF_RANK = { 'claim' => 0, 'standard' => 1, 'strong' => 2 }.freeze

    # a finite JS number: an Integer or a finite Float (never a boolean, String or nil)
    def fin?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite?)

    def clamp01(x) = x < 0 ? 0 : (x > 1 ? 1 : x)
    # non-finite => worst; else clamp to [0,1]. `worst` is 1 for risk-increasing inputs, 0 for reversibility / confidence.
    def unit(x, worst) = fin?(x) ? clamp01(x) : worst
    def wt(x) = fin?(x) && x > 0 ? x : 0
    def nz(x) = fin?(x) && x > 0 ? x : 0

    # r = clamp( a*d + b*(1-rev) + g*bl + d*taint + e*(1-conf) + z*age, 0, 1 ). Weights are clamped to >= 0.
    def risk_score(i, w)
      r = wt(w['alpha']) * unit(i['semanticDistance'], 1) +
          wt(w['beta']) * (1 - unit(i['reversibility'], 0)) +
          wt(w['gamma']) * unit(i['blastRadius'], 1) +
          wt(w['delta']) * unit(i['taint'], 1) +
          wt(w['epsilon']) * (1 - unit(i['confidence'], 0)) +
          wt(w['zeta']) * unit(i['age'], 1)
      clamp01(r)
    end

    # piecewise map: r <= theta1 -> t=1 (claim, optimistic ok unless irreversible); r <= theta2 -> t=2; else t=3. NaN r => worst.
    def required_threshold(r, p, irreversible: false)
      x = fin?(r) ? r : 1
      return { 't' => 1, 'proof' => 'claim', 'optimisticAllowed' => !irreversible } if x <= p['theta1']
      return { 't' => 2, 'proof' => 'standard', 'optimisticAllowed' => false } if x <= p['theta2']

      { 't' => 3, 'proof' => 'strong', 'optimisticAllowed' => false }
    end

    # raise a threshold to at least min_t and keep it coherent; never lowers anything
    def escalate_threshold(rt, min_t)
      t = min_t > rt['t'] ? min_t : rt['t']
      floor = PROOF_FOR_T[t]
      proof = PROOF_RANK[rt['proof']] >= PROOF_RANK[floor] ? rt['proof'] : floor
      { 't' => t, 'proof' => proof, 'optimisticAllowed' => t > 1 ? false : rt['optimisticAllowed'] }
    end

    # ---- trust budget

    # c(A) = kappa * r(A). Non-finite r => the cost of r = 1.
    def cost(r, kappa) = nz(kappa) * clamp01(fin?(r) ? r : 1)

    # passive leak dB/dt = -lambda since the last update. Idempotent for repeated calls at the same `now`.
    def leak(b, now, lambda_)
      from = b['asOf'].nil? ? b['tau'] : b['asOf']
      dt = fin?(now) && fin?(from) ? [0, now - from].max : 0
      bb = [0, b['B'] - (nz(lambda_) * (dt / 1000.0))].max
      { 'B' => bb, 'tau' => b['tau'], 'asOf' => fin?(now) ? [now, from].max : from }
    end

    # B <- max(0, B - cost). Callers must check B >= cost first (admit does).
    def debit(b, c) = b.merge('B' => [0, b['B'] - nz(c)].max)

    # human co-sign recharge: B <- min(bMax, B + rho), tau <- now. The only way budget increases.
    def recharge(b, rho, b_max, now) = { 'B' => [nz(b_max), b['B'] + nz(rho)].min, 'tau' => now, 'asOf' => now }

    # full goal re-confirmation: B <- bMax, tau <- now
    def recharge_full(_b, b_max, now) = { 'B' => nz(b_max), 'tau' => now, 'asOf' => now }

    # normalised age since the last human touch: clamp((now - tau) / horizon_ms, 0, 1)
    def age_since_touch(b, now, horizon_ms = 3_600_000)
      return 1 if !fin?(now) || !fin?(b['tau']) || !(fin?(horizon_ms) && horizon_ms > 0)

      clamp01((now - b['tau']) / horizon_ms.to_f)
    end

    # the machine-only band is t=1 AND t=2 (both metered): an action at t<3 proceeds only if B >= c(A). t is
    # required_threshold(r)['t'], budget_covers = (b['B'] >= cost(r, kappa)) (false for NaN).
    def admit_of(t, budget_covers)
      if t < 3 && !budget_covers then { 'admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false }
      elsif t == 1 then { 'admit' => true, 'needStepUp' => false, 't' => 1, 'metered' => true }
      elsif t == 2 then { 'admit' => false, 'needStepUp' => true, 't' => 2, 'metered' => true }
      else { 'admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false }
      end
    end

    def admit(r, b, p)
      admit_of(required_threshold(r, p)['t'], b['B'] >= cost(r, p['kappa']))
    end

    # the Policy VM's release decision (PolicyVm.dfy DecideCore): release needs the envelope predicates, the caveats, the delegated
    # caveats and the chain; admitted/step-up follow the budget admission; the threshold is escalated to the admission's t.
    def decide_core(pr_ok, cv_ok, dcv_ok, chain_ok, rt, adm)
      release = pr_ok && cv_ok && dcv_ok && chain_ok
      { 'release' => release, 'admit' => release && adm['admit'], 'needStepUp' => release ? adm['needStepUp'] : true,
        'threshold' => escalate_threshold(rt, adm['t']), 'debit' => release && adm['metered'] }
    end

    # between two consecutive human recharges the total risk of machine-only actions is at most bMax / kappa
    def safety_bound(p) = p['kappa'] > 0 ? [0, p['bMax']].max / p['kappa'].to_f : 0

    # ---- multi-agent budget algebra

    # a sub-agent budget B_sub = alloc, guarded by 0 <= alloc <= parent.B
    def sub_budget(parent, alloc)
      return { 'ok' => false, 'reason' => 'allocation must be finite and >= 0' } if !fin?(alloc) || alloc < 0
      return { 'ok' => false, 'reason' => 'allocation exceeds parent remaining budget' } if alloc > parent['B']

      { 'ok' => true, 'sub' => { 'B' => alloc, 'tau' => parent['tau'], 'asOf' => parent['asOf'].nil? ? parent['tau'] : parent['asOf'] } }
    end

    # a sub-agent's debit ALSO debits the parent; fails (no state change) if either cannot cover c
    def debit_consolidated(parent, sub, c)
      x = nz(c)
      return { 'ok' => false, 'reason' => 'sub-agent budget insufficient' } if sub['B'] < x
      return { 'ok' => false, 'reason' => 'parent budget insufficient' } if parent['B'] < x

      { 'ok' => true, 'parent' => debit(parent, x), 'sub' => debit(sub, x) }
    end

    # consolidated debit along a root->leaf budget path: every node must cover c, else nothing is debited and the first offender is named
    def debit_consolidated_path(path, c)
      x = nz(c)
      path.each_with_index do |b, i|
        return { 'ok' => false, 'reason' => "budget node at depth #{i} insufficient (need #{js_num(x)}, have #{js_num(b['B'])})" } unless b['B'] >= x
      end
      { 'ok' => true, 'nodes' => path.map { |b| debit(b, x) } }
    end

    # JS String(n) of a budget number (1e21 -> "1e+21", 1e-7 -> "1e-7", an integral Float without a fraction)
    def js_num(x) = x.is_a?(Integer) || x.is_a?(Float) ? Predicates.js_number_string(x) : x.to_s

    # r.toFixed(3) for r in [0, 1]: JS picks the larger n on an exact tie (0.0625 -> "0.063"), C printf rounds to even
    def to_fixed3(r)
      n = ((r.to_r * 1000) + Rational(1, 2)).floor
      format('%d.%03d', n / 1000, n % 1000)
    end

    # the riskier of two partial input sets per input (TypeScript riskier): higher is riskier, except reversibility and confidence;
    # a non-finite or missing value of the second never replaces the first; with only one side present that side stands
    def riskier(a, b)
      return a.nil? ? b : a if a.nil? || b.nil?

      out = a.dup
      b.each do |k, y|
        next unless fin?(y)

        x = a[k]
        out[k] = if !fin?(x) then y
                 elsif %w[reversibility confidence].include?(k) then [x, y].min
                 else [x, y].max
                 end
      end
      out
    end

    # ---- plan geodesic

    PRE_KEYS = %w[after depends_on requires nodes].freeze
    POST_KEYS = %w[before enables then next].freeze

    def refs_of(x, keys)
      out = []
      add = lambda do |v|
        if v.is_a?(String) then out << v
        elsif v.is_a?(Array) then v.each { |s| out << s if s.is_a?(String) }
        end
      end
      add.call(x)
      keys.each { |k| add.call(x[k]) } if x.is_a?(Hash)
      out
    end

    # normalised geodesic distance in the committed plan DAG, in [0, 1] (an approximation, as the reference): edges come from node
    # references (`pre` ids are predecessors, `post` ids successors); BFS hop count over the undirected graph divided by (n - 1);
    # unreachable or an unknown node id => 1; no edges at all => index distance |i - j| / (n - 1). Same node => 0.
    def plan_geodesic(plan, from_id, to_id)
      return 1 unless plan.is_a?(Array)

      idx = {}
      plan.each_with_index { |n, i| idx[n['id']] = i }
      a = idx[from_id]
      b = idx[to_id]
      return 1 if a.nil? || b.nil?
      return 0 if a == b

      n = plan.length
      adj = Array.new(n) { [] }
      edges = 0
      link = lambda do |i, j|
        next if i == j

        edges += 1 unless adj[i].include?(j)
        adj[i] << j unless adj[i].include?(j)
        adj[j] << i unless adj[j].include?(i)
      end
      plan.each_with_index do |node, i|
        refs_of(node['pre'], PRE_KEYS).each { |id| (j = idx[id]) && link.call(j, i) }
        refs_of(node['post'], POST_KEYS).each { |id| (j = idx[id]) && link.call(i, j) }
      end
      return clamp01((a - b).abs / (n - 1).to_f) if edges.zero?

      dist = Array.new(n, -1)
      dist[a] = 0
      q = [a]
      h = 0
      while h < q.length
        u = q[h]
        adj[u].sort.each do |v|
          next unless dist[v] == -1

          dist[v] = dist[u] + 1
          q << v
        end
        h += 1
      end
      dist[b].negative? ? 1 : clamp01(dist[b] / (n - 1).to_f)
    end
  end
end
