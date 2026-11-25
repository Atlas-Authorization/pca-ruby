# frozen_string_literal: true

# Least privilege from observed behaviour: propose a narrower grant from what its holder really did (proven subsumed by the original,
# never applied), unused-permission findings, and signed access requests. Port of the TypeScript reference (@atlasauth/pca-analyzer).
require_relative 'analyzer_exposure'

module AtlasPca
  module Analyzer
    ACCESS_REQUEST_SIG_DOMAIN = "atlas-pca/access-request/v1\0"

    module_function

    def rev_weight(r) = r.is_a?(String) && AtlasPca::REVERSIBILITY_ORDER.include?(r) ? AtlasPca::REVERSIBILITY_ORDER.index(r) + 1 : 0

    def common_prefix(rs)
      p = rs.empty? ? '' : rs[0].chars
      rs.each do |r|
        rc = r.chars
        i = 0
        i += 1 while i < p.length && i < rc.length && p[i] == rc[i]
        p = p[0, i]
      end
      cut = p.rindex('/')
      cut.nil? ? '' : p[0, cut + 1].join
    end

    def integer_num?(v) = num?(v) && jsnum(v).finite? && jsnum(v) == jsnum(v).floor

    def upper_bound_of(where, path)
      ub = Float::INFINITY
      req_list(nn(where, [])).each do |c|
        ub = [ub, jsnum(c['value'])].min if c.is_a?(Hash) && c.key?('field') && c['field'] == path && %w[lte lt].include?(c['op']) && num?(g(c, 'value'))
      end
      ub
    end

    def ctx_of(a)
      params = jget(a, 'params')
      { 'action' => { 'verb' => jget(a, 'verb'), 'resource' => jget(a, 'resource'), 'params' => params.equal?(UNDEF) || params.nil? ? {} : params } }
    end

    def matches?(p, a) = AtlasPca.predicate_matches(p, ctx_of(a))
    def params_of(a) = nn(jget(a, 'params'), {})
    def join_verbs(verbs) = verbs.map { |v| v.nil? ? '' : js_str(v) }.join(', ')

    # Propose a narrower replacement for `policy` from the ledger-sourced `observed` actions, plus unused-permission findings and
    # access requests for refused attempts. Result: {used, rejected, denied, proposal?, reason?, coversObserved, diff?, findings,
    # accessRequests, taskBinding?}. Never applies anything.
    def suggest_narrowing(policy, observed, o = nil)
      o = {} if o.nil?
      margin = nn(jget(o, 'margin'), 0.1)
      min_samples = nn(jget(o, 'minSamples'), 5)
      enum_limit = nn(jget(o, 'enumLimit'), 8)
      catalog = jget(o, 'catalog')
      model = to_model(policy)
      digest = policy_digest_of(model)
      observed = req_list(observed)

      trusted = observed.select { |x| jget(x, 'source') == 'ledger' && jget(x, 'outcome') != 'denied' }
      rejected = observed.count { |x| jget(x, 'source') != 'ledger' }
      refused = observed.select { |x| jget(x, 'source') == 'ledger' && jget(x, 'outcome') == 'denied' }

      findings = []
      pp = jget(policy, 'predicates')
      base = pp.is_a?(Array) ? pp : []

      build = lambda do |narrow_resources|
        out = []
        base.each do |p|
          hits = trusted.select { |a| matches?(p, a) }
          next if hits.empty?

          verbs = hits.map { |h| jget(h, 'verb') }.uniq.sort_by { |x| u16key(x) }
          resources = hits.map { |h| jget(h, 'resource') }.uniq.sort_by { |x| u16key(x) }
          nxt = { 'verb' => verbs.length == 1 ? verbs[0] : verbs }
          if narrow_resources
            if resources.length == 1
              nxt['resource'] = resources[0]
            else
              pre = common_prefix(resources)
              if pre.length > 1
                nxt['resource'] = "#{pre}*"
              elsif !jget(p, 'resource').equal?(UNDEF)
                nxt['resource'] = jget(p, 'resource')
              end
            end
          elsif !jget(p, 'resource').equal?(UNDEF)
            nxt['resource'] = jget(p, 'resource')
          end
          where = req_list(nn(jget(p, 'where'), [])).dup
          names = {}
          hits.each { |h| spread(params_of(h)).each_key { |k| names[k] = true } }
          names.keys.sort_by { |x| u16key(x) }.each do |name|
            path = "action.params.#{name}"
            vals = hits.map { |h| own(params_of(h), name) }
            next if vals.length < min_samples || vals.any? { |v| v.equal?(UNDEF) }

            if vals.all? { |v| num?(v) && !fin(v).nil? }
              mx = vals.map { |v| jsnum(v) }.max
              v = mx * (1 + margin)
              ceil = vals.all? { |x| integer_num?(x) } ? v.ceil : v
              where << { 'field' => path, 'op' => 'lte', 'value' => ceil } if ceil < upper_bound_of(jget(p, 'where'), path)
            elsif vals.all? { |x| x.is_a?(String) }
              st = vals.uniq.sort_by { |x| u16key(x) }
              where << { 'field' => path, 'op' => 'in', 'value' => st } if st.length <= enum_limit
            end
          end
          nxt['where'] = where unless where.empty?
          out << nxt
        end
        out
      end

      base.each_with_index do |p, i|
        hit = trusted.any? { |a| matches?(p, a) }
        pv = jget(p, 'verb')
        verbs = if pv.is_a?(String) then [pv]
                elsif pv.is_a?(Array) then pv.dup
                else []
                end
        unless hit
          v = !verbs.empty? && !verbs[0].nil? ? verbs[0] : '*'
          s = resolve_action(catalog, v == '*' ? 'unknown.any' : v)['spec']
          findings << {
            'kind' => 'unused-predicate', 'predicate' => i, 'verb' => v,
            'detail' => "no observed action used predicate #{i} (#{join_verbs(verbs).then { |x| x.empty? ? '*' : x }})",
            'blastRadius' => s['blastRadius'], 'reversibility' => s['reversibility'], 'rank' => s['blastRadius'] * rev_weight(s['reversibility'])
          }
          next
        end
        verbs.each do |v|
          next if v == '*'
          next if trusted.any? { |a| strict_eq(jget(a, 'verb'), v) && matches?(p, a) }

          s = resolve_action(catalog, v)['spec']
          findings << {
            'kind' => 'unused-verb', 'predicate' => i, 'verb' => v, 'detail' => "verb #{v} is granted by predicate #{i} but never used",
            'blastRadius' => s['blastRadius'], 'reversibility' => s['reversibility'], 'rank' => s['blastRadius'] * rev_weight(s['reversibility'])
          }
        end
        req_list(nn(jget(p, 'where'), [])).each do |c|
          next unless c.is_a?(Hash) && c['field'].is_a?(String) && %w[lte lt].include?(c['op']) && num?(g(c, 'value')) && c['field'].start_with?('action.params.')

          name = c['field']['action.params.'.length..]
          vals = trusted.select { |a| matches?(p, a) }.map { |a| own(params_of(a), name) }.select { |x| num?(x) }
          next unless vals.length >= min_samples && vals.map { |x| jsnum(x) }.max < jsnum(c['value']) / 2

          v0 = verbs.empty? ? UNDEF : verbs[0]
          s = resolve_action(catalog, !v0.equal?(UNDEF) && !v0.nil? ? v0 : 'unknown.any')['spec']
          f = { 'kind' => 'unreached-cap', 'predicate' => i }
          f['verb'] = v0 if truthy?(v0)
          f.merge!(
            'detail' => "#{name} <= #{num_str(jsnum(c['value']))} but the largest observed value is #{num_str(vals.map { |x| jsnum(x) }.max)}",
            'blastRadius' => s['blastRadius'], 'reversibility' => s['reversibility'], 'rank' => s['blastRadius'] * rev_weight(s['reversibility'])
          )
          findings << f
        end
      end
      findings = stable_sort_by(findings) { |f| [-f['rank'], f['predicate']] }

      groups = {}
      refused.each do |a|
        k = "#{js_str(jget(a, 'verb'))}\u0000#{js_str(jget(a, 'resource'))}"
        grp = groups[k]
        if grp
          grp['denied_count'] += 1
        else
          r = {
            'v' => 1, 'kind' => 'pca-access-request', 'verb' => jget(a, 'verb'), 'resource' => jget(a, 'resource'),
            'example_params' => spread(params_of(a)), 'denied_count' => 1, 'policy_digest' => digest
          }
          r['task_binding'] = jget(o, 'taskBinding') if truthy?(jget(o, 'taskBinding'))
          groups[k] = r
        end
      end
      access_requests = stable_sort_by(groups.values) { |x| [-x['denied_count'], u16key(x['verb'])] }

      res = { 'used' => trusted.length, 'rejected' => rejected, 'denied' => refused.length, 'coversObserved' => false,
              'findings' => findings, 'accessRequests' => access_requests }
      res['taskBinding'] = jget(o, 'taskBinding') if truthy?(jget(o, 'taskBinding'))

      caveats = nn(model['caveats'], []).dup
      decay = jget(o, 'decay')
      caveats << { 'type' => 'expires', 'at' => jget(decay, 'nowSec') + jget(decay, 'expiresInSecs') } if truthy?(decay)
      original = policy
      [true, false].each do |narrow|
        proposal = { 'predicates' => build.call(narrow), 'caveats' => caveats, 'vetoes' => model['vetoes'], 'tighten' => model['tighten'] }
        if proposal['predicates'].empty?
          res['reason'] = 'no ledger observation matches any predicate'
          return res
        end
        proof = subsumes(original, proposal)
        if proof['subsumes'] != true || proof['approximate'] == true
          res['reason'] = proof.fetch('reason', 'the proposal could not be proven narrower than the original')
          next
        end
        res.delete('reason')
        res['proposal'] = proposal
        res['coversObserved'] = trusted.all? do |a|
          admits_concrete(proposal, { 'verb' => jget(a, 'verb'), 'resource' => jget(a, 'resource'), 'params' => params_of(a) })
        end
        res['diff'] = diff_policies(original, proposal)
        return res
      end
      res
    end

    # ---- access requests ----------------------------------------------------------------------------------------------------

    def request_message(r)
      ACCESS_REQUEST_SIG_DOMAIN.b + Digest::SHA256.digest(AtlasPca.hash_canonical(r).b)
    end

    # The holder's signed ask (a request for a human to read; nothing here turns it into authority). `secret` is the Ed25519 seed.
    def sign_access_request(r, secret, signer_public)
      { 'request' => r, 'signer' => signer_public, 'sig' => AtlasPca.b64e(AtlasPca::KeyPair.new(secret).sign(request_message(r))) }
    end

    # Verify a signed access request (optionally against an expected signer public key); any failure is false.
    def verify_access_request(s, expected_signer = nil)
      return false if !s.is_a?(Hash) || !s['request'].is_a?(Hash) || s['request']['kind'] != 'pca-access-request' || !strict_eq(g(s['request'], 'v'), 1)
      return false if !expected_signer.nil? && !strict_eq(g(s, 'signer'), expected_signer)

      sig = s['sig']
      return false unless sig.is_a?(String)

      AtlasPca.verify_b64u(s['signer'], request_message(s['request']), sig) ? true : false
    rescue StandardError
      false
    end
  end
end
