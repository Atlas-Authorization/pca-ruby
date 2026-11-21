# frozen_string_literal: true

require_relative 'js_compat'

# PCA behind the OpenID AuthZEN Authorization API 1.0, byte-identical to the TypeScript reference: a Policy Decision Point
# (Access Evaluation, the Access Evaluations boxcar, the COAZ MCP-tool profile, the AARP approval-required step-up), a
# framework-agnostic handler over {'path', 'body'} Hashes and the three Search APIs (subject / resource / action).
# Everything fails closed: an unresolved policy, a malformed PCActn, a verifier rejection, a policy denial or any raised error
# is decision: false. The Policy-VM (decide / derive_decide_input) and the static analyzer (admits_concrete) are injected through
# the config; a PDP without them fails closed on the path that needs them. Config and context keys are snake_case; AuthZEN
# wire members keep their names.
module AtlasPca
  module Authzen
    PCA_APPROVAL_KEY = 'pca_approval'
    PCA_ACTION_KEY = 'pca_action'
    PCA_PROVENANCE_KEY = 'pca_provenance'
    DEFAULT_MAX_EVALUATIONS = 100
    EVALUATION_PATH = '/access/v1/evaluation'
    EVALUATIONS_PATH = '/access/v1/evaluations'
    COAZ_TOOL_PATH = '/access/v1/mcp/tool/evaluation'
    SEARCH_SUBJECT_PATH = '/access/v1/search/subject'
    SEARCH_RESOURCE_PATH = '/access/v1/search/resource'
    SEARCH_ACTION_PATH = '/access/v1/search/action'
    MAX_SEARCH_LIMIT = 1000
    UNDEF = Object.new.freeze # an absent member (JavaScript `undefined`), distinct from null

    module_function

    def rec?(x) = x.is_a?(Hash)
    def num?(x) = Js.num?(x) && x.to_f.finite?
    def js(v) = v.equal?(UNDEF) ? 'undefined' : Js.string(v)
    def err(e) = e.message.to_s.empty? ? 'unknown' : e.message

    # x.k in JavaScript: null / undefined throw, a primitive or array has no such member.
    def prop(x, k)
      raise TypeError, "Cannot read properties of #{x.nil? ? 'null' : 'undefined'} (reading '#{k}')" if x.nil? || x.equal?(UNDEF)

      x.is_a?(Hash) && x.key?(k) ? x[k] : UNDEF
    end

    # ---- guards ----

    def is_authzen_subject(x) = rec?(x) && x['type'].is_a?(String) && x['id'].is_a?(String)
    def is_authzen_action(x) = rec?(x) && x['name'].is_a?(String)
    def is_authzen_resource(x) = rec?(x) && x['type'].is_a?(String) && x['id'].is_a?(String)

    def is_access_evaluation_request(x)
      rec?(x) && is_authzen_subject(x['subject']) && is_authzen_action(x['action']) && is_authzen_resource(x['resource']) &&
        (!x.key?('context') || rec?(x['context']))
    end

    def is_access_evaluations_request(x) = rec?(x) && x['evaluations'].is_a?(Array)
    def is_coaz_tool_authorization_request(x) = rec?(x) && is_authzen_subject(x['subject']) && rec?(x['tool']) && x['tool']['name'].is_a?(String)

    def required_threshold?(x)
      rec?(x) && num?(x['t']) && [1, 2, 3].include?(x['t']) && x['proof'].is_a?(String) && [true, false].include?(x['optimisticAllowed'])
    end

    # ---- AARP ----

    # The AARP pending-approval reference of a decision, or nil.
    def approval_of(resp)
      ctx = prop(resp, 'context')
      return nil if ctx.equal?(UNDEF)

      p = prop(ctx, PCA_APPROVAL_KEY)
      return nil unless rec?(p) && p['approval_required'] == true && p['auth_req_id'].is_a?(String)

      tier = num?(p['tier']) && p['tier'] == 3 ? 3 : 2
      rt = p['required_threshold']
      { 'approval_required' => true, 'auth_req_id' => p['auth_req_id'], 'tier' => tier,
        'required_threshold' => required_threshold?(rt) ? rt : { 't' => tier, 'proof' => tier == 3 ? 'strong' : 'standard', 'optimisticAllowed' => false },
        'goal_commit' => p['goal_commit'].is_a?(String) ? p['goal_commit'] : '', 'risk' => num?(p['risk']) ? p['risk'] : 1,
        'reason' => p['reason'].is_a?(String) ? p['reason'] : 'approval required',
        'requested_at' => num?(p['requested_at']) ? p['requested_at'] : 0 }
    end

    def is_approval_required(resp) = !approval_of(resp).nil?

    # ---- mapping ----

    def deny(reason, id = nil, status = nil)
      context = { 'reason_admin' => { 'denied' => true, 'reason' => reason }, 'reason_user' => { 'message' => reason } }
      context['error'] = { 'status' => status, 'message' => reason } unless status.nil?
      context['id'] = id unless id.nil?
      { 'decision' => false, 'context' => context }
    end

    def permit(reason) = { 'decision' => true, 'context' => { 'reason_admin' => { 'reason' => reason } } }

    def pick_reversibility(req)
      a = req['action']['properties']
      return a['reversibility_class'] if rec?(a) && a['reversibility_class'].is_a?(String)

      c = req['context']
      rec?(c) && c['reversibility_class'].is_a?(String) ? c['reversibility_class'] : nil
    end

    def env_from_context(context)
      return nil unless rec?(context)

      out = context.reject { |k, _| [PCA_ACTION_KEY, PCA_APPROVAL_KEY].include?(k) }
      out.empty? ? nil : out
    end

    # verb = action.name; resource = "type:id" (just the type when id is empty); params = resource.properties overlaid by
    # action.properties; subject = subject.properties; env = context minus the PCA keys.
    def default_to_action(req)
      res = req['resource']
      act = req['action']
      params = {}
      params.merge!(res['properties']) if rec?(res['properties'])
      params.merge!(act['properties']) if rec?(act['properties'])
      out = { 'verb' => act['name'], 'resource' => res['id'].empty? ? res['type'] : "#{res['type']}:#{res['id']}", 'params' => params }
      rc = pick_reversibility(req)
      out['reversibilityClass'] = rc unless rc.nil?
      out['subject'] = req['subject']['properties'] if rec?(req['subject']['properties'])
      env = env_from_context(req['context'])
      out['env'] = env unless env.nil?
      out
    end

    # The forwarded PCActn Hash, nil when absent, or :malformed.
    def pcactn_from_context(context)
      return nil unless rec?(context)

      raw = context[PCA_ACTION_KEY]
      return nil if raw.nil?
      return :malformed unless raw.is_a?(String)
      return :malformed if Js.utf8(raw).bytesize > AtlasPca::MAX_ARTIFACT_BYTES

      v = AtlasPca.parse_json(raw)
      v.is_a?(Hash) ? v : :malformed
    rescue StandardError
      :malformed
    end

    def params_of(action) = rec?(action['params']) ? action['params'] : {}

    def fresh_budget(grant, now)
      env = AtlasPca.read_envelope(grant)
      b_max = env && env['risk_policy']['bMax']
      { 'B' => num?(b_max) ? b_max : 0, 'tau' => now, 'asOf' => now }
    end

    def approval_required(p, decision, grant, now)
      tier = decision['requiredThreshold']['t'] >= 3 ? 3 : 2
      reasons = decision['reasons']
      reason = reasons.is_a?(Array) && !reasons.empty? ? reasons[0] : "requires tier-#{tier} co-sign"
      act = p['action']
      body = { 'd' => 'atlas-pca/authzen/aarp/v1', 'verb' => act['verb'], 'resource' => act['resource'], 'params_digest' => act['params_digest'],
               'at' => now }
      body['counter'] = p['counter'] if p.key?('counter')
      auth_req_id = AtlasPca.hash_canonical(body)
      env = AtlasPca.read_envelope(grant)
      pending = { 'approval_required' => true, 'auth_req_id' => auth_req_id, 'tier' => tier, 'required_threshold' => decision['requiredThreshold'],
                  'goal_commit' => env ? env['goal_commit'] : '', 'risk' => decision['r'], 'reason' => reason, 'requested_at' => now }
      { 'decision' => false, 'context' => {
        'id' => auth_req_id,
        'reason_admin' => { 'stage' => 'step_up', 'risk' => decision['r'], 'threshold' => decision['requiredThreshold'], 'reasons' => reasons },
        'reason_user' => { 'message' => 'approval required before this action can proceed' }, PCA_APPROVAL_KEY => pending
      } }
    end

    def merge_evaluation(defaults, item)
      raise TypeError, "Cannot read properties of null (reading 'subject')" if item.nil?

      it = rec?(item) ? item : {}
      pick = ->(k) { it[k].nil? ? defaults[k] : it[k] }
      subject = pick.('subject')
      action = pick.('action')
      resource = pick.('resource')
      return nil unless is_authzen_subject(subject) && is_authzen_action(action) && is_authzen_resource(resource)

      out = { 'subject' => subject, 'action' => action, 'resource' => resource }
      if !it['context'].nil? then out['context'] = it['context']
      elsif defaults.key?('context') then out['context'] = defaults['context']
      end
      out
    end

    def truthy?(v) = !v.equal?(UNDEF) && Js.truthy?(v)

    # ---- the PDP ----

    # config: resolve(req) -> ctx | nil (required); audience (absent = fail closed); authorized_plan_roots;
    # insecure_skip_plan_root_check; now() -> epoch ms; tool_capability(name); require_proof (default true); authorizer(input) ->
    # {allow, reason}; require_authorizer (default true); max_evaluations; decide; derive_decide_input; admits_concrete. A ctx is
    # {grant, chain?, policy, plan?, risk?, budget?, enforce?, to_action?}.
    class Pdp
      attr_reader :config

      def initialize(config)
        @config = config
        @clock = config['now'] || -> { (Time.now.to_f * 1000).floor }
        @tool_capability = config['tool_capability'] || ->(name) { name }
      end

      def need(name)
        @config[name] or raise "authzen: config.#{name} is not provided (fail closed)"
      end

      def evaluate(req)
        c = @config
        now = @clock.call
        ctx = c['resolve'].call(req)
        return Authzen.deny('no PCA authority resolved for this request') if ctx.nil?

        mapped = (ctx['to_action'] || Authzen.method(:default_to_action)).call(req)
        carried = Authzen.pcactn_from_context(req['context'])
        return Authzen.deny('context carries a malformed PCActn') if carried == :malformed

        if carried.nil?
          return Authzen.deny('a signed PCActn is required (requireProof)') unless c['require_proof'] == false

          return need('admits_concrete').call(ctx['policy'], mapped) ? Authzen.permit('statically admissible under the declared authority') : Authzen.deny('action is not admissible under the declared authority')
        end

        p = carried
        if c['require_authorizer'] != false && c['authorizer'].nil?
          return Authzen.deny('no replay/revocation authorizer is configured (requireAuthorizer)')
        end

        # the proof must be FOR this request: verb + resource, and the attributes must hash to the signed params_digest
        act = p['action']
        raise TypeError, "Cannot read properties of #{p.key?('action') ? 'null' : 'undefined'} (reading 'verb')" if act.nil?

        act = {} unless act.is_a?(Hash)
        verb = act.fetch('verb', UNDEF)
        resource = act.fetch('resource', UNDEF)
        if verb != mapped['verb'] || resource != mapped['resource']
          return Authzen.deny("the PCActn authorizes #{Authzen.js(verb)} on #{Authzen.js(resource)}, not the requested " \
                              "#{Authzen.js(mapped['verb'])} on #{Authzen.js(mapped['resource'])}")
        end
        req_params = Authzen.params_of(mapped)
        unless AtlasPca.params_digest(req_params) == act.fetch('params_digest', UNDEF)
          return Authzen.deny("the request attributes do not match the PCActn's signed params_digest")
        end

        audience = c['audience']
        audience = p['aud'] if c.key?('audience') && audience.nil? && p['aud'].is_a?(String) && !p['aud'].empty? # explicit opt-out
        enforce = ctx['enforce'] || {}
        %w[attestation freshness taint].each do |k|
          raise "authzen: enforce.#{k} is not supported by this verifier (fail closed)" unless enforce[k].nil?
        end
        v = AtlasPca.verify_pcactn(p, ctx['grant'], now: now, audience: audience, authorized_plan_roots: c['authorized_plan_roots'],
                                                    insecure_skip_plan_root_check: c['insecure_skip_plan_root_check'] ? true : false)
        unless v.allow
          return { 'decision' => false, 'context' => {
            'reason_admin' => { 'denied' => true, 'stage' => 'verify', 'checks' => v.checks, 'reason' => v.reason || 'PCActn verification failed' },
            'reason_user' => { 'message' => 'the proof-carrying action did not verify' }
          } }
        end

        dctx = { 'grant' => ctx['grant'], 'chain' => ctx['chain'].nil? ? p['cap_chain'] : ctx['chain'], 'params' => req_params,
                 'risk' => ctx['risk'] || {}, 'budget' => ctx['budget'] || Authzen.fresh_budget(ctx['grant'], now), 'now' => now }
        dctx['plan'] = ctx['plan'] unless ctx['plan'].nil?
        dctx['subject'] = mapped['subject'] unless mapped['subject'].nil?
        dctx['env'] = mapped['env'] unless mapped['env'].nil?
        decision = need('decide').call(need('derive_decide_input').call(p, dctx))

        unless Js.truthy?(decision['releaseGuardianShare'])
          return { 'decision' => false, 'context' => {
            'reason_admin' => { 'denied' => true, 'stage' => 'policy', 'reasons' => decision['reasons'], 'risk' => decision['r'] },
            'reason_user' => { 'message' => 'the policy does not permit this action' }
          } }
        end
        return Authzen.approval_required(p, decision, ctx['grant'], now) unless Js.truthy?(decision['admit'])

        unless c['authorizer'].nil?
          ain = { 'operation' => { 'verb' => mapped['verb'], 'resource' => mapped['resource'], 'params' => req_params }, 'pcactn' => p }
          ain['provenance'] = req['context'][PCA_PROVENANCE_KEY] if Authzen.rec?(req['context']) && req['context'].key?(PCA_PROVENANCE_KEY)
          az = c['authorizer'].call(ain)
          unless Js.truthy?(az['allow'])
            return { 'decision' => false, 'context' => {
              'reason_admin' => { 'denied' => true, 'stage' => 'authorize', 'reason' => az['reason'] },
              'reason_user' => { 'message' => 'the proof-carrying action was not authorized' }
            } }
          end
        end
        { 'decision' => true, 'context' => { 'reason_admin' => { 'stage' => 'policy', 'risk' => decision['r'], 'threshold' => decision['requiredThreshold'] } } }
      rescue StandardError => e
        Authzen.deny("evaluation error (fail closed): #{Authzen.err(e)}", nil, 500)
      end

      def evaluations(req)
        items = Authzen.prop(req, 'evaluations')
        return { 'evaluations' => [] } unless items.is_a?(Array)

        opts = Authzen.prop(req, 'options')
        semantic = opts.is_a?(Hash) ? opts['evaluations_semantic'] : nil
        semantic = 'execute_all' if semantic.nil?
        refuse = ->(reason) { { 'evaluations' => items.map { Authzen.deny(reason, nil, 400) } } }
        return refuse.('unsupported evaluations_semantic') unless %w[execute_all deny_on_first_deny permit_on_first_permit].include?(semantic)

        mx = @config['max_evaluations'].nil? ? DEFAULT_MAX_EVALUATIONS : @config['max_evaluations']
        return refuse.("too many evaluations (limit #{Js.string(mx)})") if items.length > mx

        merged = items.map { |it| Authzen.merge_evaluation(req, it) }
        out = []
        merged.each do |m|
          r = m.nil? ? Authzen.deny('incomplete evaluation (missing subject/action/resource)', nil, 400) : evaluate(m)
          out << r
          break if semantic == 'deny_on_first_deny' && r['decision'] == false
          break if semantic == 'permit_on_first_permit' && r['decision'] == true
        end
        { 'evaluations' => out }
      end

      def evaluate_tool(req)
        tool = req['tool']
        begin
          capability = @tool_capability.call(tool['name'])
        rescue StandardError => e
          r = Authzen.deny("evaluation error (fail closed): #{Authzen.err(e)}", nil, 500)
          return { 'decision' => false, 'tool' => tool['name'], 'required_capability' => '', 'context' => r['context'] }
        end
        action = { 'name' => capability }
        action['properties'] = tool['arguments'] if tool.key?('arguments')
        mapped = { 'subject' => req['subject'], 'action' => action, 'resource' => { 'type' => 'mcp_tool', 'id' => tool['name'] } }
        mapped['context'] = req['context'] if req.key?('context')
        resp = evaluate(mapped)
        out = { 'decision' => resp['decision'], 'tool' => tool['name'], 'required_capability' => capability }
        out['context'] = resp['context'] if resp.key?('context')
        out
      end
    end

    def authzen_pdp(config) = Pdp.new(config)

    # ---- handler ----

    def route(pdp, req)
      path = req.fetch('path', UNDEF)
      body = req['body']
      bad = ->(what) { { 'status' => 400, 'body' => { 'error' => "invalid #{what} request" } } }
      ok = ->(b) { { 'status' => 200, 'body' => b } }
      case path
      when EVALUATION_PATH
        is_access_evaluation_request(body) ? ok.(pdp.evaluate(body)) : bad.('AuthZEN Access Evaluation')
      when EVALUATIONS_PATH
        # an absent or empty `evaluations` array is a plain single Access Evaluation
        if rec?(body) && (!body.key?('evaluations') || (body['evaluations'].is_a?(Array) && body['evaluations'].empty?))
          return is_access_evaluation_request(body) ? ok.(pdp.evaluate(body)) : bad.('AuthZEN Access Evaluations')
        end

        is_access_evaluations_request(body) ? ok.(pdp.evaluations(body)) : bad.('AuthZEN Access Evaluations')
      when COAZ_TOOL_PATH
        is_coaz_tool_authorization_request(body) ? ok.(pdp.evaluate_tool(body)) : bad.('COAZ MCP-tool authorization')
      else { 'status' => 404, 'body' => { 'error' => "unknown AuthZEN path: #{js(path)}" } }
      end
    end

    # handler.call({'path', 'body'}) -> {'status', 'body'}. A malformed body is a 400 (a PEP enforces it as a deny); any raised
    # error is a 500 with no detail.
    def authzen_handler(pdp)
      lambda do |req|
        route(pdp, req)
      rescue StandardError
        { 'status' => 500, 'body' => { 'error' => 'internal error' } }
      end
    end

    # ---- search ----

    def nonempty_str?(x) = x.is_a?(String) && !x.empty?

    def entity?(x, need_id)
      rec?(x) && nonempty_str?(x['type']) && (!need_id || nonempty_str?(x['id'])) && (!x.key?('properties') || rec?(x['properties']))
    end

    def action?(x) = rec?(x) && nonempty_str?(x['name']) && (!x.key?('properties') || rec?(x['properties']))

    def safe_nonneg_int?(v)
      return false unless Js.num?(v)
      return false if v.is_a?(Float) && (!v.finite? || v != v.floor || Js.neg_zero?(v))

      v >= 0 && v <= AtlasPca::MAX_SAFE
    end

    def page_ok?(p)
      return true if p.equal?(UNDEF)
      return false unless rec?(p)
      return false if p.key?('token') && !p['token'].is_a?(String)
      return false if p.key?('limit') && !safe_nonneg_int?(p['limit'])

      !p.key?('properties') || rec?(p['properties'])
    end

    def base_ok?(b) = (!b.key?('context') || rec?(b['context'])) && page_ok?(b.fetch('page', UNDEF))

    def is_subject_search(b) = rec?(b) && base_ok?(b) && entity?(b['subject'], false) && action?(b['action']) && entity?(b['resource'], true)
    def is_resource_search(b) = rec?(b) && base_ok?(b) && entity?(b['subject'], true) && action?(b['action']) && entity?(b['resource'], false)
    def is_action_search(b) = rec?(b) && base_ok?(b) && !b.key?('action') && entity?(b['subject'], true) && entity?(b['resource'], true)

    def provider_fn(p, name)
      fn = p.is_a?(Hash) ? p[name] : (p.respond_to?(name) ? p.method(name) : nil)
      fn.respond_to?(:call) ? fn : nil
    end

    # Fragment for /.well-known/authzen-configuration; a missing endpoint means that search is unsupported.
    def search_metadata(base, p)
      out = {}
      out['search_subject_endpoint'] = base + SEARCH_SUBJECT_PATH if provider_fn(p, 'search_subject')
      out['search_resource_endpoint'] = base + SEARCH_RESOURCE_PATH if provider_fn(p, 'search_resource')
      out['search_action_endpoint'] = base + SEARCH_ACTION_PATH if provider_fn(p, 'search_action')
      out
    end

    def strip_id(req, key) = req.merge(key => req[key].reject { |k, _| k == 'id' })

    def shape(r, limit, type_ok)
      results_in = prop(r, 'results')
      raise TypeError, 'results.filter is not a function' unless results_in.is_a?(Array)

      seen = {}
      results = results_in.select do |t|
        k = Js.json(t)
        next false if !type_ok.(t) || seen.key?(k)

        seen[k] = true
      end
      capped = !limit.equal?(UNDEF) && limit.positive? ? results.first(limit.to_i) : results
      # a provider that ignores the limit would hide results behind a page marker we cannot resume: fail closed
      raise ArgumentError, 'provider returned more than the page limit' if capped.length < results.length

      out = {}
      pg = r.fetch('page', UNDEF)
      if truthy?(pg)
        raise TypeError, "Cannot use 'in' operator to search for 'next_token'" unless rec?(pg)

        page = {}
        page['next_token'] = pg['next_token'] if pg.key?('next_token')
        page['count'] = capped.length
        page['total'] = pg['total'] if pg.key?('total')
        page['properties'] = pg['properties'] if Js.truthy?(pg['properties'])
        out['page'] = page
      end
      out['context'] = r['context'] if Js.truthy?(r['context'])
      out['results'] = capped
      out
    end

    def search_route(p, req)
      path = req.fetch('path', UNDEF)
      body = req['body']
      spec = { SEARCH_SUBJECT_PATH => ['search_subject', 'subject', 'subject'], SEARCH_RESOURCE_PATH => ['search_resource', 'resource', 'resource'],
               SEARCH_ACTION_PATH => ['search_action', 'action', nil] }[path]
      return nil if spec.nil?

      name, what, key = spec
      fn = provider_fn(p, name)
      return { 'status' => 404, 'body' => { 'error' => "#{what} search is not supported" } } if fn.nil?

      valid = { 'subject' => :is_subject_search, 'resource' => :is_resource_search, 'action' => :is_action_search }[what]
      return { 'status' => 400, 'body' => { 'error' => "invalid AuthZEN #{what} search request" } } unless public_send(valid, body)

      lim = body.key?('page') ? body['page'].fetch('limit', UNDEF) : UNDEF
      return { 'status' => 200, 'body' => shape(fn.call(body), lim, ->(_t) { true }) } if key.nil?

      type = body[key]['type']
      { 'status' => 200, 'body' => shape(fn.call(strip_id(body, key)), lim, ->(e) { prop(e, 'type') == type }) }
    end

    # Returns nil for a path that is not a search path, so it can be chained after authzen_handler's result.
    def authzen_search_handler(p)
      lambda do |req|
        search_route(p, req)
      rescue StandardError
        { 'status' => 500, 'body' => { 'error' => 'internal error' } }
      end
    end
  end
end
