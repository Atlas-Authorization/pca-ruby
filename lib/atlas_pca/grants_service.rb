# frozen_string_literal: true

# The grant management resource and its HTTP bindings (the TypeScript reference, @atlasauth/pca-grants): list / inspect / amend / revoke
# and incremental authorization for principals, nothing widening in place. GrantService runs over a grant store you pass (MemoryGrantStore
# is for tests and single-process use); grant_resource_handler and lease_resource_handler turn it into framework-neutral handlers over a
# plain request Hash { 'method', 'path', 'query'?, 'body'? } returning { 'status', 'body' }; GrantClient is the matching client over an
# injected transport. The pure verification side (amendment, revoke and need-approval decisions) is k3.rb. Hooks are plain callables.
require_relative 'grants'

module AtlasPca
  module GrantsService
    NEED_REQUEST_DOMAIN = "atlas-pca/need-request/v1\x00".b.freeze
    GRANT_STEPUP_DOMAIN = "atlas-pca/grant-stepup/v1\x00".b.freeze
    GRANTS_PATH = '/pca/grants'
    NEEDS_PATH = '/pca/needs'
    LEASES_PATH = '/pca/leases'

    # A refusal with a stable code: not_found, conflict, bad_request, not_narrower, signature_required, bad_signature, step_up_required,
    # not_active, need_not_lowered_only, need_not_adjustable, forbidden.
    class GrantError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    class GrantApiError < StandardError
      attr_reader :status, :code

      def initialize(status, code, message)
        super(message)
        @status = status
        @code = code
      end
    end

    FAIL_MESSAGE = {
      'not_found' => 'no such grant', 'conflict' => 'conflict', 'bad_request' => 'malformed request',
      'not_narrower' => 'a narrow amendment must be strictly narrower', 'signature_required' => 'the amendment is signed (by the principal when it widens)',
      'bad_signature' => 'the signature does not verify for this grant revision', 'step_up_required' => 'widening needs a satisfied step-up',
      'not_active' => 'grant is not active', 'need_not_lowered_only' => 'an approval may only lower amounts of the requested needs',
      'need_not_adjustable' => 'the need is not adjustable', 'forbidden' => 'not authorised'
    }.freeze
    STATUS = { 'not_found' => 404, 'conflict' => 409, 'bad_request' => 400, 'not_narrower' => 422, 'signature_required' => 401, 'bad_signature' => 401,
               'step_up_required' => 403, 'not_active' => 409, 'need_not_lowered_only' => 422, 'need_not_adjustable' => 422, 'forbidden' => 403 }.freeze

    module_function

    def sign_grant_body(domain, body, key) = Grants.sign_body(domain, body, key)
    def need_request_message(grant_id, rev, needs) = { 'grant' => grant_id, 'rev' => rev, 'needs' => needs }
    def step_up_message(grant_id, challenge_id, nonce) = { 'grant' => grant_id, 'challenge' => challenge_id, 'nonce' => nonce }

    # In-process grant store (forgets everything on restart). get/put/list for grants and get_need/put_need/list_needs.
    class MemoryGrantStore
      def initialize
        @g = {}
        @n = {}
      end

      def get(gid) = Grants.deep_copy(@g[gid])
      def put(g) = (@g[g['id']] = Grants.deep_copy(g)) && nil
      def list = @g.values.map { |x| Grants.deep_copy(x) }
      def get_need(nid) = Grants.deep_copy(@n[nid])
      def put_need(n) = (@n[n['id']] = Grants.deep_copy(n)) && nil
      def list_needs(grant_id) = @n.values.select { |x| x['grant_id'] == grant_id }.map { |x| Grants.deep_copy(x) }
    end

    # AtlasPca.verify_amendment with a custom authority comparison (same normative check order).
    def verify_amendment(cur, req, step_up_ok, cmp)
      return { 'ok' => false, 'code' => 'bad_request' } unless req.is_a?(Hash) && %w[narrow merge replace].include?(req['action'])
      return { 'ok' => false, 'code' => 'bad_request' } unless AtlasPca.authority_ok?(req['authority'])
      return { 'ok' => false, 'code' => 'not_active' } if cur['status'] != 'active'

      action = req['action']
      auth = req['authority']
      nxt = action == 'merge' ? AtlasPca.merge_authority(cur['authority'], auth) : auth
      order = cmp.call(cur['authority'], nxt)
      widens = %w[wider incomparable].include?(order)
      return { 'ok' => false, 'code' => 'not_narrower' } if (!widens && action == 'narrow' && order == 'equal') || (widens && action == 'narrow')

      signed_by = req['signed_by']
      return { 'ok' => false, 'code' => 'signature_required' } if !req['sig'].is_a?(String) || !%w[holder principal].include?(signed_by)
      return { 'ok' => false, 'code' => 'signature_required' } if widens && signed_by != 'principal'

      who = signed_by == 'principal' ? cur['principal'] : cur['agent']
      return { 'ok' => false, 'code' => 'bad_signature' } unless AtlasPca.k3_verify_body(GRANT_AMEND_DOMAIN, AtlasPca.amend_message(cur, action, auth), who, req['sig'])
      return { 'ok' => false, 'code' => 'step_up_required' } if widens && !step_up_ok

      { 'ok' => true, 'widens' => widens, 'next' => nxt }
    rescue StandardError
      { 'ok' => false, 'code' => 'bad_request' }
    end

    def id_lt?(a, b) = AtlasPca.utf16_key(a) < AtlasPca.utf16_key(b)

    # store (MemoryGrantStore or your own), now.() -> epoch ms, new_id.(kind) with kind 'grant' or 'need'; optional compare.(old, new) ->
    # order, providers ({'usage', 'remaining_budget', 'policy_card', 'residual'}: each .(grant) -> value), verify_step_up.(ref, grant) ->
    # bool (absent: widening is refused), on_revoke.(ids, scope, root), on_change.(kind, grant) and validate_need.(need) -> error string | nil.
    class GrantService
      attr_reader :store

      def initialize(store, now, new_id, compare: nil, providers: nil, verify_step_up: nil, on_revoke: nil, on_change: nil, validate_need: nil)
        @store = store
        @now = now
        @new_id = new_id
        @cmp = compare || ->(a, b) { AtlasPca.compare_authority(a, b) }
        @providers = providers
        @verify_step_up = verify_step_up
        @on_revoke = on_revoke
        @on_change = on_change
        @validate_need = validate_need
      end

      # Create a grant record (the host calls this when a grant is registered).
      def register(g)
        raise GrantError.new('bad_request', 'malformed authority') unless AtlasPca.authority_ok?(g['authority'])
        raise GrantError.new('conflict', 'grant id exists') unless @store.get(g['id']).nil?

        now = @now.call
        status = g['status']
        rec = g.merge('status' => status.nil? ? 'active' : status, 'rev' => 1, 'created_at' => now,
                      'history' => [{ 'rev' => 1, 'authority_digest' => AtlasPca.authority_digest(g['authority']), 'at' => now, 'action' => 'create' }])
        @store.put(rec)
        rec
      end

      def list(f = nil)
        f ||= {}
        lim = f['limit']
        limit = [[lim.nil? ? 50 : lim, 1].max, 200].min
        allg = @store.list.select do |g|
          (f['principal'].nil? || g['principal'] == f['principal']) && (f['agent'].nil? || g['agent'] == f['agent']) && (f['status'].nil? || g['status'] == f['status'])
        end
        allg = allg.sort_by { |g| AtlasPca.utf16_key(g['id']) }
        allg = allg.select { |g| GrantsService.id_lt?(f['cursor'], g['id']) } unless f['cursor'].nil?
        page = allg.first(limit.to_i)
        out = { 'grants' => page.map { |g| view(g, false) } }
        out['next_cursor'] = page.last['id'] if allg.length > limit
        out
      end

      def inspect(gid) = view(must(gid), true)

      def amend(gid, req)
        cur = must(gid)
        v = GrantsService.verify_amendment(cur, req, false, @cmp)
        # evaluate the (possibly consuming) step-up only when everything else already passed
        if !v['ok'] && v['code'] == 'step_up_required' && Js.truthy?(req['step_up_ref']) && @verify_step_up && @verify_step_up.call(req['step_up_ref'], cur)
          v = GrantsService.verify_amendment(cur, req, true, @cmp)
        end
        raise GrantError.new(v['code'], FAIL_MESSAGE.fetch(v['code'])) unless v['ok']

        now = @now.call
        unless v['widens']
          cur['authority'] = v['next']
          cur['rev'] += 1
          cur['history'] << { 'rev' => cur['rev'], 'authority_digest' => AtlasPca.authority_digest(v['next']), 'at' => now, 'action' => req['action'] }
          @store.put(cur)
          changed('amend', cur)
          return { 'grant' => view(cur, true), 'created' => false }
        end
        nid = @new_id.call('grant')
        fresh = cur.merge('id' => nid, 'authority' => v['next'], 'rev' => 1, 'status' => 'active', 'supersedes' => cur['id'], 'created_at' => now,
                          'history' => [{ 'rev' => 1, 'authority_digest' => AtlasPca.authority_digest(v['next']), 'at' => now, 'action' => "supersedes:#{cur['id']}" }])
        fresh.delete('superseded_by')
        cur['status'] = 'superseded'
        cur['superseded_by'] = nid
        @store.put(fresh)
        @store.put(cur)
        changed('supersede', fresh)
        { 'grant' => view(fresh, true), 'created' => true }
      end

      # Authorised by the principal's signature over {grant id, scope} (auth = {'sig' => ...}) or by a host-authenticated admin
      # (auth = {'admin' => true}). 'agent' revokes every grant of the grant's agent and principal; 'subtree' the grant and every descendant.
      def revoke(gid, scope, auth)
        raise GrantError.new('bad_request', 'unknown scope') unless %w[grant agent subtree].include?(scope)

        root = must(gid)
        if auth.key?('sig')
          rv = AtlasPca.verify_revoke_signature(root, scope, auth['sig'])
          raise GrantError.new(rv['code'], FAIL_MESSAGE.fetch(rv['code'])) unless rv['ok']
        elsif auth['admin'] != true
          raise GrantError.new('forbidden', 'not authorised')
        end
        allg = @store.list
        hit = case scope
              when 'grant' then [root]
              when 'agent' then allg.select { |g| g['agent'] == root['agent'] && g['principal'] == root['principal'] }
              else
                ids = { gid => true }
                grew = true
                while grew
                  grew = false
                  allg.each do |g|
                    next unless !g['parent'].nil? && ids.key?(g['parent']) && !ids.key?(g['id'])

                    ids[g['id']] = true
                    grew = true
                  end
                end
                allg.select { |g| ids.key?(g['id']) }
              end
        revoked = []
        hit.each do |g|
          next if g['status'] == 'revoked'

          g['status'] = 'revoked'
          g['history'] << { 'rev' => g['rev'], 'authority_digest' => AtlasPca.authority_digest(g['authority']), 'at' => @now.call, 'action' => "revoke:#{scope}" }
          @store.put(g)
          revoked << g['id']
        end
        @on_revoke&.call(revoked, scope, root)
        changed('revoke', root)
        { 'revoked' => revoked }
      end

      # Agent side: ask for more. Typed needs only (validated); no authority changes until the principal approves.
      def request_needs(grant_id, needs)
        g = must(grant_id)
        raise GrantError.new('not_active', "grant is #{g['status']}") if g['status'] != 'active'
        raise GrantError.new('bad_request', '1..32 needs') if !needs.is_a?(Array) || needs.empty? || needs.length > 32

        needs.each do |n|
          if !n.is_a?(Hash) || !AtlasPca.k3_str?(n['verb'], 128) || !AtlasPca.k3_str?(n['resource'], 512) ||
             (n.key?('limits') && !(n['limits'].is_a?(Hash) && n['limits'].values.all? { |v| v.is_a?(Numeric) && (!v.is_a?(Float) || v.finite?) && v >= 0 }))
            raise GrantError.new('bad_request', 'malformed need')
          end

          e = @validate_need ? @validate_need.call(n) : nil
          raise GrantError.new('bad_request', e) if Js.truthy?(e)
        end
        nr = { 'id' => @new_id.call('need'), 'grant_id' => grant_id, 'needs' => Grants.deep_copy(needs), 'status' => 'pending', 'created_at' => @now.call }
        @store.put_need(nr)
        changed('need', g)
        nr
      end

      # Principal side: approve the delta (amounts may only be LOWERED, and only when the need is adjustable); the result is a widening merge.
      def approve_needs(need_id, approved, sig, step_up_ref = nil)
        nr = @store.get_need(need_id)
        raise GrantError.new('not_found', 'no such need request') if nr.nil?
        raise GrantError.new('conflict', "need request is #{nr['status']}") if nr['status'] != 'pending'

        g = must(nr['grant_id'])
        v = AtlasPca.verify_need_approval(nr, g, approved, sig, false)
        v = AtlasPca.verify_need_approval(nr, g, approved, sig, true) if !v['ok'] && v['code'] == 'step_up_required' && Js.truthy?(step_up_ref) && @verify_step_up && @verify_step_up.call(step_up_ref, g)
        raise GrantError.new(v['code'], FAIL_MESSAGE.fetch(v['code'])) unless v['ok']

        authority = v['authority']
        nid = @new_id.call('grant')
        now = @now.call
        fresh = g.merge('id' => nid, 'authority' => authority, 'rev' => 1, 'status' => 'active', 'supersedes' => g['id'], 'created_at' => now,
                        'history' => [{ 'rev' => 1, 'authority_digest' => AtlasPca.authority_digest(authority), 'at' => now, 'action' => "needs:#{need_id}" }])
        fresh.delete('superseded_by')
        g['status'] = 'superseded'
        g['superseded_by'] = nid
        nr['status'] = 'approved'
        nr['result_grant_id'] = nid
        @store.put(fresh)
        @store.put(g)
        @store.put_need(nr)
        changed('supersede', fresh)
        { 'grant' => view(fresh, true), 'created' => true }
      end

      # The grant a need request belongs to (the HTTP binding uses it to scope a caller to its own grants).
      def need_grant_id(need_id)
        nr = @store.get_need(need_id)
        raise GrantError.new('not_found', 'no such need request') if nr.nil?

        nr['grant_id']
      end

      def deny_needs(need_id)
        nr = @store.get_need(need_id)
        raise GrantError.new('not_found', 'no such need request') if nr.nil?
        raise GrantError.new('conflict', "need request is #{nr['status']}") if nr['status'] != 'pending'

        nr['status'] = 'denied'
        @store.put_need(nr)
        nil
      end

      private

      def view(g, rich)
        v = g.reject { |k, _| k == 'history' }
        v['authority_digest'] = AtlasPca.authority_digest(g['authority'])
        v['pending_needs'] = @store.list_needs(g['id']).select { |n| n['status'] == 'pending' }.map { |n| n['id'] }
        p = @providers
        if rich && p && !p.empty?
          %w[usage remaining_budget policy_card residual].each { |name| v[name] = p[name].call(g) if Js.truthy?(p[name]) }
        end
        v
      end

      def must(gid)
        g = @store.get(gid)
        raise GrantError.new('not_found', 'no such grant') if g.nil?

        g
      end

      def changed(kind, g) = @on_change&.call(kind, g)
    end

    # ---- HTTP binding -------------------------------------------------------------------------------------------------

    # Discovery fragment for /.well-known/pca-configuration.
    def grant_management_metadata(base)
      { 'grant_management' => { 'grants_endpoint' => base + GRANTS_PATH, 'needs_endpoint' => base + NEEDS_PATH, 'amend_actions' => %w[narrow merge replace],
                                'revoke_scopes' => %w[grant agent subtree], 'widening' => 'new_grant_id_with_supersedes' } }
    end

    def err(e)
      return { 'status' => STATUS.fetch(e.code), 'body' => { 'error' => e.code, 'message' => e.message } } if e.is_a?(GrantError)

      { 'status' => 500, 'body' => { 'error' => 'server_error' } }
    end

    def segments(path) = path.to_s.split('/').reject(&:empty?)

    def js_number(x) = Actions::SvfJS.num(x)

    # authenticate.(request) -> {'principal'?, 'admin'?} | nil: who is calling, as the host authenticated them. `principal` limits every
    # read and write to that principal's grants.
    def grant_resource_handler(svc, authenticate)
      lambda do |req|
        who = authenticate.call(req)
        return { 'status' => 401, 'body' => { 'error' => 'unauthenticated' } } if !Js.truthy?(who) || (who.respond_to?(:empty?) && who.empty?) || (!Js.truthy?(who['admin']) && !Js.truthy?(who['principal']))

        seg = segments(req['path'])
        q = Js.truthy?(req['query']) ? req['query'] : {}
        b = req['body'].is_a?(Hash) ? req['body'] : {}
        method = req['method']
        own = lambda do |gid|
          g = svc.inspect(gid)
          raise GrantError.new('not_found', 'no such grant') if !Js.truthy?(who['admin']) && g['principal'] != who['principal']
        end
        return { 'status' => 404, 'body' => { 'error' => 'not_found' } } if seg.empty? || seg[0] != 'pca'

        kind = seg[1]
        if kind == 'grants'
          if seg.length == 2 && method == 'GET'
            status = q['status']
            raise GrantError.new('bad_request', 'bad status') if !status.nil? && !%w[active revoked superseded].include?(status)

            principal = Js.truthy?(who['admin']) ? q['principal'] : who['principal']
            limit = q['limit'].nil? ? nil : js_number(q['limit'])
            f = {}
            f['principal'] = principal if Js.truthy?(principal)
            f['agent'] = q['agent'] if Js.truthy?(q['agent'])
            f['status'] = status if Js.truthy?(status)
            f['limit'] = limit if !limit.nil? && !limit.nan? && !limit.infinite?
            f['cursor'] = q['cursor'] if Js.truthy?(q['cursor'])
            return { 'status' => 200, 'body' => svc.list(f) }
          end
          gid = seg[2]
          return { 'status' => 404, 'body' => { 'error' => 'not_found' } } if !Js.truthy?(gid)

          own.call(gid)
          return { 'status' => 200, 'body' => svc.inspect(gid) } if seg.length == 3 && method == 'GET'

          if seg.length == 3 && method == 'DELETE'
            scope = q['scope'].nil? ? 'grant' : q['scope']
            sig = b['sig'].is_a?(String) ? b['sig'] : nil
            # a principal-scoped caller must still sign; only an admin may revoke without a principal signature
            r = svc.revoke(gid, scope, Js.truthy?(who['admin']) && !Js.truthy?(sig) ? { 'admin' => true } : { 'sig' => Js.truthy?(sig) ? sig : '' })
            return { 'status' => 200, 'body' => r }
          end
          if seg.length == 4 && seg[3] == 'amend' && method == 'POST'
            r = svc.amend(gid, req['body'])
            return { 'status' => r['created'] ? 201 : 200, 'body' => r['grant'] }
          end
          return { 'status' => 201, 'body' => svc.request_needs(gid, b['needs']) } if seg.length == 4 && seg[3] == 'needs' && method == 'POST'
        end
        if kind == 'needs' && seg.length > 3 && seg[3] == 'approve' && method == 'POST'
          own.call(svc.need_grant_id(seg[2]))
          raise GrantError.new('bad_request', 'sig and approved are required') if !b['sig'].is_a?(String) || !b['approved'].is_a?(Array)

          r = svc.approve_needs(seg[2], b['approved'], b['sig'], b['step_up_ref'].is_a?(String) ? b['step_up_ref'] : nil)
          return { 'status' => 201, 'body' => r['grant'] }
        end
        if kind == 'needs' && seg.length > 3 && seg[3] == 'deny' && method == 'POST'
          own.call(svc.need_grant_id(seg[2]))
          svc.deny_needs(seg[2])
          return { 'status' => 200, 'body' => { 'status' => 'denied' } }
        end
        { 'status' => 404, 'body' => { 'error' => 'not_found' } }
      rescue StandardError => e # a handler never raises
        err(e)
      end
    end

    # ---- lease HTTP binding -------------------------------------------------------------------------------------------

    LEASE_STATUS = { 'bad_record' => 400, 'bad_seq' => 409, 'stale_seq' => 409, 'lease_fork' => 409, 'renewal_mismatch' => 422, 'over_max_ttl' => 422,
                     'ttl_ceiling' => 422, 'not_extending' => 422, 'stale_justification' => 422, 'expired_lease' => 409, 'revoked' => 409, 'sod' => 403,
                     'unknown_authority' => 403, 'store_unreachable' => 503 }.freeze

    def lease_management_metadata(base) = { 'leases' => { 'leases_endpoint' => base + LEASES_PATH, 'revoke_targets' => %w[lease prefix grant] } }

    # Hosted lease routes. The server only stores records the lease authority already signed; it never mints one.
    # POST /pca/leases {lease, chain?} issues or renews; GET /pca/leases/:id; POST /pca/leases/:id/check {lease}; POST /pca/leases/revoke
    # {revocation}. authenticate.(request) -> {'admin'?, 'principal'?} | nil.
    def lease_resource_handler(reg, authenticate, now = nil)
      clock = now || -> { (Time.now.to_f * 1000).to_i }
      lambda do |req|
        who = authenticate.call(req)
        return { 'status' => 401, 'body' => { 'error' => 'unauthenticated' } } if !Js.truthy?(who) || (who.respond_to?(:empty?) && who.empty?) || (!Js.truthy?(who['admin']) && !Js.truthy?(who['principal']))

        seg = segments(req['path'])
        b = req['body'].is_a?(Hash) ? req['body'] : {}
        method = req['method']
        return { 'status' => 404, 'body' => { 'error' => 'not_found' } } if seg.length < 2 || seg[0] != 'pca' || seg[1] != 'leases'

        visible = ->(holder) { who['admin'] == true || who['principal'] == holder }
        if seg.length == 2 && method == 'POST'
          return { 'status' => 403, 'body' => { 'error' => 'forbidden' } } unless Js.truthy?(who['admin'])

          chain = b['chain'].is_a?(Array) && b['chain'].all? { |x| x.is_a?(String) } ? b['chain'] : []
          r = reg.accept(b['lease'], chain)
          return { 'status' => r['replaced'] ? 201 : 200, 'body' => r } if r['ok']

          return { 'status' => LEASE_STATUS.fetch(r['code'], 400), 'body' => { 'error' => r['code'] }.merge(Js.truthy?(r['reason']) ? { 'message' => r['reason'] } : {}) }
        end
        if seg.length == 3 && seg[2] == 'revoke' && method == 'POST'
          return { 'status' => 403, 'body' => { 'error' => 'forbidden' } } unless Js.truthy?(who['admin'])

          r = reg.revoke(b['revocation'])
          return { 'status' => 200, 'body' => r } if r['ok']

          return { 'status' => r['code'] == 'store_unreachable' ? 503 : r['code'] == 'unknown_authority' ? 403 : 400, 'body' => { 'error' => r['code'] } }
        end
        lid = seg[2]
        return { 'status' => 404, 'body' => { 'error' => 'not_found' } } unless Js.truthy?(lid)

        if seg.length == 3 && method == 'GET'
          cur = reg.get(lid)
          return { 'status' => 404, 'body' => { 'error' => 'not_found' } } if cur.nil? || !visible.call(cur['holder'])

          return { 'status' => 200, 'body' => { 'lease' => cur, 'history' => reg.history(lid) } }
        end
        if seg.length == 4 && seg[3] == 'check' && method == 'POST'
          cur = reg.get(lid)
          return { 'status' => 404, 'body' => { 'error' => 'not_found' } } if cur.nil? || !visible.call(cur['holder'])

          d = AtlasPca.check_lease(b['lease'], reg, clock.call)
          return { 'status' => d['decision'] == 'allow' ? 200 : 403, 'body' => d }
        end
        { 'status' => 404, 'body' => { 'error' => 'not_found' } }
      rescue StandardError
        { 'status' => 500, 'body' => { 'error' => 'server_error' } }
      end
    end

    # ---- client -------------------------------------------------------------------------------------------------------

    # application/x-www-form-urlencoded component (URLSearchParams): alphanumerics and * - . _ stay, a space is +, the rest %XX.
    def form_component(s) = Js.string(s).b.gsub(/[^A-Za-z0-9*\-._ ]/n) { |c| format('%%%02X', c.ord) }.tr(' ', '+').force_encoding('UTF-8')

    def form(q) = q.reject { |_, v| v.nil? }.map { |k, v| "#{form_component(k)}=#{form_component(v)}" }.join('&')

    def comp(s) = Js.encode_uri_component(Js.string(s))

    # Client for the grant management resource over an injected transport: fetch.({'method', 'url', 'headers', 'body'}) -> {'status',
    # 'headers', 'body'} where body is the response text (or an already parsed value) and headers a Hash (looked up case-insensitively).
    # The client carries the newest `pca-fresh-at` token it has seen: attached to later requests, and with fresh_signer set a header that
    # does not verify is ignored.
    class GrantClient
      def initialize(base_url, fetch, fresh_signer = nil, headers = nil)
        @base = base_url.end_with?('/') ? base_url[0...-1] : base_url
        @fetch = fetch
        @signer = fresh_signer
        @headers = headers
        @latest = nil
      end

      # The newest consistency token seen on any response: attach it to later requests to make them read-your-writes.
      def fresh_at = @latest

      def fold_fresh_at(s) = @latest ? Grants.merge_fresh_at(@latest, s) : nil

      def list(q = nil)
        s = GrantsService.form(q || {})
        call('GET', GRANTS_PATH + (s.empty? ? '' : "?#{s}"))
      end

      def inspect(gid) = call('GET', "#{GRANTS_PATH}/#{GrantsService.comp(gid)}")
      def amend(gid, req) = call('POST', "#{GRANTS_PATH}/#{GrantsService.comp(gid)}/amend", req)

      def revoke(gid, scope = 'grant', sig = nil)
        call('DELETE', "#{GRANTS_PATH}/#{GrantsService.comp(gid)}?scope=#{scope}", Js.truthy?(sig) ? { 'sig' => sig } : nil)
      end

      def request_needs(gid, needs) = call('POST', "#{GRANTS_PATH}/#{GrantsService.comp(gid)}/needs", { 'needs' => needs })

      def approve_needs(need_id, approved, sig, step_up_ref = nil)
        call('POST', "#{NEEDS_PATH}/#{GrantsService.comp(need_id)}/approve", { 'approved' => approved, 'sig' => sig }.merge(Js.truthy?(step_up_ref) ? { 'step_up_ref' => step_up_ref } : {}))
      end

      def deny_needs(need_id) = call('POST', "#{NEEDS_PATH}/#{GrantsService.comp(need_id)}/deny")

      private

      def call(method, path, body = nil)
        hdrs = { 'content-type' => 'application/json' }
        hdrs['pca-fresh-at'] = Js.json(@latest) if @latest
        hdrs.merge!(@headers.call) if @headers
        req = { 'method' => method, 'url' => @base + path, 'headers' => hdrs }
        req['body'] = Js.json(body) unless body.nil?
        res = @fetch.call(req)
        rh = (res['headers'] || {}).to_h { |k, v| [k.to_s.downcase, v] }
        tok = rh['pca-fresh-at']
        if Js.truthy?(tok)
          begin
            t = Js.parse(tok)
            raise ArgumentError, 'unverified' if !@signer.nil? && !AtlasPca.verify_fresh_at(t, @signer)

            lt = @latest
            # monotone fold: never replace a fresher token with an older one
            if !lt || (t['revocation_epoch'] >= lt['revocation_epoch'] && t['policy_revision'] >= lt['policy_revision'] &&
                       t['ledger_tree_size'] >= lt['ledger_tree_size'] && t['budget_version'] >= lt['budget_version'])
              @latest = t
            end
          rescue StandardError # freshness is only ever tightened by a valid token
            nil
          end
        end
        raw = res['body']
        data = begin
          raw.is_a?(String) ? Js.parse(raw) : (raw.nil? ? {} : raw)
        rescue StandardError
          {}
        end
        status = res['status']
        unless status >= 200 && status < 300
          d = data.is_a?(Hash) ? data : {}
          raise GrantApiError.new(status, Js.truthy?(d['error']) ? d['error'] : 'error', Js.truthy?(d['message']) ? d['message'] : (Js.truthy?(res['reason']) ? res['reason'].to_s : status.to_s))
        end
        data
      end
    end

    def create_grant_client(base_url, fetch, fresh_signer = nil, headers = nil) = GrantClient.new(base_url, fetch, fresh_signer, headers)
  end
end
