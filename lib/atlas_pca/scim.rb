# frozen_string_literal: true

require_relative 'js_compat'

# SCIM 2.0 provisioning for PCA agents, byte-identical to the TypeScript reference: the passport <-> SCIM `Agent` mapping, a
# framework-agnostic `/Agents` resource server over request Hashes (list + `eq` filter + pagination, get, POST registers a
# passport, PUT, PATCH, DELETE), and the push adapters for Microsoft Entra Agent ID and Okta with an injected fetch callable.
# Resources, requests and responses are String-keyed Hashes with the wire member names (a 204 response has no 'body'); the
# options are snake_case: base_url, now (callable -> epoch ms), authenticate (callable), allow_unauthenticated.
module AtlasPca
  module Scim
    AGENT_SCHEMA_URN = 'urn:ietf:params:scim:schemas:atlas:2.0:Agent'
    LIST_RESPONSE_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'
    PATCH_OP_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
    ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error'
    AGENT_RESOURCE_TYPE = 'Agent'
    ENTRA_AGENT_EXTENSION_URN = 'urn:ietf:params:scim:schemas:extension:microsoft:agent:2.0:Agent'
    OKTA_AGENT_EXTENSION_URN = 'urn:okta:scim:schemas:custom:1.0:Agent'
    SCIM_CONTENT_TYPE = 'application/scim+json'
    UNDEF = Object.new.freeze # an absent member (JavaScript `undefined`), distinct from null

    # A refusal with its SCIM `scimType` (invalidSyntax, invalidValue, invalidFilter, mutability, noTarget).
    class ValueError < StandardError
      attr_reader :scim_type

      def initialize(scim_type, detail)
        super(detail)
        @scim_type = scim_type
      end
    end

    module_function

    def js(v) = v.equal?(UNDEF) ? 'undefined' : Js.string(v)
    def str(v) = v.is_a?(String) ? v : nil
    def str_list(v) = Js.str_list?(v) ? v : nil
    def first(*vals) = vals.find { |v| !v.nil? }

    def bool(v)
      return v if [true, false].include?(v)
      return true if v == 'true'
      return false if v == 'false'

      nil
    end

    # Number(v) of a JSON value.
    def js_number(v)
      case v
      when nil, false then 0
      when true then 1
      when Integer, Float then v
      when String then AtlasPca.js_string_to_number(v)
      when Array then AtlasPca.js_string_to_number(Js.string(v))
      else Float::NAN
      end
    end

    def integer?(n) = n.is_a?(Integer) || (n.finite? && n == n.floor)

    # ---- passports ----

    def passport_fingerprint(p) = AtlasPca.passport_fingerprint(p)
    def issue_passport(identity) = AtlasPca.issue_passport(identity)

    # A read-only passport index by id.
    class Registry
      def initialize(passports)
        @by_id = {}
        passports.each { |p| @by_id[p.fetch('id')] = p }
      end

      def get(id) = @by_id[id]
      def has(id) = !get(id).nil?
      def all = @by_id.values
    end

    def build_registry(passports) = Registry.new(passports)

    # ---- passport <-> SCIM mapping ----

    # new Date(ms).toISOString()
    def iso_at(now)
      ms = now.call.to_i
      Time.at(Rational(ms, 1000)).utc.strftime('%Y-%m-%dT%H:%M:%S.%LZ')
    end

    def now_default = -> { (Time.now.to_f * 1000).floor }

    def build_meta(id, sans_meta, inp)
      now = inp['now'].nil? ? now_default : inp['now']
      base = inp.key?('base_url') ? inp['base_url'].sub(%r{/+\z}, '') : ''
      { 'resourceType' => AGENT_RESOURCE_TYPE,
        'created' => inp['created'].nil? ? iso_at(now) : inp['created'],
        'lastModified' => inp['last_modified'].nil? ? iso_at(now) : inp['last_modified'],
        'location' => "#{base}/Agents/#{Js.encode_uri_component(Js.string(id))}",
        'version' => "W/\"#{AtlasPca.hash_canonical(sans_meta)}\"" }
    end

    # A SCIM `Agent` for a passport. proj: owner (required), displayName?, active?, capabilities?, externalId?, holder?.
    # meta: base_url?, created?, last_modified?, now?.
    def passport_to_scim(passport, proj, meta = nil)
      meta ||= {}
      id = passport.fetch('id')
      base = {
        'schemas' => [AGENT_SCHEMA_URN], 'id' => id,
        'displayName' => proj['displayName'].nil? ? "#{js(passport.fetch('model_id', UNDEF))} (#{js(passport.fetch('operator', UNDEF))})" : proj['displayName'],
        'active' => proj['active'].nil? ? true : proj['active'],
        'capabilities' => proj['capabilities'].nil? ? [] : Js.spread(proj['capabilities']),
        'passportRef' => id, 'passport' => passport
      }
      raise TypeError, 'canonicalize: unsupported type undefined' unless proj.key?('owner') # the reference hashes an undefined owner

      base['owner'] = proj['owner']
      base['externalId'] = proj['externalId'] if proj.key?('externalId')
      base['holder'] = proj['holder'] if proj.key?('holder')
      base.merge('meta' => build_meta(id, base, meta))
    end

    def read_identity(body)
      nested = body['passport']
      if nested.is_a?(Hash)
        model_id = str(nested['model_id'])
        operator = str(nested['operator'])
        raise ValueError.new('invalidValue', 'passport.model_id and passport.operator are required') if model_id.nil? || operator.nil?

        hw = bool(nested['hardware_rooted'])
        identity = { 'model_id' => model_id, 'operator' => operator, 'hardware_rooted' => hw.nil? ? false : hw,
                     'issued_at' => Js.num?(nested['issued_at']) ? nested['issued_at'] : 0 }
        %w[weights_digest system_prompt_digest tool_manifest_digest runtime_measurement].each do |k|
          v = str(nested[k])
          identity[k] = v unless v.nil?
        end
        measured = bool(nested['weights_measured'])
        identity['weights_measured'] = measured unless measured.nil?
        return identity
      end
      model_id = first(str(body['model']), str(body['model_id']))
      operator = str(body['operator'])
      if model_id.nil? || operator.nil?
        raise ValueError.new('invalidValue', 'an Agent requires either a `passport` object or `model` + `operator`')
      end

      hw = bool(body['hardwareRooted'])
      { 'model_id' => model_id, 'operator' => operator, 'hardware_rooted' => hw.nil? ? false : hw, 'issued_at' => 0 }
    end

    def read_projection(body)
      nested = body['passport']
      proj = { 'owner' => first(str(body['owner']), str(body['operator']), nested.is_a?(Hash) ? str(nested['operator']) : nil, '') }
      { 'displayName' => str(body['displayName']), 'externalId' => str(body['externalId']), 'active' => bool(body['active']),
        'capabilities' => str_list(body['capabilities']), 'holder' => str(body['holder']) }.each { |k, v| proj[k] = v unless v.nil? }
      proj
    end

    # {identity, projection} from an untrusted SCIM write body (a nested `passport` or the flat IdP form); raises ValueError.
    def scim_to_provisioning_request(value)
      raise ValueError.new('invalidSyntax', 'request body must be a JSON object') unless value.is_a?(Hash)
      if value.key?('schemas') && !(value['schemas'].is_a?(Array) && value['schemas'].include?(AGENT_SCHEMA_URN))
        raise ValueError.new('invalidValue', "schemas must include #{AGENT_SCHEMA_URN}")
      end

      { 'identity' => read_identity(value), 'projection' => read_projection(value) }
    end

    # ---- store ----

    # The in-memory store; any object with all/get/put/delete/registry works. Entries are {'resource', 'passport'}.
    class MemoryStore
      def initialize(seed = nil)
        @by_id = {}
        (seed || []).each { |s| @by_id[s['resource']['id']] = s }
      end

      def all = @by_id.values
      def get(id) = @by_id[id]
      def put(stored) = (@by_id[stored['resource']['id']] = stored)

      def delete(id)
        return false unless @by_id.key?(id)

        @by_id.delete(id)
        true
      end

      def registry = Scim.build_registry(@by_id.values.map { |s| s['passport'] })
    end

    def create_memory_store(seed = nil) = MemoryStore.new(seed)

    # ---- envelopes + filter ----

    def scim_error(status, detail, scim_type = UNDEF)
      body = { 'schemas' => [ERROR_SCHEMA], 'status' => Js.string(status), 'detail' => detail }
      body['scimType'] = scim_type unless scim_type.equal?(UNDEF)
      body
    end

    def scim_list_response(resources, total_results, start_index)
      { 'schemas' => [LIST_RESPONSE_SCHEMA], 'totalResults' => total_results, 'startIndex' => start_index,
        'itemsPerPage' => resources.length, 'Resources' => resources }
    end

    FILTERABLE = %w[userName displayName externalId id active owner].freeze
    WS = "[#{Js::WS}]".freeze
    NOT_LT = "[^\n\r  ]" # JavaScript `.`
    # ASCII-only case folding, as the reference's non-unicode /i: no `ſ` / Kelvin-sign matches
    FILTER = /\A#{WS}*([A-Za-z0-9_]+)#{WS}+[eE][qQ]#{WS}+(?:"((?:[^"\\]|\\#{NOT_LT})*)"|([tT][rR][uU][eE]|[fF][aA][lL][sS][eE]))#{WS}*\z/
    UNESC = /\\(#{NOT_LT})/

    # The `attr eq "value"` / `attr eq true|false` subset; raises ValueError('invalidFilter').
    def parse_filter(filter)
      raise ValueError.new('invalidFilter', 'filter must be a string') unless filter.is_a?(String)

      m = filter.valid_encoding? ? FILTER.match(filter) : nil
      raise ValueError.new('invalidFilter', "unsupported filter (only `attr eq \"value\"` is supported): #{filter}") if m.nil?

      attr = m[1]
      raise ValueError.new('invalidFilter', "filter attribute not supported: #{attr}") unless FILTERABLE.include?(attr)
      return { 'attr' => attr, 'value' => m[3].downcase == 'true' } unless m[3].nil?

      { 'attr' => attr, 'value' => (m[2] || '').gsub(UNESC, '\1') }
    end

    def seq?(a, b) = a.class == b.class && a == b # === for strings and booleans

    def matches_filter?(agent, f)
      case f['attr']
      when 'userName', 'displayName' then seq?(agent['displayName'], f['value'])
      when 'externalId', 'id', 'owner', 'active' then seq?(agent[f['attr']], f['value'])
      else false
      end
    end

    # ---- PATCH ----

    MUTABLE_PATHS = %w[active displayName externalId owner capabilities holder].freeze

    def read_patch_ops(value)
      raise ValueError.new('invalidSyntax', 'PATCH body must be a JSON object') unless value.is_a?(Hash)

      ops = value['Operations']
      raise ValueError.new('invalidValue', 'PATCH requires a non-empty Operations array') unless ops.is_a?(Array) && !ops.empty?

      ops.map do |raw|
        o = raw.is_a?(Hash) ? raw : nil
        op_raw = o ? o.fetch('op', UNDEF) : UNDEF
        op = op_raw.is_a?(String) ? op_raw.downcase : nil
        raise ValueError.new('invalidValue', "unsupported PATCH op: #{js(op_raw)}") unless %w[add replace remove].include?(op)

        parsed = { 'op' => op }
        path = o && str(o['path'])
        parsed['path'] = path unless path.nil?
        parsed['value'] = o['value'] if o&.key?('value')
        parsed
      end
    end

    def projection_of(resource)
      proj = { 'owner' => resource['owner'], 'active' => resource['active'], 'capabilities' => Js.spread(resource['capabilities']) }
      %w[displayName externalId holder].each { |k| proj[k] = resource[k] unless resource[k].nil? }
      proj
    end

    def apply_scalar(proj, path, op, value)
      case path
      when 'active'
        return proj['active'] = true if op == 'remove'

        b = bool(value)
        raise ValueError.new('invalidValue', '`active` must be a boolean') if b.nil?

        proj['active'] = b
      when 'capabilities'
        return proj['capabilities'] = [] if op == 'remove'

        arr = str_list(value) or raise ValueError.new('invalidValue', '`capabilities` must be a string array')
        proj['capabilities'] = op == 'add' ? (proj['capabilities'] || []) + arr : arr.dup
      else
        if op == 'remove'
          raise ValueError.new('mutability', "`#{path}` cannot be removed") if %w[displayName owner].include?(path)

          proj.delete(path) if %w[externalId holder].include?(path)
          return
        end
        s = str(value) or raise ValueError.new('invalidValue', "`#{path}` must be a string")
        proj[path] = s
      end
    end

    def apply_patch_op(proj, op)
      unless op.key?('path')
        raise ValueError.new('noTarget', 'a `remove` op requires a `path`') if op['op'] == 'remove'

        obj = op['value']
        raise ValueError.new('invalidValue', 'a pathless PATCH value must be an object') unless obj.is_a?(Hash)

        Js.js_keys(obj).each do |key|
          raise ValueError.new('mutability', "attribute is immutable or unknown: #{key}") unless MUTABLE_PATHS.include?(key)

          apply_scalar(proj, key, 'replace', obj[key])
        end
        return
      end
      raise ValueError.new('mutability', "attribute is immutable or unknown: #{op['path']}") unless MUTABLE_PATHS.include?(op['path'])

      apply_scalar(proj, op['path'], op['op'], op['value'])
    end

    # ---- the SCIM server ----

    def json_response(status, body, extra = {})
      { 'status' => status, 'body' => body, 'headers' => { 'content-type' => SCIM_CONTENT_TYPE }.merge(extra) }
    end

    def error_response(status, detail, scim_type = UNDEF) = json_response(status, scim_error(status, detail, scim_type))
    def value_error_response(e) = error_response(400, e.message, e.scim_type)

    def resource_response(status, resource)
      json_response(status, resource, { 'location' => resource['meta']['location'], 'etag' => resource['meta']['version'] })
    end

    def parse_int_param(v, fallback)
      return fallback if v.equal?(UNDEF)

      n = js_number(v)
      integer?(n) ? n : fallback
    end

    def page_bound(x) = [x, 2**62].min.to_i

    # handler.call({'method', 'id'?, 'query'?, 'body'?}) -> {'status', 'body', 'headers'}. authenticate.call(req) must return
    # exactly true to admit a request (false, a raise or any other value is a 401); it is required unless
    # allow_unauthenticated is true.
    def scim_handler(store, options = nil)
      Handler.new(store, options || {})
    end

    # The /Agents resource server (see scim_handler).
    class Handler
      def initialize(store, options)
        @store = store
        @o = options
        @auth = options['authenticate']
        return if @auth.respond_to?(:call) || options['allow_unauthenticated'] == true

        raise TypeError, 'scimHandler: `authenticate` is required (or pass allow_unauthenticated: true explicitly)'
      end

      def to_proc = method(:call).to_proc

      def call(req)
        if @auth.respond_to?(:call)
          ok = begin
            @auth.call(req) == true
          rescue StandardError
            false # a raising check is a refusal
          end
          unless ok
            r = Scim.error_response(401, 'authentication required')
            r['headers'] = { 'content-type' => SCIM_CONTENT_TYPE, 'www-authenticate' => 'Bearer' }
            return r
          end
        end
        method = req.fetch('method', UNDEF)
        id = req.fetch('id', UNDEF)
        none = id.equal?(UNDEF)
        case method
        when 'GET' then none ? list(req['query']) : get_one(id)
        when 'POST' then none ? create(req['body']) : Scim.error_response(405, 'POST is not allowed on an individual Agent')
        when 'PUT' then none ? Scim.error_response(405, 'PUT requires an Agent id') : replace(id, req['body'])
        when 'PATCH' then none ? Scim.error_response(405, 'PATCH requires an Agent id') : patch(id, req['body'])
        when 'DELETE' then none ? Scim.error_response(405, 'DELETE requires an Agent id') : delete(id)
        else Scim.error_response(405, "method not allowed: #{Scim.js(method)}")
        end
      end

      private

      def meta_input
        inp = {}
        inp['base_url'] = @o['base_url'] if @o.key?('base_url')
        inp['now'] = @o['now'] unless @o['now'].nil?
        inp
      end

      def list(query)
        q = query.is_a?(Hash) ? query : {}
        items = @store.all.map { |s| s['resource'] }
        flt = q.fetch('filter', UNDEF)
        if !flt.equal?(UNDEF) && flt != ''
          begin
            parsed = Scim.parse_filter(flt)
          rescue ValueError => e
            return Scim.value_error_response(e)
          end
          items = items.select { |a| Scim.matches_filter?(a, parsed) }
        end
        total = items.length
        start = [1, Scim.parse_int_param(q.fetch('startIndex', UNDEF), 1)].max
        lo = Scim.page_bound(start - 1)
        cnt_raw = q.fetch('count', UNDEF)
        page = if cnt_raw.equal?(UNDEF)
                 items[lo..] || []
               else
                 cnt = [0, Scim.parse_int_param(cnt_raw, total)].max
                 items[lo...Scim.page_bound(start - 1 + cnt)] || []
               end
        Scim.json_response(200, Scim.scim_list_response(page, total, start))
      end

      def rematerialize(existing, proj)
        Scim.passport_to_scim(existing['passport'], proj, meta_input.merge('created' => existing['resource']['meta']['created']))
      end

      def not_found(id) = Scim.error_response(404, "Agent #{Scim.js(id)} not found")

      def create(body)
        req = Scim.scim_to_provisioning_request(body)
        passport = Scim.issue_passport(req['identity'])
        if @store.get(passport['id'])
          return Scim.error_response(409, "an agent with this attested identity already exists (id #{passport['id']})", 'uniqueness')
        end

        resource = Scim.passport_to_scim(passport, req['projection'], meta_input)
        @store.put({ 'resource' => resource, 'passport' => passport })
        Scim.resource_response(201, resource)
      rescue ValueError => e
        Scim.value_error_response(e)
      end

      def replace(id, body)
        existing = @store.get(id) or return not_found(id)
        return Scim.error_response(400, 'request body must be a JSON object', 'invalidSyntax') unless body.is_a?(Hash)

        proj = Scim.read_projection(body)
        proj['owner'] = existing['resource']['owner'] if proj['owner'] == ''
        store_resource(existing, proj)
      end

      def patch(id, body)
        existing = @store.get(id) or return not_found(id)
        proj = Scim.projection_of(existing['resource'])
        begin
          Scim.read_patch_ops(body).each { |op| Scim.apply_patch_op(proj, op) }
        rescue ValueError => e
          return Scim.value_error_response(e)
        end
        store_resource(existing, proj)
      end

      def store_resource(existing, proj)
        resource = rematerialize(existing, proj)
        @store.put({ 'resource' => resource, 'passport' => existing['passport'] })
        Scim.resource_response(200, resource)
      end

      def delete(id)
        return not_found(id) unless @store.delete(id)

        { 'status' => 204, 'headers' => {} }
      end

      def get_one(id)
        existing = @store.get(id) or return not_found(id)
        Scim.resource_response(200, existing['resource'])
      end
    end

    # ---- push adapters ----

    def extension_attributes(agent)
      pp = agent['passport']
      attrs = { 'owner' => agent['owner'], 'model' => pp['model_id'], 'operator' => pp['operator'], 'hardwareRooted' => pp['hardware_rooted'],
                'capabilities' => Js.spread(agent['capabilities']), 'passportRef' => agent['passportRef'] }
      attrs['holder'] = agent['holder'] unless agent['holder'].nil?
      attrs
    end

    def external_id(agent) = agent['externalId'].nil? ? agent['passportRef'] : agent['externalId']

    def to_entra_agent_payload(agent)
      { 'schemas' => [AGENT_SCHEMA_URN, ENTRA_AGENT_EXTENSION_URN], 'externalId' => external_id(agent), 'displayName' => agent['displayName'],
        'active' => agent['active'], ENTRA_AGENT_EXTENSION_URN => extension_attributes(agent) }
    end

    def to_okta_scim_payload(agent)
      { 'schemas' => [AGENT_SCHEMA_URN, OKTA_AGENT_EXTENSION_URN], 'userName' => agent['passportRef'], 'externalId' => external_id(agent),
        'displayName' => agent['displayName'], 'active' => agent['active'], OKTA_AGENT_EXTENSION_URN => extension_attributes(agent) }
    end

    # POST a provisioning payload. target: {'endpoint', 'token', 'fetch'}; fetch.call(url, {'method', 'headers', 'body'}) returns a
    # Hash (or object) with ok, status and json (a callable): injected, there is no default network client.
    def push_provision(payload, target)
      f = target['fetch']
      raise ArgumentError, 'pushProvision: no fetch available - pass one explicitly' unless f.respond_to?(:call)

      res = f.call(target['endpoint'], { 'method' => 'POST',
                                         'headers' => { 'authorization' => "Bearer #{Js.string(target['token'])}", 'content-type' => SCIM_CONTENT_TYPE },
                                         'body' => Js.json(payload) })
      get = res.is_a?(Hash) ? ->(k) { res[k] } : ->(k) { res.public_send(k) }
      body = begin
        get.('json').call
      rescue StandardError
        nil # an unreadable body is null
      end
      { 'ok' => get.('ok'), 'status' => get.('status'), 'body' => body }
    end

    def push_to_entra(agent, target) = push_provision(to_entra_agent_payload(agent), target)
    def push_to_okta(agent, target) = push_provision(to_okta_scim_payload(agent), target)
  end
end
