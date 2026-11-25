# frozen_string_literal: true

# OpenAPI 3.x and Swagger 2 to drafts (native port of the OpenAPI importer of the TypeScript reference @atlasauth/pca-actions): one
# def per operation, parameters from path / query / body (nested bodies flattened to dotted names), the method giving the initial
# effects. `x-` extensions are ignored unless allow-listed. Every draft is `unreviewed`.
require_relative 'actions_import_common'

module AtlasPca
  module ActionsImportOpenapi
    C = AtlasPca::ActionsImportCommon
    J = C::J
    U16 = C::U16
    UNDEF = C::UNDEF
    Err = C::Err

    METHODS = %w[get put post delete options head patch trace].freeze
    EFFECT_OF = { 'get' => ['read'], 'head' => ['read'], 'options' => ['read'], 'trace' => ['read'], 'post' => ['create'],
                  'put' => ['update'], 'patch' => ['update'], 'delete' => ['delete'] }.freeze
    NATURAL = %w[get head options trace put delete].freeze
    BODY_TYPES = %w[application/json application/x-www-form-urlencoded multipart/form-data].freeze
    # JS /i folds ASCII only here: letters are spelled as [xX] classes (Ruby's /i would also fold U+017F and U+212A)
    def self.ci(s) = s.gsub(/[a-z]/i) { |ch| "[#{ch.downcase}#{ch.upcase}]" }
    VERSIONISH = /\A(?:#{ci('v')}[0-9]+(?:\.[0-9]+)?|#{ci('api')}|#{ci('rest')}|#{ci('public')}|#{ci('latest')})\z/
    PARAM_SEG = /\A\{[^\n\r  ]+\}\z/
    VERB_EXT = /\A[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){1,5}\z/
    JSON_PLUS = /\A#{ci('application')}\/[^;]*\+#{ci('json')}(?:;|\z)/
    IDEM = /\A#{ci('idempotency-key')}\z/

    module_function

    # The object a `$ref` chain ends at (an array is possible: callers read members through g()); nil when it does not resolve.
    def deref(c, x, where)
      return nil unless x.is_a?(Hash)
      return x unless x['$ref'].is_a?(String)

      seen = []
      cur = x
      while cur.is_a?(Hash) && cur['$ref'].is_a?(String)
        if seen.include?(cur['$ref']) || seen.length > c.lim['max_ref_depth']
          C.add_todo(c, where, 'cyclic_ref', 'a reference chain is cyclic or too deep')
          return nil
        end
        seen << cur['$ref']
        t = C.pointer(c.root, cur['$ref'])
        if t.nil?
          C.add_todo(c, where, 'unresolved_ref', "reference '#{C.clip(cur['$ref'], 120)}' does not resolve locally")
          return nil
        end
        cur = t
      end
      cur
    end

    def path_facts(path)
      segs = U16.to_pua(path).split('/').reject(&:empty?)
      ends = !segs.empty? && PARAM_SEG.match?(segs[-1])
      nouns = segs.reject { |s| s.include?('{') || s.include?('}') || VERSIONISH.match?(s) }.flat_map { |s| C.tokens_of(s) }
      [nouns, ends]
    end

    def swagger2_param(p)
      return p if p.key?('schema') || p['in'] == 'body'

      skip = %w[name in required description]
      out = p.slice(*skip)
      out['schema'] = p.reject { |k, _| skip.include?(k) }
      out
    end

    def body_schema(c, op, params, swagger, where)
      if swagger
        params.each { |q| return q.fetch('schema', UNDEF) if q['in'] == 'body' }
        return UNDEF
      end
      rb = deref(c, op.fetch('requestBody', UNDEF), where)
      content = C.g(rb, 'content')
      return UNDEF unless content.is_a?(Hash)

      keys = J.sort_utf8(content.keys)
      pick = nil
      BODY_TYPES.each do |t|
        pick = keys.find { |k| U16.to_pua(k).downcase.split(';', -1)[0].to_s.gsub(C::WS_EDGE, '') == t }
        break unless pick.nil?
      end
      pick = keys.find { |k| JSON_PLUS.match?(U16.to_pua(k)) } if pick.nil?
      if pick.nil?
        if keys.length.positive?
          C.add_todo(c, where, 'body_type',
                     "request body media types (#{keys[0, 3].map { |k| C.clip(k, 40) }.join(', ')}) are not form or JSON; the body is not declared")
        end
        return UNDEF
      end
      C.g(content[pick], 'schema')
    end

    def import_openapi(source, opts = nil)
      c = C.new_ctx('openapi', source, opts)
      raise Err.new('bad_source', 'an OpenAPI document must be an object') unless source.is_a?(Hash)

      swagger = source['swagger'].is_a?(String) && J.u8(source['swagger']).b.start_with?('2')
      v3 = source['openapi'].is_a?(String) && J.u8(source['openapi']).b.start_with?('3.')
      unless swagger || v3
        raise Err.new('bad_source', "not an OpenAPI 3.x or Swagger 2 document (missing 'openapi: 3.x' or 'swagger: 2.0')")
      end

      paths = source['paths'].is_a?(Hash) ? source['paths'] : {}
      global_security = source['security'].is_a?(Array) ? source['security'] : nil
      ns = opts['ns']
      J.sort_utf8(paths.keys).each do |path|
        item0 = deref(c, paths[path], path)
        next if item0.nil?

        shared = C.g(item0, 'parameters')
        shared = [] unless shared.is_a?(Array)
        METHODS.each do |method|
          op = C.g(item0, method)
          next unless op.is_a?(Hash)

          where = "#{method.upcase} #{C.clip(path, 120)}"
          oid = op['operationId']
          operation_id = oid.is_a?(String) && J.u16len(oid).positive? && J.u16len(oid) <= 200 ? oid : nil
          nouns, ends = path_facts(path)
          name_raw = op['x-pca-verb'].is_a?(String) && C.ext?(c, 'x-pca-verb') ? op['x-pca-verb'] : nil
          verb = if !name_raw.nil? && J.rx?(VERB_EXT, name_raw) && name_raw.start_with?("#{ns}.")
                   name_raw
                 elsif !operation_id.nil?
                   C.verb_of(ns, operation_id)
                 else
                   C.verb_of(ns, (nouns.last(2) + [method == 'get' && !ends ? 'list' : method]).join(' '))
                 end
          c.root = source
          bud = C.new_budget(c)
          merged = {}
          own_params = op['parameters']
          (shared + (own_params.is_a?(Array) ? own_params : [])).each do |raw|
            q0 = deref(c, raw, where)
            next if !q0.is_a?(Hash) || !q0['name'].is_a?(String) || !q0['in'].is_a?(String)

            q = swagger ? swagger2_param(q0) : q0
            merged["#{q['in']}:#{q['name']}"] = q
          end
          allp = merged.values
          params = {}
          idem_param = nil
          body = body_schema(c, op, allp, swagger, where)
          unless body.equal?(UNDEF)
            b = C.resolve_schema(body, c, bud, "#{where}: request body")
            if b['type'] == 'object' || b['properties'].is_a?(Hash)
              C.flatten_object(b, c, bud, where, params)
            else
              C.add_todo(c, where, 'body_shape', 'the request body is not an object schema; it is not declared')
            end
          end
          allp.sort { |a, b| J.compare_utf8("#{a['in']}:#{a['name']}", "#{b['in']}:#{b['name']}") }.each do |q|
            name = q['name']
            if q['in'] == 'header' && J.rx?(IDEM, name)
              idem_param = 'idempotency_key'
              next
            end
            next if q['in'] == 'body'

            unless %w[path query formData].include?(q['in'])
              C.add_todo(c, where, 'param_location',
                         "#{C.clip(q['in'], 12)} parameter '#{C.clip(name, 60)}' is not an action parameter (path, query and body only)")
              next
            end
            sname = C.param_seg(name)
            C.add_todo(c, "#{where}: #{name}", 'renamed_param', "parameter '#{C.clip(name, 80)}' is declared as '#{sname}'") if sname != name
            if params.key?(sname) || params.keys.any? { |k| k.start_with?("#{sname}.") }
              C.add_todo(c, "#{where}: #{name}", 'skipped_param', "'#{sname}' is declared by the body and by a #{q['in']} parameter; kept the body's")
              next
            end
            if params.length >= 64
              C.add_todo(c, where, 'too_many_params', 'more than 64 parameters; the rest are dropped')
              break
            end
            sq = q['schema']
            sq = {} if sq.nil?
            qd = q.fetch('description', UNDEF)
            extra = J.truthy?(qd) && !J.truthy?(C.g(sq, 'description')) ? { 'description' => qd } : {}
            sch = C.resolve_schema(C.spread_obj(sq).merge(extra), c, bud, "#{where}: #{name}")
            params[sname] = C.leaf_param(sch, q['in'] == 'path' || q['required'] == true, c, bud, "#{where}: #{name}")
          end
          if !idem_param.nil? && !params.key?(idem_param)
            params[idem_param] = { 'type' => 'string', 'required' => false, 'max_len' => 255 }
          else
            idem_param = nil
          end
          scope = ends || method == 'post' ? 'one' : 'set'
          sec = op['security'].is_a?(Array) ? op['security'] : global_security
          scopes = J.sort_utf8(((sec || []).select { |r| r.is_a?(Hash) }.flat_map { |r| r.values.select { |v| v.is_a?(Array) }.flatten(1) }.select { |x| x.is_a?(String) }).uniq)
          C.add_todo(c, where, 'required_scope', "requires scope: #{scopes[0, 12].map { |s| C.clip(s, 60) }.join(', ')}") unless scopes.empty?
          C.add_todo(c, where, 'deprecated', 'the operation is marked deprecated') if op['deprecated'] == true
          op.each_key do |k|
            if k.start_with?('x-') && !C.ext?(c, k)
              C.add_todo(c, where, 'extension_ignored', "extension '#{C.clip(k, 60)}' is ignored (not allow-listed)")
              break
            end
          end
          summary = op['summary']
          desc = op['description']
          idem = if !idem_param.nil? then { 'mode' => 'key_param', 'param' => idem_param }
                 elsif NATURAL.include?(method) then { 'mode' => 'natural' }
                 end
          C.emit_def(
            c, operation_id.nil? ? where : operation_id, EFFECT_OF[method].dup, scope, params,
            { 'openapi' => { 'operationId' => operation_id.nil? ? C.clip("#{method}_#{path}", 200) : operation_id,
                             'method' => method.upcase, 'path' => C.clip(path, 240) } },
            verb: verb, no_alias: operation_id.nil?,
            title: summary.is_a?(String) && !summary.empty? ? summary : operation_id,
            description: desc.is_a?(String) ? desc : (summary.is_a?(String) ? summary : nil),
            idempotency: idem
          )
        end
      end
      C.finish(c)
    end
  end
end
