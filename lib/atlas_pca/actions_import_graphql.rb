# frozen_string_literal: true

# GraphQL SDL or introspection JSON to drafts (native port of the GraphQL importer of the TypeScript reference @atlasauth/pca-actions).
# Query fields are reads, Mutation fields are writes, Subscription fields are streaming reads; arguments and input objects are flattened
# to dotted params. There is no method signal, so everything stays `unreviewed`. A schema is {'types' => {name => typedef}, 'query'?,
# 'mutation'?, 'subscription'?}; a typedef is {'kind','name','fields' => [{'name','args','type','desc'?,'deprecated'}],'values'}; a type
# is {'k' => 'named'|'list'|'nonnull', ...}.
require_relative 'actions_import_common'

module AtlasPca
  module ActionsImportGraphql
    C = AtlasPca::ActionsImportCommon
    J = C::J
    U16 = C::U16
    UNDEF = C::UNDEF
    Err = C::Err

    SPACE = " \t\n\r,﻿".chars.freeze
    PUNCT = '!$&():=@[]{|}'.chars.freeze
    NAME0 = ('A'..'Z').to_a + ('a'..'z').to_a + ['_']
    NAMEN = NAME0 + ('0'..'9').to_a
    NUM0 = ['-'] + ('0'..'9').to_a
    NUMN = %w[- + . e E] + ('0'..'9').to_a
    KINDS = { 'OBJECT' => 'object', 'INPUT_OBJECT' => 'input', 'ENUM' => 'enum', 'SCALAR' => 'scalar', 'INTERFACE' => 'interface', 'UNION' => 'union' }.freeze
    SCALARS = {
      'Int' => { 'type' => 'integer', 'format' => 'int32' }, 'String' => { 'type' => 'string' }, 'ID' => { 'type' => 'string' },
      'Boolean' => { 'type' => 'boolean' }, 'Float' => { 'type' => 'number' }, 'Date' => { 'type' => 'string', 'format' => 'date' },
      'DateTime' => { 'type' => 'string', 'format' => 'date-time' }, 'Email' => { 'type' => 'string', 'format' => 'email' },
      'UUID' => { 'type' => 'string', 'format' => 'uuid' }, 'URL' => { 'type' => 'string', 'format' => 'url' },
      'URI' => { 'type' => 'string', 'format' => 'url' }
    }.freeze

    module_function

    def sw?(a, str, i) = a[i, str.length].join == str

    # Tokens are [kind, text]; the source is walked as characters with a lone surrogate as a private-use stand-in (restored in strings).
    def lex(source, max_tokens)
      src = U16.to_pua(source).chars
      out = []
      n = src.length
      i = 0
      push = lambda do |t|
        raise Err.new('import_limit', 'the GraphQL source has too many tokens') if out.length >= max_tokens

        out << t
      end
      while i < n
        ch = src[i]
        if SPACE.include?(ch)
          i += 1
          next
        end
        if ch == '#'
          i += 1 while i < n && src[i] != "\n"
          next
        end
        if ch == '"'
          if sw?(src, '"""', i)
            j = i + 3
            s = []
            while j < n && !sw?(src, '"""', j)
              if sw?(src, '\\"""', j)
                s << '"""'
                j += 4
              else
                s << src[j]
                j += 1
              end
            end
            raise Err.new('bad_source', 'unterminated GraphQL block string') if j >= n

            push.call(['str', U16.from_pua(s.join)])
            i = j + 3
          else
            j = i + 1
            s = []
            while j < n && src[j] != '"'
              raise Err.new('bad_source', 'unterminated GraphQL string') if src[j] == "\n"

              if src[j] == '\\'
                s << (j + 1 < n ? src[j + 1] : '')
                j += 2
              else
                s << src[j]
                j += 1
              end
            end
            raise Err.new('bad_source', 'unterminated GraphQL string') if j >= n

            push.call(['str', U16.from_pua(s.join)])
            i = j + 1
          end
          next
        end
        if NAME0.include?(ch)
          j = i + 1
          j += 1 while j < n && NAMEN.include?(src[j])
          push.call(['name', src[i...j].join])
          i = j
          next
        end
        if NUM0.include?(ch)
          j = i + 1
          j += 1 while j < n && NUMN.include?(src[j])
          push.call(['int', src[i...j].join])
          i = j
          next
        end
        if sw?(src, '...', i)
          push.call(%w[punct ...])
          i += 3
          next
        end
        if PUNCT.include?(ch)
          push.call(['punct', ch])
          i += 1
          next
        end
        raise Err.new('bad_source', "unexpected character in GraphQL source at offset #{i}")
      end
      push.call(['eof', ''])
      out
    end

    class Parser
      attr_reader :i

      def initialize(toks, schema, max_depth)
        @i = 0
        @toks = toks
        @schema = schema
        @max_depth = max_depth
      end

      def cur = @toks[@i]

      def next_tok
        t = @toks[@i]
        @i += 1 if t[0] != 'eof'
        t
      end

      def is?(v) = cur[0] != 'str' && cur[1] == v

      def eat(v)
        return false unless is?(v)

        @i += 1
        true
      end

      def expect(v)
        raise Err.new('bad_source', "GraphQL parse error: expected '#{v}' near '#{C.clip(cur[1], 30)}'") unless eat(v)
      end

      def name
        t = next_tok
        raise Err.new('bad_source', "GraphQL parse error: expected a name near '#{C.clip(t[1], 30)}'") if t[0] != 'name'

        t[1]
      end

      def desc = cur[0] == 'str' ? next_tok[1] : nil

      def type(depth = 0)
        raise Err.new('import_limit', 'GraphQL type nesting is too deep') if depth > @max_depth

        if eat('[')
          t = { 'k' => 'list', 'of' => type(depth + 1) }
          expect(']')
        else
          t = { 'k' => 'named', 'name' => name }
        end
        eat('!') ? { 'k' => 'nonnull', 'of' => t } : t
      end

      def value(depth = 0)
        raise Err.new('import_limit', 'GraphQL value nesting is too deep') if depth > @max_depth

        t = cur
        if %w[str int name].include?(t[0])
          @i += 1
          return
        end
        if eat('[')
          value(depth + 1) while !is?(']') && cur[0] != 'eof'
          expect(']')
          return
        end
        if eat('{')
          while !is?('}') && cur[0] != 'eof'
            name
            expect(':')
            value(depth + 1)
          end
          expect('}')
          return
        end
        if eat('$')
          name
          return
        end
        raise Err.new('bad_source', "GraphQL parse error: unexpected '#{C.clip(t[1], 30)}'")
      end

      def directives
        deprecated = false
        while eat('@')
          deprecated = true if name == 'deprecated'
          next unless eat('(')

          while !is?(')') && cur[0] != 'eof'
            name
            expect(':')
            value
          end
          expect(')')
        end
        deprecated
      end

      def args
        out = []
        return out unless eat('(')

        until is?(')')
          raise Err.new('bad_source', 'GraphQL parse error: unterminated argument list') if cur[0] == 'eof'

          d = desc
          n = name
          expect(':')
          ty = type
          value if eat('=')
          directives
          out << ({ 'name' => n, 'type' => ty }.merge(d.nil? || d.empty? ? {} : { 'desc' => d }))
        end
        expect(')')
        out
      end

      def fields(inp)
        out = []
        return out unless eat('{')

        until is?('}')
          raise Err.new('bad_source', 'GraphQL parse error: unterminated field list') if cur[0] == 'eof'

          d = desc
          n = name
          a = inp ? [] : args
          expect(':')
          ty = type
          value if inp && eat('=')
          dep = directives
          out << ({ 'name' => n, 'args' => a, 'type' => ty, 'deprecated' => dep }.merge(d.nil? || d.empty? ? {} : { 'desc' => d }))
        end
        expect('}')
        out
      end

      def definition
        desc
        kw = name
        if kw == 'extend'
          definition
          return
        end
        if kw == 'schema'
          directives
          expect('{')
          until is?('}')
            raise Err.new('bad_source', 'GraphQL parse error: unterminated schema block') if cur[0] == 'eof'

            op = name
            expect(':')
            ty = name
            @schema[op] = ty if %w[query mutation subscription].include?(op)
          end
          expect('}')
          return
        end
        if kw == 'scalar'
          n = name
          directives
          merge({ 'kind' => 'scalar', 'name' => n, 'fields' => [], 'values' => [] })
          return
        end
        if kw == 'directive'
          expect('@')
          name
          args
          @i += 1 if cur[1] == 'repeatable'
          @i += 1 if cur[1] == 'on'
          eat('|')
          name
          name while eat('|')
          return
        end
        if %w[type interface input].include?(kw)
          n = name
          if cur[1] == 'implements'
            @i += 1
            eat('&')
            name
            name while eat('&')
          end
          directives
          merge({ 'kind' => kw == 'type' ? 'object' : (kw == 'input' ? 'input' : 'interface'), 'name' => n, 'fields' => fields(kw == 'input'), 'values' => [] })
          return
        end
        if kw == 'union'
          n = name
          directives
          if eat('=')
            eat('|')
            name
            name while eat('|')
          end
          merge({ 'kind' => 'union', 'name' => n, 'fields' => [], 'values' => [] })
          return
        end
        if kw == 'enum'
          n = name
          directives
          values = []
          if eat('{')
            until is?('}')
              raise Err.new('bad_source', 'GraphQL parse error: unterminated enum') if cur[0] == 'eof'

              desc
              values << name
              directives
            end
            expect('}')
          end
          merge({ 'kind' => 'enum', 'name' => n, 'fields' => [], 'values' => values })
          return
        end
        raise Err.new('bad_source', "GraphQL parse error: unsupported definition '#{C.clip(kw, 30)}' (only type-system definitions are imported)")
      end

      def merge(d)
        old = @schema['types'][d['name']]
        if old.nil?
          @schema['types'][d['name']] = d
          return
        end
        old['fields'].concat(d['fields'])
        old['values'].concat(d['values'])
      end
    end

    def parse_graphql_sdl(src, max_tokens = 2_000_000)
      toks = lex(src, max_tokens)
      schema = { 'types' => {} }
      p = Parser.new(toks, schema, 32)
      p.definition while p.cur[0] != 'eof'
      schema
    end

    # ---- introspection -> model
    def introspect_type(t, depth = 0)
      raise Err.new('bad_source', 'malformed introspection type reference') if depth > 16 || !t.is_a?(Hash)
      return { 'k' => 'nonnull', 'of' => introspect_type(t['ofType'], depth + 1) } if t['kind'] == 'NON_NULL'
      return { 'k' => 'list', 'of' => introspect_type(t['ofType'], depth + 1) } if t['kind'] == 'LIST'
      raise Err.new('bad_source', 'malformed introspection type reference') unless t['name'].is_a?(String)

      { 'k' => 'named', 'name' => t['name'] }
    end

    def field_of(f)
      return nil if !f.is_a?(Hash) || !f['name'].is_a?(String)

      raw = f['args']
      args = []
      (raw.is_a?(Array) ? raw : []).each do |a|
        next unless a.is_a?(Hash) && a['name'].is_a?(String)

        args << ({ 'name' => a['name'], 'type' => introspect_type(a['type']) }.merge(a['description'].is_a?(String) ? { 'desc' => a['description'] } : {}))
      end
      out = { 'name' => f['name'], 'args' => args, 'type' => f.key?('type') ? introspect_type(f['type']) : { 'k' => 'named', 'name' => 'String' },
              'deprecated' => f['isDeprecated'] == true }
      out['desc'] = f['description'] if f['description'].is_a?(String)
      out
    end

    def from_introspection(doc)
      root = doc.is_a?(Hash) && doc['data'].is_a?(Hash) ? doc['data'] : doc
      s = root.is_a?(Hash) && root['__schema'].is_a?(Hash) ? root['__schema'] : nil
      raise Err.new('bad_source', 'not a GraphQL introspection result (no __schema.types)') if s.nil? || !s['types'].is_a?(Array)

      schema = { 'types' => {} }
      { 'query' => 'queryType', 'mutation' => 'mutationType', 'subscription' => 'subscriptionType' }.each do |key, k|
        n = s[k].is_a?(Hash) && s[k]['name'].is_a?(String) ? s[k]['name'] : nil
        schema[key] = n if n && !n.empty?
      end
      s['types'].each do |t|
        next if !t.is_a?(Hash) || !t['name'].is_a?(String) || !t['kind'].is_a?(String)
        next if t['name'].b.start_with?('__')

        kind = KINDS[t['kind']]
        next if kind.nil?

        raw = kind == 'input' ? t['inputFields'] : t['fields']
        ev = t['enumValues']
        schema['types'][t['name']] = {
          'kind' => kind, 'name' => t['name'],
          'fields' => (raw.is_a?(Array) ? raw : []).map { |x| field_of(x) }.compact,
          'values' => (ev.is_a?(Array) ? ev : []).select { |e| e.is_a?(Hash) && e['name'].is_a?(String) }.map { |e| e['name'] }
        }
      end
      schema
    end

    # ---- model -> JSON-schema-like -> params
    def schema_of(t, gs, c, bud, stack, where)
      nonnull = false
      cur = t
      while cur['k'] == 'nonnull'
        nonnull = true
        cur = cur['of']
      end
      return [{ 'type' => 'array', 'items' => schema_of(cur['of'], gs, c, bud, stack, where)[0] }, nonnull] if cur['k'] == 'list'

      name = cur['name']
      spent = bud.left <= 0
      bud.left -= 1
      if spent
        unless bud.exhausted
          bud.exhausted = true
          C.add_todo(c, where, 'ref_budget', 'type expansion stopped at the node budget (declared string; refine or drop)')
        end
        return [{}, nonnull]
      end
      return [SCALARS[name].dup, nonnull] if SCALARS.key?(name)

      d = gs['types'][name]
      if d.nil?
        C.add_todo(c, where, 'unknown_type', "type '#{C.clip(name, 60)}' is not defined in the schema (declared string)")
        return [{}, nonnull]
      end
      return [{ 'type' => 'string', 'enum' => d['values'].uniq }, nonnull] if d['kind'] == 'enum'
      return [{ 'type' => 'string' }, nonnull] if d['kind'] == 'scalar'

      if d['kind'] == 'input'
        if stack.include?(name)
          C.add_todo(c, where, 'cyclic_ref', "input type '#{C.clip(name, 60)}' is recursive (declared string; refine or drop)")
          return [{}, nonnull]
        end
        properties = {}
        required = []
        d['fields'].each do |f|
          r, nn = schema_of(f['type'], gs, c, bud, stack + [name], where)
          # assigning `__proto__` on a JS object sets its prototype: never a member
          properties[f['name']] = r.merge(f['desc'].nil? || f['desc'].empty? ? {} : { 'description' => f['desc'] }) if f['name'] != '__proto__'
          required << f['name'] if nn
        end
        return [{ 'type' => 'object', 'properties' => properties, 'required' => required }, nonnull]
      end
      C.add_todo(c, where, 'output_type', "type '#{C.clip(name, 60)}' is an output type and cannot be an argument (declared string)")
      [{}, nonnull]
    end

    # `source` is SDL text or an introspection result (parsed JSON).
    def import_graphql(source, opts = nil)
      c = C.new_ctx('graphql', source, opts)
      gs = source.is_a?(String) ? parse_graphql_sdl(source) : from_introspection(source)
      roots = [[gs.fetch('query', 'Query'), 'query'], [gs.fetch('mutation', 'Mutation'), 'mutation'], [gs.fetch('subscription', 'Subscription'), 'subscription']]
      roots.each do |root_name, op|
        rt = gs['types'][root_name]
        next if rt.nil?

        rt['fields'].each_with_index.sort { |(a, x), (b, y)| (r = J.compare_utf8(a['name'], b['name'])).zero? ? x <=> y : r }.map(&:first).each do |f|
          where = "#{op} #{C.clip(f['name'], 80)}"
          c.root = nil
          bud = C.new_budget(c)
          properties = {}
          required = []
          f['args'].each do |a|
            r, nn = schema_of(a['type'], gs, c, bud, [], "#{where}(#{a['name']})")
            properties[a['name']] = r.merge(a['desc'].nil? || a['desc'].empty? ? {} : { 'description' => a['desc'] }) if a['name'] != '__proto__'
            required << a['name'] if nn
          end
          params = {}
          C.flatten_object({ 'type' => 'object', 'properties' => properties, 'required' => required }, c, bud, where, params)
          C.add_todo(c, where, 'deprecated', 'the field is marked @deprecated') if f['deprecated']
          desc = f['desc']
          has = !desc.nil? && !desc.empty?
          C.emit_def(
            c, f['name'], op == 'mutation' ? ['update'] : ['read'], 'one', params, { 'graphql' => { 'op' => op, 'field' => C.clip(f['name'], 200) } },
            title: has ? U16.from_pua(U16.to_pua(desc).split("\n", -1)[0]) : f['name'], description: desc,
            idempotency: op == 'mutation' ? nil : { 'mode' => 'natural' },
            traits: op == 'subscription' ? C.with_trait(nil, 'pca.bulk') : nil
          )
        end
      end
      C.finish(c)
    end
  end
end
