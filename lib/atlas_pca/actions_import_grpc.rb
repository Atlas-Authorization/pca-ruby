# frozen_string_literal: true

# Protobuf services to drafts, from `.proto` text or a binary FileDescriptorSet (native port of the gRPC importer of the TypeScript
# reference @atlasauth/pca-actions). `service.method` becomes the verb; `google.api.http` gives method and path; `idempotency_level`
# gives read / idempotent; field behavior (REQUIRED, OUTPUT_ONLY) refines params; streaming methods get `pca.bulk`. Offline, bounded, no
# code generation. A model is {'messages' => {full => {full, fields, mapEntry}}, 'enums' => {full => {full, values}}, 'services' => [{full, name, methods}]}.
require_relative 'actions_import_common'

module AtlasPca
  module ActionsImportGrpc
    C = AtlasPca::ActionsImportCommon
    J = C::J
    U16 = C::U16
    Err = C::Err

    SCALAR_NAMES = %w[double float int32 int64 uint32 uint64 sint32 sint64 fixed32 fixed64 sfixed32 sfixed64 bool string bytes].freeze
    WS = (["\t", "\n", "\v", "\f", "\r", ' ', " ", " ", " ", " ", " ", " ", "　", "﻿"] +
          (0x2000..0x200a).map { |u| [u].pack('U') }).freeze
    ID0 = (('A'..'Z').to_a + ('a'..'z').to_a + ['_', '.']).freeze
    IDN = (ID0 + ('0'..'9').to_a).freeze
    NUM0 = (['-'] + ('0'..'9').to_a).freeze
    NUMN = (%w[- + .] + ('0'..'9').to_a + ('A'..'Z').to_a + ('a'..'z').to_a).freeze
    PUNCT = '{}[]()<>=;,:'.chars.freeze
    FTYPES = { 1 => 'double', 2 => 'float', 3 => 'int64', 4 => 'uint64', 5 => 'int32', 6 => 'fixed64', 7 => 'fixed32', 8 => 'bool', 9 => 'string',
               12 => 'bytes', 13 => 'uint32', 15 => 'sfixed32', 16 => 'sfixed64', 17 => 'sint32', 18 => 'sint64' }.freeze
    BEHAV = { '2' => 'REQUIRED', '3' => 'OUTPUT_ONLY', '4' => 'INPUT_ONLY', '5' => 'IMMUTABLE' }.freeze
    HTTP_VERBS = { 2 => 'GET', 3 => 'PUT', 4 => 'POST', 5 => 'DELETE', 6 => 'PATCH' }.freeze
    WKT_STRING = %w[google.protobuf.StringValue google.protobuf.BytesValue].freeze
    WKT_INT = %w[google.protobuf.Int32Value google.protobuf.Int64Value google.protobuf.UInt32Value google.protobuf.UInt64Value].freeze

    module_function

    def new_model = { 'messages' => {}, 'enums' => {}, 'services' => [] }

    def lex(source, max_tokens)
      src = U16.to_pua(source).chars
      out = []
      n = src.length
      i = 0
      push = lambda do |t|
        raise Err.new('import_limit', 'the proto source has too many tokens') if out.length >= max_tokens

        out << t
      end
      while i < n
        ch = src[i]
        if WS.include?(ch)
          i += 1
          next
        end
        if ch == '/' && src[i + 1] == '/'
          i += 1 while i < n && src[i] != "\n"
          next
        end
        if ch == '/' && src[i + 1] == '*'
          j = i + 2
          j += 1 while j < n && !(src[j] == '*' && src[j + 1] == '/')
          raise Err.new('bad_source', 'unterminated comment in proto source') if j >= n

          i = j + 2
          next
        end
        if ch == '"' || ch == "'"
          j = i + 1
          s = []
          while j < n && src[j] != ch
            raise Err.new('bad_source', 'unterminated string in proto source') if src[j] == "\n"

            if src[j] == '\\'
              s << (j + 1 < n ? src[j + 1] : '')
              j += 2
            else
              s << src[j]
              j += 1
            end
          end
          raise Err.new('bad_source', 'unterminated string in proto source') if j >= n

          push.call(['str', U16.from_pua(s.join)])
          i = j + 1
          next
        end
        if ID0.include?(ch)
          j = i + 1
          j += 1 while j < n && IDN.include?(src[j])
          push.call(['id', src[i...j].join])
          i = j
          next
        end
        if NUM0.include?(ch)
          j = i + 1
          j += 1 while j < n && NUMN.include?(src[j])
          push.call(['num', src[i...j].join])
          i = j
          next
        end
        if PUNCT.include?(ch)
          push.call(['p', ch])
          i += 1
          next
        end
        raise Err.new('bad_source', "unexpected character in proto source at offset #{i}")
      end
      out
    end

    def qual(scope, name) = scope == '' ? name : "#{scope}.#{name}"

    class Parser
      def initialize(toks, model, max_depth)
        @i = 0
        @pkg = ''
        @toks = toks
        @m = model
        @max_depth = max_depth
      end

      def cur = @i >= 0 && @i < @toks.length ? @toks[@i] : nil

      def is?(v)
        t = cur
        !t.nil? && t[0] != 'str' && t[1] == v
      end

      def eat(v)
        return false unless is?(v)

        @i += 1
        true
      end

      def fail(msg)
        t = cur
        raise Err.new('bad_source', "proto parse error: #{msg} near '#{C.clip(t.nil? ? '<end>' : t[1], 30)}'")
      end

      def expect(v) = eat(v) || fail("expected '#{v}'")

      def id
        t = cur
        fail('expected an identifier') if t.nil? || t[0] != 'id'
        @i += 1
        t[1]
      end

      def take
        t = cur
        @i += 1
        t
      end

      def skip_to(open_, close, depth = 1)
        while depth.positive?
          t = take
          fail('unterminated block') if t.nil?
          next unless t[0] == 'p'

          if t[1] == open_ then depth += 1
          elsif t[1] == close then depth -= 1
          end
        end
      end

      def skip_statement
        while !cur.nil? && !is?(';')
          if is?('{')
            @i += 1
            skip_to('{', '}')
            return
          end
          @i += 1
        end
        eat(';')
      end

      def file
        until cur.nil?
          next if eat(';')

          kw = id
          case kw
          when 'package'
            @pkg = id
            expect(';')
          when 'message' then message(@pkg, 0)
          when 'enum' then enum_def(@pkg)
          when 'service' then service
          when 'extend'
            id
            expect('{')
            skip_to('{', '}')
          else skip_statement
          end
        end
      end

      def enum_def(scope)
        full = AtlasPca::ActionsImportGrpc.qual(scope, id)
        expect('{')
        values = []
        until is?('}')
          fail('unterminated enum') if cur.nil?
          if is?('option') || is?('reserved')
            skip_statement
            next
          end
          values << id
          skip_statement
        end
        expect('}')
        @m['enums'][full] = { 'full' => full, 'values' => values }
      end

      def field_options
        behavior = []
        return behavior unless eat('[')

        depth = 1
        in_behavior = false
        while depth.positive?
          t = take
          fail('unterminated field options') if t.nil?
          if t[0] == 'p'
            if ['[', '{'].include?(t[1]) then depth += 1
            elsif [']', '}'].include?(t[1]) then depth -= 1
            elsif t[1] == ',' then in_behavior = false
            end
          elsif t[0] == 'id'
            if t[1].end_with?('field_behavior') then in_behavior = true
            elsif in_behavior && t[1].match?(/\A[A-Z_]+\z/) then behavior << t[1]
            end
          end
        end
        behavior
      end

      def message(scope, depth)
        raise Err.new('import_limit', 'proto message nesting is too deep') if depth > @max_depth

        full = AtlasPca::ActionsImportGrpc.qual(scope, id)
        msg = { 'full' => full, 'fields' => [], 'mapEntry' => false }
        @m['messages'][full] = msg
        expect('{')
        field = lambda do |label, oneof|
          repeated = label == 'repeated'
          typ = id
          fmap = nil
          if typ == 'map' && eat('<')
            k = id
            expect(',')
            v = id
            expect('>')
            fmap = [k, v]
            typ = 'map'
            repeated = false
          end
          fname = id
          expect('=')
          @i += 1 # field number
          behavior = field_options
          expect(';')
          f = { 'name' => fname, 'type' => typ, 'scope' => full, 'repeated' => repeated, 'optional' => label == 'optional' || oneof, 'behavior' => behavior }
          f['map'] = fmap if fmap
          msg['fields'] << f
        end
        until is?('}')
          fail('unterminated message') if cur.nil?
          next if eat(';')

          kw = cur[0] == 'id' ? cur[1] : ''
          case kw
          when 'message'
            @i += 1
            message(full, depth + 1)
          when 'enum'
            @i += 1
            enum_def(full)
          when 'oneof'
            @i += 1
            id
            expect('{')
            until is?('}')
              fail('unterminated oneof') if cur.nil?
              if is?('option')
                skip_statement
                next
              end
              field.call(nil, true)
            end
            expect('}')
          when 'option', 'reserved', 'extensions', 'group' then skip_statement
          when 'extend'
            @i += 1
            id
            expect('{')
            skip_to('{', '}')
          when 'repeated', 'optional', 'required'
            @i += 1
            field.call(kw, false)
          else field.call(nil, false)
          end
        end
        expect('}')
      end

      def stream?
        t = cur
        if !t.nil? && t[1] == 'stream' && t[0] == 'id'
          @i += 1
          return true
        end
        false
      end

      def service
        name = id
        svc = { 'full' => AtlasPca::ActionsImportGrpc.qual(@pkg, name), 'name' => name, 'methods' => [] }
        expect('{')
        until is?('}')
          fail('unterminated service') if cur.nil?
          next if eat(';')

          if id != 'rpc'
            skip_statement
            next
          end
          mname = id
          expect('(')
          cs = stream?
          inp = id
          expect(')')
          fail("expected 'returns'") if id != 'returns'
          expect('(')
          ss = stream?
          out = id
          expect(')')
          m = { 'name' => mname, 'input' => inp, 'output' => out, 'cs' => cs, 'ss' => ss, 'scope' => @pkg }
          if eat('{')
            until is?('}')
              fail('unterminated rpc body') if cur.nil?
              unless is?('option')
                skip_statement
                next
              end
              @i += 1
              if eat('(')
                oname = id
                expect(')')
              else
                oname = id
              end
              expect('=')
              if is?('{')
                @i += 1
                depth = 1
                while depth.positive?
                  t = take
                  fail('unterminated option') if t.nil?
                  if t[0] == 'p'
                    if t[1] == '{' then depth += 1
                    elsif t[1] == '}' then depth -= 1
                    end
                    next
                  end
                  if depth == 1 && oname.end_with?('http') && t[0] == 'id' && %w[get put post delete patch].include?(t[1]) && is?(':')
                    @i += 1
                    path = !cur.nil? && cur[0] == 'str' ? cur[1] : ''
                    @i += 1
                    m['http'] = { 'method' => t[1].upcase, 'path' => path } unless m.key?('http')
                  elsif depth == 1 && oname.end_with?('http') && t[0] == 'id' && t[1] == 'body' && is?(':')
                    @i += 1
                    m['http']['body'] = cur[1] if !cur.nil? && cur[0] == 'str' && m.key?('http')
                    @i += 1
                  end
                end
                eat(';')
              else
                v = cur
                @i += 1
                m['idem'] = v[1] if oname.end_with?('idempotency_level') && !v.nil?
                eat(';')
              end
            end
            expect('}')
            eat(';')
          else
            expect(';')
          end
          svc['methods'] << m
        end
        expect('}')
        @m['services'] << svc
      end
    end

    def parse_proto(src, max_tokens = 2_000_000)
      m = new_model
      Parser.new(lex(src, max_tokens), m, 32).file
      m
    end

    # ---- binary descriptor set
    class Reader
      attr_accessor :p
      attr_reader :fin

      def initialize(b, fin = nil)
        @p = 0
        @b = b
        @fin = fin.nil? ? b.bytesize : fin
      end

      def more? = @p < @fin

      # A JavaScript number: accumulated in double arithmetic, as the reference does (a 10-byte varint loses low bits).
      def varint
        r = 0.0
        mul = 1.0
        10.times do
          raise Err.new('bad_source', 'truncated descriptor') if @p >= @fin

          byte = @b.getbyte(@p)
          @p += 1
          r += (byte & 0x7F).to_f * mul
          return r if (byte & 0x80).zero?

          mul *= 128
        end
        raise Err.new('bad_source', 'overlong varint in descriptor')
      end

      def len
        n = varint
        raise Err.new('bad_source', 'descriptor length exceeds the buffer') if n > @fin - @p

        r = Reader.new(@b, @p + n.to_i)
        r.p = @p
        @p += n.to_i
        r
      end

      def skip(wt)
        case wt
        when 0 then varint
        when 1 then adv(8)
        when 2 then len
        when 5 then adv(4)
        else raise Err.new('bad_source', "unsupported wire type #{wt} in descriptor")
        end
      end

      def adv(n)
        raise Err.new('bad_source', 'truncated descriptor') if n > @fin - @p

        @p += n
      end

      def str
        r = len
        raw = @b.byteslice(r.p, r.fin - r.p)
        raw = raw.byteslice(3, raw.bytesize - 3) if raw.start_with?("\xEF\xBB\xBF".b) # TextDecoder drops a leading byte-order mark
        raw.dup.force_encoding(Encoding::UTF_8).scrub("�")
      end
    end

    def tag(r)
      t = r.varint
      [(t / 8).floor, (t % 8).to_i]
    end

    def fnum(f) = f.is_a?(Float) && f.finite? && f == f.floor ? f.to_i : f

    def parse_descriptor_set(data)
      m = new_model
      top = Reader.new(data.b)

      read_enum = lambda do |r, scope|
        name = ''
        values = []
        while r.more?
          f, wt = tag(r)
          if f == 1 && wt == 2
            name = r.str
          elsif f == 2 && wt == 2
            v = r.len
            while v.more?
              vf, vw = tag(v)
              if vf == 1 && vw == 2 then values << v.str
              else v.skip(vw)
              end
            end
          else
            r.skip(wt)
          end
        end
        full = qual(scope, name)
        m['enums'][full] = { 'full' => full, 'values' => values }
      end

      read_msg = nil
      read_msg = lambda do |r, scope, depth|
        raise Err.new('import_limit', 'descriptor message nesting is too deep') if depth > 32

        name = ''
        fields = []
        nested = []
        enums = []
        map_entry = false
        while r.more?
          f, wt = tag(r)
          if f == 1 && wt == 2
            name = r.str
          elsif f == 2 && wt == 2
            fr = r.len
            fd = { 'name' => '', 'type' => 0.0, 'label' => 1.0, 'typeName' => '', 'proto3opt' => false, 'behavior' => [] }
            while fr.more?
              ff, fw = tag(fr)
              if ff == 1 && fw == 2 then fd['name'] = fr.str
              elsif ff == 4 && fw.zero? then fd['label'] = fr.varint
              elsif ff == 5 && fw.zero? then fd['type'] = fr.varint
              elsif ff == 6 && fw == 2 then fd['typeName'] = fr.str
              elsif ff == 17 && fw.zero? then fd['proto3opt'] = fr.varint == 1
              elsif ff == 8 && fw == 2
                o = fr.len
                while o.more?
                  of, ow = tag(o)
                  if of == 1052 && ow.zero?
                    fd['behavior'] << AtlasPca::Predicates.js_number_string(o.varint)
                  elsif of == 1052 && ow == 2
                    pk = o.len
                    fd['behavior'] << AtlasPca::Predicates.js_number_string(pk.varint) while pk.more?
                  else
                    o.skip(ow)
                  end
                end
              else
                fr.skip(fw)
              end
            end
            fields << fd
          elsif f == 3 && wt == 2
            nested << r.len
          elsif f == 4 && wt == 2
            enums << r.len
          elsif f == 7 && wt == 2
            o = r.len
            while o.more?
              of, ow = tag(o)
              if of == 7 && ow.zero? then map_entry = o.varint == 1
              else o.skip(ow)
              end
            end
          else
            r.skip(wt)
          end
        end
        full = qual(scope, name)
        m['messages'][full] = { 'full' => full, 'mapEntry' => map_entry, 'fields' => fields.map do |fd|
          { 'name' => fd['name'], 'scope' => full, 'repeated' => fd['label'] == 3, 'optional' => fd['proto3opt'],
            'type' => fd['typeName'] != '' ? fd['typeName'] : FTYPES.fetch(fnum(fd['type']), 'bytes'),
            'behavior' => fd['behavior'].map { |b| BEHAV.fetch(b, '') } }
        end }
        nested.each { |n| read_msg.call(n, full, depth + 1) }
        enums.each { |e| read_enum.call(e, full) }
      end

      while top.more?
        f, wt = tag(top)
        if f != 1 || wt != 2
          top.skip(wt)
          next
        end
        fr = top.len
        pkg = ''
        msgs = []
        enums = []
        svcs = []
        while fr.more? # package may follow the messages in the wire order: collect first, then resolve scopes
          ff, fw = tag(fr)
          if ff == 2 && fw == 2 then pkg = fr.str
          elsif ff == 4 && fw == 2 then msgs << fr.len
          elsif ff == 5 && fw == 2 then enums << fr.len
          elsif ff == 6 && fw == 2 then svcs << fr.len
          else fr.skip(fw)
          end
        end
        msgs.each { |r| read_msg.call(r, pkg, 0) }
        enums.each { |r| read_enum.call(r, pkg) }
        svcs.each do |r|
          name = ''
          methods = []
          while r.more?
            sf, sw = tag(r)
            if sf == 1 && sw == 2
              name = r.str
            elsif sf == 2 && sw == 2
              mr = r.len
              me = { 'name' => '', 'input' => '', 'output' => '', 'cs' => false, 'ss' => false, 'scope' => pkg }
              while mr.more?
                mf, mw = tag(mr)
                if mf == 1 && mw == 2 then me['name'] = mr.str
                elsif mf == 2 && mw == 2 then me['input'] = mr.str
                elsif mf == 3 && mw == 2 then me['output'] = mr.str
                elsif mf == 5 && mw.zero? then me['cs'] = mr.varint == 1
                elsif mf == 6 && mw.zero? then me['ss'] = mr.varint == 1
                elsif mf == 4 && mw == 2
                  o = mr.len
                  while o.more?
                    of, ow = tag(o)
                    if of == 34 && ow.zero?
                      me['idem'] = { 1 => 'NO_SIDE_EFFECTS', 2 => 'IDEMPOTENT' }.fetch(fnum(o.varint), 'IDEMPOTENCY_UNKNOWN')
                    elsif of == 72_295_728 && ow == 2
                      h = o.len
                      while h.more?
                        hf, hw = tag(h)
                        if HTTP_VERBS.key?(hf) && hw == 2
                          if me.key?('http') then h.str
                          else me['http'] = { 'method' => HTTP_VERBS[hf], 'path' => h.str }
                          end
                        elsif hf == 7 && hw == 2
                          b = h.str
                          me['http']['body'] = b if me.key?('http')
                        else
                          h.skip(hw)
                        end
                      end
                    else
                      o.skip(ow)
                    end
                  end
                else
                  mr.skip(mw)
                end
              end
              methods << me
            else
              r.skip(sw)
            end
          end
          m['services'] << { 'full' => qual(pkg, name), 'name' => name, 'methods' => methods }
        end
      end
      m
    end

    # ---- model -> params
    def resolve_name(m, name, scope)
      return name[1..] if name.start_with?('.')

      parts = scope == '' ? [] : scope.split('.')
      parts.length.downto(0) do |k|
        cand = (parts[0, k] + [name]).join('.')
        return cand if m['messages'].key?(cand) || m['enums'].key?(cand)
      end
      m['messages'].key?(name) || m['enums'].key?(name) ? name : nil
    end

    def field_schema(m, f, c, stack, where, budget)
      one = lambda do |typ, scope|
        if SCALAR_NAMES.include?(typ)
          next({ 'type' => 'integer', 'format' => 'int64' }) if typ.include?('int') || typ.include?('fixed')
          next({ 'type' => 'boolean' }) if typ == 'bool'
          next({ 'type' => 'string' }) if %w[string bytes].include?(typ)

          next({ 'type' => 'number' })
        end
        ab = typ.start_with?('.') ? typ[1..] : nil
        next({ 'type' => 'string', 'format' => 'date-time' }) if ab == 'google.protobuf.Timestamp' || typ == 'google.protobuf.Timestamp'

        t = ab.nil? ? typ : ab
        next({ 'type' => 'string' }) if WKT_STRING.include?(t)
        next({ 'type' => 'integer', 'format' => 'int64' }) if WKT_INT.include?(t)
        next({ 'type' => 'boolean' }) if t == 'google.protobuf.BoolValue'
        next({}) if t.start_with?('google.protobuf.')

        full = resolve_name(m, typ, scope)
        if full.nil?
          C.add_todo(c, where, 'unknown_type', "type '#{C.clip(typ, 60)}' is not defined in the proto source (declared string)")
          next({})
        end
        en = m['enums'][full]
        next({ 'type' => 'string', 'enum' => en['values'].uniq }) if en

        msg_schema(m, full, c, stack, where, budget)
      end
      return { 'type' => 'object' } if f['map']

      s = one.call(f['type'], f['scope'])
      f['repeated'] ? { 'type' => 'array', 'items' => s } : s
    end

    def msg_schema(m, full, c, stack, where, budget)
      msg = m['messages'][full]
      return {} if msg.nil?

      if stack.include?(full)
        C.add_todo(c, where, 'cyclic_ref', "message '#{C.clip(full, 80)}' is recursive (declared string; refine or drop)")
        return {}
      end
      stop = stack.length > c.lim['max_ref_depth']
      unless stop
        budget['n'] -= 1
        stop = budget['n'] <= 0
      end
      if stop
        C.add_todo(c, where, 'ref_budget', 'message expansion stopped at the bound (declared string; refine or drop)')
        return {}
      end
      properties = {}
      required = []
      msg['fields'].each do |f|
        next if f['behavior'].include?('OUTPUT_ONLY')

        properties[f['name']] = field_schema(m, f, c, stack + [full], "#{where}.#{f['name']}", budget) if f['name'] != '__proto__'
        required << f['name'] if f['behavior'].include?('REQUIRED')
      end
      { 'type' => 'object', 'properties' => properties, 'required' => required }
    end

    def stable_sort(xs, &key) = xs.each_with_index.sort { |(a, i), (b, j)| (r = J.compare_utf8(key.call(a), key.call(b))).zero? ? i <=> j : r }.map(&:first)

    # `source` is `.proto` text or the bytes (a binary String) of a binary FileDescriptorSet.
    def import_grpc(source, opts = nil)
      c = C.new_ctx('grpc', source, opts)
      raise Err.new('bad_source', 'a gRPC source is .proto text or a binary FileDescriptorSet') unless source.is_a?(String)

      m = source.encoding == Encoding::BINARY ? parse_descriptor_set(source) : parse_proto(source)
      stable_sort(m['services']) { |s| s['full'] }.each do |svc|
        stable_sort(svc['methods']) { |s| s['name'] }.each do |me|
          where = "#{svc['name']}/#{me['name']}"
          c.root = nil
          bud = C.new_budget(c)
          inp = resolve_name(m, me['input'], me['scope'])
          inp = me['input'].sub(/\A\./, '') if inp.nil?
          schema = msg_schema(m, inp, c, [], where, { 'n' => c.lim['max_ref_nodes'] })
          params = {}
          if schema.key?('properties')
            C.flatten_object(schema, c, bud, where, params)
          elsif !m['messages'].key?(inp) && !inp.start_with?('google.protobuf.')
            C.add_todo(c, where, 'unknown_type', "request type '#{C.clip(me['input'], 60)}' is not defined in the source (no parameters)")
          end
          http = me['http']
          hm = http ? http['method'] : nil
          effects = if hm == 'GET' then ['read']
                    elsif hm == 'DELETE' then ['delete']
                    elsif hm == 'POST' then ['create']
                    elsif %w[PUT PATCH].include?(hm) then ['update']
                    elsif me['idem'] == 'NO_SIDE_EFFECTS' then ['read']
                    else ['update']
                    end
          natural = %w[NO_SIDE_EFFECTS IDEMPOTENT].include?(me['idem']) || %w[GET PUT DELETE].include?(hm)
          traits = nil
          if me['cs'] || me['ss']
            traits = C.with_trait(traits, 'pca.bulk')
            C.add_todo(c, where, 'streaming', 'a streaming method: acts on many messages (pca.bulk added)')
          end
          bindings = { 'grpc' => { 'service' => C.clip(svc['full'], 250), 'method' => C.clip(me['name'], 250) } }
          bindings['http'] = { 'method' => http['method'], 'path' => C.clip(http['path'], 250) } if http && !http['path'].empty?
          C.emit_def(
            c, "#{svc['name']} #{me['name']}", effects, 'one', params, bindings,
            title: me['name'].gsub(/([a-z0-9])([A-Z])/, '\1 \2'), idempotency: natural ? { 'mode' => 'natural' } : nil, traits: traits
          )
        end
      end
      C.finish(c)
    end
  end
end
