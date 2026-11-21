# frozen_string_literal: true

# What every action importer shares (native port of the import limits and common helpers of the TypeScript reference
# @atlasauth/pca-actions): the input bounds, result shapes, text hygiene, verb naming, the bounded `$ref` resolver, the JSON Schema
# to ParamDef flattening and the single place a draft ActionDef is assembled (always `unreviewed`). Sources are parsed JSON values
# (Hash / Array / String / Integer / Float / true / false / nil); an importer returns {'defs','todo','source'}. JavaScript string
# semantics (UTF-16 lengths, lone surrogates as WTF-8, property reads on any value) are reproduced where an output depends on them.
require 'digest'
require 'set'
require_relative 'intent_v2'
require_relative 'actions'
require_relative 'siem'

module AtlasPca
  module ActionsImportCommon
    A = AtlasPca::Actions
    J = AtlasPca::V2JS
    U16 = AtlasPca::Siem::U16
    UNDEF = J::UNDEF
    Err = A::ActionKitError

    MAX_PARAM_PATH_DEPTH = 3

    DEFAULT_IMPORT_LIMITS = { 'max_bytes' => 64 * 1024 * 1024, 'max_ops' => 20_000, 'max_json_depth' => 64, 'max_nodes' => 6_000_000,
                              'max_ref_nodes' => 20_000, 'max_ref_depth' => 8 }.freeze
    HARD_IMPORT_LIMITS = { 'max_bytes' => 256 * 1024 * 1024, 'max_ops' => 50_000, 'max_json_depth' => 128, 'max_nodes' => 20_000_000,
                           'max_ref_nodes' => 200_000, 'max_ref_depth' => 16 }.freeze
    IMPORT_KINDS = %w[openapi mcp graphql grpc asyncapi jsonschema].freeze
    DEFAULT_EXTENSIONS = %w[x-pca-verb x-pca-role x-pca-internal].freeze
    NS_RE = /\A[a-z][a-z0-9_]{0,31}\z/
    JS_WS = "\\t\\n\\v\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
    LONE_RE = /\xED[\xA0-\xBF][\x80-\xBF]/n
    CTRL_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f  ‪-‮⁦-⁩]/
    WS_RUN = /[#{JS_WS}]+/
    WS_EDGE = /\A[#{JS_WS}]+|[#{JS_WS}]+\z/
    RESERVED = %w[__proto__ constructor prototype].freeze
    INT_ROLES = %w[money.amount money.fee count.limit bytes.size].freeze
    FORMATS = { 'email' => 'email', 'uuid' => 'uuid', 'uri' => 'url', 'url' => 'url', 'idn-email' => 'email', 'semver' => 'semver' }.freeze
    RTYPE_RE = /\A[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,4}\z/
    ACTION_WORDS = %w[get list read fetch find search query show describe create add new make insert post put set update patch edit modify
                      delete remove destroy drop send notify publish invite cancel refund charge pay run exec execute invoke start stop
                      enable disable approve reject close open merge export import upload download subscribe unsubscribe revoke grant
                      transfer].to_set.freeze

    class Ctx
      attr_accessor :ns, :kind, :lim, :todo, :source, :ext, :root, :verbs, :aliases, :defs

      def initialize(ns, kind, lim, source, ext, root)
        @ns = ns
        @kind = kind
        @lim = lim
        @todo = []
        @source = source
        @ext = ext
        @root = root
        @verbs = Set.new
        @aliases = {}
        @defs = []
      end
    end

    class Budget
      attr_accessor :left, :exhausted

      def initialize(left)
        @left = left
        @exhausted = false
      end
    end

    module_function

    # ---- limits
    def num?(v) = v.is_a?(Integer) || v.is_a?(Float)

    def safe_integer?(v)
      return false unless num?(v)
      return false if v.is_a?(Float) && (!v.finite? || v != v.floor)

      v.abs <= (2**53) - 1
    end

    def resolve_limits(over = nil)
      out = DEFAULT_IMPORT_LIMITS.dup
      out.each_key do |k|
        next unless over.is_a?(Hash) && over.key?(k)

        v = over[k]
        raise Err.new('bad_limit', "limit #{k} must be a positive safe integer") if !safe_integer?(v) || v < 1

        out[k] = [v.to_i, HARD_IMPORT_LIMITS[k]].min
      end
      out
    end

    def text_size_check(text, lim)
      raise Err.new('bad_source', 'the source must be text') unless text.is_a?(String)

      return unless J.u16len(text) * 3 > lim['max_bytes'] && te_len(text) > lim['max_bytes']

      raise Err.new('import_limit', "the source is larger than #{lim['max_bytes']} bytes")
    end

    def te_len(s) = J.te_bytes(s).bytesize

    def check_parsed(root, lim)
      nodes = 0
      size = 0
      stack = [[root, 0]]
      until stack.empty?
        v, d = stack.pop
        nodes += 1
        raise Err.new('import_limit', "the source has more than #{lim['max_nodes']} nodes") if nodes > lim['max_nodes']
        raise Err.new('import_limit', "the source nests deeper than #{lim['max_json_depth']}") if d > lim['max_json_depth']

        if v.nil? || v == true || v == false
          size += 4
        elsif num?(v)
          raise Err.new('bad_source', 'the source holds a non-finite number') if v.is_a?(Float) && !v.finite?

          size += 8
        elsif v.is_a?(String)
          size += J.u16len(v)
        elsif v.is_a?(Array)
          size += 2 + v.length
          v.each { |x| stack << [x, d + 1] }
        elsif v.is_a?(Hash)
          v.each do |k, x|
            size += J.u16len(k) + 4
            stack << [x, d + 1]
          end
        else
          raise Err.new('bad_source', "the source holds a #{v.class}")
        end
        raise Err.new('import_limit', "the source is larger than #{lim['max_bytes']} bytes") if size > lim['max_bytes']
      end
      nodes
    end

    # ---- canonical hash of a parsed source (lenient: lone surrogates are written as escapes, numbers as ECMAScript prints them)
    def lenient(v)
      case v
      when nil then 'null'
      when true then 'true'
      when false then 'false'
      when String then AtlasPca::Js.json_string(v)
      when Integer, Float
        raise TypeError, 'canonicalize: non-finite number' if v.is_a?(Float) && !v.finite?

        AtlasPca::Predicates.js_number_string(v)
      when Array then "[#{v.map { |x| lenient(x) }.join(',')}]"
      when Hash then "{#{J.sort_utf8(v.keys).map { |k| "#{AtlasPca::Js.json_string(k)}:#{lenient(v[k])}" }.join(',')}}"
      else raise TypeError, "canonicalize: unsupported type #{v.class}"
      end
    end

    def sha_b64u(bytes) = AtlasPca.b64e(Digest::SHA256.digest(bytes))
    def hash_canonical_lenient(v) = sha_b64u(J.te_bytes(lenient(v)))

    def new_ctx(kind, source, opts)
      o = opts.is_a?(Hash) ? opts : {}
      ns = o['ns']
      raise Err.new('bad_ns', 'ns must match [a-z][a-z0-9_]{0,31}') unless ns.is_a?(String) && J.rx?(NS_RE, ns)

      lim = resolve_limits(o['limits'])
      if source.is_a?(String) && source.encoding != Encoding::BINARY
        text_size_check(source, lim)
        digest = sha_b64u(J.te_bytes(source))
      elsif source.is_a?(String)
        raise Err.new('import_limit', "the source is larger than #{lim['max_bytes']} bytes") if source.bytesize > lim['max_bytes']

        digest = sha_b64u(source)
      else
        check_parsed(source, lim)
        digest = hash_canonical_lenient(source)
      end
      now = o['now']
      now = 0 if now.nil?
      raise Err.new('bad_opts', 'now must be a non-negative integer') if !safe_integer?(now) || now < 0

      uri = o['uri']
      licence = o['licence']
      ext = o['allowExtensions']
      if ext.nil? then ext = DEFAULT_EXTENSIONS
      elsif ext.is_a?(String) then ext = U16.to_pua(ext).each_char.map { |ch| U16.from_pua(ch) }
      elsif !ext.is_a?(Array) then raise TypeError, 'allowExtensions is not iterable'
      end
      src = { 'kind' => kind, 'uri' => clip(uri.nil? ? "source:#{kind}" : uri, 2048), 'spec_digest' => digest,
              'licence' => clip(licence.nil? ? 'unknown' : licence, 128), 'imported_at' => now.to_i }
      Ctx.new(ns, kind, lim, src, ext.to_set { |x| x.is_a?(String) ? x.b : x }, source)
    end

    def ext?(c, name) = c.ext.include?(name.b)

    def add_todo(c, where, code, message)
      n = c.todo.length
      if n < 5000
        c.todo << { 'where' => clip(where, 200), 'code' => code, 'message' => clip(message, 400) }
      elsif n == 5000
        c.todo << { 'where' => '*', 'code' => 'todo_truncated', 'message' => 'further notes omitted' }
      end
    end

    def finish(c) = { 'defs' => c.defs, 'todo' => c.todo, 'source' => c.source }

    # ---- text hygiene
    def u8(s) = te_len(s)

    def clip(s, max_bytes)
      return '' unless s.is_a?(String)

      t = J.u8(s).b.gsub(LONE_RE, '').force_encoding(Encoding::UTF_8)
      t = t.gsub(CTRL_RE, ' ').unicode_normalize(:nfc).gsub(WS_RUN, ' ').gsub(WS_EDGE, '')
      return t if te_len(t) <= max_bytes

      out = +''
      n = 0
      t.each_char do |ch|
        w = ch.bytesize
        break if n + w > max_bytes

        out << ch
        n += w
      end
      out.gsub(WS_EDGE, '')
    end

    def first_text(mx, *xs)
      xs.each do |x|
        t = clip(x, mx)
        return t unless t.empty?
      end
      ''
    end

    # ---- tokens and verbs
    def tokens_of(name)
      s = U16.to_pua(J.js_str(name)).unicode_normalize(:nfkd).gsub(/[̀-ͯ]/, '')
      s = s.gsub(/([a-z0-9])([A-Z])/, '\1 \2').gsub(/([A-Z]+)([A-Z][a-z])/, '\1 \2').downcase
      s.split(/[^a-z0-9]+/).reject(&:empty?)
    end

    def seg(toks)
      s = toks.join('_')
      return s if s.length <= 32

      h = AtlasPca.b64e(Digest::SHA256.digest(s)).gsub(/[^a-z0-9]/i, '').downcase[0, 4].ljust(4, '0')
      "#{s[0, 27]}_#{h}"
    end

    def verb_of(ns, raw)
      parts = U16.to_pua(J.js_str(raw)).split(%r{[./:#{JS_WS}]+}).map { |p| tokens_of(p) }.reject(&:empty?)
      if parts.length >= 2
        segs = parts.map { |p| seg(p) }
      else
        t = parts[0] || ['op']
        segs = if t.length >= 2 && ACTION_WORDS.include?(t[0]) then [seg(t[1..]), seg([t[0]])]
               elsif t.length >= 2 && ACTION_WORDS.include?(t[-1]) then [seg(t[0..-2]), seg([t[-1]])]
               else [seg(t)]
               end
      end
      segs = segs[0, 2] + segs[-3..] if segs.length > 5
      v = "#{ns}.#{segs.join('.')}"
      return "#{ns}.op" if !A::VERB_RE.match?(v) || v.bytesize > 128

      v
    end

    def alias_of(raw, verb)
      a = tokens_of(raw).join('_')
      a.length.positive? && a.length <= 64 && A::ALIAS_RE.match?(a) && a != verb ? a : nil
    end

    def humanize(name)
      t = tokens_of(name)
      t.empty? ? '' : ([t[0][0].upcase + t[0][1..]] + t[1..]).join(' ')
    end

    def unique_verb(c, verb, where)
      return verb unless c.verbs.include?(verb)

      (2...100_000).each do |n|
        sfx = "_#{n}"
        dot = verb.rindex('.')
        last = verb[(dot + 1)..]
        cand = "#{verb[0..dot]}#{last[0, 32 - sfx.length]}#{sfx}"
        if !c.verbs.include?(cand) && A::VERB_RE.match?(cand)
          add_todo(c, where, 'duplicate_verb', "verb '#{verb}' is taken by an earlier operation; this one is '#{cand}'")
          return cand
        end
      end
      raise Err.new('import_limit', 'too many operations map to one verb')
    end

    # ---- JSON value helpers
    def obj?(v) = v.is_a?(Hash)
    def g(o, k) = o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    def present?(v) = !v.equal?(UNDEF)

    # {...v}: an object's members, an array's / string's indexed members, nothing for a scalar.
    def spread_obj(v)
      case v
      when Hash then v.dup
      when Array then v.each_with_index.to_h { |x, i| [i.to_s, x] }
      when String then U16.units(v).each_with_index.to_h { |u, i| [i.to_s, U16.from_units([u])] }
      else {}
      end
    end

    # [...v]: an array or a string (by code point); anything else is not iterable.
    def spread_arr(v)
      return v.dup if v.is_a?(Array)
      return U16.to_pua(v).each_char.map { |ch| U16.from_pua(ch) } if v.is_a?(String)

      raise TypeError, 'value is not iterable'
    end

    # decodeURIComponent, or the raw segment when the escape is malformed.
    def decode_uri(s)
      b = s.b
      return s if b.match?(/%(?![0-9A-Fa-f]{2})/n)

      out = b.gsub(/(?:%[0-9A-Fa-f]{2})+/n) do |run|
        bytes = run.scan(/%(..)/n).flatten.map { |h| h.hex.chr.b }.join
        return s unless bytes.dup.force_encoding(Encoding::UTF_8).valid_encoding?

        bytes
      end
      out.force_encoding(Encoding::UTF_8)
    end

    # Follow a local `#/a/b` JSON pointer in `root`; nil when absent, not local, or not an object or array.
    def pointer(root, ref)
      return nil unless ref.is_a?(String) && J.u8(ref).b.start_with?('#/')

      cur = root
      rest = J.u8(ref).b[2..]
      (rest.empty? ? [''.b] : rest.split('/', -1)).each do |raw|
        seg = decode_uri(raw.gsub('~1', '/').gsub('~0', '~').force_encoding(Encoding::UTF_8))
        if cur.is_a?(Hash)
          return nil unless cur.key?(seg)

          cur = cur[seg]
        elsif cur.is_a?(Array)
          return nil unless seg.match?(/\A(?:0|[1-9][0-9]*)\z/) && seg.to_i < cur.length

          cur = cur[seg.to_i]
        else
          return nil
        end
      end
      cur.is_a?(Hash) || cur.is_a?(Array) ? cur : nil
    end

    def new_budget(c) = Budget.new(c.lim['max_ref_nodes'])

    def nn(v) = v.nil? ? [] : v

    def merge_all(a, m)
      out = a.merge(m)
      out['properties'] = spread_obj(a['properties']).merge(spread_obj(m['properties']))
      out['required'] = spread_arr(nn(a['required'])) + spread_arr(nn(m['required']))
      out
    end

    def null_type?(m)
      t = g(m, 'type')
      (t.is_a?(String) && t == 'null') || (t.is_a?(Array) && !t.empty? && t.all? { |x| x.is_a?(String) && x == 'null' })
    end

    def str_enum?(e) = e.is_a?(Array) && e.all?(String)

    # Follow local `$ref`s, merge `allOf`, collapse `anyOf`/`oneOf` to the single non-null variant or to a union of string constants.
    # What stays unrepresentable is noted and left as {} (declared string, which fails closed).
    def resolve_schema(s, c, bud, where, chain = [], depth = 0)
      return {} unless s.is_a?(Hash)

      if bud.left <= 0
        unless bud.exhausted
          bud.exhausted = true
          add_todo(c, where, 'ref_budget', "schema expansion stopped after #{c.lim['max_ref_nodes']} nodes (declared string; refine or drop)")
        end
        return {}
      end
      bud.left -= 1
      if depth > c.lim['max_ref_depth']
        add_todo(c, where, 'ref_depth', "schema nesting or reference chain deeper than #{c.lim['max_ref_depth']} (declared string; refine or drop)")
        return {}
      end
      cur = s
      if cur['$ref'].is_a?(String)
        ref = cur['$ref']
        if chain.include?(ref)
          add_todo(c, where, 'cyclic_ref', "reference '#{clip(ref, 120)}' is cyclic (declared string; refine or drop)")
          return {}
        end
        target = pointer(c.root, ref)
        if target.nil?
          add_todo(c, where, 'unresolved_ref', "reference '#{clip(ref, 120)}' is not a local reference that resolves (declared string; refine or drop)")
          return {}
        end
        siblings = cur.reject { |k, _| k == '$ref' }
        cur = resolve_schema(target, c, bud, where, chain + [ref], depth + 1).merge(siblings)
      end
      if cur['allOf'].is_a?(Array)
        rest = cur.reject { |k, _| k == 'allOf' }
        merged = {}
        cur['allOf'].map { |m| resolve_schema(m, c, bud, where, chain, depth + 1) }.each { |m| merged = merge_all(merged, m) }
        cur = merged.merge(rest)
      end
      alts = if cur['anyOf'].is_a?(Array) then cur['anyOf']
             elsif cur['oneOf'].is_a?(Array) then cur['oneOf']
             end
      unless alts.nil?
        rest = cur.reject { |k, _| %w[anyOf oneOf].include?(k) }
        live = alts.map { |m| resolve_schema(m, c, bud, where, chain, depth + 1) }.reject { |m| null_type?(m) }
        return live[0].merge(rest) if live.length == 1

        consts = live.map do |m|
          if m['const'].is_a?(String) then [m['const']]
          elsif m['enum'].is_a?(Array) && m['enum'].all?(String) then m['enum']
          end
        end
        return rest.merge('type' => 'string', 'enum' => consts.flatten.uniq) if live.length > 1 && consts.none?(&:nil?)

        add_todo(c, where, 'union', "a union of #{live.length} schemas has no representation (declared string; refine or drop)")
        return rest
      end
      cur = cur.merge('enum' => [cur['const']]) if cur.key?('const') && !cur.key?('enum') && cur['const'].is_a?(String)
      cur
    end

    # ---- JSON Schema -> params
    # [A-Za-z0-9_]{1,64}; anything else becomes _ (an astral character is two UTF-16 units, so two).
    def param_seg(raw)
      s = U16.units(raw).map { |u| (u >= 48 && u <= 57) || (u >= 65 && u <= 90) || (u >= 97 && u <= 122) || u == 95 ? u.chr : '_' }.join
      s = '' if s.match?(/\A_+\z/)
      s = s[0, 64]
      s.empty? ? 'p' : s
    end

    def role_ok?(r) = A::CORE_ROLES.include?(r) || J.rx?(A::ID_ROLE_RE, r) || J.rx?(A::CUSTOM_ROLE_RE, r)
    def int_num?(n) = safe_integer?(n) && !J.neg_zero?(n)

    def enum_strs(e)
      ok = e.is_a?(Array) && !e.empty? && e.length <= 256 && e.all? do |x|
        x.is_a?(String) && !x.empty? && u8(x) <= 256 && J.u8(x).valid_encoding? && x == x.unicode_normalize(:nfc)
      end
      ok ? e.uniq : nil
    end

    # Array.isArray(t) ? t.find(x => x !== 'null') : t (undefined when none)
    def first_non_null(t)
      return t unless t.is_a?(Array)

      t.each { |x| return x unless x.is_a?(String) && x == 'null' }
      UNDEF
    end

    def leaf_param(s, required, c, bud, where)
      t0 = first_non_null(g(s, 'type'))
      enum_str = enum_strs(s['enum'])
      items = s['items']
      t = if !t0.equal?(UNDEF) && !t0.nil? then t0
          elsif enum_str then 'string'
          elsif items.is_a?(Array) || items.is_a?(Hash) then 'array'
          else UNDEF
          end
      base = { 'type' => 'string' }
      base['required'] = false unless required
      desc = clip(s['description'], 280)
      base['description'] = desc unless desc.empty?
      role_ext = ext?(c, 'x-pca-role') && s['x-pca-role'].is_a?(String) ? s['x-pca-role'] : nil
      with_role = lambda do |p|
        next p if role_ext.nil?

        if !role_ok?(role_ext) || (INT_ROLES.include?(role_ext) && p['type'] != 'integer')
          add_todo(c, where, 'role_ignored', "x-pca-role '#{clip(role_ext, 64)}' is not valid for a #{p['type']} parameter")
          next p
        end
        p.merge('role' => role_ext)
      end
      fmt = s['format']
      if t == 'integer' || (t == 'number' && fmt.is_a?(String) && %w[int32 int64].include?(fmt))
        p = base.merge('type' => 'integer')
        mn = s['minimum']
        mx = s['maximum']
        ex_min = s['exclusiveMinimum']
        ex_max = s['exclusiveMaximum']
        if int_num?(mn) && ex_min != true then p['min'] = mn.to_i
        elsif int_num?(ex_min) then p['min'] = ex_min.to_i + 1
        elsif int_num?(mn) && ex_min == true then p['min'] = mn.to_i + 1
        end
        if int_num?(mx) && ex_max != true then p['max'] = mx.to_i
        elsif int_num?(ex_max) then p['max'] = ex_max.to_i - 1
        elsif int_num?(mx) && ex_max == true then p['max'] = mx.to_i - 1
        end
        if p.key?('min') && p.key?('max') && p['min'] > p['max']
          p.delete('min')
          p.delete('max')
        end
        return with_role.call(p)
      end
      return with_role.call(base.merge('type' => 'boolean')) if t == 'boolean'

      if t == 'string'
        f = fmt.is_a?(String) ? fmt : ''
        return with_role.call(base.merge('type' => 'date')) if f == 'date'
        return with_role.call(base.merge('type' => 'datetime')) if f == 'date-time'

        p = base.merge('type' => 'string')
        if enum_str then p['values'] = enum_str
        elsif s['enum'].is_a?(Array) && !s['enum'].empty?
          add_todo(c, where, 'enum_dropped', 'enum values are not 1..256 plain strings (declared as a free string; refine)')
        end
        p['format'] = FORMATS[f] if FORMATS.key?(f)
        ml = s['maxLength']
        p['max_len'] = ml.to_i if int_num?(ml) && ml.positive? && ml <= 16_777_216
        return with_role.call(p)
      end
      if t == 'array'
        it = resolve_schema(items, c, bud, "#{where}[]")
        it_enum = enum_strs(it['enum'])
        lim = {}
        lim['max_items'] = s['maxItems'].to_i if int_num?(s['maxItems']) && s['maxItems'] >= 0
        lim['min_items'] = s['minItems'].to_i if int_num?(s['minItems']) && s['minItems'] >= 0
        if lim.key?('min_items') && lim.key?('max_items') && lim['min_items'] > lim['max_items']
          lim.delete('min_items')
          lim.delete('max_items')
        end
        return with_role.call(base.merge('type' => 'set', 'values' => it_enum).merge(lim)) if s['uniqueItems'] == true && it_enum

        it_t = first_non_null(g(it, 'type'))
        item = it_t.is_a?(String) && %w[integer string boolean].include?(it_t) ? it_t : nil
        if item.nil? && !it_t.equal?(UNDEF)
          add_todo(c, where, 'array_items', "array items of type '#{clip(J.js_str(it_t), 40)}' are not declared (items left open)")
        end
        return with_role.call(base.merge('type' => 'array').merge(item ? { 'items' => item } : {}).merge(lim))
      end
      shown = J.js_str(t.equal?(UNDEF) || t.nil? ? 'none' : t)
      if t == 'number'
        add_todo(c, where, 'unsupported_type', "type 'number' (fractions) has no ActionDef representation (declared string; use an integer unit, or refine)")
      else
        add_todo(c, where, 'unsupported_type', "type '#{clip(shown, 40)}' has no representation (declared string; refine or drop)")
      end
      with_role.call(base.merge('type' => 'string'))
    end

    # Nested objects become dotted names up to MAX_PARAM_PATH_DEPTH segments; an object below that (or without properties) is a string
    # placeholder; a child of an optional parent is optional. At most MAX_DEF_PARAMS params; the rest are dropped, noted.
    def flatten_object(schema, c, bud, where, out, prefix = [], parent_required = true, force_required = [])
      props = schema['properties'].is_a?(Hash) ? schema['properties'] : {}
      r = schema['required']
      req = r.is_a?(Array) ? r.select { |x| x.is_a?(String) }.to_set(&:b) : Set.new
      forced = force_required.map(&:b)
      J.sort_utf8(props.keys).each do |name|
        if RESERVED.include?(name)
          add_todo(c, "#{where}: #{name}", 'skipped_param', "parameter name '#{name}' is reserved; dropped")
          next
        end
        child = resolve_schema(props[name], c, bud, "#{where}: #{name}")
        next if child['readOnly'] == true

        sname = param_seg(name)
        add_todo(c, "#{where}: #{name}", 'renamed_param', "parameter '#{clip(name, 80)}' is declared as '#{sname}'") if sname != name
        path = prefix + [sname]
        full = path.join('.')
        required = parent_required && (req.include?(name.b) || forced.include?(name.b))
        is_object = child['type'] == 'object' || (!child.key?('type') && child['properties'].is_a?(Hash))
        if is_object && child['properties'].is_a?(Hash) && !child['properties'].empty? && path.length < MAX_PARAM_PATH_DEPTH
          flatten_object(child, c, bud, "#{where}: #{full}", out, path, required)
          next
        end
        if out.length >= A::MAX_DEF_PARAMS
          add_todo(c, where, 'too_many_params', "more than #{A::MAX_DEF_PARAMS} parameters; '#{full}' and the rest are dropped")
          return
        end
        if out.key?(full) || out.keys.any? { |k| k.start_with?("#{full}.") || full.start_with?("#{k}.") }
          add_todo(c, "#{where}: #{full}", 'skipped_param', "parameter '#{full}' collides with another; kept the first")
          next
        end
        out[full] = is_object ? placeholder_object(child, required, c, "#{where}: #{full}") : leaf_param(child, required, c, bud, "#{where}: #{full}")
      end
    end

    def placeholder_object(s, required, c, where)
      add_todo(c, where, 'object_leaf', 'an object with no (or too deeply nested) properties has no representation (declared string; refine or drop)')
      p = { 'type' => 'string' }
      p['required'] = false unless required
      d = clip(s['description'], 280)
      p['description'] = d unless d.empty?
      p
    end

    # ---- assembling a draft def
    # Assemble, validate and register a draft def. A def that fails validation is dropped, noted (never emitted).
    def emit_def(c, name, effects, scope, params, bindings, verb: nil, title: nil, description: nil, idempotency: nil, traits: nil, no_alias: false)
      raise Err.new('import_limit', "more than #{c.lim['max_ops']} operations") if c.defs.length >= c.lim['max_ops']

      raw_verb = verb.nil? ? verb_of(c.ns, name) : verb
      verb = unique_verb(c, J.rx?(A::VERB_RE, raw_verb) ? raw_verb : verb_of(c.ns, name), name)
      segs = verb.split('.')
      rtype = segs.length > 2 ? segs[0..-2].join('.') : segs[0]
      ttl = first_text(A::MAX_TITLE_BYTES, title, humanize(name), verb)
      desc = clip(description, [A::MAX_DESCRIPTION_BYTES, 600].min)
      al = no_alias ? nil : alias_of(name, verb)
      d = { 'v' => 1, 'kind' => 'pca-action-def', 'verb' => verb }
      d['aliases'] = [al] if !al.nil? && !c.aliases.key?(al) && !c.verbs.include?(al)
      d['title'] = ttl.empty? ? verb : ttl
      d['description'] = desc unless desc.empty?
      d['effects'] = effects.uniq.sort
      d['resource'] = { 'type' => RTYPE_RE.match?(rtype) ? rtype : segs[0], 'id' => { 'prefix' => '', 'class' => 'any_safe', 'len' => [1, 128] }, 'scope' => scope }
      d['params'] = params
      d['idempotency'] = idempotency if idempotency && !idempotency.empty?
      d['traits'] = traits.uniq.sort if traits && !traits.empty?
      d['bindings'] = bindings
      d['review'] = { 'state' => 'unreviewed' }
      d['source'] = c.source.slice('kind', 'uri', 'spec_digest', 'licence', 'imported_at')
      bad = A.validate_def(d)
      unless bad.nil?
        add_todo(c, name, 'invalid_def', "not emitted: #{bad}")
        return nil
      end
      c.verbs << verb
      c.aliases[d['aliases'][0]] = verb if d.key?('aliases')
      c.defs << d
      d
    end

    def with_trait(traits, t) = ((traits || []) + [t]).uniq
  end
end
