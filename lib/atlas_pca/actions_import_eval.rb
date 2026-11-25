# frozen_string_literal: true

# Measure the suggestion rules against a labeled corpus (native port of the evaluation of the TypeScript reference
# @atlasauth/pca-actions). Every corpus entry is turned into a source document of its own kind, run through the real importer and the real
# suggestion engine, and the traits the system flags are compared with the labels: precision and recall per trait, with an exact
# Clopper-Pearson bound on each. These are heuristic numbers on a reviewed corpus, published as what they are, never as a safety guarantee.
require_relative 'actions_import_pipeline'
require_relative 'intent_clopper'

module AtlasPca
  module ActionsImportEval
    C = AtlasPca::ActionsImportCommon
    S = AtlasPca::ActionsImportSuggest
    P = AtlasPca::ActionsImportPipeline
    A = C::A
    J = C::J
    U16 = C::U16
    UNDEF = C::UNDEF

    LABEL_SHORT = {
      'money' => 'money_moving', 'destr' => 'destructive', 'comm' => 'external_communication', 'priv' => 'privilege_change', 'exp' => 'data_export',
      'exec' => 'code_execution', 'cred' => 'credential_access', 'bulk' => 'bulk', 'pii' => 'pii_access', 'pub' => 'public_exposure',
      'pers' => 'persistence', 'infra' => 'infra_mutation', 'cost' => 'cost_incurring', 'legal' => 'legal_binding', 'imp' => 'impersonation',
      'egress' => 'network_egress', 'fin' => 'financial_data_read', 'reg' => 'regulated_data', 'sched' => 'scheduled', 'spawn' => 'agent_spawning'
    }.freeze
    SPEC_RE = /\A[^:]+:([a-z]+)(?::([^\n\r  ]+))?\z/
    TYPE_RE = /\A[^:]+:([a-z]+)/
    READ_FIRST = %w[get list find search count describe show lookup check validate preview calculate estimate convert format compare summarize sort
                    filter read fetch query view browse open].freeze
    GQL = { 'string' => 'String', 'integer' => 'Int', 'boolean' => 'Boolean', 'array' => '[String]' }.freeze
    PROTO = { 'string' => 'string', 'integer' => 'int64', 'boolean' => 'bool', 'array' => 'repeated string' }.freeze

    module_function

    # str.split(sep): an empty string is one empty field (Ruby's split gives none)
    def split(s, sep) = s.empty? ? [''] : U16.to_pua(s).split(sep, -1).map { |x| U16.from_pua(x) }

    def parse_hand_tsv(text)
      out = []
      n = 0
      split(text, "\n").each do |line|
        next if U16.to_pua(line).gsub(C::WS_EDGE, '').empty? || line.b.start_with?('#')

        c = split(line, "\t")
        raise ArgumentError, "hand corpus line needs 6 columns: #{U16.slice(line, 80)}" if c.length < 6

        kind, name, loc, params, labels, description = c[0, 6]
        n += 1
        e = { 'id' => format('hand-%04d', n), 'src' => 'hand', 'kind' => kind, 'name' => name, 'params' => params == '-' ? [] : split(params, ','),
              'labels' => labels == '-' ? [] : split(labels, ',').map { |x| LABEL_SHORT.fetch(x, x) }, 'description' => description }
        if kind == 'openapi'
          parts = split(loc, ' ')
          e['method'] = parts[0]
          e['path'] = parts[1..].join(' ')
        end
        e['labels'].each { |x| raise ArgumentError, "unknown label '#{x}' in #{name}" unless LABEL_SHORT.value?(x) }
        out << e
      end
      out
    end

    def parse_corpus_jsonl(text)
      split(text, "\n").reject { |l| U16.to_pua(l).gsub(C::WS_EDGE, '').empty? }.map { |l| AtlasPca::Js.parse(l) }
    end

    # ---- entries -> source documents
    def schema_of(spec)
      m = SPEC_RE.match(U16.to_pua(spec))
      typ = m && m[1]
      fmt = m && m[2]
      return { 'type' => 'array', 'items' => { 'type' => 'string' } } if typ == 'array'

      { 'type' => typ == 'number' ? 'number' : (typ.nil? ? 'string' : typ) }.merge(fmt.nil? || fmt.empty? ? {} : { 'format' => U16.from_pua(fmt) })
    end

    # slice(0, indexOf(':')) with indexOf -1 drops the last character
    def pname(spec)
      u = U16.to_pua(spec)
      i = u.index(':')
      U16.from_pua(i.nil? ? u[0...-1] : u[0, i])
    end

    def first_word(n)
      m = /\A[A-Za-z][a-z0-9]*/.match(U16.to_pua(n))
      (m ? m[0] : U16.to_pua(n)).downcase.then { |x| U16.from_pua(x) }
    end

    def openapi_doc(es)
      paths = {}
      es.each do |e|
        method = (e['method'].nil? ? 'get' : e['method']).downcase
        body = %w[post put patch].include?(method)
        props = e['params'].to_h { |p| [pname(p), schema_of(p)] }
        path_params = U16.to_pua(S.pyfalsy?(e['path']) ? '' : e['path']).scan(/\{([^}]+)\}/).map do |(g)|
          { 'name' => U16.from_pua(g), 'in' => 'path', 'required' => true, 'schema' => { 'type' => 'string' } }
        end
        op = {}
        op['operationId'] = e['name'] if S.pyfalsy?(e['name']) == false
        op['summary'] = e['description'] if S.pyfalsy?(e['description']) == false
        query = body ? [] : e['params'].reject { |p| path_params.any? { |q| q['name'] == pname(p) } }.map { |p| { 'name' => pname(p), 'in' => 'query', 'schema' => schema_of(p) } }
        op['parameters'] = path_params + query
        if body && !e['params'].empty?
          op['requestBody'] = { 'content' => { 'application/json' => { 'schema' => { 'type' => 'object', 'properties' => props, 'required' => [] } } } }
        end
        (paths[e['path'].nil? ? 'undefined' : e['path']] ||= {})[method] = op
      end
      { 'openapi' => '3.0.3', 'info' => { 'title' => 'corpus', 'version' => '1' }, 'paths' => paths }
    end

    def type_word(spec)
      m = TYPE_RE.match(U16.to_pua(spec))
      m ? m[1] : 'string'
    end

    def graphql_sdl(es)
      q = []
      m = []
      es.each do |e|
        args = e['params'].empty? ? '' : "(#{e['params'].map { |p| "#{pname(p)}: #{GQL.fetch(type_word(p), 'String')}" }.join(', ')})"
        target = READ_FIRST.include?(first_word(e['name'])) || U16.to_pua(e['name']).match?(/\A[a-z]+s?\z/) ? q : m
        target << "  \"#{U16.from_pua(U16.to_pua(e['description']).gsub('"', "'"))}\"\n  #{e['name']}#{args}: String"
      end
      (q.empty? ? '' : "type Query {\n#{q.join("\n")}\n}\n") + (m.empty? ? '' : "type Mutation {\n#{m.join("\n")}\n}\n")
    end

    def proto_text(es)
      svcs = {}
      es.each { |e| (svcs[split(e['name'], '/')[0]] ||= []) << e }
      msgs = ['message Empty {}']
      out = []
      svcs.each do |s, lst|
        rpcs = []
        lst.each do |e|
          mname = split(e['name'], '/')[1]
          fields = e['params'].each_with_index.map { |p, i| "  #{PROTO.fetch(type_word(p), 'string')} #{pname(p)} = #{i + 1};" }.join("\n")
          msgs << "message #{mname}Request {\n#{fields}\n}"
          rpcs << "  rpc #{mname}(#{mname}Request) returns (Empty);"
        end
        out << "service #{s} {\n#{rpcs.join("\n")}\n}"
      end
      "syntax = \"proto3\";\npackage corpus;\n#{msgs.join("\n")}\n#{out.join("\n")}\n"
    end

    def async_doc(es)
      channels = es.to_h do |e|
        [e['name'], { 'publish' => { 'summary' => e['description'],
                                     'message' => { 'payload' => { 'type' => 'object', 'properties' => e['params'].to_h { |p| [pname(p), schema_of(p)] } } } } }]
      end
      { 'asyncapi' => '2.6.0', 'info' => { 'title' => 'corpus', 'version' => '1' }, 'channels' => channels }
    end

    def mcp_doc(es)
      es.map do |e|
        { 'name' => e['name'], 'description' => e['description'],
          'inputSchema' => { 'type' => 'object', 'properties' => e['params'].to_h { |p| [pname(p), schema_of(p)] } } }
      end
    end

    def key_of(e)
      return e['name'] unless e['kind'] == 'openapi'

      "#{(e['method'].nil? ? 'GET' : e['method']).upcase} #{J.js_str(e.fetch('path', UNDEF))}"
    end

    def def_key(d)
      b = d['bindings']
      b = {} if S.pyfalsy?(b)
      oa = b['openapi']
      gq = b['graphql']
      gr = b['grpc']
      aa = b['asyncapi']
      mc = b['mcp']
      cands = [
        !S.pyfalsy?(oa) && !S.pyfalsy?(oa['path']) ? "#{oa['method']} #{oa['path']}" : nil,
        S.pyfalsy?(oa) ? nil : oa['operationId'],
        S.pyfalsy?(mc) ? nil : mc['tool'],
        S.pyfalsy?(gq) ? nil : gq['field'],
        S.pyfalsy?(gr) ? nil : "#{split(gr['service'], '.')[-1]}/#{gr['method']}",
        S.pyfalsy?(aa) ? nil : aa['channel']
      ]
      cands.find { |x| !x.nil? } || ''
    end

    # Import every entry with the real importer of its kind: the drafts by entry id (an entry whose def was not emitted is absent).
    def import_corpus(entries)
      defs = {}
      todo = 0
      groups = {}
      entries.each { |e| (groups["#{e['kind']}|#{e['spec'].nil? ? '' : e['spec']}"] ||= []) << e }
      groups.each do |g, es|
        kind = g.split('|')[0]
        src = case kind
              when 'openapi' then openapi_doc(es)
              when 'mcp' then mcp_doc(es)
              when 'graphql' then graphql_sdl(es)
              when 'grpc' then proto_text(es)
              else async_doc(es)
              end
        r = P.import_actions(kind, src, { 'ns' => 'corpus', 'limits' => { 'max_ops' => 50_000, 'max_nodes' => 20_000_000, 'max_bytes' => 200_000_000 } })
        todo += r['todo'].length
        by_key = {}
        r['defs'].each { |d| by_key[def_key(d)] = d }
        es.each do |e|
          d = by_key[key_of(e)]
          defs[e['id']] = d if d
        end
      end
      { 'defs' => defs, 'todo' => todo }
    end

    # ---- scoring
    # Deterministic split of the real corpus by specification: rules are tuned on `tune` specs only; `holdout` specs are never looked at.
    def real_split(spec = nil)
      h = 2_166_136_261
      U16.to_pua(S.pyfalsy?(spec) ? '' : spec).each_codepoint do |o|
        # charCodeAt(0) of a code point: its first UTF-16 unit (a lone surrogate rides as a plane-15 stand-in)
        unit = if o >= 0xF0000 && o <= 0xF07FF then 0xD800 + (o - 0xF0000)
               elsif o <= 0xFFFF then o
               else 0xD800 + ((o - 0x10000) >> 10)
               end
        h = ((h ^ unit) * 16_777_619) & 0xFFFFFFFF
      end
      ((h >> 7) % 2).zero? ? 'tune' : 'holdout'
    end

    def source_of(e) = e['src'] == 'real' ? "real/#{real_split(e['spec'])}" : e['src']

    def stat(trait, rows, alpha)
      tp = fp = fn = 0
      rows.each do |actual, predicted|
        if actual && predicted then tp += 1
        elsif predicted then fp += 1
        elsif actual then fn += 1
        end
      end
      pos = tp + fn
      pred = tp + fp
      cp = AtlasPca::IntentClopper
      {
        'trait' => trait, 'positives' => pos, 'predicted' => pred, 'tp' => tp, 'fp' => fp, 'fn' => fn,
        'precision' => pred.zero? ? nil : tp.to_f / pred,
        'recall' => pos.zero? ? nil : tp.to_f / pos,
        'recall_lower' => pos.zero? ? nil : 1 - cp.clopper_pearson_upper(fn, pos, alpha),
        # the exact bound costs O(n * k) big-integer products: affordable for recall (few misses), not for precision over thousands of flags
        'precision_lower' => pred.zero? || pred > 600 ? nil : 1 - cp.clopper_pearson_upper(fp, pred, alpha)
      }
    end

    def strip_pca(t) = t.sub(/\Apca\./, '')

    def eval_suggest(entries, rules = nil, registry = nil, alpha = nil)
      rules = S.default_rules if S.pyfalsy?(rules)
      registry = A::CORE_REGISTRY if S.pyfalsy?(registry)
      alpha = 0.05 if alpha.nil?
      defs = import_corpus(entries)['defs']
      trait_names = S.u16sort(registry.keys.reject { |t| %w[pca.unreviewed pca.irreversible].include?(t) }.map { |t| strip_pca(t) })
      flagged = {}
      added = {}
      entries.each do |e|
        d = defs[e['id']]
        next unless d

        s = S.suggest_with_rules(d, rules, registry)
        sd = S.apply_suggestion(d, s, { 'rules' => { 'version' => rules['version'], 'digest' => '', 'fired' => s['fired'] } })
        flagged[e['id']] = A.closure(registry, A.hint_traits(sd)).reject { |t| t == 'pca.unreviewed' }.map { |t| strip_pca(t) }
        added[e['id']] = s['traits'].map { |t| strip_pca(t) }
      end
      score = lambda do |es, pred|
        stats = trait_names.map { |t| stat(t, es.map { |e| [e['labels'].include?(t), (pred[e['id']] || []).include?(t)] }, alpha) }
        stats.select { |s| s['positives'].positive? || s['predicted'].positive? }
      end
      srcs = entries.map { |e| source_of(e) }
      srcs << 'real' if entries.any? { |e| e['src'] == 'real' }
      by_source = {}
      S.u16sort(srcs.uniq).each do |s|
        es = entries.select { |e| s == 'real' ? e['src'] == 'real' : source_of(e) == s }
        by_source[s] = { 'entries' => es.length, 'flagged' => score.call(es, flagged) }
      end
      { 'alpha' => alpha, 'entries' => entries.length, 'mapped' => defs.length, 'rules_version' => rules['version'], 'flagged' => score.call(entries, flagged),
        'suggested' => score.call(entries, added), 'by_source' => by_source }
    end

    # Number.prototype.toFixed(1) as a percentage: the exact binary value, rounded half up.
    def pct(x)
      return '-' if x.nil?

      n = (((x * 100).to_r * 10) + Rational(1, 2)).floor
      "#{n / 10}.#{n % 10}%"
    end

    def render_eval_markdown(r)
      table = lambda do |stats|
        (['| trait | labeled | flagged | recall | recall lower bound | precision | missed | false alarms |', '|---|---:|---:|---:|---:|---:|---:|---:|'] +
          stats.map { |s| "| #{s['trait']} | #{s['positives']} | #{s['predicted']} | #{pct(s['recall'])} | #{pct(s['recall_lower'])} | #{pct(s['precision'])} | #{s['fn']} | #{s['fp']} |" }).join("\n")
      end
      lines = [
        "# Suggestion rules #{r['rules_version']}: measured on a labeled corpus",
        '',
        "#{r['entries']} labeled operations (#{r['mapped']} imported). Lower bounds are one-sided exact Clopper-Pearson at alpha = #{AtlasPca::Predicates.js_number_string(r['alpha'])}.",
        'These are heuristic numbers on a reviewed corpus. They are not a safety guarantee: an unreviewed action is always held at the most restrictive floor.',
        '',
        '## What a reviewer is shown (importer facts plus suggestions)', '', table.call(r['flagged']), '',
        '## What the suggestion rules added', '', table.call(r['suggested']), ''
      ]
      r['by_source'].each { |s, v| lines += ["## Source: #{s} (#{v['entries']} operations)", '', table.call(v['flagged']), ''] }
      lines.join("\n")
    end

    # Empty when the report meets the floors; else one line per failure.
    def floor_failures(r, f)
      out = []
      real = r['by_source']['real/holdout']
      if real.nil? || real['entries'] < f['real']['min_entries']
        out << "the real-spec hold-out has #{real ? real['entries'] : 0} operations, fewer than the required #{f['real']['min_entries']}"
      end
      out << "#{r['entries'] - r['mapped']} corpus operations were not imported" if r['mapped'] < r['entries']
      f['real']['recall_lower'].each do |t, floor|
        s = real ? real['flagged'].find { |x| x['trait'] == t } : nil
        need = f['real']['min_positives'].fetch(t, 0)
        if s.nil? || s['positives'] < need
          out << "#{t}: #{s ? s['positives'] : 0} real labeled positives, fewer than the #{need} the floor needs"
        elsif s['recall_lower'].nil? || s['recall_lower'] < floor
          out << "#{t}: hold-out recall lower bound #{pct(s['recall_lower'])} is below the recorded floor #{pct(floor)}"
        end
      end
      syn = r['by_source']['syn']
      f['regression']['recall_lower'].each do |t, floor|
        s = syn ? syn['flagged'].find { |x| x['trait'] == t } : nil
        if s.nil? || s['recall_lower'].nil? || s['recall_lower'] < floor
          out << "#{t}: regression-set recall lower bound #{pct(s ? s['recall_lower'] : nil)} is below #{pct(floor)}"
        end
      end
      out
    end
  end
end
