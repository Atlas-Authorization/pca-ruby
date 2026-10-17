# frozen_string_literal: true

# Corpus loader + characterization snapshot for mutation testing (see tools/pca-audit/ruby-mutate).
# The conformance files pin only allow/checks; the snapshot additionally pins the diagnostic `reason`, the strict-JSON
# rejection message and the canonical forms, so every observable output is under test.
#   ruby -Ilib sdks/ruby-pca/test/support/corpus.rb write sdks/ruby-pca/test-data/reasons.tsv.gz
require_relative '../../lib/atlas_pca'
require 'zlib'
require 'json'

module Corpus
  DIR = File.expand_path('../../conformance', __dir__)
  SNAP = File.expand_path('../../test-data/reasons.tsv.gz', __dir__)

  module_function

  def core
    @core ||= AtlasPca.parse_json(File.read(File.join(DIR, 'vectors.json'), encoding: 'UTF-8'), loose: true)
  end

  def adv
    @adv ||= begin
      txt = Zlib::GzipReader.open(File.join(DIR, 'vectors-adversarial.json.gz'), &:read).force_encoding('UTF-8')
      AtlasPca.parse_json(txt, loose: true)
    end
  end

  def esc(s)
    return '<nil>' if s.nil?

    s.to_s.each_char.map do |c|
      case c
      when "\\" then '\\\\'
      when "\n" then '\\n'
      when "\t" then '\\t'
      when "\r" then '\\r'
      else c.ord < 0x20 || !c.valid_encoding? ? format('\\u%04x', c.ord) : c
      end
    end.join
  end

  # Intent Layer M2: `intent_policy_json` (raw JSON TEXT, parsed with the platform parser) wins over `intent_policy`.
  def intent_policy(ctx)
    ctx.key?('intent_policy_json') ? AtlasPca.parse_intent_policy_json(ctx['intent_policy_json']) : ctx['intent_policy']
  end

  # Intent Layer v2: `intent_v2` (the verifier state of a v2 vector or fuzz input; a JSON object, or its JSON text).
  def intent_v2(ctx)
    v = ctx['intent_v2']
    v.is_a?(String) ? JSON.parse(v) : v
  end

  def verify_one(v)
    ctx = v['context']
    input = v.key?('pcactn_json') ? v['pcactn_json'] : v['pcactn']
    AtlasPca.verify_pcactn(input, v['grant'], now: ctx['now'], audience: ctx['aud'], allowed_suites: ctx['allowed_suites'],
                                              intent_policy: intent_policy(ctx), intent_v2: intent_v2(ctx))
  end

  def parse_outcome(input, **opt)
    AtlasPca.canonicalize(AtlasPca.parse_json(input, **opt))
  rescue AtlasPca::Malformed => e
    "malformed:#{esc(e.message)}"
  rescue StandardError, SystemStackError => e
    "#{e.class}:#{esc(e.message)}"
  end

  # Ordered [[key, value], ...] for every vector i with i % step == k, plus primitives when k == 0.
  def compute(doc, tag, k, step)
    out = []
    doc['vectors'].each_with_index do |v, i|
      next unless (i % step) == k

      val = begin
        g = verify_one(v)
        "#{g.allow}|#{g.checks.map { |ck, cv| "#{ck}=#{cv}" }.join(',')}|#{esc(g.reason)}"
      rescue StandardError, SystemStackError => e
        "THROW:#{e.class}:#{esc(e.message)}"
      end
      out << ["#{tag}:v:#{v['name']}", val]
    end
    prim = doc['primitives']
    if k.zero? && prim
      (prim['json_parse'] || []).each_with_index do |j, n|
        inp = j['input']
        strict = parse_outcome(inp, any_top: true)
        lenient = parse_outcome(inp, loose: true, any_top: true)
        out << ["#{tag}:jp:#{n}:#{esc(inp[0, 80])}", "#{strict}|len=#{lenient}"]
      end
      (prim['canonical'] || []).each_with_index do |c, n|
        s = begin
          "#{AtlasPca.canonicalize(c['value'])}|#{AtlasPca.hash_canonical(c['value'])}"
        rescue StandardError => e
          "ERR:#{e.class}:#{esc(e.message)}"
        end
        out << ["#{tag}:cn:#{n}", esc(s)]
      end
      # exact verify_chain reasons / verdicts over every chain-shaped table (conformance pins only booleans here)
      safe = lambda do |&blk|
        blk.call
      rescue StandardError, SystemStackError => e
        "THROW:#{e.class}"
      end
      (prim['chain_pin'] || []).each do |v|
        out << ["#{tag}:cp:#{v['name']}", esc(safe.call do
          rs, ok = AtlasPca.verify_chain(v['chain'], v['expected_root_issuer'], !v['expected_root_issuer'].nil?, v['allowed_suites'], v['pq_pins'], v['trusted_root'])
          "#{ok}|#{rs}"
        end)]
      end
      (prim['malformed'] || []).each do |m|
        inp = m['input']
        out << ["#{tag}:mf:#{m['name']}", esc(safe.call do
          case m['api']
          when 'chain' then AtlasPca.verify_chain(inp['chain'], inp['expected_root_issuer'], true).reverse.join('|')
          when 'threshold_share' then AtlasPca.verify_threshold_share(inp).inspect
          when 'pcactn_json'
            g = AtlasPca.verify_pcactn(inp['text'], inp['grant'], now: inp['now'], audience: inp['aud'])
            "#{g.allow}|#{g.checks.map { |ck, cv| "#{ck}=#{cv}" }.join(',')}|#{g.reason}"
          end
        end)]
      end
      (prim['depth'] || []).each do |d|
        inp = expand(d['input'], d['expand'])
        out << ["#{tag}:dp:#{d['name']}", esc(safe.call do
          case d['api']
          when 'chain' then AtlasPca.verify_chain(inp['chain'], inp['expected_root_issuer'], !inp['expected_root_issuer'].nil?).reverse.join('|')
          when 'threshold_share' then AtlasPca.verify_threshold_share(inp).inspect
          when 'pcactn_json'
            g = AtlasPca.verify_pcactn(inp['text'], inp['grant'], now: inp['now'], audience: inp['aud'])
            "#{g.allow}|#{g.checks.map { |ck, cv| "#{ck}=#{cv}" }.join(',')}|#{g.reason}"
          when 'json_parse' then parse_outcome(inp['text'], any_top: true)[0, 200]
          end
        end)]
      end
      (prim['b64u'] || []).each_with_index do |b, n|
        r = AtlasPca.b64d(b['input'], b['len'])
        out << ["#{tag}:b6:#{n}", r.nil? ? 'nil' : r.unpack1('H*')]
      end
    end
    out
  end

  # the runtime capability manifest, read once from the unmutated library at load (conformance.rb's SUPPORTED_SIG_SUITES)
  SUPPORTED = AtlasPca.supported_suites.freeze

  def nest(levels, leaf)
    v = leaf
    levels.times { v = [v] }
    v
  end

  # primitives.depth `expand` (see conformance.rb): built iteratively on a deep copy-free path (the input is shallow).
  def expand(input, ex)
    return input if ex.nil?
    if input.is_a?(Hash) && input['text'].is_a?(String) && input['text'].include?(ex['marker'])
      return input.merge('text' => input['text'].sub(ex['marker']) { ('[' * ex['levels']) + AtlasPca.canonicalize(ex['leaf']) + (']' * ex['levels']) })
    end
    copy = Marshal.load(Marshal.dump(input))
    deep = nest(ex['levels'], ex['leaf'])
    stack = [copy]
    until stack.empty?
      node = stack.pop
      if node.is_a?(Hash)
        node.each { |k, x| x == ex['marker'] ? (node[k] = deep) : stack.push(x) }
      elsif node.is_a?(Array)
        node.each_index { |i| node[i] == ex['marker'] ? (node[i] = deep) : stack.push(node[i]) }
      end
    end
    copy
  end

  # Every non-vector conformance table of `doc` (what conformance.rb checks besides the vectors): threshold_share,
  # pq_artifact, merkle (+ every proof), params_digest, chain_pin (verdict + pin-refusal reason), threshold_set,
  # signer_set_hash, malformed (clean deny), depth. Returns the names of the failing checks ([] == all pass).
  def prim_failures(doc)
    p = doc['primitives'] || {}
    bad = []
    chk = lambda do |name, &blk|
      ok = begin
        blk.call
      rescue Exception # rubocop:disable Lint/RescueException
        false
      end
      bad << name unless ok
    end
    (p['threshold_share'] || []).each { |s| chk.call("ts:#{s['name']}") { AtlasPca.verify_threshold_share(s) == (s.key?('valid') ? s['valid'] : true) } }
    (p['pq_artifact'] || []).each do |a|
      alg = a['alg'].is_a?(String) ? a['alg'] : 'ed25519'
      next unless SUPPORTED.include?(alg)

      chk.call("pa:#{a['artifact']}/#{alg}") { AtlasPca.verify_pq_artifact(a) == (a.key?('valid') ? a['valid'] : true) }
    end
    (p['merkle'] || []).each_with_index do |m, n|
      chk.call("mk:#{n}") do
        root = AtlasPca.merkle_root(m['leaves'])
        root == m['root'] && m['proofs'].each_with_index.all? { |pr, i| AtlasPca.verify_inclusion(root, pr, m['leaves'][i]) }
      end
    end
    chk.call('params_digest') { AtlasPca.params_digest(nil) == p['params_digest_empty'] && AtlasPca.params_digest == p['params_digest_empty'] }
    (p['chain_pin'] || []).each do |v|
      chk.call("cp:#{v['name']}") do
        rs, ok = AtlasPca.verify_chain(v['chain'], v['expected_root_issuer'], !v['expected_root_issuer'].nil?, v['allowed_suites'], v['pq_pins'], v['trusted_root'])
        reason = v['expect']['reason'].to_s
        ok == v['expect']['ok'] && (!reason.start_with?('hop 0: root suite') || rs == reason)
      end
    end
    (p['threshold_set'] || []).each do |e|
      next if e['requires'] && !SUPPORTED.include?(e['requires'])

      chk.call("tset:#{e['name']}") { AtlasPca.verify_threshold_share(e) == e['valid'] }
    end
    (p['signer_set_hash'] || []).each { |e| chk.call("ssh:#{e['name']}") { AtlasPca.b64e(AtlasPca.signer_set_hash(e['signer_set'])) == e['hash'] } }
    (p['malformed'] || []).each do |m|
      inp = m['input']
      chk.call("mf:#{m['name']}") do
        case m['api']
        when 'chain' then AtlasPca.verify_chain(inp['chain'], inp['expected_root_issuer'], true).last == false
        when 'threshold_share' then AtlasPca.verify_threshold_share(inp) == false
        when 'pcactn_json' then AtlasPca.verify_pcactn(inp['text'], inp['grant'], now: inp['now'], audience: inp['aud']).allow == false
        end
      end
    end
    v2_prim_checks(p, chk)
    # Intent Layer v2 `requires_suite` vectors whose suite this runtime does not implement (not in supported_suites: absent
    # from the dispatch, or its backend unavailable here): a deny, with `unsupported_suite` in the reason when a v2 check
    # fails first (implemented ones are compared as usual).
    v2 = %w[schema intent_session layers accumulators map facts provenance classes]
    (doc['vectors'] || []).each do |v|
      rs = v['requires_suite']
      next unless rs.is_a?(String) && !SUPPORTED.include?(rs)

      chk.call("v2suite:#{v['name']}") do
        g = verify_one(v)
        first = g.checks.find { |_, ok| !ok }&.first
        g.allow == false && (!v2.include?(first) || g.reason.to_s.include?('unsupported_suite'))
      end
    end
    (p['depth'] || []).each do |d|
      chk.call("dp:#{d['name']}") do
        inp = expand(d['input'], d['expand'])
        got = case d['api']
              when 'chain' then AtlasPca.verify_chain(inp['chain'], inp['expected_root_issuer'], !inp['expected_root_issuer'].nil?).last
              when 'threshold_share' then AtlasPca.verify_threshold_share(inp)
              when 'pcactn_json' then AtlasPca.verify_pcactn(inp['text'], inp['grant'], now: inp['now'], audience: inp['aud']).allow
              when 'json_parse'
                begin
                  AtlasPca.parse_json(inp['text'], any_top: true)
                  true
                rescue AtlasPca::Malformed
                  false
                end
              end
        got == d['valid']
      end
    end
    bad
  end

  # The Intent Layer v2 primitive tables (as conformance.rb compares them; reasons never compared). A table absent from the
  # corpus, or a function this build lacks, contributes nothing.
  def v2_prim_checks(p, chk)
    run = lambda do |name, fn, &blk|
      rows = p[name]
      next unless rows.is_a?(Array) && AtlasPca.respond_to?(fn)

      # `input_json` (raw text; a bare -0 stays negative zero) takes precedence over `input` (README "Raw JSON text members").
      rows.each do |e|
        chk.call("#{name}:#{e['name']}") do
          blk.call(e.key?('input_json') ? AtlasPca.parse_json_text(e['input_json']) : e['input'], e['expect'])
        end
      end
    end
    run.call('intent_schema', :verify_action_schema) do |i, x|
      c = AtlasPca.conform_action(i['schema'], i['verb'], i['params'])
      AtlasPca.verify_action_schema(i['schema'], i['keys'])['ok'] == x['sig'] &&
        (!x.key?('digest') || AtlasPca.action_schema_digest(i['schema']) == x['digest']) &&
        c['ok'] == x['conform']['ok'] && c['code'] == x['conform']['code'] && c['path'] == x['conform']['path']
    end
    run.call('intent_revocation', :intent_revocation_primitive) { |i, x| AtlasPca.intent_revocation_primitive(i)['ok'] == x['ok'] }
    run.call('intent_world', :decide_intent_world) do |i, x|
      g = AtlasPca.decide_intent_world(i)
      g['ok'] == x['ok'] && (!x['ok'] || (g['world'] == x['world'] && g['single_source'] == x['single_source']))
    end
    run.call('intent_provenance', :decide_param_provenance) do |i, x|
      g = AtlasPca.decide_param_provenance(i)
      g['outcome'] == x['outcome'] && (x['outcome'] == 'deny' || (g['labels'] == x['labels'] && g['classes'] == x['classes'])) &&
        (x['outcome'] != 'question' || g['friction'] == x['friction'])
    end
    run.call('intent_classifier', :decide_classifier_dimensions) do |i, x|
      g = AtlasPca.decide_classifier_dimensions(i)
      g['ok'] == x['ok'] && (!x['ok'] || g['classes'] == x['classes'])
    end
    run.call('intent_wb_active', :intent_wb_active) do |i, x|
      g = AtlasPca.intent_wb_active(i)
      %w[facts provenance classes].all? { |k| g[k] == x[k] }
    end
    run.call('intent_map_commit', :map_commit_of_leaves) { |i, x| AtlasPca.map_commit_of_leaves(i['leaves']) == x['map_commit'] }
    run.call('intent_map', :intent_map_primitive) do |i, x|
      g = AtlasPca.intent_map_primitive(i)
      g['ok'] == x['ok'] && (!x['ok'] || (g['cell'] == x['cell'] && g['p_ppm'] == x['p_ppm']))
    end
    run.call('intent_read_purpose', :decide_read_purpose) do |i, x|
      g = AtlasPca.decide_read_purpose(i)
      %w[outcome minimise uncovered].all? { |k| g[k] == x[k] }
    end
  end

  INPUTS = File.expand_path('../../../../tools/pca-audit/native-mutation/inputs.jsonl.gz', __dir__)

  def inputs
    @inputs ||= Zlib::GzipReader.open(INPUTS) { |g| g.read.force_encoding('UTF-8') }.each_line.map { |l| JSON.parse(l) }
  end

  # Pinned outputs over the shared structural / parse fuzz inputs, entries i % step == k.
  def compute_inputs(k, step)
    out = []
    inputs.each_with_index do |c, i|
      next unless (i % step) == k

      raw = c['raw']
      val = if c['kind'] == 'verify'
              begin
                grant = AtlasPca.parse_json(c['grant'], loose: true)
                g = AtlasPca.verify_pcactn(raw, grant, now: c['now'], audience: c['aud'], allowed_suites: c['allowed_suites'],
                                                     intent_policy: intent_policy(c), intent_v2: intent_v2(c))
                "#{g.allow}|#{g.checks.map { |ck, cv| "#{ck}=#{cv}" }.join(',')}|#{esc(g.reason)}"
              rescue StandardError, SystemStackError => e
                "THROW:#{e.class}:#{esc(e.message)}"
              end
            else
              "#{parse_outcome(raw, any_top: true)}|len=#{parse_outcome(raw, loose: true, any_top: true)}"
            end
      out << ["in:#{c['id']}", val.length > 600 ? val[0, 600] + "##{val.bytesize}" : val]
    end
    out
  end

  def snapshot
    @snapshot ||= Zlib::GzipReader.open(SNAP) { |g| g.read.force_encoding('UTF-8') }.each_line.to_h do |l|
      key, val = l.chomp.split("\t", 2)
      [key, val]
    end
  end
end

if $PROGRAM_NAME == __FILE__ && ARGV[0] == 'write'
  lines = Corpus.compute(Corpus.core, 'core', 0, 1) + Corpus.compute(Corpus.adv, 'adv', 0, 1) + Corpus.compute_inputs(0, 1)
  Zlib::GzipWriter.open(ARGV[1]) do |gz|
    gz.mtime = 0
    lines.each { |k, v| gz.write("#{Corpus.esc(k)}\t#{v}\n") }
  end
  puts "wrote #{lines.length} lines"
end
