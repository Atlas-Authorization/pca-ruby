# frozen_string_literal: true
require 'json'
require 'zlib'
# The k05 differential oracles (PCA 0.5): test-data/k05-<module>.json.gz = tools/pca-audit/k05-oracles/<module>-oracle.mts, one
# case per line {fn, name, args, out}; bytes are {"$bytes": b64url}, a TS throw is {"$throws": message, code?}. Each b*_k05_*
# file maps every fn to the Ruby twin and registers ONE kill test per fn. A heavy oracle runs only when MUT_FILE (mutate.rb) is
# a lib file it bears on; under run_kill.rb (MUT_FILE unset) every module runs in full, one streaming pass per module.
module MutationKill
  module K05
    module_function

    # A line the C JSON parser would read differently from the platform reading (DiffUtil.parse): -0, a lone-surrogate escape,
    # an integer beyond 2^53. Those lines (few) go through the platform parser; the rest through JSON.parse (fast).
    SLOW = /(?<![\w.])-0(?![\w.])|\\u[dD][89a-fA-F]|\d{16}/

    CACHE = {} # rubocop:disable Style/MutableConstant
    PQ_RE = /ml-dsa|slh-dsa|fn-dsa|less-cat|"pq_|hybrid/

    def pq_host?
      @pq_host = AtlasPca.supported_suites.include?('ml-dsa-65') if @pq_host.nil?
      @pq_host
    end

    def parse_line(l) = l.match?(SLOW) ? DiffUtil.parse(l) : JSON.parse(l)

    def stream(file)
      Zlib::GzipReader.open(File.join(DiffUtil::DATA, file)) do |gz|
        gz.each_line do |l|
          next unless l.start_with?('{"fn"')

          l = l.chomp.chomp(',').force_encoding('UTF-8')
          c = parse_line(l)
          # a host without the PQ suites (OpenSSL < 3.5): a case whose inputs name one cannot agree (the refusal is by design)
          c['$pq'] = true if !pq_host? && l.match?(PQ_RE)
          yield c
        end
      end
    end

    # Mutation mode: the oracle is parsed ONCE in the parent (registry load), grouped by fn, so a mutant child only compares.
    def preload(file, libs)
      f = ENV['MUT_FILE']
      return if f.nil? || f.empty? || !libs.include?(f)

      g = Hash.new { |h, k| h[k] = [] }
      stream(file) { |c| g[c['fn']] << c }
      CACHE[file] = g
    end

    # ---- values -----------------------------------------------------------------------------------------------------------
    # oracle JSON -> Ruby argument: {$bytes} -> binary String
    def dec(x)
      case x
      when Hash
        return AtlasPca.b64d(x['$bytes']) if x.length == 1 && x.key?('$bytes')

        x.transform_values { |v| dec(v) }
      when Array then x.map { |v| dec(v) }
      else x
      end
    end

    # comparable text: member order ignored (canonical-JSON equality), numbers by value, binary strings as {$bytes}
    def canon(v)
      case v
      when nil then 'null'
      when true, false then v.to_s
      when Symbol then canon(v.to_s)
      when String
        if v.encoding == Encoding::BINARY && !v.ascii_only?
          canon({ '$bytes' => AtlasPca.b64e(v) })
        else
          s = v.dup.force_encoding('UTF-8')
          s.valid_encoding? ? s.inspect : "!#{s.b.inspect}"
        end
      when Hash then '{' + v.map { |k, x| [canon(k.to_s), canon(x)] }.sort.map { |k, x| "#{k}:#{x}" }.join(',') + '}'
      when Array then '[' + v.map { |x| canon(x) }.join(',') + ']'
      when Integer then v.to_s
      when Float
        if v.finite? && v == v.floor && v.abs < 1e300 then v.zero? && (1.0 / v).negative? ? '-0' : v.to_i.to_s
        else v.to_s
        end
      else "<#{v.class}>"
      end
    end

    def strkeys(x)
      case x
      when Hash then x.to_h { |k, v| [k.is_a?(Symbol) ? k.to_s : k, strkeys(v)] }
      when Array then x.map { |v| strkeys(v) }
      else x
      end
    end

    def throws?(out) = out.is_a?(Hash) && out.key?('$throws')

    # ---- running ----------------------------------------------------------------------------------------------------------
    Raised = Struct.new(:error)

    # Compare one case. `cmp` (got, out, case) -> nil when equal, else a mismatch text. A Ruby raise is Raised(e): it matches a
    # {$throws} (and its code when the oracle has one and the error carries a `code`).
    def check(spec, c)
      return nil if c['$pq'] || (spec.skip && spec.skip.call(c))

      got = begin
        spec.fns.fetch(c['fn']).call(dec(c['args']), c)
      rescue StandardError, SystemStackError => e
        Raised.new(e)
      end
      out = c['out']
      if throws?(out)
        return "want throw #{out['$throws'][0, 80].inspect}, got #{canon(got)[0, 200]}" unless got.is_a?(Raised)

        code = out['code']
        have = got.error.respond_to?(:code) ? got.error.code : nil
        return nil if code.nil? || have.to_s == code

        return "want code #{code}, got #{have.inspect} (#{got.error.message[0, 80]})"
      end
      return "raised #{got.error.class}: #{got.error.message[0, 120]}" if got.is_a?(Raised)

      (spec.cmp[c['fn']] || spec.cmp[:default]).call(fail_closed(got), fail_closed(out), c)
    end

    # A caught runtime error's text after "(fail closed): " is the engine's own message (a JS TypeError vs a Ruby one): the
    # decision and the marker must agree, the tail is not compared.
    FC = '(fail closed): '
    def fail_closed(v)
      case v
      when String then (i = v.b.index(FC.b)) ? v.b[0, i + FC.bytesize].force_encoding(v.encoding) : v
      when Hash then v.to_h { |k, x| [k, fail_closed(x)] }
      when Array then v.map { |x| fail_closed(x) }
      else v
      end
    end

    EXACT = lambda do |got, out, _c|
      g = canon(got).b
      w = canon(out).b
      return nil if g == w

      at = [(0...[g.length, w.length].min).find { |i| g[i] != w[i] } || [g.length, w.length].min, 80].max - 80 # show the first difference
      "got #{at.zero? ? '' : '...'}#{g[at, 300]}\n    want #{at.zero? ? '' : '...'}#{w[at, 300]}"
    end
    # Engine-specific message tails. `cmp: "code"`: the native's text must carry the same `<code>:` prefix (the TS tail is a JS
    # TypeError text). `textPrefix: P`: the same decision, its message (the string, or the result's `reason`) STARTS WITH P.
    PREFIX = lambda do |got, out, c|
      got = strkeys(got)
      if c['cmp'] == 'code' && got.is_a?(String) && out.is_a?(String)
        next got.split(':', 2)[0] == out.split(':', 2)[0] ? nil : "code of #{got.inspect} != code of #{out.inspect}"
      end
      if (pre = c['textPrefix']).is_a?(String)
        next(got.start_with?(pre) ? nil : "#{got.inspect} does not start with #{pre.inspect}") if got.is_a?(String) && out.is_a?(String)
        if got.is_a?(Hash) && out.is_a?(Hash) && got['reason'].is_a?(String) && out['reason'].is_a?(String) && got['reason'].start_with?(pre)
          got = got.merge('reason' => out['reason'])
        end
      end
      EXACT.call(got, out, c)
    end

    Spec = Struct.new(:file, :libs, :fns, :cmp, :skip, :title, keyword_init: true)

    # first mismatch per fn (mutation mode stops at the first), or every fn's verdict in one streaming pass (run_kill)
    def verdicts(spec)
      @verdicts ||= {}
      @verdicts[spec.file] ||= begin
        bad = Hash.new { |h, k| h[k] = [] }
        n = Hash.new(0)
        stream(spec.file) do |c|
          next if DiffUtil.pq_case?(c['name']) || c['fn'].end_with?('@suspect')

          n[c['fn']] += 1
          m = check(spec, c)
          bad[c['fn']] << "#{c['name']}: #{m}" if m
        end
        { bad: bad, n: n }
      end
    end

    def first_bad(spec, fn)
      if (g = CACHE[spec.file])
        g[fn].each do |c|
          next if DiffUtil.pq_case?(c['name'])

          m = check(spec, c)
          return "#{c['name']}: #{m}" if m
        end
        return nil
      end
      v = verdicts(spec)
      b = v[:bad][fn]
      return nil if b.empty?

      "#{b.length}/#{v[:n][fn]} mismatches; first #{[b.length, 12].min}:\n  " + b.first(12).join("\n  ")
    end

    # @suspect cases (TS behaviour the generator flags as questionable): reported, never failed
    def report_suspects(spec)
      return if ENV['MUT_FILE'] && !ENV['MUT_FILE'].empty?

      bad = []
      stream(spec.file) do |c|
        next unless c['fn'].end_with?('@suspect')

        m = check(spec, c.merge('fn' => c['fn'].delete_suffix('@suspect')))
        bad << c['name'] if m
      end
      warn "  k05 #{spec.title}: #{bad.length} @suspect case(s) differ (report only): #{bad.first(5).join(' | ')}" unless bad.empty?
    end

    def register(spec, fn_names)
      preload(spec.file, spec.libs)
      fn_names.each do |fn|
        MutationKill.t("k05 #{spec.title} differential (TS oracle): #{fn}") do
          next true if DiffUtil.skip?(*spec.libs)

          bad = first_bad(spec, fn)
          warn "k05 #{spec.title} #{fn}: #{bad}" if bad && !ENV['MUT_FILE']
          bad.nil?
        end
      end
    end
  end
end
