# frozen_string_literal: true
# The linear-time regex engine (safe_regex.rb) and the safe-source guard (predicates.rb) differential kills against the TS
# reference (safe-regex.ts, predicates.ts, regex-budget.ts): test-data/killRegex.json.gz is the shared, language-neutral oracle
# (tools/pca-audit/kotlin-mutate/killRegex-oracle-gen.mjs; the Kotlin, Python and PHP suites run it): full-match results (true /
# false / refused) of a pattern corpus crossed with boundary subjects, compiled program sizes, the step boundary, the safe-source
# guard and per-document budget sequences. Engine-only probes nested deeper than any protocol entry point admits (every one caps
# a regex at 200 units, so <= 100 groups) are skipped: they refuse on stack exhaustion at a language-specific depth.
module MutationKill
  module RegexDiff
    module_function
    REACHABLE = 100
    FILES = %w[safe_regex.rb predicates.rb].freeze
    def data = (@data ||= DiffUtil.load('killRegex.json.gz'))

    def depth(p)
      d = m = 0
      p.each_char do |ch|
        d += 1 if ch == '('
        d -= 1 if ch == ')'
        m = d if d > m
      end
      m
    end

    def deep?(p) = depth(p) > REACHABLE
    def want(r) = r == 'n' ? nil : r.to_s == '1'

    def check_fm
      data['fm'].each do |p, subs, rs|
        next if deep?(p)
        subs.each_with_index do |s, i|
          w = want(rs[i])
          got = AtlasPca.safe_regex_full_match(p, s)
          return "fm /#{p}/ on #{s.inspect}: want #{w.inspect} got #{got.inspect}" unless got == w
        end
      end
      nil
    end

    def check_size
      data['size'].each do |p, w|
        next if deep?(p)
        c = AtlasPca.compile_safe_regex(p)
        ok = w.negative? ? c.nil? : (!c.nil? && c.program.length == w)
        return "size /#{p}/: want #{w} got #{c.nil? ? 'nil' : c.program.length}" unless ok
      end
      nil
    end

    def check_steps
      return 'limits' unless [AtlasPca::SafeRegex::MAX_NFA_INSTRUCTIONS, AtlasPca::SafeRegex::MAX_REPEAT, AtlasPca::SafeRegex::MAX_MATCH_STEPS] == [4096, 64, 2_000_000]
      data['steps'].each do |p, n, r|
        next if deep?(p)
        w = r.negative? ? nil : r == 1
        got = AtlasPca.safe_regex_full_match(p, 'a' * n)
        return "steps /#{p[0, 20]}/ n=#{n}: want #{w.inspect} got #{got.inspect}" unless got == w
      end
      nil
    end

    def check_safe
      data['safe'].each do |p, w|
        next if deep?(p)
        got = AtlasPca.is_safe_regex_source(p)
        return "safe /#{p}/: want #{w} got #{got}" unless got == w
      end
      nil
    end

    def check_budgets
      data['budgets'].each_with_index do |b, k|
        budget = AtlasPca::RegexBudget.new
        b['ops'].each_with_index do |(src, n), i|
          got = budget.charge(src, n)
          return "budget ##{k} op #{i}: want #{b['res'][i]} got #{got}" unless got == b['res'][i]
        end
        got = %i[@evaluations @chars @steps @refusals].map { |v| budget.instance_variable_get(v) }
        return "budget ##{k} final: want #{b['fin']} got #{got}" unless got == b['fin']
      end
      nil
    end
  end

  %w[fm size steps safe budgets].each do |kind|
    t("regex engine differential (TS oracle): #{kind}") do
      next true if DiffUtil.skip?(*RegexDiff::FILES)
      bad = RegexDiff.send(:"check_#{kind}")
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
