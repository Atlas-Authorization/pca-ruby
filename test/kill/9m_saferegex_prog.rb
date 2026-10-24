# frozen_string_literal: true
require 'zlib'
require 'digest'
# The linear-time regex engine (safe_regex.rb) and the safe-source guard (predicates.rb), PROGRAM level: test-data/
# k042-saferegex.txt.gz = tools/pca-audit/java-mutate/k042-saferegex-oracle.mjs (the Go, Rust, PHP, Java and Kotlin suites run the
# same file): every pattern of the corpus must compile to the EXACT NFA program of the TS reference (instruction for
# instruction) or be refused alike, get the same is_safe_regex_source verdict, and full-match every recorded subject with the
# same true / false / budget-refused answer. P lines: `P <pattern> <safe 0|1> <program|N>`, M lines: `M <subject> <T|F|N>` for
# the preceding P; strings are the hex of their UTF-16 code units ('-' = ""). First mismatch of a group ends it.
module MutationKill
  module SafeRegexProg
    module_function
    FILE = File.expand_path('../../test-data/k042-saferegex.txt.gz', __dir__)
    GROUPS = 24
    FILES = %w[safe_regex.rb predicates.rb].freeze

    # [[pattern_hex, safe, program_text, [[subject_hex, result]...]]...], read once (the registry is loaded by the unmutated parent)
    def records
      @records ||= begin
        out = []
        Zlib::GzipReader.open(FILE) do |gz|
          gz.each_line do |ln|
            f = ln.chomp.split(' ')
            if f[0] == 'P' then out << [f[1], f[2] == '1', f[3], []]
            else out.last[3] << [f[1], f[2]]
            end
          end
        end
        out
      end
    end

    # a Ruby String holding these UTF-16 code units, as (generalized) UTF-8: a valid pair is one astral character, a lone
    # surrogate keeps its own 3-byte form (WTF-8), exactly what the library's `units` reads back
    def str(hex)
      return +'' if hex == '-'

      u = hex.scan(/.{4}/).map { |h| h.to_i(16) }
      out = +''.b
      i = 0
      while i < u.length
        c = u[i]
        if c.between?(0xd800, 0xdbff) && (n = u[i + 1]) && n.between?(0xdc00, 0xdfff)
          c = 0x10000 + ((c - 0xd800) << 10) + (n - 0xdc00)
          i += 1
        end
        out << if c < 0x80 then [c].pack('C')
               elsif c < 0x800 then [0xc0 | (c >> 6), 0x80 | (c & 0x3f)].pack('C*')
               elsif c < 0x10000 then [0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)].pack('C*')
               else [0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)].pack('C*')
               end
        i += 1
      end
      out.force_encoding('UTF-8')
    end

    def dump(prog)
      s = prog.map do |op, x, y, set|
        head = "#{op},#{x},#{y},"
        if set.nil? then head + '-,-'
        else
          rs = set.ranges.empty? ? 'E' : set.ranges.map { |a, b| "#{a}-#{b}" }.join(':')
          "#{head}#{set.negated ? 1 : 0},#{rs}"
        end
      end.join(';')
      s.length > 1000 ? "H#{Digest::SHA256.hexdigest(s)}" : s
    end

    def first_bad(g)
      records.each_with_index do |(ph, safe, prog, subs), i|
        next unless i % GROUPS == g
        pat = str(ph)
        c = AtlasPca.compile_safe_regex(pat)
        got = c.nil? ? 'N' : dump(c.program)
        return "compile #{ph[0, 80]}: want #{prog[0, 120]} got #{got[0, 120]}" unless got == prog
        gs = AtlasPca.is_safe_regex_source(pat)
        return "safe #{ph[0, 80]}: want #{safe} got #{gs}" unless gs == safe
        subs.each do |sh, want|
          r = AtlasPca.safe_regex_full_match(pat, str(sh))
          got = r.nil? ? 'N' : (r ? 'T' : 'F')
          return "run #{ph[0, 80]} on #{sh[0, 40]}: want #{want} got #{got}" unless got == want
        end
      end
      nil
    end

    records # read once, at registry load, by the unmutated parent
  end

  SafeRegexProg::GROUPS.times do |g|
    t("regex program differential (TS oracle): part #{g + 1}") do
      next true if DiffUtil.skip?(*SafeRegexProg::FILES)
      bad = SafeRegexProg.first_bad(g)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
