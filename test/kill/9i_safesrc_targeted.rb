# frozen_string_literal: true
# Exact kills for the linear-time-safe regex source guard (predicates.rb safe_source? / guard_brace via
# AtlasPca.is_safe_regex_source): every branch of the scanner (escapes, classes, groups, alternation, quantifier forms, the
# nested-quantifier rule, the repeat bound and the 22-bit cost budget) on a table checked against the TS reference rules.
# Complements the shared killRegex oracle (9d). Bears on predicates.rb / safe_regex.rb.
module MutationKill
  module SafeSrcT
    module_function
    ROWS = [
      ["a", true],
      ["a*", true],
      ["a+", true],
      ["a?", true],
      ["a{2}", true],
      ["a{2,}", true],
      ["a{2,5}", true],
      ["(?:a|b)", true],
      ["(ab)c", true],
      ["[a-z]+", true],
      ["[^a]", true],
      ["[\\]]", true],
      ["[]a]", true],
      ["a*?", true],
      ["a{2,3}?", true],
      ["\\d+", true],
      ["(a)", true],
      ["(?:a)", true],
      ["a\\", false],
      ["(a)\\1", false],
      ["\\k<n>", false],
      ["(?=a)", false],
      ["(?!a)", false],
      ["(?<n>a)", false],
      ["(?<=a)", false],
      ["(?:", false],
      ["(a", false],
      ["a)", false],
      ["[a", false],
      ["[a\\", false],
      ["*", false],
      ["+a", false],
      ["?", false],
      ["{2}", false],
      ["(*)", false],
      ["(a*)*", false],
      ["(a+)+", false],
      ["(a|b)*", false],
      ["(a*)+", false],
      ["(a?)*", false],
      ["(a)*", true],
      ["(a*)b", true],
      ["a{3,2}", false],
      ["a{65}", false],
      ["a{64}", true],
      ["a{1,65}", false],
      ["a{0,64}", true],
      ["a{2", false],
      ["a{,3}", false],
      ["a{2,x}", false],
      ["a{2,3", false],
      ["a{x}", false],
      ["a{1,64}", true],
      ["a{64,}", true],
      ["a{65,}", false],
      ["a{0}", true],
      ["a{0,0}", true],
      ["|", true],
      ["a|", true],
      ["|a", true],
      ["a||b", true],
      ["\\b", false],
      ["\\B", false],
      ["a\\1", false],
      ["\\0", true],
      ["\\9", false],
      ["\\8a", false],
      ["a\\k", false],
      ["\\ka", false],
      ["a**", false],
      ["a+*", false],
      ["a?*", false],
      ["a*+", false],
      ["a{2}*", false],
      ["a{2}{3}", false],
      ["a*?*", false],
      ["a??", true],
      ["(a)?", true],
      ["(a|b)c", true],
      ["((a))", true],
      ["(a)(b)", true],
      ["((a)|b)", true],
      ["((a*))", true],
      ["((a)*)", true],
      ["(?:a*)*", false],
      ["(?:a|b|c)+", false],
      ["^a$", true],
      ["^", true],
      ["$", true],
      [".", true],
      [".*", true],
      ["(?:)", true],
      ["()", true],
      ["(|)", true],
      ["[^]", true],
      ["[a-", false],
      ["a*b*", true],
      ["a*b*c*", false],
      ["a*b*|c|d|e|f|g|h", true],
      ["a*b*|c|d|e|f|g|h|i", false],
      ["a*a*", true],
      ["(", false],
      ["()))", false],
      ["(()", false],
      ["a{2,2}", true],
      ["a{2,1}", false],
      ["a{5,5}", true],
      ["[a]*", true],
      ["[a]{2}", true],
      ["[a]*?", true],
      ["[^\\]]", true],
      ["[\\\\]", true],
      ["\\\\*", true],
      ["\\.+", true],
      ["x{010}", true],
      ["x{00}", true],
      ["x{0,010}", true],
      ["é+", true],
      ["\\u00e9+", true],
    ].freeze

    def gen
      r = []
      r << ['a' + '|a' * 22, true] << ['a' + '|a' * 23, false] << ['a?' * 22, true] << ['a?' * 23, false]
      r << ['a*b*|c|d|e|f|g|h', true] << ['a*b*|c|d|e|f|g|h|i', false] << ['a{0,3}' * 11, true] << ['a{0,3}' * 12, false]
      r << ['a{2,3}' * 22, true] << ['a{2,3}' * 23, false] << ['a{0,7}' * 7, true] << ['a{0,8}' * 7, false] << ['a{1,4}' * 7, true]
      r << ['(' * 50 + 'a' + ')' * 50, true] << ['(' * 50 + 'a' + ')' * 49, false] << ['(' * 49 + 'a' + ')' * 50, false]
      r
    end

    def run
      (ROWS + gen).each do |s, want|
        got = AtlasPca.is_safe_regex_source(s)
        return "/#{s[0, 50]}/: want #{want} got #{got.inspect}" unless got.equal?(want)
      end
      [nil, 5, :a, ['a'], {}].each { |v| return "nonstring #{v.inspect}" unless AtlasPca.is_safe_regex_source(v).equal?(false) }
      nil
    end
  end

  t('safe regex source guard: every scanner branch') do
    next true if DiffUtil.skip?('predicates.rb', 'safe_regex.rb')
    bad = SafeSrcT.run
    warn bad if bad && !ENV['MUT_FILE']
    bad.nil?
  end
end
