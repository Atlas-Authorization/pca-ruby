# frozen_string_literal: true
require 'timeout'
# Deadline kill tests (BRIEF: a timeout is not a kill) for lib/atlas_pca/safe_regex.rb and lib/atlas_pca/predicates.rb: every loop whose
# counter / cursor a mutant stops advancing is driven on an input where the real code finishes in milliseconds. A hang is cut
# by Timeout (the engine entry points rescue StandardError and answer nil, so each case also pins the EXACT real answer: a
# nil / wrong answer fails the test just as a raised Timeout::Error would).
module MutationKill
  module C14
    module_function

    SR = AtlasPca::SafeRegex
    PR = AtlasPca::Predicates

    def within(sec = 3)
      Timeout.timeout(sec) { yield }
    rescue SystemStackError
      false
    end

    def m(src, subj) = AtlasPca.safe_regex_full_match(src, subj)

    def u(s) = SR.units(s)
  end

  t('deadline: CharSet#has? binary search terminates and answers below, on, between and above every range') do
    next true if (f = ENV['MUT_FILE']) && !f.empty? && !%w[safe_regex.rb].include?(f)

    cs = AtlasPca::SafeRegex::CharSet.new([[10, 20], [30, 40], [50, 60], [70, 80]], false)
    ng = AtlasPca::SafeRegex::CharSet.new([[10, 20], [30, 40], [50, 60], [70, 80]], true)
    ins = [10, 15, 20, 30, 35, 40, 50, 55, 60, 70, 75, 80]
    outs = [0, 5, 9, 21, 25, 29, 41, 45, 49, 61, 65, 69, 81, 100]
    C14.within { ins.all? { |c| cs.has?(c) && !ng.has?(c) } && outs.none? { |c| cs.has?(c) } && outs.all? { |c| ng.has?(c) } }
  end

  t('deadline: units_have_lone_surrogate? terminates on pairs, plain units, lone high and lone low') do
    next true if (f = ENV['MUT_FILE']) && !f.empty? && !%w[safe_regex.rb].include?(f)

    sr = AtlasPca::SafeRegex
    C14.within do
      sr.units_have_lone_surrogate?([0x41, 0xd83d, 0xde00, 0x42]) == false && sr.units_have_lone_surrogate?([0x41, 0x42, 0x43]) == false &&
        sr.units_have_lone_surrogate?([0x41, 0xd83d]) == true && sr.units_have_lone_surrogate?([0xde00, 0x41]) == true &&
        sr.units_have_lone_surrogate?([]) == false
    end
  end

  t('deadline: the safe regex parser and matcher terminate on alternation, concatenation, groups, classes, braces and long subjects') do
    next true if (f = ENV['MUT_FILE']) && !f.empty? && !%w[safe_regex.rb].include?(f)

    C14.within(1.5) do # short: a runaway parser mutant allocates fast, and must be cut by the deadline before the memory cap
      [
        ['a|b|c', 'b', true], ['a|b|c', 'd', false], ['abc', 'abc', true], ['abc', 'abd', false], ['(ab)c', 'abc', true],
        ['(?:ab|cd)e', 'cde', true], ['a.c', 'abc', true], ['^a$', 'a', true], ['[a-c]x', 'bx', true], ['[^a-c]x', 'bx', false],
        ['[abc]x', 'cx', true], ['a{2,3}', 'aa', true], ['a{2,3}', 'a', false], ['a{3}', 'aaa', true], ['a{2,}', 'aaaa', true],
        ['a{12,34}', 'a' * 20, true], ['a{12,34}', 'a' * 35, false], ['a{2,34}b', 'aab', true], ['a+b*c?', 'aabbc', true],
        ['x\\.y', 'x.y', true], ['a*', 'a' * 50, true], ['a*b', 'a' * 50 + 'c', false]
      ].all? { |src, subj, want| C14.m(src, subj) == want }
    end
  end

  t('deadline: the compiled-regex cache evicts one entry at a time and terminates past its bound') do
    next true if (f = ENV['MUT_FILE']) && !f.empty? && !%w[safe_regex.rb].include?(f)

    sr = AtlasPca::SafeRegex
    C14.within(10) do
      (0...(sr::CACHE_MAX_ENTRIES + 20)).all? { |i| C14.m("k#{i}", "k#{i}") == true } && sr::CACHE.length <= sr::CACHE_MAX_ENTRIES
    end
  end

  t('deadline: predicates code_points terminates and decodes pairs') do
    next true if (f = ENV['MUT_FILE']) && !f.empty? && !%w[predicates.rb].include?(f)

    C14.within { C14::PR.code_points(C14.u("a\u{1F600}b")) == [0x61, 0x1F600, 0x62] && C14::PR.code_points([]) == [] }
  end

  t('deadline: predicates glob_match terminates and answers stars, ?, backtracking and trailing stars') do
    next true if (f = ENV['MUT_FILE']) && !f.empty? && !%w[predicates.rb].include?(f)

    C14.within do
      [['a*c', 'abc', true], ['a*c', 'abd', false], ['a?c', 'abc', true], ['a?c', 'ac', false], ['a*b*c', 'aXbYc', true],
       ['*b', 'aab', true], ['*b', 'aba', false], ['a*', 'a', true], ['a*', 'abcd', true], ['a**', 'a', true], ['*', '', true],
       ['*', 'xyz', true], ['abc', 'abc', true], ['abc', 'abcd', false], ['', '', true], ['a*a*a', 'aXaYa', true],
       ['a*c', "a\u{1F600}c", true]].all? { |g, s, want| C14::PR.glob_match(g, s) == want }
    end
  end

  t('deadline: predicates guard_brace terminates on every digit run and returns the exact span') do
    next true if (f = ENV['MUT_FILE']) && !f.empty? && !%w[predicates.rb].include?(f)

    inf = AtlasPca::SafeRegex::INF
    C14.within do
      g = ->(src, i = 0) { C14::PR.guard_brace(C14.u(src), i) }
      g.call('{2,34}') == [6, 2, 34] && g.call('{12}') == [4, 12, 12] && g.call('{3,}') == [4, 3, inf] && g.call('{}').nil? &&
        g.call('{a}').nil? && g.call('{2,3').nil? && g.call('{2').nil? && g.call('x{10,20}', 1) == [7, 10, 20]
    end
  end

  t('deadline: predicates safe_source? terminates on escapes, classes (escaped ] included), unterminated classes and plain text') do
    next true if (f = ENV['MUT_FILE']) && !f.empty? && !%w[predicates.rb].include?(f)

    C14.within do
      s = ->(src) { C14::PR.safe_source?(C14.u(src), src) }
      s.call('ab') == true && s.call('[ab]c') == true && s.call('\\.a') == true && s.call('[a\\]b]') == true && s.call('[^ab]c') == true &&
        s.call('\\1') == false && s.call('[ab') == false && s.call('[a\\') == false && s.call('a\\') == false
    end
  end
end
