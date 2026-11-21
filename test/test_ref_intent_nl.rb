# frozen_string_literal: true

# Replays the reference corpus for the natural-language facade compiler (nl_prompt, parse_nl_policy, nl_facade_compiler) from
# test-data/ref-intent-nl-java.json.gz.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/intent_compilers'
require 'minitest/autorun'

class TestRefIntentNl < Minitest::Test
  CO = AtlasPca::IntentCompilers
  BY_FN = Ref.load('intent-nl-java')

  def self.cat(extras)
    return nil if extras.nil?

    AtlasPca::BUILTIN_ACTIONS + extras.map { |e| e.merge('verb' => "#{e['connector']}.#{e['action']}") }
  end

  def self.run_case(c)
    fn = c['fn']
    args = c['args']
    return CO.nl_prompt(args[0], cat(args[1])) if fn == 'nlPrompt'
    return CO.parse_nl_policy(args[0], cat(args[1])) if fn == 'parseNLPolicy'

    text, raw, extras = args
    seen = []
    complete = lambda do |p|
      seen << p
      raise 'llm down' if raw == 'THROWS'

      raw
    end
    comp = CO.nl_facade_compiler('nl', 'fam', complete)
    return CO.run_compilers({ 'text' => text, 'catalog' => cat(extras) }, [comp]) unless fn == 'nlCompile'

    out = comp.compile({ 'text' => text, 'catalog' => cat(extras) })
    { 'prompt' => seen[0], 'output' => out }
  end

  def test_nl_corpus
    bad = []
    BY_FN.each_value do |cases|
      cases.each do |c|
        args = Ref.dec(c['args'])
        ok = begin
          got = self.class.run_case(c.merge('args' => args))
          Ref.canon(got) == Ref.canon(c['out'])
        rescue StandardError => e
          got = e.message
          Ref.throws?(c['out'])
        end
        bad << [c['name'], got] unless ok
      end
    end
    assert_empty bad.first(3)
  end

  # the corpus is pinned: its fn set and every fn's case count (a fn the replay skips, or a changed corpus, fails here)
  def test_the_corpus_is_pinned_in_full
    assert_equal({ 'nlPrompt' => 8, 'parseNLPolicy' => 104, 'nlCompile' => 112, 'nlRun' => 26 }, BY_FN.transform_values(&:length))
  end

end
