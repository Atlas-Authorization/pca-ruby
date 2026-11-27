# frozen_string_literal: true

# Replay of the authoring-file text loader (YAML 1.2 core and JSON, with source positions) against the reference corpus. A syntax
# error is compared by class (the parser's wording is its own); a result where this loader is deliberately STRICTER than the reference
# (see ActionsYamlLoad) must be a single "not YAML" refusal on a text that uses one of the documented constructs, never a different
# successful value.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_author'
require 'minitest/autorun'

class TestRefActionsYamlLoad < Minitest::Test
  CASES = Ref.load('actions-yaml-load-py')['loadActionsText']
  SYNTAX = ['not YAML', 'YAML warning', 'not JSON'].freeze
  STRICTER = /(^|\s)!(?!!(str|map|seq)\b)\S|\? \[|\r(?!\n)|!!binary/

  def norm(r) = r.slice('defs', 'notes', 'errors', 'locs', 'rules', 'ns')

  def test_matches_the_reference
    bad = []
    CASES.each do |c|
      text, fmt = c['args']
      got = AtlasPca::ActionsAuthor.load_actions_text(text, fmt)
      exp = c['out']
      e0 = ((exp['errors'] || [{}])[0] || {})['message'].to_s
      ok = if SYNTAX.any? { |p| e0.start_with?(p) }
             got['errors'].length == 1 && got['defs'] == [] && got['errors'][0]['message'].start_with?(fmt == 'yaml' ? 'not YAML' : 'not JSON')
           elsif Ref.canon(norm(got)) == Ref.canon(norm(exp)) then true
           else
             STRICTER.match?(text) && got['errors'].length == 1 && got['errors'][0]['message'].start_with?('not YAML') && got['defs'] == []
           end
      bad << [c['name'], text[0, 80], got.to_s[0, 300], exp.to_s[0, 300]] unless ok
    end
    assert bad.empty?, "#{bad.length} of #{CASES.length} differ:\n#{bad.first(12).map(&:inspect).join("\n")}"
  end

  # the corpus is pinned: its fn set and every fn's case count (a fn the replay skips, or a changed corpus, fails here)
  def test_the_corpus_is_pinned_in_full
    assert_equal({ 'loadActionsText' => 105 }, Ref.load('actions-yaml-load-py').transform_values(&:length))
  end

end
