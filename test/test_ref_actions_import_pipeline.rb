# frozen_string_literal: true

# Replays the TS-reference oracle of the import pipeline, the importer registry, the JSON Lines forms and the suggestion evaluation
# (test-data/ref-actions-import-review.json.gz; its review half is replayed with the review flow).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_import_eval'
require 'minitest/autorun'

class TestRefActionsImportPipeline < Minitest::Test
  EV = AtlasPca::ActionsImportEval
  PL = AtlasPca::ActionsImportPipeline
  S = AtlasPca::ActionsImportSuggest
  BY_FN = Ref.load('actions-import-review')
  REVIEW_FNS = %w[confirmDef verifyAttestation reviewStatus revertStale reviewPriority prepareReview reviewQueueOrder].freeze

  # the corpus holds lone surrogates, which JSON.generate refuses: compare the JS-order serialization
  SAME = ->(got, out, _c) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(got))) == AtlasPca::Js.json(Ref.sort_keys(Ref.norm(out))) }

  class Adapter
    attr_reader :id, :version

    def initialize(spec)
      @id = spec['id']
      @version = spec['version']
      @spec = spec
    end

    def complete(_req)
      raise @spec['throws'] if @spec.key?('throws')

      @spec['answer']
    end
  end

  def self.suggest_opts(s)
    o = s.dup
    if o['rules'] == 'default'
      r = S.default_rules
      o['rules'] = r.merge('rules' => r['rules'][0, 20])
    end
    o['models'] = o['models'].map { |m| Adapter.new(m) } unless o['models'].nil?
    o
  end

  T = TestRefActionsImportPipeline
  MAP = {
    'parseHandTsv' => EV.method(:parse_hand_tsv),
    'parseCorpusJsonl' => EV.method(:parse_corpus_jsonl),
    'realSplit' => EV.method(:real_split),
    'importCorpus' => EV.method(:import_corpus),
    'evalSuggest' => ->(entries, rules = nil, alpha = nil) { EV.eval_suggest(entries, rules.nil? || rules == 'default' ? nil : rules, nil, alpha) },
    'renderEvalMarkdown' => EV.method(:render_eval_markdown),
    'floorFailures' => EV.method(:floor_failures),
    'importActions' => PL.method(:import_actions),
    'IMPORTERS' => PL.method(:run_importer),
    'importAndSuggest' => ->(kind, d, op, so) { PL.import_and_suggest(kind, d, op, T.suggest_opts(so)) },
    'suggestDefs' => ->(d, s = nil) { PL.suggest_defs(d, T.suggest_opts(s || {})) },
    'defsToJsonl' => PL.method(:defs_to_jsonl),
    'jsonlToDefs' => PL.method(:jsonl_to_defs)
  }.freeze

  def test_every_function_is_covered
    assert_equal REVIEW_FNS.sort, (BY_FN.keys - MAP.keys).sort
    assert_equal [], MAP.keys - BY_FN.keys
  end

  MAP.each do |fn, call|
    define_method("test_#{fn}_matches_the_reference") { assert_operator Ref.run(self, BY_FN[fn], call, compare: SAME), :>, 0 }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 362, BY_FN.values.sum(&:length), 'actions-import-review'
  end

end
