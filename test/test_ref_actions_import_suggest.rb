# frozen_string_literal: true

# Replays the TS-reference oracle of the suggestion rules (validation, digest, signature, matching, application), the model assist and the
# provider adapters (test-data/ref-actions-import-suggest.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_import_suggest'
require_relative '../lib/atlas_pca/actions_import_model'
require 'minitest/autorun'
require 'digest'

class TestRefActionsImportSuggest < Minitest::Test
  S = AtlasPca::ActionsImportSuggest
  M = AtlasPca::ActionsImportModel
  CORE = AtlasPca::Actions::CORE_REGISTRY
  BY_FN = Ref.load('actions-import-suggest')

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

  Res = Struct.new(:ok, :status, :json_value, :bad_json) do
    def json = bad_json ? raise('bad json') : json_value
  end

  def self.rules(x) = x == 'default' ? S.default_rules : x
  def self.reg(x) = x == 'core' ? CORE : nil
  def self.seed(label) = Digest::SHA256.digest("atlas-pca-conformance/#{label}")

  def self.provider(cfg, spec, req)
    calls = []
    fetch = lambda do |url, init|
      calls << { 'url' => url, 'headers' => init['headers'], 'body' => init['body'] }
      raise spec['throws'] if spec.key?('throws')

      Res.new(spec.fetch('ok', true), spec.fetch('status', 200), spec['json'], spec['badjson'])
    end
    a = M.provider_adapter(M::ModelEnvConfig.new(cfg['provider'], cfg['model'], cfg['apiKey']), fetch)
    begin
      { 'call' => calls[0], 'text' => a.complete(req) }
    rescue StandardError => e
      { 'call' => calls[0], 'error' => e.message }
    end
  end

  T = TestRefActionsImportSuggest
  MAP = {
    'stem' => S.method(:stem),
    'factsOf' => S.method(:facts_of),
    'DEFAULT_RULES' => -> { S.default_rules },
    'DEFAULT_RULES_SEALED_DIGEST' => -> { S.default_rules_sealed['digest'] },
    'suggestRulesError' => ->(r, k = nil) { S.suggest_rules_error(T.rules(r), k) },
    'rulesDigest' => ->(r) { S.rules_digest(T.rules(r)) },
    'sealRules' => S.method(:seal_rules),
    'signRules' => ->(r, kid, label) { S.sign_rules(r, kid, T.seed(label)) },
    'verifyRules' => S.method(:verify_rules),
    'suggestWithRules' => ->(d, r, g = nil) { S.suggest_with_rules(d, T.rules(r), T.reg(g)) },
    'applySuggestion' => S.method(:apply_suggestion),
    'unionSuggestions' => S.method(:union_suggestions),
    'vocabulary' => ->(g) { M.vocabulary(T.reg(g) || CORE) },
    'promptDigest' => ->(g) { M.prompt_digest(T.reg(g) || CORE) },
    'buildRequest' => ->(d) { M.build_request(d, CORE) },
    'parseTraitList' => ->(t) { M.parse_trait_list(t, CORE) },
    'suggestWithModels' => ->(d, ads) { M.suggest_with_models(d, ads.map { |a| Adapter.new(a) }, CORE) },
    'modelConfigFromEnv' => ->(env, flags) { M.model_config_from_env(env, flags).to_map },
    'providerAdapterComplete' => ->(cfg, spec, req) { T.provider(cfg, spec, req) }
  }.freeze

  def test_every_function_is_covered
    assert_equal [], BY_FN.keys - MAP.keys
    assert_equal [], MAP.keys - BY_FN.keys
  end

  MAP.each do |fn, call|
    define_method("test_#{fn}_matches_the_reference") { assert_operator Ref.run(self, BY_FN[fn], call, compare: SAME), :>, 0 }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1236, BY_FN.values.sum(&:length), 'actions-import-suggest'
  end

end
