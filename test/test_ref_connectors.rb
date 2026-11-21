# frozen_string_literal: true

# Replays the TS-reference oracle of the connector catalog (test-data/ref-connectors.json.gz): manifest validation and digests, the
# provider registry, authorize URL / PKCE / URL variables, access-token placement, code exchange and refresh into the vault, and the
# manifest-to-vault-provider mapping. Errors are compared as data (class name and message); a failure that is not a connector error
# is the generic "Error".
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/connectors'
require 'minitest/autorun'

class TestRefConnectors < Minitest::Test
  C = AtlasPca::Connectors
  V = AtlasPca::Connect
  Js = AtlasPca::Js
  BY_FN = Ref.load('connectors')

  def self.err_out(e)
    return { 'ok' => false, 'name' => 'Error' } unless e.is_a?(C::ConnectorError)

    out = { 'ok' => false, 'name' => e.class.name.split('::').last, 'message' => e.message }
    out['issues'] = e.issues.dup if e.respond_to?(:issues) && !e.issues.empty?
    out
  end

  def self.guard(&f)
    lambda do |*a|
      { 'ok' => true, 'value' => f.call(*a) }
    rescue StandardError => e
      err_out(e)
    end
  end

  def self.with_reg(customs)
    r = C.create_default_registry
    (customs || []).each { |m| r.register(m) }
    r
  end

  class Resp
    attr_reader :ok, :status

    def initialize(r)
      @r = r
      @ok = r['ok']
      @status = r['status']
    end

    def json
      raise 'bad json' if @r['jsonThrows']

      @r['json']
    end

    def text
      raise 'bad text' if @r['textThrows']

      @r.fetch('text', '')
    end
  end

  def self.transport(script, log)
    return nil if script.nil?

    n = [0]
    lambda do |url, init|
      log << { 'url' => url, 'method' => init['method'], 'headers' => init['headers'], 'body' => init['body'] }
      r = script[[n[0], script.length - 1].min]
      n[0] += 1
      raise r['throws'] if r.key?('throws')

      Resp.new(r)
    end
  end

  def self.build_authorize(pid, opts, customs)
    guard { C.build_authorize_url(pid, opts.merge('registry' => with_reg(customs))) }.call
  end

  def self.token_run(which)
    lambda do |c|
      log = []
      store = V::InMemoryConnectionStore.new
      vault = V::TokenVault.new(strict: false, insecure_skip_plan_root_check: true, store: store, now: -> { c['now'] })
      bind = c['bind']
      authority = { 'principal' => bind['principal'] }
      %w[scopes audience].each { |k| authority[k] = bind[k] if bind.key?(k) }
      args = c.reject { |k, _| %w[bind script customs].include?(k) }.merge('fetch' => transport(c['script'], log), 'registry' => with_reg(c['customs']),
                                                                              'bind' => { 'vault' => vault, 'agentId' => bind['agentId'], 'authority' => authority })
      args['bind']['connectionId'] = bind['connectionId'] if bind.key?('connectionId')
      result = begin
        { 'ok' => true, 'value' => C.send(which, args) }
      rescue StandardError => e
        err_out(e)
      end
      g = store.get({ 'agentId' => bind['agentId'], 'provider' => c['providerId'], 'connectionId' => bind.fetch('connectionId', 'default') })
      { 'result' => result, 'fetchCalls' => log, 'stored' => g.nil? ? nil : V.clone_connection(g) }
    end
  end

  def self.registry(s)
    r = Js.truthy?(s['empty']) ? C::ProviderRegistry.new : C.create_default_registry
    s['ops'].map do |op|
      v = case op['op']
          when 'register' then r.register(op['manifest'], op['opts'])
          when 'get' then r.get(op['id'])
          when 'require' then r.require_provider(op['id'])
          when 'has' then r.has?(op['id'])
          when 'list' then r.list
          when 'ids' then r.ids
          else C.catalog_digest(r)
          end
      { 'ok' => true, 'value' => v }
    rescue StandardError => e
      err_out(e)
    end
  end

  def self.catalog
    { 'ids' => C.list_providers.map { |m| m['id'] }, 'manifests' => C.list_providers, 'digest' => C.catalog_digest,
      'google' => C.get_provider('google'), 'nope' => C.get_provider('nope') }
  end

  MAP = {
    'validateManifest' => ->(x) { C.validate_manifest(x) },
    'assertManifest' => guard { |x| C.assert_manifest(x) },
    'manifestDigest' => ->(x) { C.manifest_digest(x) },
    'catalog' => -> { catalog },
    'registry' => ->(s) { registry(s) },
    'substituteVars' => guard { |u, v| C.substitute_vars(u, v) },
    'pkceChallenge' => guard { |*a| C.pkce_challenge(*a) },
    'buildAuthorizeUrl' => ->(pid, opts, customs) { build_authorize(pid, opts, customs) },
    'applyAccessToken' => guard { |m, t| C.apply_access_token(m, t) },
    'manifestToProviderConfig' => guard { |i, creds| C.manifest_to_provider_config(C.get_provider(i), creds) },
    'buildVaultProviders' => guard { |c| C.build_vault_providers(c) },
    'exchange' => token_run(:exchange_code),
    'refresh' => token_run(:refresh)
  }.freeze

  # lone-surrogate safe comparison of canonical forms
  CMP = ->(g, o, _c) { Js.json(Ref.sort_keys(Ref.norm(g))) == Js.json(Ref.sort_keys(Ref.norm(o))) }

  def test_every_fn_is_mapped
    assert_empty BY_FN.keys - MAP.keys
    assert_empty MAP.keys - BY_FN.keys
  end

  MAP.each { |fn, call| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call, compare: CMP) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1708, BY_FN.values.sum(&:length), 'connectors'
  end

end
