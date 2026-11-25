# frozen_string_literal: true

# Replays the TS-reference oracle of the ERC-7715 mapping (test-data/ref-erc7715.json.gz). The generator passes the BigInt
# chainId as its decimal string; it becomes an Integer here.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefErc7715 < Minitest::Test
  E = AtlasPca::Erc7715
  CASES = Ref.load('erc7715')

  def self.opts(x)
    o = Ref.snake(x)
    o.is_a?(Hash) && o['chain_id'].is_a?(String) ? o.merge('chain_id' => Integer(o['chain_id'], 10)) : o
  end

  FNS = {
    'grantToPermissionRequest' => ->(g, x) { E.grant_to_permission_request(g, opts(x)) },
    'supportsRequest' => ->(s, r) { E.supports_request(s, r) },
    # the one zero-argument case is revokeParams(undefined): its member is dropped, which Ruby has no value for
    'revokeParams' => ->(*a) { a.empty? ? {} : E.revoke_params(a[0]) },
    'verifyGrantedPermission' => lambda do |g, s, got, x|
      o = { 'allowed_managers' => x['allowedManagers'] }
      o['context_owner'] = ->(c) { x['owners'][c] } if x['owners']
      E.verify_granted_permission(g, s, got, o)
    end,
    'grantDigestOf' => ->(g) { E.grant_digest_of(g) }
  }.freeze

  def test_every_fn_is_mapped
    assert_empty CASES.keys - FNS.keys
  end

  FNS.each { |fn, call| define_method("test_#{fn}") { Ref.run(self, CASES[fn], call) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 4314, CASES.values.sum(&:length), 'erc7715'
  end

end
