# frozen_string_literal: true

# Replays the reference oracle of signBuiltins (test-data/ref-sign-builtins.json.gz); the reviewer key derives from a seed label.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_builtin'
require 'minitest/autorun'

class TestRefSignBuiltins < Minitest::Test
  BY_FN = Ref.load('sign-builtins')

  def test_sign_builtins
    Ref.run(self, BY_FN['signBuiltins'], lambda { |label, kid, ts|
      secret = Digest::SHA256.digest("atlas-pca-conformance/#{label}")
      AtlasPca::ActionsBuiltin.sign_builtins(kid: kid, secret: secret, ts: ts).to_h { |d| [d['verb'], d['review']['attestation']] }
    })
  end

  # the corpus is pinned: its fn set and every fn's case count (a fn the replay skips, or a changed corpus, fails here)
  def test_the_corpus_is_pinned_in_full
    assert_equal({ 'signBuiltins' => 3 }, BY_FN.transform_values(&:length))
  end

end
