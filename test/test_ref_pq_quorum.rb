# frozen_string_literal: true

# Replays the TS-reference oracle of the post-quantum quorum sets and their rotation (test-data/ref-pq-threshold-quorum.json.gz,
# 389 cases): building and loading a set, the quorum message and action digest, signing a share, assembling and verifying a
# proof, the rotation digest / certificate / chain and the fork predicate, the proof size report. Every fn has a handler and the
# total is asserted. A secret is {"$seed": label} = sha256("atlas-pca-conformance/" + label) (the ML-DSA key generation seed for
# mlDsa / mlDsa87; ML-DSA signing is deterministic, so shares compare byte for byte); SLH-DSA signatures are data (verify only).
# The signing and verifying fns need ML-DSA and SLH-DSA in the runtime (OpenSSL >= 3.5); the structural fns run everywhere.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefPqQuorum < Minitest::Test
  A = AtlasPca
  Q = AtlasPca::PqQuorum
  BY_FN = Ref.load('pq-threshold-quorum')
  PQ = (%w[ml-dsa-65 ml-dsa-87 slh-dsa-sha2-128f slh-dsa-sha2-256s] - A.supported_suites).empty?
  CRYPTO_FNS = %w[signQuorumShare signRotationShare verifyQuorum verifyQuorumApproval verifyRotationChain].freeze

  # the signing keys of a corpus key object ({edSecret?, mlDsa?, mlDsa87?}: seeds)
  def self.keys(k)
    raise TypeError, 'keys is not an object' unless k.is_a?(Hash)

    out = {}
    out['ed'] = A::KeyPair.from_seed_b64u(k['edSecret']) if k.key?('edSecret')
    out['ml_dsa'] = A::PqKeyPair.from_seed('ML-DSA-65', Ref.b64d(k['mlDsa'])) if k.key?('mlDsa')
    out['ml_dsa87'] = A::PqKeyPair.from_seed('ML-DSA-87', Ref.b64d(k['mlDsa87'])) if k.key?('mlDsa87')
    out
  end

  HANDLERS = {
    'constants' => -> { { 'PQ_QUORUM_MAX_SIGNERS' => A::PQ_QUORUM_MAX_SIGNERS, 'PQ_QUORUM_MAX_CHAIN' => A::PQ_QUORUM_MAX_CHAIN } },
    'buildQuorumSet' => ->(*a) { Q.build_quorum_set(*a) }, # the diversity floor is absent or present (null included)
    'loadQuorumSet' => ->(x) { Q.load_quorum_set(x) },
    'quorumMessage' => ->(set_id, epoch, digest) { { '$bytes' => Ref.b64e(Q.quorum_message(set_id, epoch, digest)) } },
    'quorumActionDigest' => ->(message) { Q.quorum_action_digest(message) },
    'signQuorumShare' => ->(set, index, epoch, digest, k) { Q.sign_quorum_share(set, index, epoch, digest, keys(k)) },
    'assembleQuorumProof' => ->(set, shares) { Q.assemble_quorum_proof(set, shares) },
    'verifyQuorum' => ->(input) { Q.verify_quorum(input) },
    # the reference takes bytes (a Uint8Array): a corpus value that is text (a UTF-8 String, not the binary of a {$bytes} member) is refused
    'verifyQuorumApproval' => ->(set, proof, message, *rest) { message.is_a?(String) && message.encoding != Encoding::BINARY ? false : Q.verify_quorum_approval(set, proof, message, *rest) },
    'rotationActionDigest' => ->(to_set_id, to_epoch) { Q.rotation_action_digest(to_set_id, to_epoch) },
    'signRotationShare' => ->(from, index, from_epoch, to, k) { Q.sign_rotation_share(from, index, from_epoch, to, keys(k)) },
    'buildRotationCert' => ->(from, from_epoch, to, shares) { Q.build_rotation_cert(from, from_epoch, to, shares) },
    'verifyRotationChain' => ->(genesis, epoch, chain) { Q.verify_rotation_chain(genesis, epoch, chain) },
    'isRotationFork' => ->(a, b) { Q.rotation_fork?(a, b) },
    'quorumProofSize' => ->(*a) { Q.quorum_proof_size(*a) } # the index list is absent or present
  }.freeze

  def test_every_fn_of_the_corpus_has_a_handler
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal 389, BY_FN.values.sum(&:length)
  end

  def test_the_post_quantum_cases_run_where_required
    assert PQ, 'this runtime must have ML-DSA-65/87 and SLH-DSA-SHA2-128f/256s' if ENV['PCA_REQUIRE_PQ'] == '1'
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      skip 'needs ML-DSA and SLH-DSA (OpenSSL >= 3.5)' if !PQ && CRYPTO_FNS.include?(fn)
      Ref.run(self, BY_FN.fetch(fn), handler)
    end
  end
end
