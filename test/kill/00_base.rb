# frozen_string_literal: true

# Registry for the hand-written mutation-kill tests of the Ruby verifier. Each entry is [name, lambda] and the lambda
# returns truthy when the behaviour is correct. Loaded by tools/pca-audit/ruby-mutate/oracle.rb (and runnable on its
# own: ruby -Ilib test/run_kill.rb).
module MutationKill
  TESTS = [] # rubocop:disable Style/MutableConstant

  # `needs`: a signature suite the test exercises for real (an OpenSSL without it - e.g. 3.0 - cannot run it). run_kill.rb
  # skips such a test, with a count, when the runtime's manifest lacks the suite; the mutation oracle runs on a host with it.
  def self.t(name, needs: nil, &blk)
    TESTS << [name, blk, needs]
  end
end
