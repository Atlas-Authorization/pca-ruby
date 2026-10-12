# frozen_string_literal: true

# Registry for the hand-written mutation-kill tests of the Ruby verifier. Each entry is [name, lambda] and the lambda
# returns truthy when the behaviour is correct. Loaded by tools/pca-audit/ruby-mutate/oracle.rb (and runnable on its
# own: ruby -Ilib test/run_kill.rb).
module MutationKill
  TESTS = [] # rubocop:disable Style/MutableConstant

  def self.t(name, &blk)
    TESTS << [name, blk]
  end
end
