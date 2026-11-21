# frozen_string_literal: true

# Standalone runner for the mutation-kill registry (the same lambdas the mutation oracle runs):
#   ruby -Ilib test/run_kill.rb      (exit 1 on any failure; a raised exception of ANY class is a failure)
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'atlas_pca'
require 'atlas_pca/rack_middleware'
require_relative 'support/corpus'
Dir[File.join(__dir__, 'kill', '*.rb')].sort.each { |f| load f }

$mn_verbose = true # the oracle leaves this off: a mutant's failing test is the expected outcome
fails = 0
skipped = Hash.new(0)
supported = AtlasPca.supported_suites
# KILL_SHARD=i/n runs every n-th test (the CI job starts n processes in parallel); unset runs them all
shard_i, shard_n = (ENV['KILL_SHARD'] || '0/1').split('/').map(&:to_i)
MutationKill::TESTS.each_with_index do |(name, fn, needs), idx|
  next unless (idx % shard_n) == shard_i

  if needs && !supported.include?(needs)
    skipped[needs] += 1
    next
  end
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  ok = begin
    fn.call
  rescue Exception => e # rubocop:disable Lint/RescueException
    warn "  #{name}: raised #{e.class}: #{e.message[0, 120]}"
    false
  end
  dt = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0
  warn "SLOW: #{name} #{dt.round(1)}s" if dt > 10 # the registry's cost profile, so a slow entry is found from the log
  next if ok

  fails += 1
  warn "FAIL: #{name}"
end
puts "kill tests: #{MutationKill::TESTS.length}, failures: #{fails}" +
     (skipped.empty? ? '' : "; skipped (suite not in this runtime): #{skipped.map { |s, n| "#{s} #{n}" }.join(', ')}")
exit(fails.zero? ? 0 : 1)
