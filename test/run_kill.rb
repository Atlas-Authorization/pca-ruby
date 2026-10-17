# frozen_string_literal: true

# Standalone runner for the mutation-kill registry (the same lambdas the mutation oracle runs):
#   ruby -Ilib test/run_kill.rb      (exit 1 on any failure; a raised exception of ANY class is a failure)
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'atlas_pca'
require 'atlas_pca/rack_middleware'
require_relative 'support/corpus'
Dir[File.join(__dir__, 'kill', '*.rb')].sort.each { |f| load f }

fails = 0
skipped = Hash.new(0)
supported = AtlasPca.supported_suites
MutationKill::TESTS.each do |name, fn, needs|
  if needs && !supported.include?(needs)
    skipped[needs] += 1
    next
  end
  ok = begin
    fn.call
  rescue Exception => e # rubocop:disable Lint/RescueException
    warn "  #{name}: raised #{e.class}: #{e.message[0, 120]}"
    false
  end
  next if ok

  fails += 1
  warn "FAIL: #{name}"
end
puts "kill tests: #{MutationKill::TESTS.length}, failures: #{fails}" +
     (skipped.empty? ? '' : "; skipped (suite not in this runtime): #{skipped.map { |s, n| "#{s} #{n}" }.join(', ')}")
exit(fails.zero? ? 0 : 1)
