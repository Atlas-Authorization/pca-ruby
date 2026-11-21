# frozen_string_literal: true

# The oracle of an opt-in module's mutation shard: the module's own replay tests (Minitest files named in MUT_MODULE_TESTS, space
# separated, relative to the library root) as mutation-kill entries "mod_<file>". The mutation job copies this file into
# test/kill/ of its layout; the oracle loads it with the rest of the registry, and MUT_FIRST=mod_ runs these first.
#
# Each entry re-loads its test file from a clean constant table on every call: a test class binds the module under test in a
# constant (A = AtlasPca::Aggsig) and the oracle replaces AtlasPca with the mutant, so a class loaded once would keep testing
# the ORIGINAL. A run where every test skipped (a missing native library) FAILS: a skip must never read as a surviving mutant.
require 'minitest'
require 'stringio'

module ModuleKill
  ROOT = File.expand_path('../..', __dir__)

  # the test files require minitest/autorun: keep it from running them again at process exit
  Minitest.class_variable_set(:@@installed_at_exit, true)
  Minitest.seed = 0

  def self.load_file(path, names)
    names.each { |n| Object.send(:remove_const, n) if Object.const_defined?(n) }
    before = Minitest::Runnable.runnables.dup
    verbose, $VERBOSE = $VERBOSE, nil # constants a test file defines at top level are re-assigned per call
    begin
      load path
    ensure
      $VERBOSE = verbose
    end
    Minitest::Runnable.runnables - before
  end

  def self.run_file(path, names)
    sum = Minitest::SummaryReporter.new(StringIO.new)
    rep = Minitest::CompositeReporter.new
    rep << sum
    rep.start
    load_file(path, names).each { |k| k.run(rep, {}) }
    rep.report
    sum.count.positive? && sum.skips < sum.count && sum.passed?
  end
end

ENV.fetch('MUT_MODULE_TESTS', '').split.each do |rel|
  path = File.join(ModuleKill::ROOT, rel)
  # first load: defines the classes (and loads the module under test, which the oracle then re-evaluates per mutant)
  names = ModuleKill.load_file(path, []).map(&:name).compact
  MutationKill.t("mod_#{File.basename(rel, '.rb')}") { ModuleKill.run_file(path, names) }
end
