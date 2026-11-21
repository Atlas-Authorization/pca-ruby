# frozen_string_literal: true

# The pca-evidence command line: usage and parse errors exit 2, a malformed bundle fails the replay (exit 1) and the digest command refuses it.
require_relative '../lib/atlas_pca'
require_relative '../lib/atlas_pca/evidence_cli'
require 'minitest/autorun'
require 'tmpdir'

class TestEvidenceCli < Minitest::Test
  C = AtlasPca::EvidenceCli

  def run_cli(*argv)
    out = []
    err = []
    code = C.main(argv, ->(s) { out << s }, ->(s) { err << s })
    [code, out.join("\n"), err.join("\n")]
  end

  def with_files(files)
    Dir.mktmpdir('pca-evidence-cli') do |dir|
      paths = files.to_h { |name, text| [name, File.join(dir, name).tap { |p| File.write(p, text) }] }
      yield paths
    end
  end

  def test_usage_errors_exit_two
    assert_equal 2, run_cli[0]
    assert_equal 2, run_cli('nope')[0]
    assert_equal 2, run_cli('verify')[0]
    assert_equal 2, run_cli('digest', '--trust', 'x', 'f')[0]
    assert_equal 2, run_cli('verify', 'a', 'b')[0]
  end

  def test_unreadable_and_unknown_trust_exit_two
    assert_equal 2, run_cli('verify', '/nonexistent/bundle.json')[0]
    with_files('b.json' => '{}', 't.json' => '{"bogus":1}') do |p|
      code, _out, err = run_cli('verify', p['b.json'], '--trust', p['t.json'])
      assert_equal 2, code
      assert_includes err, 'unknown trust member "bogus"'
    end
  end

  def test_a_malformed_bundle_fails_the_replay_and_the_digest_refuses_it
    with_files('b.json' => '{"v":1}') do |p|
      code, out, = run_cli('verify', p['b.json'])
      assert_equal 1, code
      assert_includes out, 'FAILED'
      assert_includes out, 'report '
      assert_equal 1, run_cli('verify', p['b.json'], '--json')[0]
      code, _out, err = run_cli('digest', p['b.json'])
      assert_equal 2, code
      assert_includes err, 'pca-evidence: '
    end
  end
end
