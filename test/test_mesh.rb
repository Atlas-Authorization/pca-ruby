# frozen_string_literal: true

# The shared mesh corpus (packages/pca/conformance/mesh-vectors.json): whole mesh proofs with the TypeScript verdict.
#   ruby -Ilib test/test_mesh.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestMesh < Minitest::Test
  FILE = File.expand_path('../conformance/mesh-vectors.json', __dir__)

  def test_vectors
    vecs = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)['mesh']
    assert_operator vecs.length, :>=, 100
    bad = []
    vecs.each do |v|
      expect = v['expect']
      got = AtlasPca.verify_mesh_proof(v['proof'], v['trust'])
      if got.ok != expect['ok']
        bad << "#{v['name']}: ok=#{got.ok} (#{got.reason.inspect}) want #{expect['ok']} (#{expect['reason'].inspect})"
        next
      end
      next if expect['ok']

      want = expect['reason']
      if want.is_a?(String) && want.start_with?('chain:')
        bad << "#{v['name']}: reason #{got.reason.inspect} want a chain refusal" unless got.reason.start_with?('chain:')
        next
      end
      bad << "#{v['name']}: reason #{got.reason.inspect} want #{want.inspect}" if got.reason != want
      want_hop = expect.key?('hop') ? expect['hop'] : -1
      bad << "#{v['name']}: hop #{got.hop} want #{want_hop}" if got.hop != want_hop
    end
    assert_equal [], bad.first(20)
  end

  # a head pinned at size 0 (root '') advances: '' is checked as the RFC 9162 empty-tree root; a non-vacuous or mis-sized proof is refused.
  def test_empty_head_advances
    j = AtlasPca.parse_json('{"e":{"domain":"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A","size":0,"root":"","rev_root":"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8","rev_size":0,"timestamp":1800000000000},"n":{"domain":"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A","size":3,"root":"CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow","rev_root":"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8","rev_size":0,"timestamp":1800000000000},"ok":{"oldSize":0,"newSize":3,"path":[]},"path":{"oldSize":0,"newSize":3,"path":["CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow"]},"old1":{"oldSize":1,"newSize":3,"path":[]}}', loose: true)
    adv = ->(pf) { AtlasPca.mesh_check_head_advance(j['e'], j['n'], pf) }
    assert_nil adv.call(j['ok'])
    assert_equal 'consistency proof required for a larger head', adv.call(nil)
    assert_equal 'head is not consistent with the previous head (fork or rewrite)', adv.call(j['path'])
    assert_equal 'consistency proof required for a larger head', adv.call(j['old1'])
  end

  def test_total_on_garbage
    [nil, 5, 'x', [], {}].each do |g|
      r = AtlasPca.verify_mesh_proof(g, g)
      refute r.ok
      assert_equal(-1, r.hop)
    end
  end
end
