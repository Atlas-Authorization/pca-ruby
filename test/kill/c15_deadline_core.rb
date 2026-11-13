# frozen_string_literal: true
require 'timeout'
require 'openssl'
# Deadline kill tests (BRIEF: a timeout is not a kill): each call below finishes in milliseconds on the real code, and a mutant
# that stops a loop counter advancing (or recurses without end) hangs: Timeout::Error / a rescued SystemStackError fails the test,
# so a TEST decides the mutant. Covers lib/atlas_pca.rb (skip_ws, parse_string, split_point/build, Ed25519Strict.mul) and
# lib/atlas_pca/intent_v2.rb (map_tree_root, map_root_from_path).
module MutationKill
  module C15
    module_function

    def within(sec = 2)
      Timeout.timeout(sec) { yield }
    rescue SystemStackError
      false
    end

    def sha(s) = OpenSSL::Digest::SHA256.digest(s)

    def tree(n) = Array.new(n) { |i| sha("leaf #{i}") }

    # RFC 9162 audit path of leaf m in the tree hs, by the reference's recursion
    def path(hs, m)
      return [] if hs.length == 1

      k = AtlasPca::IntentV2.send(:split_point, hs.length)
      if m < k
        path(hs[0, k], m) + [AtlasPca::IntentV2.map_tree_root(hs[k..])]
      else
        path(hs[k..], m - k) + [AtlasPca::IntentV2.map_tree_root(hs[0, k])]
      end
    end
  end

  t('deadline: skip_ws advances over every whitespace byte') do
    C15.within { AtlasPca.parse_json(" \n\t\r{\"a\" \n:\r 1}  ") == { 'a' => 1 } }
  end

  t('deadline: parse_string terminates on escapes, plain runs after an escape, a closing quote and a raw control byte') do
    C15.within do
      v = AtlasPca.parse_json('{"k":"a\\nb c\\"d\\\\e\\/f\\tg"}')
      ctl = begin
        AtlasPca.parse_json("{\"k\":\"x\x01y\"}")
        false
      rescue AtlasPca::Malformed
        true
      end
      v == { 'k' => "a\nb c\"d\\e/f\tg" } && ctl && AtlasPca.parse_json('{"k":"\\u0041\\ud83d\\ude00z"}') == { 'k' => "A\u{1F600}z" }
    end
  end

  t('deadline: merkle split_point and build terminate and agree with the RFC 6962 shape for 1..17 leaves') do
    C15.within(5) do
      (1..17).all? do |n|
        leaves = Array.new(n) { |i| { 'i' => i } }
        root = AtlasPca.merkle_root(leaves)
        shape = (0...n).map { |m| AtlasPca.send(:path_shape, m, n) }
        root.is_a?(String) && shape.all?(Array) && AtlasPca.send(:split_point, n) == (n == 1 ? 1 : 2**((n - 1).bit_length - 1))
      end
    end
  end

  t('deadline: Ed25519 strict verification terminates (mul loop) and still verifies') do
    k = OpenSSL::PKey.new_raw_private_key('ED25519', "\x09".b * 32)
    msg = 'deadline'
    sig = k.sign(nil, msg)
    C15.within(5) { AtlasPca::Ed25519Strict.verify(k.raw_public_key, msg, sig) == true && AtlasPca::Ed25519Strict.verify(k.raw_public_key, msg + 'x', sig) == false }
  end

  t('deadline: intent map tree root and RFC 9162 inclusion paths terminate for 1..13 leaves and recompute the root') do
    next true if (f = ENV['MUT_FILE']) && !f.empty? && !%w[intent_v2.rb].include?(f)

    iv = AtlasPca::IntentV2
    C15.within(5) do
      (1..13).all? do |n|
        hs = C15.tree(n)
        root = iv.map_tree_root(hs)
        (0...n).all? { |m| iv.map_root_from_path(m, n, hs[m], C15.path(hs, m)) == root }
      end
    end
  end
  t('deadline: merkle_root of no leaves is refused with Malformed, never a runaway recursion') do
    C15.within(5) do
      begin
        AtlasPca.merkle_root([])
        false
      rescue AtlasPca::Malformed
        true
      end
    end
  end
end
