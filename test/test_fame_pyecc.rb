# frozen_string_literal: true

# FAME group elements against an independent implementation (py_ecc): setup, keygen and encrypt with fixed scalars, byte for byte.
# Needs libblst built together with the GT shim (PCA_BLST_LIB).
require 'json'
require 'minitest/autorun'
require_relative '../lib/atlas_pca/abe'

class TestFamePyecc < Minitest::Test
  F = AtlasPca::Fame
  P = AtlasPca::AbePolicy
  FILE = File.expand_path('../test-data/fame-pyecc/fame-pyecc.json', __dir__)

  def hex(points) = points.map { |p| p.compress.unpack1('H*') }
  def scalars(list) = list.map { |s| s.to_i(16) }

  def test_matches_pyecc
    cases = JSON.parse(File.read(FILE))['cases']
    refute_empty cases
    cases.each do |c|
      name = c['name']
      n = P.normalize(c['policy'])
      assert n['ok'], name
      s = c['scalars']
      ms = F.setup(scalars(s['a']), scalars(s['b']), scalars(s['d']))
      key = F.keygen(ms.msk, c['attrs'], scalars(s['r']), scalars(s['sigma']), s['sigmaPrime'].to_i(16))
      e = F.encrypt(ms.mpk, n['tree'], scalars(s['s']))
      assert_equal c['h'], hex([ms.mpk.h1, ms.mpk.h2]), "#{name} h"
      assert_equal c['mskg'], hex(ms.msk.g), "#{name} mskg"
      assert_equal c['k0'], hex(key.k0), "#{name} k0"
      assert_equal c['kp'], hex(key.kp), "#{name} kp"
      c['key'].each { |attr, want| assert_equal want, hex(key.attrs[attr]), "#{name} key #{attr}" }
      assert_equal c['ct0'], hex(e.ct.ct0), "#{name} ct0"
      assert_equal c['rows'], e.ct.rows.map { |r| hex(r) }, "#{name} rows"
      # the reference decrypted these with the attribute set it was issued; so must the native
      dec = F.decrypt(key, n['tree'], e.ct)
      assert_equal e.k, dec, "#{name} decrypt" if P.satisfies?(n['tree'], c['attrs'])
    end
  end
end
