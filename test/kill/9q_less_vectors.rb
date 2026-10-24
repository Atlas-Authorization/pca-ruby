# frozen_string_literal: true
require 'json'
# The LESS known answers (packages/pca/conformance/less-vectors.json) through libatlas_less, as test_less.rb runs them but INSIDE
# the mutation oracle: before 0.4.2 only the standalone runner checked them, so every LESS path of atlas_pca.rb / less_ffi.rb
# (pq_verify's LessFfi branch, the variable-length signature rule, the seed-padding malleation refusal) was invisible to the
# mutator. Each vector: wire verdict AND leaf-suite verdict must equal the recorded expectation.
module MutationKill
  module LessVectors
    module_function
    FILE = File.expand_path('../../conformance/less-vectors.json', __dir__)
    def doc = (@doc ||= JSON.parse(File.read(FILE)))

    def check(part, parts)
      return 'vector count' unless doc['vectors'].size >= 25

      doc['vectors'].each_with_index do |v, i|
        next unless i % parts == part

        key = doc['keys'][v['key']]
        art = { 'alg' => v['alg'], 'sig' => v['sig'], 'pq_pk' => v.fetch('pq_pk_override', key['pq_pk']) }
        art['pq_sig'] = v['pq_sig'] if v.key?('pq_sig')
        msg = AtlasPca.b64d(v['message'])
        wire_ok = AtlasPca.validate_signature_wire(art).nil?
        allow = wire_ok && AtlasPca.verify_leaf_suite(art, key['ed_pub'], msg)
        return "#{v['name']}: wire #{wire_ok} allow #{allow}" unless wire_ok == v['expect']['wire_ok'] && allow == v['expect']['allow']
      end
      nil
    end

    # the FFI layer itself
    def ffi
      l = AtlasPca::LessFfi
      return 'constants' unless [l::KEY_TYPE, l::PUBLIC_KEY_BYTES, l::SIGNATURE_MIN_BYTES, l::SIGNATURE_MAX_BYTES, l::SIGNATURE_STEP_BYTES] == ['LESS-cat1', 97_484, 1153, 1329, 16]
      return 'not available' unless l.available?

      (1100..1400).each { |n| return "sig_len_ok?(#{n})" unless l.sig_len_ok?(n) == (n.between?(1153, 1329) && ((1329 - n) % 16).zero?) }
      v = doc['vectors'].find { |x| x['expect']['allow'] == true && !x.key?('pq_sig') && x['alg'] == 'less-cat1' }
      return nil unless v # no pure positive vector in this corpus

      key = doc['keys'][v['key']]
      pk = AtlasPca.b64d(key['pq_pk'])
      sg = AtlasPca.b64d(v['sig'])
      msg = AtlasPca.b64d(v['message'])
      return 'positive refused' unless l.verify(pk, msg, sg) == true && AtlasPca.pq_verify('LESS-cat1', pk, msg, sg) == true
      return 'wrong message accepted' if l.verify(pk, msg + 'x', sg) || AtlasPca.pq_verify('LESS-cat1', pk, msg + 'x', sg)
      return 'short pk accepted' if l.verify(pk[0, pk.bytesize - 1], msg, sg) || AtlasPca.pq_verify('LESS-cat1', pk[0, pk.bytesize - 1], msg, sg)
      return 'bad sig length accepted' if l.verify(pk, msg, sg + 'x') || AtlasPca.pq_verify('LESS-cat1', pk, msg, sg + 'x')
      return 'empty msg' if l.verify(pk, ''.b, sg)
      return 'b64u wrapper' unless AtlasPca.pq_verify_b64u('LESS-cat1', key['pq_pk'], msg, v['sig']) == true

      nil
    end
  end

  3.times do |k|
    t("LESS known answers (libatlas_less): part #{k + 1}", needs: 'less-cat1') do
      next true if DiffUtil.skip?('atlas_pca.rb', 'less_ffi.rb')

      bad = LessVectors.check(k, 3)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
  t('LESS FFI layer', needs: 'less-cat1') do
    next true if DiffUtil.skip?('atlas_pca.rb', 'less_ffi.rb')

    bad = LessVectors.ffi
    warn bad if bad && !ENV['MUT_FILE']
    bad.nil?
  end
end
