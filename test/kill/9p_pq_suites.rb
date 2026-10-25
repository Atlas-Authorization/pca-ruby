# frozen_string_literal: true
require 'base64'
# Post-quantum suite tables and the PQ primitives (atlas_pca.rb: SIG_SUITES, PQ_PRIMS, REGISTERED_SUITES, pq_sig_len_ok?,
# pq_sig_ok?, pq_verify, pq_verify_b64u, pq_prim_available?, supported_suites, validate_suite_fields). The expected values below
# are the sizes of the standards (FIPS 204 ML-DSA, FIPS 205 SLH-DSA, the LESS cat1 reference) written out here on purpose, NOT
# read from the library: a table entry that drifts (a length +-1, a flag flipped, a name emptied) fails.
module MutationKill
  module PqSuites
    module_function
    # alg => [sig bytes, needs pq_pk, pq_pk bytes, needs pq_sig, primitive]
    SUITES = {
      'ed25519' => [64, false, 0, false, nil],
      'ml-dsa-65' => [3309, true, 1952, false, 'ML-DSA-65'],
      'hybrid-ed25519-ml-dsa-65' => [64, true, 1952, true, 'ML-DSA-65'],
      'hybrid-nested-ed25519-ml-dsa-65' => [64, true, 1952, true, 'ML-DSA-65'],
      'slh-dsa-sha2-128f' => [17_088, true, 32, false, 'SLH-DSA-SHA2-128f'],
      'hybrid-ed25519-slh-dsa-sha2-128f' => [64, true, 32, true, 'SLH-DSA-SHA2-128f'],
      'ml-dsa-87' => [4627, true, 2592, false, 'ML-DSA-87'],
      'hybrid-ed25519-ml-dsa-87' => [64, true, 2592, true, 'ML-DSA-87'],
      'slh-dsa-sha2-256s' => [29_792, true, 64, false, 'SLH-DSA-SHA2-256s'],
      'hybrid-ed25519-slh-dsa-sha2-256s' => [64, true, 64, true, 'SLH-DSA-SHA2-256s'],
      'less-cat1' => [1329, true, 97_484, false, 'LESS-cat1'],
      'hybrid-ed25519-less-cat1' => [64, true, 97_484, true, 'LESS-cat1']
    }.freeze
    # primitive => [public key bytes, signature bytes (LESS: the maximum)]
    PRIMS = { 'ML-DSA-65' => [1952, 3309], 'ML-DSA-87' => [2592, 4627], 'SLH-DSA-SHA2-128f' => [32, 17_088],
              'SLH-DSA-SHA2-256s' => [64, 29_792], 'LESS-cat1' => [97_484, 1329] }.freeze
    REGISTERED = %w[ed25519 ml-dsa-65 hybrid-ed25519-ml-dsa-65 hybrid-nested-ed25519-ml-dsa-65 slh-dsa-sha2-128f
                    hybrid-ed25519-slh-dsa-sha2-128f ml-dsa-87 hybrid-ed25519-ml-dsa-87 slh-dsa-sha2-256s
                    hybrid-ed25519-slh-dsa-sha2-256s fn-dsa-512 fn-dsa-1024 less-cat1 hybrid-ed25519-less-cat1].freeze
    LESS_LENS = (1153..1329).step(16).to_a.freeze
    OPENSSL_PRIMS = %w[ML-DSA-65 ML-DSA-87 SLH-DSA-SHA2-128f SLH-DSA-SHA2-256s].freeze

    # what the unmutated library supports on this host (taken at registry load by the parent)
    SUPPORTED = AtlasPca.supported_suites.freeze

    def b64(n) = Base64.urlsafe_encode64("\x00".b * n, padding: false)

    # a wire-valid signature block of `alg`, with optional per-member overrides of the byte lengths
    def block(alg, sig: nil, pk: nil, psig: nil)
      sl, needs_pk, pkl, needs_sig, prim = SUITES.fetch(alg)
      h = {}
      h['alg'] = alg unless alg == 'ed25519'
      h['sig'] = b64(sig || sl)
      h['pq_pk'] = b64(pk || pkl) if needs_pk
      h['pq_sig'] = b64(psig || (prim == 'LESS-cat1' ? 1329 : PRIMS[prim][1])) if needs_sig
      h
    end

    def tables
      return 'SIG_SUITES' unless AtlasPca::SIG_SUITES == SUITES.to_h { |a, (sl, npk, _, nsg, prim)| [a, [sl, npk, nsg, prim, a.start_with?('hybrid-nested')]] }
      return 'PQ_PRIMS' unless AtlasPca::PQ_PRIMS == PRIMS
      return 'REGISTERED_SUITES' unless AtlasPca::REGISTERED_SUITES == REGISTERED
      return 'constants' unless [AtlasPca::ML_DSA_65_PUBLIC_KEY_BYTES, AtlasPca::ML_DSA_65_SIGNATURE_BYTES, AtlasPca::ED25519_SIGNATURE_BYTES] == [1952, 3309, 64]
      return 'UNSUPPORTED_SUITE' unless AtlasPca::UNSUPPORTED_SUITE == 'unsupported_suite'

      nil
    end

    def wire(alg)
      v = ->(h) { AtlasPca.validate_signature_wire(h) }
      sl, needs_pk, pkl, needs_sig, prim = SUITES.fetch(alg)
      v.call(block(alg)).nil? or return "#{alg}: a well-formed block is refused"
      # every length is exact
      return "#{alg}: sig+1 accepted" unless v.call(block(alg, sig: sl + 1))&.start_with?("'sig'")
      return "#{alg}: sig-1 accepted" unless v.call(block(alg, sig: sl - 1))&.start_with?("'sig'")
      if needs_pk
        return "#{alg}: pq_pk+1 accepted" unless v.call(block(alg, pk: pkl + 1))&.start_with?("'pq_pk'")
        return "#{alg}: pq_pk-1 accepted" unless v.call(block(alg, pk: pkl - 1))&.start_with?("'pq_pk'")
        h = block(alg)
        h.delete('pq_pk')
        return "#{alg}: missing pq_pk accepted" unless v.call(h)&.start_with?("'pq_pk'")
      else
        h = block(alg).merge('pq_pk' => b64(32))
        return "#{alg}: stray pq_pk accepted" unless v.call(h)&.start_with?("'pq_pk' must be absent")
      end
      if needs_sig
        top = prim == 'LESS-cat1' ? 1329 : PRIMS[prim][1]
        return "#{alg}: pq_sig+1 accepted" unless v.call(block(alg, psig: top + 1))&.start_with?("'pq_sig'")
        return "#{alg}: pq_sig-1 accepted" unless v.call(block(alg, psig: top - 1))&.start_with?("'pq_sig'")
        h = block(alg)
        h.delete('pq_sig')
        return "#{alg}: missing pq_sig accepted" unless v.call(h)&.start_with?("'pq_sig'")
        if prim == 'LESS-cat1'
          LESS_LENS.each { |n| v.call(block(alg, psig: n)).nil? or return "#{alg}: LESS pq_sig #{n} refused" }
          [1137, 1152, 1154, 1160, 1328, 1330, 1345, 0].each { |n| v.call(block(alg, psig: n)) && next; return "#{alg}: LESS pq_sig #{n} accepted" }
        end
      else
        h = block(alg).merge('pq_sig' => b64(64))
        return "#{alg}: stray pq_sig accepted" unless v.call(h)&.start_with?("'pq_sig' must be absent")
      end
      if prim == 'LESS-cat1' && !needs_sig # pure LESS: `sig` itself is the variable-length signature
        LESS_LENS.each { |n| v.call(block(alg, sig: n)).nil? or return "#{alg}: LESS sig #{n} refused" }
        [1137, 1152, 1154, 1160, 1328, 1330, 1345, 0].each { |n| v.call(block(alg, sig: n)) && next; return "#{alg}: LESS sig #{n} accepted" }
      end
      # a share carries no pq_pk check (an optional echo)
      s = block(alg)
      s.delete('pq_pk')
      AtlasPca.validate_share_signature_wire(s).nil? or return "#{alg}: a share without pq_pk is refused"
      s['pq_pk'] = b64(3)
      AtlasPca.validate_share_signature_wire(s).nil? or return "#{alg}: a share's pq_pk echo is judged"
      nil
    end

    def lens
      %w[ML-DSA-65 ML-DSA-87 SLH-DSA-SHA2-128f SLH-DSA-SHA2-256s].each do |pr|
        n = PRIMS[pr][1]
        [n, n + 1, n - 1, 0].each do |l|
          want = l == n
          return "pq_sig_len_ok?(#{pr}, #{l}) != #{want}" unless AtlasPca.pq_sig_len_ok?(pr, l) == want
          return "pq_sig_ok?(#{pr}, #{l}) != #{want}" unless AtlasPca.pq_sig_ok?(b64(l), pr) == want
        end
      end
      (1100..1400).each do |l|
        want = LESS_LENS.include?(l)
        return "pq_sig_len_ok?(LESS, #{l}) != #{want}" unless AtlasPca.pq_sig_len_ok?('LESS-cat1', l) == want
        return "pq_sig_ok?(LESS, #{l}) != #{want}" unless AtlasPca.pq_sig_ok?(b64(l), 'LESS-cat1') == want
      end
      return 'unknown prim length ok' if AtlasPca.pq_sig_len_ok?('NOPE', 3309) || AtlasPca.pq_sig_len_ok?('ed25519', 64)
      return 'pq_sig_ok? nil' if AtlasPca.pq_sig_ok?(nil, 'ML-DSA-65') || AtlasPca.pq_sig_ok?('!!', 'ML-DSA-65')
      return 'pq_sig_ok? non-canonical' if AtlasPca.pq_sig_ok?("#{b64(3309)}=", 'ML-DSA-65')

      nil
    end

    def suites
      return "supported_suites #{AtlasPca.supported_suites.inspect}" unless AtlasPca.supported_suites == SUPPORTED
      return 'supported_suites lacks ed25519' unless AtlasPca.supported_suites.first == 'ed25519'
      return 'fn-dsa supported' if AtlasPca.supported_suites.any? { |a| a.start_with?('fn-dsa') }
      return 'LESS availability' unless AtlasPca.pq_prim_available?('LESS-cat1') == AtlasPca::LessFfi.available?
      return 'LESS suite vs library' unless SUPPORTED.include?('less-cat1') == AtlasPca::LessFfi.available?
      OPENSSL_PRIMS.each do |pr|
        want = SUPPORTED.include?(SUITES.find { |_, v| v[4] == pr }.first)
        return "pq_prim_available?(#{pr}) != #{want}" unless AtlasPca.pq_prim_available?(pr) == want
        return "memo #{pr}" unless AtlasPca.pq_prim_available?(pr) == want
      end
      return 'unknown prim available' if AtlasPca.pq_prim_available?('NOPE')
      return 'resolve_suite' unless AtlasPca.resolve_suite({ 'alg' => 'fn-dsa-512' }) == [nil, 'unsupported_suite: fn-dsa-512']
      return 'resolve_suite unknown' unless AtlasPca.resolve_suite({ 'alg' => 'nope' }) == [nil, "unknown signature alg 'nope'"]

      nil
    end

    # real keys, made once by the unmutated parent
    KEYS = OPENSSL_PRIMS.to_h do |pr|
      next [pr, nil] unless AtlasPca.pq_prim_available?(pr)

      k = OpenSSL::PKey.generate_key(pr)
      msg = 'pca pq kill message'.b
      [pr, [k.raw_public_key, msg, k.sign(nil, msg)]]
    rescue StandardError
      [pr, nil]
    end.freeze

    def verify(pr)
      pk, msg, sig = KEYS.fetch(pr)
      pkl, sgl = PRIMS[pr]
      return "#{pr}: sizes #{pk.bytesize}/#{sig.bytesize}" unless [pk.bytesize, sig.bytesize] == [pkl, sgl]
      return "#{pr}: valid refused" unless AtlasPca.pq_verify(pr, pk, msg, sig) == true
      return "#{pr}: wrapper" unless AtlasPca.pq_verify_b64u(pr, Base64.urlsafe_encode64(pk, padding: false), msg, Base64.urlsafe_encode64(sig, padding: false)) == true
      return "#{pr}: wrong message accepted" if AtlasPca.pq_verify(pr, pk, msg + 'x', sig)
      bad = sig.dup
      bad.setbyte(5, bad.getbyte(5) ^ 1)
      return "#{pr}: tampered sig accepted" if AtlasPca.pq_verify(pr, pk, msg, bad)
      return "#{pr}: short pk accepted" if AtlasPca.pq_verify(pr, pk[0, pkl - 1], msg, sig)
      return "#{pr}: long pk accepted" if AtlasPca.pq_verify(pr, pk + 'x', msg, sig)
      return "#{pr}: short sig accepted" if AtlasPca.pq_verify(pr, pk, msg, sig[0, sgl - 1])
      return "#{pr}: long sig accepted" if AtlasPca.pq_verify(pr, pk, msg, sig + 'x')
      return "#{pr}: unknown prim accepted" if AtlasPca.pq_verify('NOPE', pk, msg, sig)
      pb = Base64.urlsafe_encode64(pk, padding: false)
      sb = Base64.urlsafe_encode64(sig, padding: false)
      return "#{pr}: b64 nil pk accepted" if AtlasPca.pq_verify_b64u(pr, nil, msg, sb)
      return "#{pr}: b64 nil sig accepted" if AtlasPca.pq_verify_b64u(pr, pb, msg, nil)
      return "#{pr}: b64 garbage pk accepted" if AtlasPca.pq_verify_b64u(pr, '!!', msg, sb)
      return "#{pr}: b64 garbage sig accepted" if AtlasPca.pq_verify_b64u(pr, pb, msg, '!!')
      return "#{pr}: b64 padded pk accepted" if AtlasPca.pq_verify_b64u(pr, "#{pb}=", msg, sb)
      return "#{pr}: b64 unknown prim accepted" if AtlasPca.pq_verify_b64u('NOPE', pb, msg, sb)
      if pr == 'ML-DSA-65'
        return 'mldsa65_verify' unless AtlasPca.mldsa65_verify(pk, msg, sig) == true && !AtlasPca.mldsa65_verify(pk, msg + 'x', sig)
        return 'mldsa65_verify_b64u' unless AtlasPca.mldsa65_verify_b64u(pb, msg, sb) == true && !AtlasPca.mldsa65_verify_b64u(pb, msg + 'x', sb)
      end
      nil
    end
  end

  t('PQ tables (sizes of the standards)') do
    bad = PqSuites.tables
    warn bad if bad && !ENV['MUT_FILE']
    bad.nil?
  end
  t('PQ signature lengths') do
    next true if DiffUtil.skip?('atlas_pca.rb')
    bad = PqSuites.lens
    warn bad if bad && !ENV['MUT_FILE']
    bad.nil?
  end
  t('PQ supported suites / capability probe') do
    next true if DiffUtil.skip?('atlas_pca.rb')
    bad = PqSuites.suites
    warn bad if bad && !ENV['MUT_FILE']
    bad.nil?
  end
  PqSuites::SUITES.each_key do |alg|
    t("PQ suite wire: #{alg}", needs: alg == 'ed25519' ? nil : alg) do
      next true if DiffUtil.skip?('atlas_pca.rb')
      bad = PqSuites.wire(alg)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
  PqSuites::OPENSSL_PRIMS.each do |pr|
    next unless PqSuites::KEYS[pr]

    t("PQ verify: #{pr}") do
      next true if DiffUtil.skip?('atlas_pca.rb')
      bad = PqSuites.verify(pr)
      warn bad if bad && !ENV['MUT_FILE']
      bad.nil?
    end
  end
end
