# frozen_string_literal: true

require 'openssl'
require 'set'
require_relative '../atlas_pca'
require_relative 'js_compat'

module AtlasPca
  # Wesolowski VDF over an RSA group plus the PCA timelock (the TypeScript reference, @atlasauth/pca-vdf). Bignum math on Integer.
  # Same domains, transcript, error texts and check order as the reference. An RSA-group VDF needs a modulus of unknown
  # factorisation (RSA_2048_CHALLENGE_MODULUS / check_production_modulus); insecure_dev_setup is for tests only.
  # A JS number is a Float or a safe Integer; a bigint is an Integer: the two stay distinct where the reference distinguishes them.
  module Vdf
    CHALLENGE_PRIME_BITS = 256
    INSECURE_DEV_SETUP_DEFAULT_BITS = 2048
    MIN_PRODUCTION_MODULUS_BITS = 2048
    RSA_2048_CHALLENGE_MODULUS = (
      '25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072' \
      '84499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686' \
      '99875491824224336372590851418654620435767984233871847744479207399342365848238242811981638150106748104516603773060562016196762561338441436038339044149526' \
      '34432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822' \
      '120720357'
    ).to_i
    DEFAULT_MODULUS = RSA_2048_CHALLENGE_MODULUS
    MAX_SAFE = (2**53) - 1
    SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97].freeze
    HASH_TO_PRIME_DOMAIN = "atlas-pca/vdf/wesolowski/hash-to-prime/v1\x00".b.freeze
    X_DERIVATION_DOMAIN = "atlas-pca/vdf/timelock/input/v2\x00"

    INSECURE_DEV_MODULI = Set.new
    PRODUCTION_SCREEN_PASSED = Set.new

    module_function

    def int?(v) = v.is_a?(Integer)

    # The value as an Integer when it is a JS-safe integer (a Float with an integral value counts, as in JS), else nil.
    def safe_int(v)
      return (v.abs <= MAX_SAFE ? v : nil) if int?(v)
      return v.to_i if v.is_a?(Float) && v.finite? && v.abs <= MAX_SAFE && v == v.to_i

      nil
    end

    def umod(x, n) = ((x % n.abs) + n.abs) % n.abs

    def utf8(s) = Js.utf8(s.to_s)

    def bytes_to_big_int(b) = b.to_s.b.unpack1('H*').then { |h| h.empty? ? 0 : h.to_i(16) }

    def big_int_to_bytes(value)
      raise ArgumentError, 'bigIntToBytes: negative value' if value.negative?
      return "\x00".b if value.zero?

      [format('%0*x', ((value.bit_length + 7) / 8) * 2, value)].pack('H*')
    end

    def u32be(n) = [n & 0xFFFFFFFF].pack('N')
    def u64be(n) = [n & 0xFFFFFFFFFFFFFFFF].pack('Q>')
    def len_prefixed(b) = u32be(b.bytesize) + b.b

    def normalize_steps(t)
      s = safe_int(t)
      raise ArgumentError, "VDF: steps T must be a non-negative safe integer, got #{t}" if s.nil? || s.negative?

      s
    end

    def gcd(a, b) = a.abs.gcd(b.abs)

    def unit?(v, n) = v.positive? && v < n && gcd(v, n) == 1

    def modpow(base, exp, mod)
      raise ArgumentError, 'modpow: modulus must be positive' if mod <= 0
      return 0 if mod == 1
      raise ArgumentError, 'modpow: negative exponent (no inverse in a group of unknown order)' if exp.negative?

      base.pow(exp, mod)
    end

    # ---- primality: Baillie-PSW (strong Miller-Rabin on the first 25 primes + strong Lucas)
    def perfect_square?(n)
      return false if n.negative?
      return true if n < 2

      r = Integer.sqrt(n)
      r * r == n
    end

    def jacobi(a, n)
      r = 1
      a %= n
      until a.zero?
        while (a & 1).zero?
          a >>= 1
          r = -r if [3, 5].include?(n & 7)
        end
        a, n = n, a
        r = -r if (a & 3) == 3 && (n & 3) == 3
        a %= n
      end
      n == 1 ? r : 0
    end

    def strong_lucas_probable_prime?(n)
      return false if n < 3 || (n & 1).zero? || perfect_square?(n)

      d_ = 5
      loop do
        j = jacobi(d_, n)
        break if j == -1
        return false if j.zero? && d_.abs != n

        d_ = d_ > 0 ? -(d_ + 2) : -d_ + 2
      end
      p = 1
      q = (1 - d_) / 4
      d = n + 1
      s = 0
      while (d & 1).zero?
        d >>= 1
        s += 1
      end
      u = 1
      v = p
      qk = q % n
      bits = d.to_s(2)
      (1...bits.length).each do |i|
        u = (u * v) % n
        v = ((v * v) - (2 * qk)) % n
        qk = (qk * qk) % n
        next unless bits[i] == '1'

        u1 = half(((p * u) + v) % n, n)
        v1 = half(((d_ * u) + (p * v)) % n, n)
        u = u1
        v = v1
        qk = (qk * q) % n
      end
      return true if u.zero? || v.zero?

      (1...s).each do
        v = ((v * v) - (2 * qk)) % n
        return true if v.zero?

        qk = (qk * qk) % n
      end
      false
    end

    def half(x, n) = ((x & 1) == 1 ? x + n : x) >> 1

    def miller_rabin_probable_prime?(n)
      return false if n < 3 || (n & 1).zero?

      d = n - 1
      s = 0
      while (d & 1).zero?
        d >>= 1
        s += 1
      end
      SMALL_PRIMES.each do |a|
        base = a % n
        next if base.zero?

        x = base.pow(d, n)
        next if x == 1 || x == n - 1

        composite = true
        (1...s).each do
          x = (x * x) % n
          if x == n - 1
            composite = false
            break
          end
        end
        return false if composite
      end
      true
    end

    def probable_prime?(n)
      return false if n < 2

      SMALL_PRIMES.each do |p|
        return true if n == p
        return false if (n % p).zero?
      end
      miller_rabin_probable_prime?(n) && strong_lucas_probable_prime?(n)
    end

    # ---- Fiat-Shamir challenge prime
    def hash_to_prime(x, y, t, n, bits = CHALLENGE_PRIME_BITS)
      b = safe_int(bits)
      raise ArgumentError, 'hashToPrime: bits must be an integer in [8, 8192]' if b.nil? || b < 8 || b > 8192

      steps = normalize_steps(t)
      transcript = HASH_TO_PRIME_DOMAIN + len_prefixed(big_int_to_bytes(umod(x, n))) + len_prefixed(big_int_to_bytes(umod(y, n))) +
                   len_prefixed(big_int_to_bytes(steps)) + len_prefixed(big_int_to_bytes(n)) + len_prefixed(u32be(b))
      seed = OpenSSL::Digest::SHA256.digest(transcript)
      bytes_needed = (b + 7) / 8
      top_bit = 1 << (b - 1)
      mask = (1 << b) - 1
      counter = 0
      loop do
        chunks = ''.b
        block_index = 0
        while chunks.bytesize < bytes_needed
          chunks << OpenSSL::Digest::SHA256.digest(seed + u64be(counter) + u32be(block_index))
          block_index += 1
        end
        cand = (bytes_to_big_int(chunks.byteslice(0, bytes_needed)) & mask) | top_bit | 1
        return cand if probable_prime?(cand)

        counter += 1
      end
    end

    # ---- the VDF
    def sequential_square(x, t, n)
      raise ArgumentError, 'VDF: modulus N must be > 1' if n <= 1

      steps = normalize_steps(t)
      y = umod(x, n)
      steps.times { y = (y * y) % n }
      y
    end

    def wesolowski_proof(x, t, l, n)
      xr = umod(x, n)
      pi = 1 % n
      r = 1 % l
      t.times do
        two_r = r * 2
        b = two_r / l
        r = two_r % l
        pi = (pi * pi) % n
        pi = (pi * xr) % n if b == 1
      end
      pi
    end

    def check_eval_input(x, n)
      xr = umod(x, n)
      return if unit?(xr, n) && xr != 1 && xr != n - 1

      raise ArgumentError, 'VDF: input x must be a non-trivial unit mod N (not 0, 1, -1, or sharing a factor with N)'
    end

    def vdf_eval(x, t, n)
      raise ArgumentError, 'VDF: modulus N must be odd and > 3' if n <= 3 || (n & 1).zero?

      steps = normalize_steps(t)
      check_eval_input(x, n)
      y = sequential_square(x, t, n)
      { 'y' => y, 'pi' => wesolowski_proof(x, steps, hash_to_prime(x, y, t, n), n) }
    end

    def verdict(ok, reason = nil) = ok ? { 'ok' => true } : { 'ok' => false, 'reason' => reason }

    def verify_inner(x, y, pi, t, n, canonical)
      return verdict(false, 'malformed-input') unless int?(x) && int?(y) && int?(pi) && int?(n)
      return verdict(false, 'bad-modulus') if n <= 3 || (n & 1).zero?

      steps = safe_int(t)
      return verdict(false, 'bad-steps') if steps.nil? || steps.negative?
      return verdict(false, 'non-canonical-y') if !unit?(y, n) || (canonical && y > n - y)
      return verdict(false, 'non-canonical-pi') if !unit?(pi, n) || (canonical && pi > n - pi)

      xr = umod(x, n)
      return verdict(false, 'bad-input-x') if !unit?(xr, n) || xr == 1 || xr == n - 1

      l = hash_to_prime(x, y, steps, n)
      r = modpow(2, steps, l)
      lhs = (modpow(pi, l, n) * modpow(xr, r, n)) % n
      good = canonical ? (lhs == y || lhs == n - y) : lhs == y
      verdict(good, 'equation-mismatch')
    rescue StandardError
      verdict(false, 'malformed-input')
    end

    def vdf_verify_detailed(x, y, pi, t, n) = verify_inner(x, y, pi, t, n, false)
    def canonical_vdf_output(y, n) = y > n - y ? n - y : y

    def vdf_eval_canonical(x, t, n)
      raise ArgumentError, 'VDF: modulus N must be odd and > 3' if n <= 3 || (n & 1).zero?

      steps = normalize_steps(t)
      check_eval_input(x, n)
      y = canonical_vdf_output(sequential_square(x, t, n), n)
      { 'y' => y, 'pi' => canonical_vdf_output(wesolowski_proof(x, steps, hash_to_prime(x, y, t, n), n), n) }
    end

    def vdf_verify_canonical_detailed(x, y, pi, t, n) = verify_inner(x, y, pi, t, n, true)
    def vdf_verify_canonical(x, y, pi, t, n) = vdf_verify_canonical_detailed(x, y, pi, t, n)['ok']
    def vdf_verify(x, y, pi, t, n) = vdf_verify_detailed(x, y, pi, t, n)['ok']

    # ---- modulus screening
    def screen_primes
      @screen_primes ||= begin
        limit = 1 << 16
        sieve = Array.new(limit, false)
        out = []
        (2...limit).each do |i|
          next if sieve[i]

          out << i
          (i * i).step(limit - 1, i) { |j| sieve[j] = true }
        end
        out
      end
    end

    def random_prime(bits, rnd)
      raise ArgumentError, 'randomPrime: bits too small' if bits < 16

      nbytes = (bits + 7) / 8
      top_bit = 1 << (bits - 1)
      mask = (1 << bits) - 1
      50_000.times do
        cand = (bytes_to_big_int(rnd.call(nbytes)) & mask) | top_bit | 1
        return cand if probable_prime?(cand)
      end
      raise 'insecureDevSetup: randomness source failed to yield a prime (stuck or constant RNG?)'
    end

    # TEST ONLY: a modulus whose factors the caller knows (so it delays nobody). Registered so the production screen refuses it.
    def insecure_dev_setup(bits = nil, random_bytes = nil)
      bits = INSECURE_DEV_SETUP_DEFAULT_BITS if bits.nil?
      raise ArgumentError, 'insecureDevSetup: bits must be a safe integer >= 32' if safe_int(bits).nil? || bits < 32

      rnd = random_bytes || ->(k) { OpenSSL::Random.random_bytes(k) }
      half = bits / 2
      p = random_prime(half, rnd)
      q = random_prime(bits - half, rnd)
      i = 0
      while p == q
        raise 'insecureDevSetup: randomness source returned the same prime repeatedly (constant RNG?)' if i >= 8

        q = random_prime(bits - half, rnd)
        i += 1
      end
      n = p * q
      INSECURE_DEV_MODULI.add(n)
      { 'insecureDevOnly' => true, 'N' => n, 'p' => p, 'q' => q, 'bits' => n.bit_length }
    end

    def check_production_modulus(n)
      return { 'ok' => false, 'reason' => 'modulus is not a bigint' } unless int?(n)
      return { 'ok' => true } if !INSECURE_DEV_MODULI.include?(n) && PRODUCTION_SCREEN_PASSED.include?(n)
      return { 'ok' => false, 'reason' => 'modulus came from insecureDevSetup(): its factors are known, so it provides no delay' } if INSECURE_DEV_MODULI.include?(n)
      return { 'ok' => false, 'reason' => 'modulus is too small' } if n <= 3
      return { 'ok' => false, 'reason' => "modulus is below #{MIN_PRODUCTION_MODULUS_BITS} bits" } if n.bit_length < MIN_PRODUCTION_MODULUS_BITS
      return { 'ok' => false, 'reason' => 'modulus is even' } if (n & 1).zero?
      return { 'ok' => false, 'reason' => 'modulus is a perfect square' } if perfect_square?(n)
      return { 'ok' => false, 'reason' => 'modulus is prime (group order N-1 is public)' } if probable_prime?(n)

      screen_primes.each do |p|
        return { 'ok' => false, 'reason' => "modulus has the small prime factor #{p}" } if (n % p).zero?
      end
      PRODUCTION_SCREEN_PASSED.add(n)
      { 'ok' => true }
    end

    # ---- PCA timelock: the VDF challenge is bound to the action and to an unpredictable beacon
    # A String action is an opaque, precomputed digest; anything else is a PCActn digested like the ledger.
    def action_digest(action) = action.is_a?(String) ? action : AtlasPca.hash_canonical(action)

    def beacon_bytes(beacon)
      b = beacon.is_a?(String) ? utf8(beacon) : beacon
      raise ArgumentError, 'timelock: a non-empty beacon (unpredictable, post-action value) is required' unless b.is_a?(String) && !b.empty?

      b.b
    end

    def derive_timelock_input(action, n, beacon)
      raise ArgumentError, 'deriveTimelockInput: modulus N must be a bigint > 3' if !int?(n) || n <= 3

      msg = utf8(X_DERIVATION_DOMAIN) + len_prefixed(utf8(action_digest(action))) + len_prefixed(beacon_bytes(beacon))
      raw = bytes_to_big_int(OpenSSL::Digest::SHA256.digest(msg)) % n
      raw <= 1 ? raw + 2 : raw
    end

    def require_production_modulus(n, allow)
      return if allow == true

      check = check_production_modulus(n)
      return if check['ok']

      raise ArgumentError, "timelock: refusing this modulus: #{check['reason']}. Use RSA_2048_CHALLENGE_MODULUS or a ceremony modulus; " \
                           'tests may pass allowInsecureDevModulus: true.'
    end

    def require_steps(steps)
      s = safe_int(steps)
      raise ArgumentError, "timelock: steps must be a safe integer >= 1, got #{steps}" if s.nil? || s < 1

      s
    end

    def require_timelock(action, steps, n, beacon, allow_insecure_dev_modulus = nil)
      s = require_steps(steps)
      require_production_modulus(n, allow_insecure_dev_modulus)
      x = derive_timelock_input(action, n, beacon)
      { 'kind' => 'vdf-timelock', 'x' => x, 'steps' => s, 'N' => n, 'actionDigest' => action_digest(action) }
    end

    # Runs the VDF: the squarings ARE the cooling-off, so this is deliberately slow.
    def prove_timelock_elapsed(action, steps, n, beacon, allow_insecure_dev_modulus = nil)
      s = require_steps(steps)
      require_production_modulus(n, allow_insecure_dev_modulus)
      proof = vdf_eval_canonical(derive_timelock_input(action, n, beacon), s, n)
      { 'kind' => 'vdf-timelock-proof', 'y' => proof['y'], 'pi' => proof['pi'], 'steps' => s }
    end

    # Fail closed: any malformed input or refused modulus is false. Offline, no clock.
    def verify_timelock(action, proof, steps, n, beacon, allow_insecure_dev_modulus = nil)
      required = require_steps(steps)
      require_production_modulus(n, allow_insecure_dev_modulus)
      return false unless proof.is_a?(Hash) && proof['kind'] == 'vdf-timelock-proof'
      return false if safe_int(proof['steps']).nil? || proof['steps'] != required
      return false unless int?(proof['y']) && int?(proof['pi'])

      vdf_verify_canonical(derive_timelock_input(action, n, beacon), proof['y'], proof['pi'], required, n)
    rescue StandardError
      false
    end

    # Operator helper: squarings measured here times a conservative adversary advantage, so the delay is a floor. `now` is in ms.
    def calibrate_steps(n, desired_seconds, sample_squarings = 50_000, adversary_advantage = 10, now = nil)
      raise ArgumentError, 'calibrateSteps: modulus N must be a bigint > 3' if !int?(n) || n <= 3
      raise ArgumentError, 'calibrateSteps: desiredSeconds must be > 0' unless desired_seconds.is_a?(Numeric) && desired_seconds.to_f.finite? && desired_seconds.positive?
      raise ArgumentError, 'calibrateSteps: sampleSquarings must be a safe integer >= 1' if safe_int(sample_squarings).nil? || sample_squarings < 1
      raise ArgumentError, 'calibrateSteps: adversaryAdvantage must be >= 1' if !adversary_advantage.to_f.finite? || adversary_advantage < 1

      clock = now || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) * 1000.0 }
      y = 2 % n
      t0 = clock.call
      sample_squarings.to_i.times { y = (y * y) % n }
      t1 = clock.call
      # a non-finite reading gives NaN steps (or 1 step from an infinite elapsed time): never a floor
      raise RangeError, 'calibrateSteps: the clock must return finite times' unless t0.to_f.finite? && t1.to_f.finite?

      elapsed = [t1 - t0, 2.220446049250313e-16].max
      per_s = sample_squarings / elapsed * 1000.0
      adv = per_s * adversary_advantage
      { 'steps' => [1, (adv * desired_seconds).ceil].max, 'measuredSquaringsPerSecond' => per_s, 'assumedAdversarySquaringsPerSecond' => adv }
    end
  end
end
