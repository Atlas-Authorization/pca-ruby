# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'base64'
require 'timeout'
require_relative 'ada_idna'
require_relative 'whatwg_url'
require_relative 'fdlibm_pow'

module AtlasPca
  # Quantum random number generator (QRNG) entropy as an ADD to key generation, never a trust dependency: every seed is
  # HKDF-SHA256(local CSPRNG || quantum), so a hostile, broken or unreachable quantum source can never lower the result below the
  # local CSPRNG. Parts: an HTTP QRNG source over an INJECTED transport (the library ships no network client), the unavailable
  # source, the SP 800-90B section 4.4 continuous health tests, the combiner (mix_entropy), secure_seed (CSPRNG plus best-effort,
  # health-tested QRNG; `require_quantum` makes it fail closed) and an Ed25519 key pair helper. A "quantum" source that the health
  # tests accept is not thereby proven quantum: the tests catch a stuck or heavily biased source, nothing more.
  module Entropy
    MAX_HKDF_OUTPUT = 255 * 32 # 8160
    MIN_LOCAL_BYTES = 16
    DEFAULT_SEED_BYTES = 32
    DEFAULT_MAX_QRNG_BYTES = 1024
    DEFAULT_TIMEOUT_MS = 5000
    MIX_LABEL = 'atlas-pca/entropy/mix/v1'
    MIX_SALT = 'atlas-pca/entropy/salt/v1'.b.freeze
    # what String.prototype.trim removes (WhiteSpace and LineTerminator)
    JS_SPACE = "\t\n\v\f\r    -     　﻿"
    JS_TRIM = /\A[#{JS_SPACE}]+|[#{JS_SPACE}]+\z/

    # A refusal with a machine-readable code: 'quantum_required' | 'health_test_failed' | 'insecure_transport'.
    class EntropyError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end

      def name = 'EntropyError'
    end

    # new URL() refusal: a TypeError that carries the platform's code
    class InvalidUrlError < TypeError
      def code = 'ERR_INVALID_URL'
    end

    SecureSeedResult = Struct.new(:seed, :used_quantum, :quantum_byte_count, :source)
    EntropyKeyPair = Struct.new(:secret_key, :public_key, :used_quantum)

    # The URL work of the HTTP source through Ada (the WHATWG URL parser Node uses), so a request URL is byte-identical to the
    # reference's: the query is rebuilt with URLSearchParams.set semantics and the URL serialised by the parser itself. Ada is the
    # copy in the platform gem (the default) or the one ATLAS_PCA_LIBADA names. Without it (the pure gem) the lane's own URL parser
    # does the same work for the plain shapes it serialises exactly (http / https, an ASCII host or an IPv6 literal, an optional
    # port, a path of unreserved characters, a query, a fragment of unreserved characters); any other URL (userinfo, a non-ASCII
    # host, characters the parser would have to re-encode) is refused there rather than guessed.
    module Url
      @lock = Mutex.new
      @lib = nil
      @tried = false

      module_function

      def load_lib
        require 'ffi'
        AdaIdna.candidates.each do |path|
          mod = Module.new do
            extend FFI::Library
            const_set(:Str, Class.new(FFI::Struct) { layout :data, :pointer, :length, :size_t })
          end
          mod.ffi_lib(path)
          mod.attach_function :ada_parse, %i[buffer_in size_t], :pointer
          mod.attach_function :ada_free, [:pointer], :void
          mod.attach_function :ada_is_valid, [:pointer], :bool
          mod.attach_function :ada_get_href, [:pointer], mod::Str.by_value
          mod.attach_function :ada_get_host, [:pointer], mod::Str.by_value
          mod.attach_function :ada_get_hostname, [:pointer], mod::Str.by_value
          mod.attach_function :ada_get_protocol, [:pointer], mod::Str.by_value
          mod.attach_function :ada_get_search, [:pointer], mod::Str.by_value
          mod.attach_function :ada_set_search, %i[pointer buffer_in size_t], :void
          mod.attach_function :ada_parse_search_params, %i[buffer_in size_t], :pointer
          mod.attach_function :ada_free_search_params, [:pointer], :void
          mod.attach_function :ada_search_params_set, %i[pointer buffer_in size_t buffer_in size_t], :void
          mod.attach_function :ada_search_params_to_string, [:pointer], mod::Str.by_value
          mod.attach_function :ada_free_owned_string, [mod::Str.by_value], :void
          return mod
        rescue LoadError, FFI::NotFoundError
          next
        end
        nil
      rescue LoadError
        nil
      end

      def lib
        @lock.synchronize do
          unless @tried
            @tried = true
            @lib = load_lib
          end
        end
        @lib
      end

      def available? = !lib.nil?
      def str(s) = s[:length].zero? ? '' : s[:data].read_bytes(s[:length]).force_encoding('UTF-8')
      def utf8(s) = s.to_s.encode('UTF-8', invalid: :replace, undef: :replace, replace: "�").b

      # yields the parsed URL handle, or returns nil when the URL does not parse
      def with_url(l, url)
        return nil unless url.is_a?(String)

        src = utf8(url)
        u = l.ada_parse(src, src.bytesize)
        begin
          return nil if u.null? || !l.ada_is_valid(u)

          yield u
        ensure
          l.ada_free(u) unless u.null?
        end
      end

      # {'protocol' ("https:"), 'host' (with a non-default port), 'hostname'} of a URL, nil when it does not parse
      def parts(url)
        l = lib
        unless l.nil?
          got = with_url(l, url) do |u|
            { 'protocol' => str(l.ada_get_protocol(u)), 'host' => str(l.ada_get_host(u)), 'hostname' => str(l.ada_get_hostname(u)) }
          end
          return got
        end
        res = WhatwgUrl.parse(url)
        return nil if res.nil?

        { 'protocol' => "#{res['scheme']}:", 'host' => res['host'], 'hostname' => res['host'].sub(/:\d+\z/, '') }
      end

      # The URL with each [name, value] of `pairs` set on its query (URLSearchParams.set: the first existing entry is replaced
      # in place, later duplicates dropped), serialised. Raises TypeError for a URL that does not parse.
      def with_params(url, pairs)
        l = lib
        return pure_with_params(url, pairs) if l.nil?

        href = with_url(l, url) do |u|
          query = str(l.ada_get_search(u)).delete_prefix('?').b
          sp = l.ada_parse_search_params(query, query.bytesize)
          begin
            pairs.each do |k, v|
              kb = utf8(k)
              vb = utf8(v)
              l.ada_search_params_set(sp, kb, kb.bytesize, vb, vb.bytesize)
            end
            owned = l.ada_search_params_to_string(sp)
            begin
              serialized = str(owned).b
            ensure
              l.ada_free_owned_string(owned)
            end
          ensure
            l.ada_free_search_params(sp)
          end
          l.ada_set_search(u, serialized, serialized.bytesize)
          str(l.ada_get_href(u))
        end
        raise InvalidUrlError, 'Invalid URL' if href.nil?

        href
      end
    end

    module Url
      PLAIN = %r{\A(?:[Hh][Tt][Tt][Pp][Ss]?)://(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]*)?(?:/[A-Za-z0-9._~/-]*)?(?:\?([^#]*))?(?:#([A-Za-z0-9._~-]+))?\z}
      FORM_SAFE = /[A-Za-z0-9*._-]/

      module_function

      # application/x-www-form-urlencoded, as URLSearchParams parses and serialises a query
      def form_decode(s) = s.tr('+', ' ').b.gsub(/%([0-9A-Fa-f]{2})/n) { Regexp.last_match(1).to_i(16).chr }.force_encoding('UTF-8').scrub("\uFFFD")

      def form_encode(s)
        utf8(s).each_char.map { |c| c == ' ' ? '+' : (c.match?(FORM_SAFE) ? c : format('%%%02X', c.ord)) }.join
      end

      # with_params without Ada, for the plain shapes only (see above); anything else raises
      def pure_with_params(url, pairs)
        raise InvalidUrlError, 'Invalid URL' unless url.is_a?(String)

        m = PLAIN.match(url)
        res = m && WhatwgUrl.parse(url)
        if res.nil?
          parsed = WhatwgUrl.parse(url)
          raise InvalidUrlError, 'Invalid URL' if parsed.nil?
          # the request keeps the scheme, which assert_secure_transport would refuse: no serialiser needed to say so
          raise EntropyError.new('insecure_transport', 'QRNG: endpoint must be https (http only for loopback with allowInsecureLoopback)') unless %w[http https].include?(parsed['scheme'])

          raise ArgumentError, 'HttpQrngSource: this URL needs the Ada URL library to be serialised exactly (the platform gem carries it; or set ATLAS_PCA_LIBADA, or pass build_url)'
        end
        list = (m[1] || '').split('&').reject(&:empty?).map do |seg|
          name, value = seg.split('=', 2)
          [form_decode(name.to_s), form_decode(value.to_s)]
        end
        pairs.each do |k, v|
          k = utf8(k).force_encoding('UTF-8')
          v = utf8(v).force_encoding('UTF-8')
          at = list.index { |name, _| name == k }
          if at.nil?
            list << [k, v]
          else
            list[at] = [k, v]
            list = list.each_with_index.reject { |(name, _), i| i > at && name == k }.map(&:first)
          end
        end
        query = list.map { |name, value| "#{form_encode(name)}=#{form_encode(value)}" }.join('&')
        "#{res['htu']}#{query.empty? ? '' : "?#{query}"}#{m[2] ? "##{m[2]}" : ''}"
      end
    end

    module_function

    # JS Number.isInteger: an Integer, or a finite Float with no fraction
    def int?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite? && x == x.floor)
    def num?(x) = x.is_a?(Integer) || x.is_a?(Float)
    def bytes?(x) = x.is_a?(String)

    def js_num(x)
      return 'null' if x.nil?

      num?(x) ? Predicates.js_number_string(x) : x.to_s
    end

    # ---- QRNG sources --------------------------------------------------------------------------------------------

    # A QRNG source is any object with #name and #fetch(num_bytes) -> exactly num_bytes bytes (a binary String), raising on any
    # failure (network, auth, malformed or short response). Never return fewer bytes than asked for.

    # A source that always fails: makes the "no quantum entropy" path explicit and testable.
    class NullQrngSource
      attr_reader :name

      def initialize(reason = 'no QRNG source configured')
        @name = 'null-qrng'
        @reason = reason
      end

      def fetch(_num_bytes) = raise("QRNG unavailable: #{@reason}")
    end

    def unavailable_source(*reason) = NullQrngSource.new(*reason)

    # An HTTP QRNG endpoint (an ANU-style JSON body {success, data: [0..255, ...]}, a hex body or a base64 body) over a transport the
    # caller injects: transport.call(url, headers: {...}, redirect: 'error', timeout_ms: n) -> an object with #ok, #status, #json
    # (the parsed JSON body) and #text. The request must not follow redirects and must give up after timeout_ms (the call is also
    # cut off here). https only; http is accepted solely for localhost / 127.0.0.1 / [::1] with allow_insecure_loopback: true. The
    # API key travels in a header (default x-api-key), never in the URL, and never appears in an error. Every failure raises.
    class HttpQrngSource
      attr_reader :name

      def initialize(url:, api_key: nil, api_key_header: nil, format: nil, timeout_ms: nil, max_bytes: nil, length_param: nil,
                     extra_params: nil, build_url: nil, allow_insecure_loopback: false, transport: nil)
        raise TypeError, 'HttpQrngSource: `url` must be a non-empty string' unless url.is_a?(String) && !url.empty?

        max_bytes = DEFAULT_MAX_QRNG_BYTES if max_bytes.nil?
        raise TypeError, 'HttpQrngSource: `maxBytes` must be a positive integer' unless Entropy.int?(max_bytes) && max_bytes.positive?

        timeout_ms = DEFAULT_TIMEOUT_MS if timeout_ms.nil?
        raise TypeError, 'HttpQrngSource: `timeoutMs` must be a positive integer' unless Entropy.int?(timeout_ms) && timeout_ms.positive?

        @url = url
        @api_key = api_key
        @api_key_header = api_key_header.nil? ? 'x-api-key' : api_key_header
        @format = format.nil? ? 'anu-uint8' : format
        @timeout_ms = timeout_ms
        @max_bytes = max_bytes
        @length_param = length_param.nil? ? 'length' : length_param
        @extra_params = extra_params
        @build_url = build_url
        @allow_insecure_loopback = allow_insecure_loopback == true
        @transport = transport
        host = Url.parts(url)&.fetch('host')
        @name = "http-qrng(#{host.nil? || host.empty? ? 'unknown' : host})"
      end

      def inspect = "#<AtlasPca::Entropy::HttpQrngSource #{@name}>" # never print the key

      def fetch(num_bytes)
        Entropy.require_valid_count(num_bytes, @max_bytes)
        raise 'QRNG: no fetch implementation available in this runtime' if @transport.nil?

        url = request_url(num_bytes)
        Entropy.assert_secure_transport(url, @allow_insecure_loopback)
        headers = { 'accept' => 'application/json, text/plain' }
        headers[@api_key_header] = @api_key if @api_key.is_a?(String) && !@api_key.empty?
        res = begin
          Timeout.timeout(@timeout_ms / 1000.0) { @transport.call(url, headers: headers, redirect: 'error', timeout_ms: @timeout_ms) }
        rescue Timeout::Error
          raise 'QRNG: fetch failed (timeout)'
        rescue StandardError => e
          raise "QRNG: fetch failed (#{scrub(e.message)})"
        end
        raise "QRNG: endpoint returned HTTP #{Entropy.js_num(res.status)}" unless res.ok

        bytes = parse_body(res)
        raise "QRNG: expected #{Entropy.js_num(num_bytes)} bytes, response decoded to #{bytes.bytesize}" unless bytes.bytesize == num_bytes

        bytes
      end

      private

      def request_url(num_bytes)
        return @build_url.call(@url, num_bytes) if @build_url

        Url.with_params(@url, [[@length_param, Entropy.js_num(num_bytes)], *(@extra_params || {}).to_a])
      end

      def parse_body(res)
        return Entropy.parse_anu_uint8(res.json) if @format == 'anu-uint8'

        text = res.text
        text = text.gsub(JS_TRIM, '') if text.is_a?(String) && text.valid_encoding?
        @format == 'hex' ? Entropy.parse_hex(text) : Entropy.parse_base64(text)
      end

      def scrub(msg)
        @api_key.is_a?(String) && !@api_key.empty? ? msg.to_s.split(@api_key, -1).join('[redacted]') : msg.to_s
      end
    end

    def require_valid_count(num_bytes, max_bytes)
      raise TypeError, "QRNG: numBytes must be a positive integer, got #{js_num(num_bytes)}" unless int?(num_bytes) && num_bytes.positive?
      raise RangeError, "QRNG: requested #{js_num(num_bytes)} bytes exceeds per-request cap #{js_num(max_bytes)}" if num_bytes > max_bytes
    end

    # https only; plaintext http solely for a loopback host with the explicit opt-in. Checked on the URL about to be requested.
    def assert_secure_transport(url, allow_loopback)
      u = Url.parts(url)
      raise EntropyError.new('insecure_transport', 'QRNG: endpoint URL is not a valid URL') if u.nil?
      return if u['protocol'] == 'https:'
      return if u['protocol'] == 'http:' && allow_loopback == true && ['localhost', '127.0.0.1', '[::1]'].include?(u['hostname'])

      raise EntropyError.new('insecure_transport', 'QRNG: endpoint must be https (http only for loopback with allowInsecureLoopback)')
    end

    # The bytes of an ANU-style body {success?: true, data: [0..255, ...]} (already parsed JSON). Raises on anything else.
    def parse_anu_uint8(body)
      raise 'QRNG: response body is not a JSON object' unless body.is_a?(Hash) || body.is_a?(Array)
      raise 'QRNG: response `data` is not an array' if body.is_a?(Array)
      raise 'QRNG: response reports success=false' if body.key?('success') && body['success'] != true

      data = body['data']
      raise 'QRNG: response `data` is not an array' unless data.is_a?(Array)

      data.each_with_index.map do |v, i|
        raise "QRNG: response data[#{i}] is not a 0..255 integer" unless int?(v) && v >= 0 && v <= 255

        v.to_i
      end.pack('C*')
    end

    # The bytes of a hex body (either case, even length). Raises on anything else.
    def parse_hex(text)
      raise 'QRNG: malformed hex payload' unless text.is_a?(String) && text.match?(/\A[0-9a-fA-F]*\z/) && text.length.even?

      [text].pack('H*')
    end

    # The bytes of a standard-alphabet base64 body: padding optional, but padding that does not match the length is refused;
    # non-canonical trailing bits are dropped (the forgiving decode of the web platform). Raises on anything else.
    def parse_base64(text)
      text = text.nil? ? 'null' : text.to_s if text.nil? || text == true || text == false || text.is_a?(Integer) # the reference's String(x)
      raise 'QRNG: malformed base64 payload' unless text.is_a?(String) && text.match?(%r{\A[A-Za-z0-9+/]*={0,2}\z})

      s = (text.length % 4).zero? ? text.sub(/={1,2}\z/, '') : text
      raise 'QRNG: malformed base64 payload' if s.length % 4 == 1 || s.include?('=')

      Base64.decode64(s + ('=' * (-s.length % 4)))
    end

    # ---- SP 800-90B section 4.4 continuous health tests ----------------------------------------------------------------

    # Repetition count cutoff 1 + ceil(20 / h) for a claimed min-entropy of h bits per sample (false-positive rate 2^-20).
    def repetition_cutoff(h)
      x = 20.0 / h
      x.nan? || x.infinite? ? 1 + x : 1 + x.ceil
    end

    # Adaptive proportion cutoff for window w: the smallest count the binomial(w, 2^-h) tail leaves below 2^-20.
    def proportion_cutoff(h, w)
      p = FdLibm.pow(2.0, -h.to_f) # the reference's pow, bit for bit: the cutoff is compared as an integer
      target = 1 - FdLibm.pow(2.0, -20.0)
      pmf = FdLibm.pow(1 - p, w.to_f)
      cdf = pmf
      k = 0
      while cdf < target && k < w
        pmf *= ((w - k).to_f / (k + 1)) * (p / (1 - p))
        k += 1
        cdf += pmf
      end
      1 + k
    end

    # Both health tests over a buffer of bytes: {'ok' => true}, or {'ok' => false, 'test' => 'repetition-count' |
    # 'adaptive-proportion'}. `h` (default 8) is the claimed min-entropy per byte in [1, 8], `window` (default 512) an integer >= 2.
    # Fails closed: bad parameters and an empty buffer are a failure.
    def health_test_bytes(bytes, h: nil, window: nil)
      h = 8 if h.nil?
      w0 = window.nil? ? 512 : window
      fail_rc = { 'ok' => false, 'test' => 'repetition-count' }
      return fail_rc unless num?(h) && h >= 1 && h <= 8 && int?(w0) && w0 >= 2
      raise TypeError, 'healthTestBytes: `bytes` must be a byte string' unless bytes?(bytes)
      return fail_rc if bytes.empty?

      b = bytes.unpack('C*')
      rc = repetition_cutoff(h)
      run = 1
      (1...b.length).each do |i|
        run = b[i] == b[i - 1] ? run + 1 : 1
        return fail_rc if run >= rc
      end
      w = [w0.to_i, b.length].min
      ac = proportion_cutoff(h, w)
      start = 0
      while start + w <= b.length
        first = b[start]
        return { 'ok' => false, 'test' => 'adaptive-proportion' } if b[start, w].count(first) >= ac

        start += w
      end
      { 'ok' => true }
    end

    # ---- the combiner ----------------------------------------------------------------------------------------------------

    # UTF-8 bytes as the reference encodes a string: an unpaired surrogate becomes U+FFFD
    def utf8(s) = s.b.gsub(/\xED[\xA0-\xBF][\x80-\xBF]/n, "�".b).force_encoding('UTF-8').scrub("�").b

    # HKDF-SHA256 over the length-framed pair (local, quantum): `length` bytes (default: as many as `local`), bound to `context`.
    # `local` is the CSPRNG half and must be at least 16 bytes; `quantum` may be empty.
    def mix_entropy(local, quantum, length: nil, context: nil)
      raise TypeError, 'mixEntropy: `local` must be a Uint8Array' unless bytes?(local)
      raise TypeError, 'mixEntropy: `quantum` must be a Uint8Array' unless bytes?(quantum)
      raise RangeError, "mixEntropy: local CSPRNG must be >= #{MIN_LOCAL_BYTES} bytes (fail-closed)" if local.bytesize < MIN_LOCAL_BYTES

      length = local.bytesize if length.nil?
      raise RangeError, "mixEntropy: length must be an integer in 1..#{MAX_HKDF_OUTPUT}" unless int?(length) && length.positive? && length <= MAX_HKDF_OUTPUT
      context = nil if context == true || context == false || context.is_a?(Numeric) # no `.length` in the reference: the default label
      raise TypeError, 'mixEntropy: `context` must be a string' unless context.nil? || context.is_a?(String)

      length = length.to_i
      label = context.nil? || context.empty? ? MIX_LABEL.b : utf8("#{MIX_LABEL}/#{context}")
      ikm = [local.bytesize, quantum.bytesize].pack('N2') + local.b + quantum.b
      OpenSSL::KDF.hkdf(ikm, salt: MIX_SALT, info: label + [length].pack('N'), length: length, hash: 'SHA256')
    end

    # ---- secure seed -------------------------------------------------------------------------------------------------------

    def draw_local(impl, n)
      bytes = impl ? impl.call(n) : SecureRandom.random_bytes(n)
      raise 'secureSeed: local CSPRNG did not return the requested bytes (fail-closed)' unless bytes?(bytes) && bytes.bytesize == n

      bytes
    end

    # A seed of `length` bytes (default 32) from the local CSPRNG mixed with best-effort quantum entropy from `source`.
    # The source's answer must be exactly `quantum_bytes` bytes (default max(32, length)) and pass the health tests (`health_test`:
    # false disables them, {h:, window:} tunes them); any failure falls back to the CSPRNG alone and is reported to
    # `on_qrng_error` (a callable taking the error; what it raises is swallowed). `require_quantum: true` raises EntropyError
    # 'quantum_required' instead of falling back. `random_bytes` (a callable n -> bytes) replaces the CSPRNG in tests.
    # -> SecureSeedResult(seed, used_quantum, quantum_byte_count, source name or nil)
    def secure_seed(length: nil, source: nil, quantum_bytes: nil, local_bytes: nil, context: nil, require_quantum: false, health_test: nil,
                    on_qrng_error: nil, random_bytes: nil)
      length = DEFAULT_SEED_BYTES if length.nil?
      raise RangeError, "secureSeed: length must be an integer in 1..#{MAX_HKDF_OUTPUT}" unless int?(length) && length.positive? && length <= MAX_HKDF_OUTPUT

      local_bytes = [DEFAULT_SEED_BYTES, length].max if local_bytes.nil?
      raise RangeError, "secureSeed: localBytes must be an integer >= #{MIN_LOCAL_BYTES}" unless int?(local_bytes) && local_bytes >= MIN_LOCAL_BYTES

      quantum_bytes = [DEFAULT_SEED_BYTES, length].max if quantum_bytes.nil?
      raise RangeError, 'secureSeed: quantumBytes must be a positive integer' unless int?(quantum_bytes) && quantum_bytes.positive?

      local = draw_local(random_bytes, local_bytes.to_i)
      quantum = ''.b
      used = false
      source_name = nil
      if source
        source_name = source.name
        begin
          q = source.fetch(quantum_bytes.to_i)
          raise "QRNG: source returned #{bytes?(q) ? q.bytesize : 'non-bytes'}, expected #{js_num(quantum_bytes)}" unless bytes?(q) && q.bytesize == quantum_bytes

          unless health_test == false
            v = health_test_bytes(q, **(health_test || {}).to_h { |k, x| [k.to_sym, x] }.slice(:h, :window))
            raise EntropyError.new('health_test_failed', "QRNG: #{v['test'] || 'health'} test failed; source rejected") unless v['ok']
          end
          quantum = q.b
          used = true
        rescue StandardError, ScriptError => e
          quantum = ''.b
          used = false
          if on_qrng_error
            begin
              on_qrng_error.call(e)
            rescue StandardError, ScriptError
              nil # observability must never break key generation
            end
          end
        end
      end
      if require_quantum == true && !used
        raise EntropyError.new('quantum_required', 'secureSeed: quantum entropy is required but was not obtained (fail-closed)')
      end

      SecureSeedResult.new(mix_entropy(local, quantum, length: length, context: context), used, used ? quantum.bytesize : 0, source_name)
    end

    # An Ed25519 key pair whose 32-byte secret comes from secure_seed (context 'ed25519-key' unless one is given; a `length` is
    # ignored). -> EntropyKeyPair(secret_key, public_key (32 raw bytes), used_quantum)
    def generate_key_pair_with_entropy(**opts)
      context = opts[:context].nil? ? 'ed25519-key' : opts[:context]
      r = secure_seed(**opts, length: 32, context: context)
      EntropyKeyPair.new(r.seed, OpenSSL::PKey.new_raw_private_key('ED25519', r.seed).raw_public_key, r.used_quantum)
    end
  end
end
