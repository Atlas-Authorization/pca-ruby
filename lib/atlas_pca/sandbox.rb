# frozen_string_literal: true

require 'ipaddr'
require 'openssl'
require_relative 'js_compat'
require_relative 'whatwg_url'
require_relative 'runtime_claim'
require_relative 'fresh_at'

module AtlasPca
  # Policy logic of the PCA sandbox: runtime classes and signed runtime claims, the receipt hash chain, the capability handle table,
  # the egress admission policy, the OS-profile generators (seccomp / Landlock / macOS) and the reference WebAssembly tool builders.
  # Mirrors the TypeScript reference (@atlasauth/pca-sandbox); outputs are byte-identical. The egress proxy server is in
  # atlas_pca/sandbox_egress.
  #
  # The WebAssembly / component hosts are in atlas_pca/sandbox_wasm (opt-in). Not ported: the attestation-verifier glue
  # (trustFromAttestation). A class is a claim by the host operator; nothing here proves an OS profile was applied.
  # Options are String-keyed snake_case Hashes (expires_at, extra_imports, extra_import); data is String-keyed. Bytes are
  # binary Strings: an executor must return one, any other value is an executor_error.
  module Sandbox
    IMPORT_MODULE = 'pca:act'
    ALLOWED_IMPORTS = %w[invoke handle_count handle_verb].freeze
    USE_ERR = { 'unknown_handle' => -1, 'spent' => -2, 'out_too_small' => -3, 'bad_memory' => -4, 'executor_error' => -5, 'no_executor' => -6 }.freeze
    RUNTIME_CLASSES = %w[none os_confined egress_default_deny wasi_no_ambient].freeze
    GENESIS = 'genesis'
    RUNTIME_CLAIM_DOMAIN = "atlas-pca/runtime-class-claim/v1\0"
    UNDEF = Object.new.freeze # JS `undefined`
    MAX_SAFE = 9_007_199_254_740_991

    module_function

    # ------------------------------------------------------------------------------------------------ JS helpers
    # o[k] on a JSON value: UNDEF for a missing member or a non-object.
    def get(o, k) = o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF
    def nullish?(v) = v.nil? || v.equal?(UNDEF)
    def jt?(v) = !v.equal?(UNDEF) && Js.truthy?(v)
    def num?(v) = v.is_a?(Numeric)
    def isint?(v) = v.is_a?(Integer) || (v.is_a?(Float) && v.finite? && v == v.floor)
    def text(v) = v.equal?(UNDEF) ? 'undefined' : Js.string(v)

    # `for (const v of x ?? [])`: an array or a string iterates, any other value is not iterable.
    def iterate(x)
      return [] if nullish?(x)
      return x if x.is_a?(Array)
      return x.chars if x.is_a?(String)

      raise TypeError, 'not iterable'
    end

    # Property read on a result / operation: a Hash member, or a Struct / object attribute.
    def prop(o, k)
      case o
      when Hash then o.key?(k) ? o[k] : (o.key?(k.to_sym) ? o[k.to_sym] : UNDEF)
      when nil, true, false, String, Numeric, Array, Symbol then UNDEF
      else o.respond_to?(k) ? o.public_send(k) : UNDEF
      end
    end

    def now_ms = (Process.clock_gettime(Process::CLOCK_REALTIME) * 1000).to_i
    # a non-finite clock (a -Infinity one is "before" every expiry) never keeps a handle or admission live
    def live_at?(now, expires_at) = now.to_f.finite? && now < expires_at

    # ------------------------------------------------------------------------------------------------ runtime classes / receipts
    # True only when both names are known and `attested` is at least `required`. An unknown name never satisfies.
    def satisfies_runtime_class(attested, required)
      a = attested.is_a?(String) ? RUNTIME_CLASSES.index(attested) : nil
      r = required.is_a?(String) ? RUNTIME_CLASSES.index(required) : nil
      !a.nil? && !r.nil? && a >= r
    end

    # Append-only hash chain of use receipts: every handle use and every egress decision, refusals included.
    class ReceiptLog
      attr_reader :entries

      def initialize(now: nil, sign: nil)
        @entries = []
        @now = now || -> { Sandbox.now_ms }
        @sign = sign
      end

      def append(runtime_class, body)
        unsigned = { 'v' => 1, 'seq' => @entries.length, 'prev' => @entries.empty? ? GENESIS : @entries.last['digest'], 'at' => @now.call,
                     'runtime_class' => runtime_class }
        unsigned = unsigned.merge(body) # the body is spread last, as in the reference
        digest = AtlasPca.hash_canonical(unsigned)
        r = unsigned.merge('digest' => digest)
        r['sig'] = @sign.call(digest) if @sign
        @entries << r
        r
      end
    end

    # Recompute the chain. Fails on a bad digest, a broken link, a gap, a reorder, or (with verify_sig) a bad signature.
    def verify_receipt_chain(receipts, verify_sig = nil)
      raise TypeError, 'receipts is not iterable' unless receipts.is_a?(Array)

      prev = GENESIS
      receipts.each_with_index do |r, i|
        raise TypeError, 'receipt is null' if r.nil?

        v = get(r, 'v')
        seq = get(r, 'seq')
        return { 'ok' => false, 'at' => i, 'reason' => 'bad_seq' } unless num?(v) && v == 1 && num?(seq) && seq == i

        p = get(r, 'prev')
        return { 'ok' => false, 'at' => i, 'reason' => 'broken_link' } unless p.is_a?(String) && p == prev

        digest = get(r, 'digest')
        sig = get(r, 'sig')
        rest = r.reject { |k, _| %w[digest sig].include?(k) }
        return { 'ok' => false, 'at' => i, 'reason' => 'bad_digest' } unless digest.is_a?(String) && AtlasPca.hash_canonical(rest) == digest
        return { 'ok' => false, 'at' => i, 'reason' => 'bad_sig' } if verify_sig && !(sig.is_a?(String) && verify_sig.call(digest, sig))

        prev = digest
      end
      { 'ok' => true }
    end

    # ------------------------------------------------------------------------------------------------ authorized operations
    # True only if `result` allowed exactly this operation (verb, resource, params digest). `result` is an AuthorizeResult, or any
    # object / Hash with allow (or ok) and a bound operation {verb, resource, params_digest}.
    def authorized_for?(result, operation)
      allow = prop(result, 'allow')
      ok = allow.equal?(UNDEF) ? prop(result, 'ok') : allow
      bound = prop(result, 'operation')
      o = operation.is_a?(Hash) ? operation : nil
      valid = !o.nil? && o['verb'].is_a?(String) && o['verb'] != '' && o['resource'].is_a?(String) && o['resource'] != '' && o['params'].is_a?(Hash)
      return false unless jt?(ok) && jt?(bound) && valid

      prop(bound, 'verb') == o['verb'] && prop(bound, 'resource') == o['resource'] && prop(bound, 'params_digest') == AtlasPca.hash_canonical(o['params'])
    rescue StandardError
      false
    end

    # ------------------------------------------------------------------------------------------------ OS policy
    PATH_RE = %r{\A/[A-Za-z0-9._+@=,:~ /-]*\z}
    HOST_RE = /\A[a-z0-9]([a-z0-9.-]*[a-z0-9])?\z/

    # absolute, normalized, and only characters that need no escaping in a seccomp / Landlock / SBPL string: refuse, never escape
    def check_path(p)
      ok = p.is_a?(String) && p.valid_encoding? && PATH_RE.match?(p) && !p.include?('//') && !(p.length > 1 && p.end_with?('/')) &&
           p.split('/', -1).none? { |s| ['.', '..'].include?(s) }
      raise ArgumentError, 'bad_path' unless ok

      p
    end

    # Validate, merge and sort the needs of the authorized operations into a sandbox policy {v, fs: {read, write, exec},
    # net: {proxy, hosts}}. `write` implies read of the same path; network access exists only through the egress proxy.
    def policy_from_needs(needs, proxy_port = nil)
      raise TypeError, 'needs is not iterable' unless needs.is_a?(Array)

      read = {}
      write = {}
      ex = {}
      hosts = {}
      needs.each do |n|
        raise TypeError, 'need is null' if n.nil?

        iterate(get(n, 'fs')).each do |f|
          raise TypeError, 'fs entry is null' if f.nil?

          p = check_path(get(f, 'path'))
          mode = get(f, 'mode')
          if mode == 'x'
            ex[p] = true
          elsif %w[r rw].include?(mode)
            read[p] = true
            write[p] = true if mode == 'rw'
          else
            raise ArgumentError, 'bad_mode'
          end
        end
        iterate(get(n, 'net')).each do |h|
          raise TypeError, 'net entry is null' if h.nil?

          host = get(h, 'host')
          port = get(h, 'port')
          t = text(host)
          raise ArgumentError, 'bad_net_need' unless t.valid_encoding? && HOST_RE.match?(t) && isint?(port) && port >= 1 && port <= 65_535

          hosts["#{t}:#{Js.string(port)}"] = true
        end
      end
      raise ArgumentError, 'net_needs_proxy: network access exists only through the egress proxy; pass its port' if !hosts.empty? && proxy_port.nil?
      raise ArgumentError, 'bad_proxy_port' if !proxy_port.nil? && !(isint?(proxy_port) && proxy_port >= 1 && proxy_port <= 65_535)

      { 'v' => 1, 'fs' => { 'read' => read.keys.sort, 'write' => write.keys.sort, 'exec' => ex.keys.sort },
        'net' => { 'proxy' => proxy_port.nil? ? nil : { 'host' => '127.0.0.1', 'port' => proxy_port }, 'hosts' => hosts.keys.sort } }
    end

    # Compile the OS policy from what was actually authorized: only operations that authorized_for? allows contribute. `items` are
    # {'result', 'operation'}; needs_of.call(operation) is the tool author's mapping (a falsy value contributes nothing).
    def compile_policy(items, needs_of, proxy_port = nil)
      needs = []
      items.each do |it|
        raise ArgumentError, 'not_authorized: result does not allow exactly this operation' unless authorized_for?(it['result'], it['operation'])

        n = needs_of.call(it['operation'])
        needs << n if jt?(n)
      end
      policy_from_needs(needs, proxy_port)
    end

    BASE = %w[read write close fstat newfstatat statx lseek mmap mprotect munmap mremap brk madvise rt_sigaction rt_sigprocmask rt_sigreturn
              sigaltstack pread64 pwrite64 readv writev openat getdents64 fcntl getcwd readlink readlinkat dup dup3 pipe2 poll ppoll
              epoll_create1 epoll_ctl epoll_pwait eventfd2 futex set_tid_address set_robust_list rseq arch_prctl prlimit64 sched_yield
              nanosleep clock_nanosleep clock_gettime gettimeofday getrandom getpid gettid getuid geteuid getgid getegid uname tgkill exit
              exit_group].freeze
    NET = %w[connect getsockopt setsockopt getsockname getpeername sendto recvfrom sendmsg recvmsg shutdown].freeze
    EXEC = %w[execve execveat].freeze
    AF_INET = 2
    AF_INET6 = 10

    # Docker / OCI-format seccomp profile: deny by default; network syscalls only when the policy has a proxy; `socket` only for
    # AF_INET / AF_INET6; exec only when the grant names a binary. seccomp cannot see paths or addresses: pair it with Landlock.
    def seccomp_profile(p)
      syscalls = [{ 'names' => BASE.sort, 'action' => 'SCMP_ACT_ALLOW' }]
      if p['net']['proxy']
        syscalls << { 'names' => NET.sort, 'action' => 'SCMP_ACT_ALLOW' }
        [AF_INET, AF_INET6].each do |d|
          syscalls << { 'names' => ['socket'], 'action' => 'SCMP_ACT_ALLOW', 'args' => [{ 'index' => 0, 'value' => d, 'op' => 'SCMP_CMP_EQ' }] }
        end
      end
      syscalls << { 'names' => EXEC.dup, 'action' => 'SCMP_ACT_ALLOW' } if p['fs']['exec'].length.positive?
      { 'defaultAction' => 'SCMP_ACT_ERRNO', 'defaultErrnoRet' => 1,
        'archMap' => [{ 'architecture' => 'SCMP_ARCH_X86_64', 'subArchitectures' => [] },
                      { 'architecture' => 'SCMP_ARCH_AARCH64', 'subArchitectures' => [] }],
        'syscalls' => syscalls }
    end

    FS_HANDLED = %w[EXECUTE WRITE_FILE READ_FILE READ_DIR REMOVE_DIR REMOVE_FILE MAKE_CHAR MAKE_DIR MAKE_REG MAKE_SOCK MAKE_FIFO MAKE_BLOCK
                    MAKE_SYM REFER TRUNCATE].freeze

    # Landlock ruleset (access-right names from the kernel UAPI; network rules need ABI 4): handle every right, allow only what the
    # grant names.
    def landlock_ruleset(p)
      fp = p['fs']
      fs = (fp['read'] | fp['write'] | fp['exec']).sort.map do |path|
        access = []
        access += %w[EXECUTE READ_FILE] if fp['exec'].include?(path) # execve opens the binary for reading, so the kernel also demands READ_FILE
        access += %w[READ_FILE READ_DIR] if fp['read'].include?(path)
        access += %w[WRITE_FILE TRUNCATE MAKE_REG MAKE_DIR REMOVE_FILE REMOVE_DIR] if fp['write'].include?(path)
        { 'path' => path, 'access' => access.uniq.map { |x| "LANDLOCK_ACCESS_FS_#{x}" } }
      end
      proxy = p['net']['proxy']
      { 'v' => 1, 'abi_min' => 4, 'handled_access_fs' => FS_HANDLED.map { |x| "LANDLOCK_ACCESS_FS_#{x}" },
        'handled_access_net' => %w[LANDLOCK_ACCESS_NET_BIND_TCP LANDLOCK_ACCESS_NET_CONNECT_TCP],
        'rules' => { 'fs' => fs, 'net' => proxy ? [{ 'port' => proxy['port'], 'access' => ['LANDLOCK_ACCESS_NET_CONNECT_TCP'] }] : [] } }
    end

    # macOS sandbox profile (SBPL for sandbox-exec(1)): deny by default; paths were validated to need no escaping.
    def macos_profile(p)
      q = ->(s) { "\"#{Js.string(s)}\"" }
      lines = ['(version 1)', '(deny default)', '(allow sysctl-read)', '(allow process-fork)', '(allow mach-lookup)', '(allow file-read-metadata)',
               '(allow file-read* (literal "/") (literal "/dev/null") (literal "/dev/urandom") (subpath "/usr/lib") ' \
               '(subpath "/System/Library") (subpath "/private/var/db/dyld") (subpath "/System/Volumes/Preboot/Cryptexes"))']
      p['fs']['exec'].each { |x| lines.push("(allow process-exec (literal #{q.call(x)}))", "(allow file-read* (literal #{q.call(x)}))") }
      p['fs']['read'].each { |r| lines << "(allow file-read* (subpath #{q.call(r)}))" }
      p['fs']['write'].each { |w| lines << "(allow file-write* (subpath #{q.call(w)}))" }
      lines << "(allow network-outbound (remote tcp #{q.call("localhost:#{Js.string(p['net']['proxy']['port'])}")}))" if p['net']['proxy']
      "#{lines.join("\n")}\n"
    end

    # Flatten the generated seccomp and Landlock profiles into the flags of a reference `pca-confine <flags> -- <command>` helper, so
    # what the helper enforces is exactly what the generators produced.
    def confine_args(policy)
      ll = landlock_ruleset(policy)
      sc = seccomp_profile(policy)
      short = ->(n) { n.start_with?('LANDLOCK_ACCESS_') ? n['LANDLOCK_ACCESS_'.length..] : n }
      args = ['--fs-handled', ll['handled_access_fs'].map { |x| short.call(x) }.join(',')]
      args += ['--net-handled', ll['handled_access_net'].map { |x| short.call(x) }.join(',')] if ll['rules']['net'].length.positive? || policy['net']['proxy']
      ll['rules']['fs'].each { |r| args += ['--fs', "#{r['path']}:#{r['access'].map { |x| short.call(x) }.join(',')}"] }
      ll['rules']['net'].each { |r| args += ['--net', "#{Js.string(r['port'])}:#{r['access'].map { |x| short.call(x) }.join(',')}"] }
      sc['syscalls'].each do |s|
        if s['args'] && !s['args'].empty?
          s['args'].each { |a| s['names'].each { |n| args += ['--allow-arg', "#{n}:#{a['index']}:#{a['value']}"] } }
        else
          s['names'].each { |n| args += ['--allow', n] }
        end
      end
      args
    end

    # ------------------------------------------------------------------------------------------------ runtime claims
    CLAIM_KEYS = %w[v class passport_digest evidence_digest iat exp attestor sig].freeze

    def claim_body(c) = RUNTIME_CLAIM_DOMAIN.b + AtlasPca.canon_bytes(c)

    # A signed statement that a sandbox runs at `class`, bound to the signed passport (by digest) of the agent it contains. The
    # signer is an attestor the verifier pins. Signs domain || canonical(claim without sig) with Ed25519 (OpenSSL); raises on a key
    # that is not a 32-byte seed or a claim outside the strict canonical profile. public_key is the 32 raw bytes.
    def sign_runtime_claim(secret_key, public_key, c)
      unsigned = { 'v' => 1 }.merge(c)
      unsigned['attestor'] = AtlasPca.b64e(public_key.b)
      unsigned.merge('sig' => AtlasPca.b64e(KeyPair.new(secret_key).sign(claim_body(unsigned))))
    end

    # JS Array/String#includes for a string needle.
    def includes?(coll, x)
      return coll.any? { |y| y.is_a?(String) && y == x } if coll.is_a?(Array)
      return coll.include?(x) if coll.is_a?(String)

      raise TypeError, 'includes is not a function'
    end

    # A safe integer >= 0, never -0: a negative time is never valid.
    def nat?(v) = isint?(v) && !Js.neg_zero?(v) && v >= 0 && v <= MAX_SAFE

    # The class the claim proves, or 'none' for anything missing, unsigned, unpinned, expired, for another passport, over evidence
    # nobody verified, or malformed. trust is {'pinnedAttestors', 'passportDigest', 'verifiedEvidenceDigests', 'now'}. Total.
    def verified_runtime_class(claim, trust)
      c = claim
      return 'none' unless c.is_a?(Hash) && c.length == CLAIM_KEYS.length && c.keys.all? { |k| CLAIM_KEYS.include?(k) }
      return 'none' unless num?(c['v']) && c['v'] == 1 && c['class'].is_a?(String) && RUNTIME_CLASSES.include?(c['class'])
      return 'none' unless c['sig'].is_a?(String) && AtlasPca.k3_str?(c['attestor'], 128) && AtlasPca.k3_str?(c['passport_digest'], 128) &&
                           AtlasPca.k3_str?(c['evidence_digest'], 128) && includes?(get(trust, 'pinnedAttestors'), c['attestor'])

      now = get(trust, 'now')
      iat = c['iat']
      exp = c['exp']
      return 'none' unless c['passport_digest'] == get(trust, 'passportDigest') && nat?(iat) && nat?(exp) && nat?(now) && now >= iat && now < exp
      return 'none' unless includes?(get(trust, 'verifiedEvidenceDigests'), c['evidence_digest']) && !AtlasPca.b64d(c['attestor'], 32).nil?
      return 'none' if AtlasPca.b64d(c['sig'], 64).nil?

      rest = c.reject { |k, _| k == 'sig' }
      AtlasPca.verify_b64u(c['attestor'], claim_body(rest), c['sig']) ? c['class'] : 'none'
    rescue StandardError
      'none'
    end

    def passport_digest(signed_passport) = AtlasPca.hash_canonical(signed_passport)

    # The digest a claim's evidence_digest must equal for this attestation document.
    def evidence_digest(document) = AtlasPca.hash_canonical(document)

    # ------------------------------------------------------------------------------------------------ capability handles
    # A per-sandbox capability table: indices are small integers meaningful only inside one table, like file descriptors. A slot
    # exists only because a verified PCActn authorized exactly that operation, derivation is monotone (a child can only hold what the
    # parent gave up) and revoking a slot revokes everything derived from it. `executors` maps a verb to a callable op -> binary
    # String (the op is a private copy); the executor gets the signed params, never the guest's.
    class HandleTable
      attr_reader :runtime_class

      def initialize(runtime_class, log, executors, now = nil)
        @runtime_class = runtime_class
        @log = log
        @executors = executors
        @now = now || -> { Sandbox.now_ms }
        @slots = []
      end

      # Mint a handle for the operation `result` allowed. Raises (fail closed) if `result` does not allow exactly `operation`.
      def mint(result, operation, opts = nil)
        opts ||= {}
        if !opts['requires'].nil? && !Sandbox.satisfies_runtime_class(@runtime_class, opts['requires'])
          raise ArgumentError, "runtime_class_too_weak: table is #{@runtime_class}, grant requires #{opts['requires']}"
        end
        raise ArgumentError, 'not_authorized: result does not allow exactly this operation' unless Sandbox.authorized_for?(result, operation)

        bound = Sandbox.prop(result, 'operation')
        uses = Sandbox.nullish?(opts['uses']) ? 1 : opts['uses']
        raise ArgumentError, 'bad_uses' unless Sandbox.isint?(uses) && uses >= 1 && uses <= 1_000_000

        op = Marshal.load(Marshal.dump({ 'verb' => operation['verb'], 'resource' => operation['resource'], 'params' => operation['params'] }))
        bid = Sandbox.prop(bound, 'id')
        exp = opts['expires_at']
        push({ 'op' => op, 'params_digest' => AtlasPca.hash_canonical(op['params']), 'op_id' => Sandbox.nullish?(bid) ? '' : bid, 'uses' => uses,
               'expires_at' => Sandbox.nullish?(exp) ? Float::INFINITY : exp, 'revoked' => false, 'children' => [] })
      end

      # Derive a narrower handle: takes `uses` from the parent (never more than it has) and an expiry no later than its.
      def attenuate(index, narrower = nil)
        narrower ||= {}
        p = live(index)
        raise ArgumentError, 'unknown_handle' if p.nil?

        uses = Sandbox.nullish?(narrower['uses']) ? p['uses'] : narrower['uses']
        raise ArgumentError, 'attenuate_widens' unless Sandbox.isint?(uses) && uses >= 1 && uses <= p['uses']

        expires = Sandbox.nullish?(narrower['expires_at']) ? p['expires_at'] : narrower['expires_at']
        raise ArgumentError, 'attenuate_widens' unless expires.is_a?(Numeric) && expires <= p['expires_at']

        p['uses'] -= uses
        child = push(p.merge('op' => Marshal.load(Marshal.dump(p['op'])), 'uses' => uses, 'expires_at' => expires, 'revoked' => false, 'children' => []))
        p['children'] << child
        child
      end

      # Revoke a handle and, transitively, every handle derived from it.
      def revoke(index)
        s = slot(index)
        return if s.nil? || s['revoked']

        s['revoked'] = true
        s['children'].each { |c| revoke(c) }
        nil
      end

      def size = @slots.length

      def verb_of(index)
        s = slot(index)
        s.nil? ? nil : s['op']['verb']
      end

      # Run the executor on the authorized operation and record a receipt. A use is consumed before the executor runs and stays
      # consumed if it raises (a failed side effect needs a new authorization, not a retry on the old one).
      def use(index)
        s = slot(index)
        if s.nil?
          @log.append(@runtime_class, { 'kind' => 'handle_use', 'subject' => { 'op_id' => '', 'verb' => '', 'resource' => '', 'params_digest' => '' },
                                        'outcome' => 'refused', 'reason' => 'unknown_handle' })
          return { 'ok' => false, 'reason' => 'unknown_handle' }
        end
        lv = live(index)
        return finish(s, { 'ok' => false, 'reason' => 'spent' }) if lv.nil?

        ex = @executors[s['op']['verb']]
        return finish(s, { 'ok' => false, 'reason' => 'no_executor' }) unless ex

        lv['uses'] -= 1
        begin
          result = ex.call(Marshal.load(Marshal.dump(s['op'])))
          return finish(s, { 'ok' => false, 'reason' => 'executor_error' }) unless result.is_a?(String) && result.encoding == Encoding::BINARY

          finish(s, { 'ok' => true, 'result' => result.dup })
        rescue StandardError
          finish(s, { 'ok' => false, 'reason' => 'executor_error' })
        end
      end

      private

      def finish(s, r)
        outcome = r['ok'] ? 'ok' : (r['reason'] == 'executor_error' ? 'error' : 'refused')
        @log.append(@runtime_class, { 'kind' => 'handle_use', 'subject' => { 'op_id' => s['op_id'], 'verb' => s['op']['verb'],
                                                                              'resource' => s['op']['resource'], 'params_digest' => s['params_digest'] },
                                      'outcome' => outcome, 'reason' => r['ok'] ? 'used' : r['reason'] })
        r
      end

      def slot(index)
        index.is_a?(Numeric) && Sandbox.isint?(index) && index >= 1 && index <= @slots.length ? @slots[index.to_i - 1] : nil
      end

      def live(index)
        s = slot(index)
        !s.nil? && !s['revoked'] && s['uses'].positive? && Sandbox.live_at?(@now.call, s['expires_at']) ? s : nil
      end

      def push(s)
        @slots << s
        @slots.length
      end
    end

    # ------------------------------------------------------------------------------------------------ egress
    DEFAULT_PORT = { 'http' => 80, 'https' => 443 }.freeze
    EGRESS_HOST_RE = /\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\z/
    V4_SEG = '(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])'
    V4 = "(?:#{V4_SEG}\\.){3}#{V4_SEG}"
    V4_RE = /\A#{V4}\z/
    V6_SEG = '(?:[0-9a-fA-F]{1,4})'
    V6_RE = begin
      s = V6_SEG
      v = V4
      Regexp.new(
        '\A(?:' \
        "(?:#{s}:){7}(?:#{s}|:)|" \
        "(?:#{s}:){6}(?:#{v}|:#{s}|:)|" \
        "(?:#{s}:){5}(?::#{v}|(?::#{s}){1,2}|:)|" \
        "(?:#{s}:){4}(?:(?::#{s}){0,1}:#{v}|(?::#{s}){1,3}|:)|" \
        "(?:#{s}:){3}(?:(?::#{s}){0,2}:#{v}|(?::#{s}){1,4}|:)|" \
        "(?:#{s}:){2}(?:(?::#{s}){0,3}:#{v}|(?::#{s}){1,5}|:)|" \
        "(?:#{s}:){1}(?:(?::#{s}){0,4}:#{v}|(?::#{s}){1,6}|:)|" \
        "(?::(?:(?::#{s}){0,5}:#{v}|(?::#{s}){1,7}|:))" \
        ')(?:%[0-9a-zA-Z.:\-]{1,})?\z'
      )
    end

    def ipv4?(s) = s.is_a?(String) && s.valid_encoding? && V4_RE.match?(s)
    def ipv6?(s) = s.is_a?(String) && s.valid_encoding? && V6_RE.match?(s)
    def ip?(host) = ipv4?(host) || ipv6?(host)

    def private_v4?(a, b)
      a.zero? || a == 10 || a == 127 || (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ||
        (a == 100 && b >= 64 && b <= 127) || a >= 224
    end

    # Loopback, link-local, private, CGNAT, multicast, reserved and unspecified addresses, classified on the parsed address, not its
    # spelling. IPv6: only global unicast (2000::/3) is public; an IPv4-mapped, IPv4-compatible or NAT64 (64:ff9b::/96) address
    # follows its embedded IPv4 address; a zoned address (%id) is link-scoped, so private. Anything that is not an IP literal (or not
    # a string) counts as private (refused).
    def private_address?(ip)
      return true unless ip.is_a?(String)

      if ipv4?(ip)
        a, b = ip.split('.')[0, 2].map(&:to_i)
        return private_v4?(a, b)
      end
      return true if ip.include?('%') || !ipv6?(ip)

      w = IPAddr.new(ip).hton.unpack('n8')
      zero80 = w[0, 5].all?(&:zero?)
      nat64 = w[0] == 0x64 && w[1] == 0xff9b && w[2, 4].all?(&:zero?)
      return private_v4?(w[6] >> 8, w[6] & 0xff) if (zero80 && [0, 0xffff].include?(w[5])) || nat64

      w[0] < 0x2000 || w[0] >= 0x4000
    rescue StandardError
      true
    end

    def sha256_b64u(b) = AtlasPca.b64e(OpenSSL::Digest::SHA256.digest(b))

    ENC_PATH_RE = /%2[eEfF]|%5[cC]|\\/
    BAD_TEMPLATE_PATH_RE = %r{[?#\\]|%2[eEfF]|%5[cC]|(\A|/)\.\.?(/|\z)}
    CONNECT_RE = /\A([a-zA-Z0-9.\-]+|\[[0-9a-fA-F:]+\]):([0-9]{1,5})\z/

    # What the WHATWG URL class reports beyond the parse: whether the userinfo or the fragment is non-empty (http / https).
    def url_extras(url)
      s = url.sub(/\A[\x00-\x20]+/, '').sub(/[\x00-\x20]+\z/, '').delete("\t\n\r")
      m = s.match(/\A[A-Za-z][A-Za-z0-9+.\-]*:/)
      rest = m ? m.post_match : s
      frag = rest.index('#')
      hash_set = !frag.nil? && rest.length > frag + 1
      rest = rest[0, frag] if frag
      q = rest.index('?')
      rest = rest[0, q] if q
      rest = rest.sub(%r{\A[/\\]+}, '')
      cut = rest.index(%r{[/\\]})
      authority = cut ? rest[0, cut] : rest
      user = pw = ''
      if authority.include?('@')
        info = authority.rpartition('@')[0]
        user, _, pw = info.partition(':')
      end
      { 'userinfo' => user != '' || pw != '', 'hash' => hash_set }
    end

    def parse_target(req)
      m = get(req, 'method')
      raise TypeError, 'method.toUpperCase is not a function' unless m.is_a?(String)

      method = m.upcase
      url = get(req, 'url')
      if method == 'CONNECT'
        t = text(url).scrub("�")
        mm = CONNECT_RE.match(t)
        return { 'reason' => 'bad_connect_target' } unless mm

        host = mm[1].sub(/\A\[/, '').sub(/\]\z/, '').downcase
        return { 'connect' => true, 'scheme' => 'https', 'host' => host, 'port' => mm[2].to_i, 'path' => '', 'query' => '' }
      end
      t = text(url).scrub("�")
      u = WhatwgUrl.parse(t)
      return { 'reason' => 'not_absolute_url' } if u.nil?

      scheme = u['scheme']
      return { 'reason' => 'bad_url' } unless %w[http https].include?(scheme)

      ex = url_extras(t)
      return { 'reason' => 'bad_url' } if ex['userinfo'] || ex['hash']
      # encoded dots and slashes are how a prefix match is walked out of: refuse rather than decode
      return { 'reason' => 'encoded_path' } if ENC_PATH_RE.match?(u['pathname'])

      hostport = u['host']
      if hostport.start_with?('[')
        e = hostport.index(']')
        host = hostport[1...e]
        port_text = hostport[(e + 2)..]
      else
        host, _, port_text = hostport.partition(':')
      end
      { 'connect' => false, 'scheme' => scheme, 'host' => host.downcase, 'port' => port_text.nil? || port_text.empty? ? DEFAULT_PORT[scheme] : port_text.to_i,
        'path' => u['pathname'], 'query' => u['search'].sub(/\A\?/, '') }
    end

    # Default deny. The only way a request is allowed is by matching a template admitted from a verified operation. The template is
    # the one outbound request an operation maps to: {method, scheme, host, port?, path, path_prefix?, query?, body_sha256?, tunnel?},
    # exact host, port and method; the path exact unless path_prefix; the query must equal `query` (absent = none); a request with a
    # body must match body_sha256; `tunnel` admits a CONNECT to host:port instead.
    class EgressPolicy
      def initialize(now = nil)
        @admissions = []
        @now = now || -> { Sandbox.now_ms }
      end

      # Admit the request `operation` maps to. Raises unless `result` allows exactly `operation` and the template is well formed.
      def admit(result, operation, to_request, opts = nil)
        opts ||= {}
        raise ArgumentError, 'not_authorized: result does not allow exactly this operation' unless Sandbox.authorized_for?(result, operation)

        t = to_request.call(operation)
        raise ArgumentError, 'no_egress_for_operation' unless Sandbox.jt?(t)
        raise TypeError, 'template is not an object' unless t.is_a?(Hash)

        host = t['host']
        raise TypeError, 'host.toLowerCase is not a function' unless host.is_a?(String)
        raise ArgumentError, 'bad_template_host' unless host.valid_encoding? && (Sandbox.ip?(host) || EGRESS_HOST_RE.match?(host)) && host == host.downcase

        scheme = t['scheme']
        raise ArgumentError, 'bad_template_scheme' unless %w[http https].include?(scheme)

        port = Sandbox.nullish?(t['port']) ? DEFAULT_PORT[scheme] : t['port']
        raise ArgumentError, 'bad_template_port' unless Sandbox.isint?(port) && port >= 1 && port <= 65_535

        method = t['method']
        raise ArgumentError, 'bad_template_method' unless method.is_a?(String) && /\A[A-Z]+\z/.match?(method)

        path = t['path']
        raise TypeError, 't.path.startsWith is not a function' unless path.is_a?(String)
        raise ArgumentError, 'bad_template_path' unless path.valid_encoding? && path.start_with?('/') && !BAD_TEMPLATE_PATH_RE.match?(path)

        uses = Sandbox.nullish?(opts['uses']) ? 1 : opts['uses']
        raise ArgumentError, 'bad_uses' unless Sandbox.isint?(uses) && uses >= 1

        bound = Sandbox.prop(result, 'operation')
        bid = Sandbox.prop(bound, 'id')
        exp = opts['expires_at']
        @admissions << { 'op_id' => Sandbox.nullish?(bid) ? '' : bid, 'op' => operation, 'template' => t.merge('host' => host, 'port' => port),
                         'uses' => uses, 'expires_at' => Sandbox.nullish?(exp) ? Float::INFINITY : exp }
        nil
      end

      # Decide and, if allowed, spend one use of the matching admission. Anything not matched is denied with a reason.
      def claim(req)
        parsed = Sandbox.parse_target(req)
        return { 'allow' => false, 'reason' => parsed['reason'] } if parsed.key?('reason')

        body = req['body'] || ''.b
        why = 'no_admission'
        @admissions.each do |a|
          t = a['template']
          next if parsed['connect'] != (t['tunnel'] == true)
          next if !parsed['connect'] && t['method'] != req['method'].upcase
          next if !parsed['connect'] && parsed['scheme'] != t['scheme']
          next if parsed['host'] != t['host'] || parsed['port'] != t['port']

          unless parsed['connect']
            if Sandbox.jt?(t['path_prefix'])
              prefix = t['path'].end_with?('/') ? t['path'] : "#{t['path']}/"
              ok = parsed['path'] == t['path'] || parsed['path'].start_with?(prefix)
            else
              ok = parsed['path'] == t['path']
            end
            next unless ok

            if parsed['query'] != (Sandbox.nullish?(t['query']) ? '' : t['query'])
              why = 'query_mismatch'
              next
            end
            bh = t.key?('body_sha256') ? t['body_sha256'] : UNDEF
            if body.bytesize.positive? && (bh.equal?(UNDEF) || Sandbox.sha256_b64u(body) != bh)
              why = 'body_mismatch'
              next
            end
            if body.bytesize.zero? && !bh.equal?(UNDEF) && bh != Sandbox.sha256_b64u(body)
              why = 'body_mismatch'
              next
            end
          end
          if a['uses'] < 1 || !Sandbox.live_at?(@now.call, a['expires_at']) # reported only when the request would otherwise have matched
            why = 'spent'
            next
          end
          a['uses'] -= 1
          return { 'allow' => true, 'op_id' => a['op_id'],
                   'admission' => { 'verb' => a['op']['verb'], 'resource' => a['op']['resource'], 'params_digest' => AtlasPca.hash_canonical(a['op']['params']) } }
        end
        { 'allow' => false, 'reason' => why }
      end
    end

    # ------------------------------------------------------------------------------------------------ reference WebAssembly tools
    def leb_u(n)
      out = []
      loop do
        b = n & 0x7F
        n /= 128
        b |= 0x80 if n.positive?
        out << b
        return out unless n.positive?
      end
    end

    def wstr(x) = leb_u(Js.len16(x)) + Js.utf8(x).bytes
    def section(i, body) = [i] + leb_u(body.length) + body
    def vec(items) = leb_u(items.length) + items.flatten

    def sleb(n)
      n = ((n + (2**31)) % (2**32)) - (2**31) # the reference shifts int32 values
      out = []
      loop do
        b = n & 0x7F
        n >>= 7
        return out + [b] if (n.zero? && (b & 0x40).zero?) || (n == -1 && (b & 0x40) != 0)

        out << (b | 0x80)
      end
    end

    def i32c(n) = [0x41] + sleb(n.to_i)

    # A hand-assembled core-WebAssembly module that calls pca:act.invoke(handle, ptr, cap) for each given call and returns either the
    # last call's return code or the first byte of linear memory. spec: {'calls' => [{'handle','ptr','cap'}], 'returns' => 'last' |
    # 'byte0', 'extra_imports' => [{'module','name'}], 'memory' => {'min','max'}, 'spin' => bool}.
    def build_tool(spec)
      extra = spec['extra_imports'] || []
      types = vec([[0x60, 3, 0x7F, 0x7F, 0x7F, 1, 0x7F], [0x60, 0, 1, 0x7F], [0x60, 4, 0x7F, 0x7F, 0x7F, 0x7F, 1, 0x7F]])
      imports = vec([wstr('pca:act') + wstr('invoke') + [0, 0]] + extra.map { |e| wstr(e['module']) + wstr(e['name']) + [0, 2] })
      mem = spec['memory'] || { 'min' => 1, 'max' => 1 }
      memory = vec([mem['max'].nil? ? [0] + leb_u(mem['min'].to_i) : [1] + leb_u(mem['min'].to_i) + leb_u(mem['max'].to_i)])
      run_index = 1 + extra.length
      calls = spec['calls']
      returns = spec['returns'] || 'last'
      body = [0]
      calls.each_with_index do |c, i|
        body += i32c(c['handle']) + i32c(c['ptr']) + i32c(c['cap']) + [0x10, 0]
        body << 0x1A unless i == calls.length - 1 && returns == 'last'
      end
      body += [0x03, 0x40, 0x0C, 0x00, 0x0B] if jt?(spec['spin'])
      body += i32c(0) + [0x2D, 0, 0] if spec['returns'] == 'byte0'
      body += i32c(0) if calls.empty?
      body << 0x0B
      out = [0, 0x61, 0x73, 0x6D, 1, 0, 0, 0] + section(1, types) + section(2, imports) + section(3, vec([[1]])) + section(5, memory) +
            section(7, vec([wstr('memory') + [2, 0], wstr('run') + [0] + leb_u(run_index)])) + section(10, vec([leb_u(body.length) + body]))
      out.map { |b| b & 0xFF }.pack('C*')
    end

    # A tool that asks the table what it holds: returns handle_count() * 256 + first byte of handle 1's verb.
    def build_probe_tool(cap = 64)
      types = vec([[0x60, 3, 0x7F, 0x7F, 0x7F, 1, 0x7F], [0x60, 0, 1, 0x7F]])
      imports = vec([wstr('pca:act') + wstr('invoke') + [0, 0], wstr('pca:act') + wstr('handle_count') + [0, 1], wstr('pca:act') + wstr('handle_verb') + [0, 0]])
      body = [0] + i32c(1) + i32c(0) + i32c(cap) + [0x10, 2, 0x1A, 0x10, 1] + i32c(256) + [0x6C] + i32c(0) + [0x2D, 0, 0, 0x6A, 0x0B]
      out = [0, 0x61, 0x73, 0x6D, 1, 0, 0, 0] + section(1, types) + section(2, imports) + section(3, vec([[1]])) + section(5, vec([[1, 1, 1]])) +
            section(7, vec([wstr('memory') + [2, 0], wstr('run') + [0, 3]])) + section(10, vec([leb_u(body.length) + body]))
      out.map { |b| b & 0xFF }.pack('C*')
    end

    # The reference tool as a component in the WebAssembly text format: imports only pca:act/invoke@0.1.0 and exports
    # run: func() -> s32. Options: {'handle' => default 1, 'spin' => loop forever, 'extra_import' => an import the host must refuse}.
    def reference_component_wat(o = nil)
      o ||= {}
      imp = o['extra_import']
      extra = jt?(imp) ? "(import \"#{Js.string(imp)}\" (instance (export \"get-arguments\" (func (result (list string))))))" : ''
      handle = nullish?(o['handle']) ? 1 : o['handle']
      body = if jt?(o['spin'])
               '(loop $l (br $l)) (i32.const 0)'
             else
               "(call $invoke (i32.const #{Js.string(handle)}) (i32.const 16))\n" \
                 "       (if (result i32) (i32.load8_u (i32.const 16))\n" \
                 "         (then (i32.load (i32.const 20)))\n" \
                 '         (else (i32.load8_u (i32.load (i32.const 20)))))'
             end
      "(component\n" \
        "  (import \"pca:act/invoke@0.1.0\" (instance $inv\n" \
        "    (export \"handle-count\" (func (result u32)))\n" \
        "    (export \"invoke\" (func (param \"handle\" u32) (result (result (list u8) (error s32)))))))\n" \
        "  #{extra}\n" \
        "  (core module $libc\n" \
        "    (memory (export \"memory\") 1 1)\n" \
        "    (global $bump (mut i32) (i32.const 1024))\n" \
        "    (func (export \"realloc\") (param $old i32) (param $oldsz i32) (param $align i32) (param $new i32) (result i32)\n" \
        "      (local $p i32)\n" \
        "      (local.set $p (global.get $bump))\n" \
        "      (global.set $bump (i32.add (local.get $p) (local.get $new)))\n" \
        "      (local.get $p)))\n" \
        "  (core instance $libc (instantiate $libc))\n" \
        "  (alias core export $libc \"memory\" (core memory $mem))\n" \
        "  (alias core export $libc \"realloc\" (core func $realloc))\n" \
        "  (core func $count (canon lower (func $inv \"handle-count\")))\n" \
        "  (core func $invoke (canon lower (func $inv \"invoke\") (memory $mem) (realloc $realloc)))\n" \
        "  (core module $main\n" \
        "    (import \"libc\" \"memory\" (memory 1))\n" \
        "    (import \"host\" \"count\" (func $count (result i32)))\n" \
        "    (import \"host\" \"invoke\" (func $invoke (param i32 i32)))\n" \
        "    (func (export \"run\") (result i32)\n" \
        "      #{body}))\n" \
        "  (core instance $host (export \"count\" (func $count)) (export \"invoke\" (func $invoke)))\n" \
        "  (core instance $main (instantiate $main (with \"libc\" (instance $libc)) (with \"host\" (instance $host))))\n" \
        "  (alias core export $main \"run\" (core func $run))\n" \
        "  (func $lifted (result s32) (canon lift (core func $run)))\n" \
        "  (export \"run\" (func $lifted)))\n"
    end
  end
end
