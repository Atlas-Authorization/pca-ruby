# frozen_string_literal: true

require 'socket'
require 'openssl'
require 'timeout'
require 'uri'
require_relative 'sandbox'

module AtlasPca
  module Sandbox
    # The egress forward proxy of the PCA sandbox (stdlib sockets, one thread per connection): the server side of EgressPolicy.
    #
    # Set it as a non-WASM tool's only route out. Every request is claimed against the admissions; a refusal answers 403 and is
    # receipted. The upstream address is resolved here and checked with Sandbox.private_address? BEFORE connecting, and the
    # connection goes to the checked address, so an admitted hostname cannot be re-pointed at an internal service (no DNS rebinding
    # window). Fail closed: anything the parser does not fully understand is refused.
    #
    # Stricter than the TypeScript server: a request body must carry Content-Length (Transfer-Encoding on a request is refused with
    # 400, so there is no chunked-framing ambiguity), the connection is closed after every response, and an upstream address that is
    # not an IP literal after resolution counts as private.
    class EgressProxy
      HOP = %w[connection keep-alive proxy-authenticate proxy-authorization proxy-connection te trailer transfer-encoding upgrade host].freeze
      MAX_HEAD = 65_536
      REASONS = { 200 => 'OK', 400 => 'Bad Request', 403 => 'Forbidden', 413 => 'Payload Too Large', 431 => 'Header Fields Too Large',
                  502 => 'Bad Gateway' }.freeze

      class Refused < StandardError
        attr_reader :status

        def initialize(status, reason)
          super(reason)
          @status = status
        end
      end

      attr_reader :port

      # ssl_context: how to verify https upstreams (default: system trust).
      def initialize(policy, log, runtime_class: 'egress_default_deny', allow_private: false, max_body_bytes: 1 << 20,
                     upstream_timeout_ms: 10_000, host: '127.0.0.1', port: 0, ssl_context: nil)
        @policy = policy
        @log = log
        @cls = runtime_class
        @allow_private = allow_private
        @max_body = max_body_bytes
        @timeout = upstream_timeout_ms / 1000.0
        @host = host
        @want_port = port
        @ssl = ssl_context
        @lock = Mutex.new
        @port = 0
        @conns = []
      end

      def start
        @server = TCPServer.new(@host, @want_port)
        @port = @server.addr[1]
        @acceptor = Thread.new do
          loop do
            sock = @server.accept
            t = Thread.new(sock) { |s| handle(s) }
            @lock.synchronize { @conns << t }
          end
        rescue IOError, SystemCallError
          nil
        end
        self
      end

      def close
        @server&.close
        @acceptor&.join(1)
        @lock.synchronize { @conns.dup }.each { |t| t.join(@timeout + 1) }
        nil
      end

      private

      def receipt(method, url, d, outcome, reason)
        a = d['admission'] || {}
        allow = d['allow']
        @lock.synchronize do
          @log.append(@cls, { 'kind' => 'egress', 'subject' => {
            'op_id' => allow ? d['op_id'] : '', 'verb' => allow ? (a['verb'] || '') : '',
            'resource' => allow ? (a['resource'] || '') : "#{method} #{url}"[0, 256], 'params_digest' => allow ? (a['params_digest'] || '') : ''
          }, 'outcome' => outcome, 'reason' => reason })
        end
      end

      def claim(req) = @lock.synchronize { @policy.claim(req) }

      # The first resolved address, after every resolved address passed the private-address rule (a literal is checked as is).
      def resolve(host, port)
        addrs = Addrinfo.getaddrinfo(host, port, nil, :STREAM).map(&:ip_address)
        raise Errno::EACCES if addrs.empty? || (!@allow_private && addrs.any? { |a| Sandbox.private_address?(a) })

        addrs.first
      end

      def reply(sock, status, body = '')
        head = "HTTP/1.1 #{status} #{REASONS.fetch(status, 'Error')}\r\nconnection: close\r\ncontent-length: #{body.bytesize}\r\n" \
               "#{body.empty? ? '' : "content-type: application/json\r\n"}\r\n"
        sock.write(head + body)
      rescue SystemCallError, IOError
        nil
      end

      def deny(sock, method, url, reason, status = 403)
        receipt(method, url, { 'allow' => false, 'reason' => reason }, 'refused', reason)
        reply(sock, status, %({"error":"egress_denied","reason":"#{reason}"}))
      end

      def read_head(sock, buf = ''.b)
        until (i = buf.index("\r\n\r\n"))
          raise Refused.new(431, 'head_too_large') if buf.bytesize > MAX_HEAD

          chunk = sock.readpartial(8192)
          buf << chunk.b
        end
        raise Refused.new(431, 'head_too_large') if i + 4 > MAX_HEAD

        head = buf[0, i].force_encoding('ISO-8859-1')
        rest = buf[(i + 4)..]
        lines = head.split("\r\n", -1)
        headers = lines[1..].map do |ln|
          k, sep, v = ln.partition(':')
          raise Refused.new(400, 'bad_header') if sep.empty? || k.empty? || k != k.strip || k.match?(/[ \t]/)

          [k.downcase, v.strip]
        end
        [lines[0], headers, rest.b]
      end

      def unique(headers, name)
        vals = headers.select { |k, _| k == name }.map(&:last).uniq
        raise Refused.new(400, "duplicate_#{name.tr('-', '_')}") if vals.length > 1

        vals.first
      end

      def handle(sock)
        serve(sock)
      rescue EOFError, SystemCallError, IOError
        nil
      rescue StandardError
        reply(sock, 502) # never leak an internal error shape to the tool
      ensure
        begin
          sock.close
        rescue StandardError
          nil
        end
      end

      def serve(sock)
        begin
          line, headers, rest = read_head(sock)
          parts = line.split(' ', -1)
          raise Refused.new(400, 'bad_request_line') unless parts.length == 3 && parts[2].start_with?('HTTP/1.')

          method = parts[0]
          url = parts[1]
          raise Refused.new(400, 'transfer_encoding') if headers.any? { |k, _| k == 'transfer-encoding' }

          cl = unique(headers, 'content-length')
          raise Refused.new(400, 'bad_content_length') unless cl.nil? || cl.match?(/\A[0-9]+\z/)

          n = cl.to_i
        rescue Refused => e
          return deny(sock, '', '', e.message, e.status)
        end
        return connect(sock, url) if method.upcase == 'CONNECT'
        return deny(sock, method, url, 'body_too_large', 413) if !(n <= @max_body)

        body = rest.byteslice(0, n) || ''.b
        body << sock.read(n - body.bytesize).to_s.b while body.bytesize < n && !sock.eof?
        raise EOFError if body.bytesize < n

        d = claim({ 'method' => method, 'url' => url, 'body' => body })
        return deny(sock, method, url, d['reason']) unless d['allow']

        u = URI.parse(url)
        host = u.hostname.to_s
        port = u.port || (u.scheme == 'https' ? 443 : 80)
        begin
          up = open_upstream(host, port, u.scheme == 'https')
        rescue StandardError => e
          receipt(method, url, d, 'error', "upstream:#{e.is_a?(Errno::EACCES) ? 'EACCES' : e.class.name.split('::').last}"[0, 64])
          return reply(sock, 502)
        end
        forward(sock, up, u, method, url, headers, body, d)
      end

      def open_upstream(host, port, tls)
        addr = resolve(host, port)
        raw = Timeout.timeout(@timeout) { TCPSocket.new(addr, port) }
        return raw unless tls

        ctx = @ssl || OpenSSL::SSL::SSLContext.new.tap { |c| c.set_params }
        s = OpenSSL::SSL::SSLSocket.new(raw, ctx)
        s.hostname = host
        Timeout.timeout(@timeout) { s.connect }
        s.post_connection_check(host)
        s
      rescue StandardError
        raw&.close
        raise
      end

      def forward(sock, up, u, method, url, headers, body, d)
        sent = false
        status = '502'
        path = (u.path.to_s.empty? ? '/' : u.path) + (u.query ? "?#{u.query}" : '')
        out = ["#{method} #{path} HTTP/1.1", "host: #{u.host}#{u.port == u.default_port ? '' : ":#{u.port}"}", 'connection: close']
        out += headers.reject { |k, _| HOP.include?(k) }.map { |k, v| "#{k}: #{v}" }
        up.write("#{out.join("\r\n")}\r\n\r\n".b + body)
        sline, uh, leftover = Timeout.timeout(@timeout) { read_head(up) }
        sent = true
        status = sline.split(' ')[1] || '502'
        keep = uh.reject { |k, _| HOP.include?(k) && k != 'transfer-encoding' }.map { |k, v| "#{k}: #{v}" }
        sock.write("#{sline}\r\n#{(keep + ['connection: close']).join("\r\n")}\r\n\r\n".b + leftover)
        loop do
          chunk = Timeout.timeout(@timeout) { up.readpartial(65_536) }
          sock.write(chunk)
        end
      rescue EOFError
        if sent
          receipt(method, url, d, 'ok', "status:#{status}")
        else
          receipt(method, url, d, 'error', 'upstream:EOFError')
          reply(sock, 502)
        end
      rescue StandardError => e
        receipt(method, url, d, 'error', "upstream:#{e.class.name.split('::').last}"[0, 64])
        reply(sock, 502) unless sent
      ensure
        up.close
      end

      def connect(sock, target)
        d = claim({ 'method' => 'CONNECT', 'url' => target })
        return deny(sock, 'CONNECT', target, d['reason']) unless d['allow']

        host, _, port_text = target.rpartition(':')
        host = host.delete_prefix('[').delete_suffix(']')
        begin
          up = open_upstream(host, port_text.to_i, false)
        rescue StandardError => e
          receipt('CONNECT', target, d, 'error', "upstream:#{e.is_a?(Errno::EACCES) ? 'EACCES' : 'error'}")
          return reply(sock, 502)
        end
        receipt('CONNECT', target, d, 'ok', 'tunnel')
        sock.write("HTTP/1.1 200 Connection Established\r\n\r\n")
        pump = lambda do |src, dst|
          loop { dst.write(src.readpartial(65_536)) }
        rescue EOFError, SystemCallError, IOError
          begin
            dst.close_write
          rescue StandardError
            nil
          end
        end
        t = Thread.new { pump.call(up, sock) }
        pump.call(sock, up)
        t.join
      ensure
        up&.close
      end
    end
  end
end
