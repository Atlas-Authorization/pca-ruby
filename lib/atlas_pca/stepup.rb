# frozen_string_literal: true

# Step-up client for the principal's device: list, approve and deny PCA step-ups.
#
# A step-up is a co-signature request: an action whose risk needs more than the agent's signature. The principal's device
# signs the step-up's threshold message with its Ed25519 key and the instance anchors the action once enough roles have
# signed.
#
# * `dashboard_url` plus a dashboard bearer token (a service key or a console session token) serve
#   GET/POST .../pca/stepups (list, deny). Deny needs an owner or admin role.
# * `instance_url` (the Atlas instance the agent talks to) serves the public, self-authenticating
#   POST /v1/pca/stepups/<id>/cosign; the device signature is the credential.
#
# The device key is a SOFTWARE key (the PCA principal key must be Ed25519): the seed lives in the SecretStore you give it.
# FileSecretStore writes a mode-0600 file; for a phone or desktop app back it with the platform keystore and gate approvals
# behind user presence. Standard library plus the openssl extension; HTTP redirects are never followed, so a bearer token
# never follows a redirect to another host.
require 'json'
require 'net/http'
require 'uri'

module AtlasPca
  module StepUp
    # Base of every step-up client error.
    class Error < StandardError; end
    # No principal key is stored on this device.
    class NoDeviceKey < Error; end
    # The secret is not a base64url 32-byte Ed25519 seed.
    class InvalidSecret < Error; end
    # The step-up's threshold message is not canonical base64url.
    class InvalidThresholdMessage < Error; end
    # The server refused the signature (403): this key is not the grant's principal.
    class PrincipalMismatch < Error; end
    # The request failed on the network or the answer was unreadable.
    class TransportError < Error; end

    # The server answered with an error status.
    class ApiError < Error
      attr_reader :status

      def initialize(status, message)
        super(message)
        @status = status
      end
    end

    # Where the 32-byte Ed25519 seed is persisted: #load -> String(32 bytes) | nil, #save(seed), #delete.
    class SecretStore
      def load = raise(NotImplementedError)
      def save(_secret) = raise(NotImplementedError)
      def delete = raise(NotImplementedError)
    end

    # In-memory store, for tests and previews only.
    class MemorySecretStore < SecretStore
      def initialize
        super
        @v = nil
      end

      def load = @v&.dup
      def save(secret) = (@v = secret.b.dup)
      def delete = (@v = nil)
    end

    # A file holding the seed as base64url, created with mode 0600.
    class FileSecretStore < SecretStore
      def initialize(path)
        super()
        @path = path
      end

      def load
        AtlasPca.b64d(File.read(@path, encoding: 'US-ASCII').strip)
      rescue Errno::ENOENT
        nil
      end

      def save(secret)
        File.open(@path, File::WRONLY | File::CREAT | File::TRUNC, 0o600) { |f| f.write(AtlasPca.b64e(secret.b)) }
        File.chmod(0o600, @path)
      end

      def delete
        File.delete(@path)
      rescue Errno::ENOENT
        nil
      end
    end

    # The principal's Ed25519 device key, held in a SecretStore.
    class PrincipalDeviceKey
      def initialize(store)
        @store = store
      end

      def exists?
        !@store.load.nil?
      rescue StandardError
        false
      end

      # Generate a fresh key (replacing any existing one). Returns the public key (base64url) to register as the grant's principal.
      def generate
        seed = OpenSSL::Random.random_bytes(32)
        @store.save(seed)
        AtlasPca.b64e(PrincipalDeviceKey.pkey(seed).raw_public_key)
      end

      # Import an existing principal secret (a base64url 32-byte seed). It MUST match the grant's principal. Returns the public key.
      def import_secret(secret_b64u)
        raw = AtlasPca.b64d(secret_b64u, 32)
        raise InvalidSecret, 'The secret must be a base64url 32-byte Ed25519 seed.' if raw.nil?

        @store.save(raw)
        AtlasPca.b64e(PrincipalDeviceKey.pkey(raw).raw_public_key)
      end

      # The secret (base64url seed) for backup or migration. Treat it like a password.
      def export_secret = AtlasPca.b64e(seed)

      # The public key (base64url), as registered on the grant.
      def public_key = AtlasPca.b64e(PrincipalDeviceKey.pkey(seed).raw_public_key)

      # Ed25519-sign `message`; returns the signature as base64url.
      def sign(message) = AtlasPca.b64e(PrincipalDeviceKey.pkey(seed).sign(nil, message.b))

      # Remove the key from storage.
      def delete = @store.delete

      def self.pkey(seed) = OpenSSL::PKey.new_raw_private_key('ED25519', seed)

      private

      def seed
        s = @store.load
        raise NoDeviceKey, 'No principal device key is stored.' if s.nil?
        raise InvalidSecret, 'The stored secret is not a 32-byte seed.' unless s.bytesize == 32

        s.b
      end
    end

    PendingStepUp = Struct.new(:id, :grant_ref, :action_verb, :action_resource, :required_t, :threshold_message, :expires_at,
                               keyword_init: true)
    # status: the server's status text (e.g. 'anchored' or 'pending'); anchored: true when the action is now anchored (200 and
    # allow), false on 202 (more roles are still required).
    ApproveResult = Struct.new(:status, :anchored, :http_status, keyword_init: true)

    ISO = /\A(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?Z\z/

    # '2026-10-06T18:00:00.123Z' (fraction optional, always UTC from the API) to epoch ms.
    def self.parse_iso(s)
      m = ISO.match(s) or raise ArgumentError, 'bad timestamp'
      y, mo, d, h, mi, se = (1..6).map { |i| m[i].to_i }
      frac = (m[7] || '0').ljust(3, '0')[0, 3].to_i
      Time.utc(y, mo, d, h, mi, se).to_i * 1000 + frac
    end

    def self.base(url)
      u = URI.parse(url.to_s)
      raise ArgumentError, "a step-up URL must be an http(s) URL: #{url.inspect}" unless %w[http https].include?(u.scheme) && !u.host.to_s.empty?

      url.sub(%r{/+\z}, '')
    rescue URI::InvalidURIError
      raise ArgumentError, "a step-up URL must be an http(s) URL: #{url.inspect}"
    end

    # encodeURIComponent-style escaping of a path segment (everything but A-Za-z0-9 - _ . ~).
    def self.seg(s)
      s.to_s.b.gsub(/[^A-Za-z0-9\-_.~]/n) { |c| format('%%%02X', c.ord) }
    end

    # The built-in transport: ->(method, url, headers, body) -> [status, text]; never follows a redirect.
    def self.net_transport(timeout)
      lambda do |method, url, headers, body|
        uri = URI.parse(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.open_timeout = http.read_timeout = timeout
        req = Net::HTTPGenericRequest.new(method, !body.nil?, true, uri.request_uri, headers)
        res = http.request(req, body)
        [res.code.to_i, res.body.to_s.dup.force_encoding('UTF-8')]
      rescue SystemCallError, IOError, Timeout::Error, SocketError, OpenSSL::SSL::SSLError => e
        raise TransportError, e.message
      end
    end

    # Lists, approves and denies PCA step-ups from the principal's device.
    #
    # `token` is a callable returning the dashboard bearer token (called per request). `transport` ->(method, url, headers,
    # body) { [status, text] } replaces the built-in HTTP client (tests, proxies); it raises TransportError on a network
    # failure. `now` is the clock, a callable returning epoch ms.
    class Client
      attr_reader :key

      def initialize(dashboard_url, instance_url, account_id, instance_id, key, token, transport: nil, now: nil, timeout: 30.0)
        @dash = StepUp.base(dashboard_url)
        @inst = StepUp.base(instance_url)
        @acct = account_id
        @instance_id = instance_id
        @key = key
        @token = token
        @http = transport || StepUp.net_transport(timeout)
        @now = now || -> { (Time.now.to_f * 1000).to_i }
      end

      # Pending, not-yet-expired step-ups.
      def pending
        _, text = call('GET', "#{stepups_url}?status=pending", auth)
        items = begin
          JSON.parse(text)['stepups']
        rescue StandardError
          nil
        end
        raise TransportError, 'Unreadable step-up list.' unless items.is_a?(Array)

        t = @now.call
        items.filter_map do |o|
          exp = StepUp.parse_iso(o['expires_at'])
          next nil if exp <= t

          a = o['action']
          req_t = o['required_t']
          raise ArgumentError, 'required_t' unless req_t.is_a?(Integer)

          PendingStepUp.new(id: str(o['id']), grant_ref: str(o['grant_ref']), action_verb: str(a['verb']),
                            action_resource: str(a['resource']), required_t: req_t,
                            threshold_message: str(o['threshold_message']), expires_at: exp)
        rescue StandardError
          raise TransportError, 'Unreadable step-up entry.'
        end
      end

      # Sign the step-up's threshold message with the device key and submit it. Raises PrincipalMismatch (server 403) when
      # this key is not the grant's principal.
      def approve(step_up)
        message = AtlasPca.b64d(step_up.threshold_message)
        raise InvalidThresholdMessage, "The step-up's threshold message is not canonical base64url." if message.nil?

        payload = JSON.generate({ 'role' => 'principal', 'publicKey' => @key.public_key, 'sig' => @key.sign(message) })
        url = "#{@inst}/v1/pca/stepups/#{StepUp.seg(step_up.id)}/cosign"
        status, text = call('POST', url, { 'Content-Type' => 'application/json', 'Accept' => 'application/json' }, payload)
        obj = begin
          JSON.parse(text)
        rescue StandardError
          {}
        end
        obj = {} unless obj.is_a?(Hash)
        # 200 + allow:true = anchored; 202 = more roles still required
        ApproveResult.new(status: obj['status'].is_a?(String) ? obj['status'] : '', anchored: obj['allow'] == true, http_status: status)
      end

      # Deny a pending step-up (dashboard endpoint; audited; owner or admin).
      def deny(step_up, reason = nil)
        call('POST', "#{stepups_url}/#{StepUp.seg(step_up.id)}/deny", auth.merge('Content-Type' => 'application/json'),
             JSON.generate(reason.nil? ? {} : { 'reason' => reason }))
        nil
      end

      private

      def stepups_url
        "#{@dash}/v1/dashboard/accounts/#{StepUp.seg(@acct)}/instances/#{StepUp.seg(@instance_id)}/pca/stepups"
      end

      def auth = { 'Authorization' => "Bearer #{@token.call}", 'Accept' => 'application/json' }

      def call(method, url, headers, body = nil)
        status, text = @http.call(method, url, headers, body)
        unless status >= 200 && status < 300
          msg = begin
            JSON.parse(text)['errors'][0]['message'].to_s
          rescue StandardError
            'The request failed.'
          end
          raise PrincipalMismatch, msg if status == 403

          raise ApiError.new(status, msg)
        end
        [status, text]
      end

      def str(v)
        raise ArgumentError, 'expected a string' unless v.is_a?(String)

        v
      end
    end
  end
end

module AtlasPca
  StepUpClient = StepUp::Client
  PrincipalDeviceKey = StepUp::PrincipalDeviceKey
  SecretStore = StepUp::SecretStore
  MemorySecretStore = StepUp::MemorySecretStore
  FileSecretStore = StepUp::FileSecretStore
end
