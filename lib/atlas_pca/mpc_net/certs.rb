# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'openssl'
require 'securerandom'
require_relative 'clock'

module AtlasPca
  module Mpc
    module Net
      # Per-run identity material for the TLS mesh: one P-256 key and one self-signed certificate per node, built with the openssl
      # gem (no hand-rolled crypto, no X.509 code of our own). The keys live only on the node that generated them; only the PUBLIC
      # certificates are exchanged and pinned (by the SHA-256 of their DER encoding).
      module Certs
        # PEM texts of one node's key (PKCS#8) and self-signed certificate
        Pem = Struct.new(:key_pem, :cert_pem)
        # where generate_identity wrote them
        Identity = Struct.new(:key_path, :cert_path)

        ORDER = OpenSSL::PKey::EC::Group.new('prime256v1').order.to_i
        VALID_SECONDS = 2 * 24 * 3600

        module_function

        # a fresh random key and a self-signed certificate (valid 2 days: per-run, throw-away) for cn
        def generate_pem(cn) = build(cn, OpenSSL::PKey::EC.generate('prime256v1'))

        # DETERMINISTIC key from a seed (tests only: the scalar is sha256(seed) reduced into [1, n-1]); the certificate is
        # self-signed when called, so nothing is committed
        def seeded_pem(seed, cn)
          d = (Digest::SHA256.digest("atlas-pca-mpc/test-identity/#{seed}".b).unpack1('H*').to_i(16) % (ORDER - 1)) + 1
          build(cn, key_from_scalar(d))
        end

        def key_from_scalar(d)
          group = OpenSSL::PKey::EC::Group.new('prime256v1')
          pub = group.generator.mul(OpenSSL::BN.new(d.to_s, 10))
          der = OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::Integer.new(1),
            OpenSSL::ASN1::OctetString.new([d.to_s(16).rjust(64, '0')].pack('H*')),
            OpenSSL::ASN1::ObjectId.new('prime256v1', 0, :EXPLICIT),
            OpenSSL::ASN1::BitString.new(pub.to_octet_string(:uncompressed), 1, :EXPLICIT)
          ]).to_der
          OpenSSL::PKey::EC.new(der)
        end

        def build(cn, key)
          cert = OpenSSL::X509::Certificate.new
          cert.version = 2
          cert.serial = SecureRandom.random_number(1 << 62) + 1
          cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=#{cn}")
          now = Time.now
          cert.not_before = now - 60
          cert.not_after = now + VALID_SECONDS
          cert.public_key = OpenSSL::PKey.read(key.public_to_der)
          cert.sign(key, OpenSSL::Digest.new('SHA256'))
          Pem.new(key.private_to_pem, cert.to_pem)
        end

        # writes dir/key.pem (0600) and dir/cert.pem for cn
        def generate_identity(dir, cn)
          FileUtils.mkdir_p(dir, mode: 0o700)
          pem = generate_pem(cn)
          key_path = File.join(dir, 'key.pem')
          cert_path = File.join(dir, 'cert.pem')
          File.open(key_path, 'w', 0o600) { |f| f.write(pem.key_pem) }
          File.write(cert_path, pem.cert_pem)
          Identity.new(key_path, cert_path)
        end

        # lowercase hex SHA-256 of the DER of a certificate (an X509 object or a PEM text): the pin
        def fingerprint_of(cert)
          cert = OpenSSL::X509::Certificate.new(cert) unless cert.is_a?(OpenSSL::X509::Certificate)
          Digest::SHA256.hexdigest(cert.to_der)
        end

        def read_pem(path) = File.read(path)
      end
    end
  end
end
