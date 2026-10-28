# frozen_string_literal: true

# Step-up client for the principal's device: the device key (RFC 8032 vectors), the secret stores and the client against a
# fake transport (no network).
#   ruby -Ilib test/test_stepup.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'
require 'tmpdir'

class TestStepUp < Minitest::Test
  SU = AtlasPca::StepUp
  # RFC 8032 section 7.1 test 1 (empty message) and test 2 (one byte, 0x72)
  RFC = [
    ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
     'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'],
    ['4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
     '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00']
  ].freeze
  NOW = 1_799_999_999_000 # one second before 2027-01-15T08:00:00Z (= 1_800_000_000_000 ms)
  MSG = 'threshold message bytes'.b

  def b64(bin) = AtlasPca.b64e(bin)

  def test_rfc8032_vectors
    RFC.each do |seed, pub, msg, sig|
      store = AtlasPca::MemorySecretStore.new
      key = AtlasPca::PrincipalDeviceKey.new(store)
      key.import_secret(b64([seed].pack('H*')))
      assert_equal [pub].pack('H*'), AtlasPca.b64d(key.public_key)
      assert_equal [sig].pack('H*'), AtlasPca.b64d(key.sign([msg].pack('H*')), 64)
    end
  end

  def test_key_lifecycle
    k = AtlasPca::PrincipalDeviceKey.new(AtlasPca::MemorySecretStore.new)
    refute k.exists?
    assert_raises(SU::NoDeviceKey) { k.sign('m') }
    assert_raises(SU::NoDeviceKey) { k.public_key }
    pub = k.generate
    assert k.exists?
    assert_equal pub, k.public_key
    assert AtlasPca.verify_b64u(pub, MSG, k.sign(MSG))
    other = AtlasPca::PrincipalDeviceKey.new(AtlasPca::MemorySecretStore.new)
    assert_equal pub, other.import_secret(k.export_secret)
    k.delete
    refute k.exists?
  end

  def test_import_rejects_a_bad_secret
    ['', 'AAAA', 'not base64!', b64('x' * 31), b64('x' * 33), "#{b64('x' * 32)}="].each do |bad|
      assert_raises(SU::InvalidSecret, bad) { AtlasPca::PrincipalDeviceKey.new(AtlasPca::MemorySecretStore.new).import_secret(bad) }
    end
  end

  def test_file_store_is_private_and_roundtrips
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'principal.key')
      k = AtlasPca::PrincipalDeviceKey.new(AtlasPca::FileSecretStore.new(path))
      pub = k.generate
      assert_equal 0o600, File.stat(path).mode & 0o777 unless Gem.win_platform?
      assert_equal pub, AtlasPca::PrincipalDeviceKey.new(AtlasPca::FileSecretStore.new(path)).public_key
      k.delete
      refute File.exist?(path)
      refute k.exists?
    end
  end

  # ---- the client --------------------------------------------------------------------------------------------------------

  class Fake
    attr_reader :calls

    def initialize(*answers)
      @answers = answers
      @calls = []
    end

    def call(method, url, headers, body)
      @calls << [method, url, headers, body]
      a = @answers.shift
      raise a if a.is_a?(Exception)

      a
    end
  end

  def client(fake)
    key = AtlasPca::PrincipalDeviceKey.new(AtlasPca::MemorySecretStore.new)
    key.generate
    [AtlasPca::StepUpClient.new('https://dash.example/', 'https://atlas.example', 'acct 1', 'ins_1', key, -> { 'tok' },
                                transport: fake, now: -> { NOW }), key]
  end

  def list(*items) = [200, JSON.generate({ 'stepups' => items })]

  def item(id = 'su_1', exp: '2027-01-15T08:00:00.500Z', msg: nil, **kw)
    { 'id' => id, 'grant_ref' => 'g1', 'action' => { 'verb' => 'payments.send', 'resource' => 'payments/acme' }, 'required_t' => 2,
      'threshold_message' => msg || b64(MSG), 'expires_at' => exp }.merge(kw.transform_keys(&:to_s))
  end

  def test_pending_lists_unexpired_step_ups_and_sends_the_token_to_the_dashboard_only
    fake = Fake.new(list(item, item('su_old', exp: '2020-01-01T00:00:00Z'), item('su_2', exp: '2027-01-15T08:00:00Z')))
    c, = client(fake)
    out = c.pending
    assert_equal %w[su_1 su_2], out.map(&:id)
    assert_equal ['payments.send', 'payments/acme', 2, 1_800_000_000_500], [out[0].action_verb, out[0].action_resource, out[0].required_t, out[0].expires_at]
    assert_equal 1_800_000_000_000, out[1].expires_at
    m, url, headers, body = fake.calls[0]
    assert_equal ['GET', nil], [m, body]
    assert_equal 'https://dash.example/v1/dashboard/accounts/acct%201/instances/ins_1/pca/stepups?status=pending', url
    assert_equal 'Bearer tok', headers['Authorization']
  end

  def test_pending_parses_the_fraction_exactly
    [['2027-01-15T08:00:00.5Z', 500], ['2027-01-15T08:00:00.123456Z', 123], ['2027-01-15T08:00:00Z', 0]].each do |text, ms|
      c, = client(Fake.new(list(item(exp: text))))
      assert_equal 1_800_000_000_000 + ms, c.pending[0].expires_at
    end
  end

  def test_pending_rejects_unreadable_answers
    [[200, 'not json'], [200, JSON.generate({ 'stepups' => 'x' })], [200, JSON.generate({})], list(item(exp: 'yesterday')),
     list(item(required_t: true)), list({ 'id' => 'x' })].each do |answer|
      c, = client(Fake.new(answer))
      assert_raises(SU::TransportError, answer.inspect) { c.pending }
    end
  end

  def test_approve_signs_the_threshold_message_and_never_sends_the_dashboard_token
    fake = Fake.new(list(item), [200, JSON.generate({ 'status' => 'anchored', 'allow' => true })])
    c, key = client(fake)
    r = c.approve(c.pending[0])
    assert_equal ['anchored', true, 200], [r.status, r.anchored, r.http_status]
    m, url, headers, body = fake.calls[1]
    assert_equal ['POST', 'https://atlas.example/v1/pca/stepups/su_1/cosign'], [m, url]
    refute headers.key?('Authorization')
    payload = JSON.parse(body)
    assert_equal ['principal', key.public_key], [payload['role'], payload['publicKey']]
    assert AtlasPca.verify_b64u(payload['publicKey'], MSG, payload['sig'])
  end

  def test_approve_202_means_more_roles_are_required
    c, = client(Fake.new(list(item), [202, JSON.generate({ 'status' => 'pending', 'allow' => false })]))
    r = c.approve(c.pending[0])
    assert_equal ['pending', false, 202], [r.status, r.anchored, r.http_status]
  end

  def test_approve_maps_errors
    err = ->(m) { JSON.generate({ 'errors' => [{ 'code' => 'x', 'message' => m }] }) }
    c, = client(Fake.new(list(item), [403, err.call('not the principal')], [500, err.call('boom')], [502, '<html>']))
    s = c.pending[0]
    e = assert_raises(SU::PrincipalMismatch) { c.approve(s) }
    assert_equal 'not the principal', e.message
    e = assert_raises(SU::ApiError) { c.approve(s) }
    assert_equal [500, 'boom'], [e.status, e.message]
    e = assert_raises(SU::ApiError) { c.approve(s) }
    assert_equal [502, 'The request failed.'], [e.status, e.message]
  end

  def test_approve_refuses_a_non_canonical_threshold_message_before_signing
    fake = Fake.new(list(item(msg: 'AAAA=')))
    c, = client(fake)
    assert_raises(SU::InvalidThresholdMessage) { c.approve(c.pending[0]) }
    assert_equal 1, fake.calls.length
  end

  def test_network_failure_is_a_transport_error
    c, = client(Fake.new(SU::TransportError.new('down')))
    assert_raises(SU::TransportError) { c.pending }
  end

  def test_deny_posts_the_reason_to_the_dashboard
    fake = Fake.new(list(item), [200, '{}'], [200, '{}'])
    c, = client(fake)
    s = c.pending[0]
    c.deny(s, 'not me')
    c.deny(s)
    m, url, headers, body = fake.calls[1]
    assert_equal ['POST', 'https://dash.example/v1/dashboard/accounts/acct%201/instances/ins_1/pca/stepups/su_1/deny', { 'reason' => 'not me' }],
                 [m, url, JSON.parse(body)]
    assert_equal 'Bearer tok', headers['Authorization']
    assert_equal({}, JSON.parse(fake.calls[2][3]))
  end

  def test_urls_must_be_http
    ['ftp://x', 'file:///etc/passwd', 'dash.example', ''].each do |bad|
      assert_raises(ArgumentError, bad) do
        AtlasPca::StepUpClient.new(bad, 'https://a.example', 'a', 'i', AtlasPca::PrincipalDeviceKey.new(AtlasPca::MemorySecretStore.new), -> { 't' })
      end
    end
  end
end
