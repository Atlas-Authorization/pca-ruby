# frozen_string_literal: true

# Replays the TS-reference oracle of the FROST distributed key generation (test-data/ref-frost-dkg.json.gz, 439 cases, plus the CI-generated
# ref-frost-dkg-gen.json.gz, 286 cases: the cases that carry a derived secret, never committed): rounds 1 and 2, share verification, complaints, rebuttals,
# blame, the qualified set, transcript echo agreement, finalize, the whole ceremony, the wire codec, the per-peer inbox, the in-memory network, one party's
# ceremony over a scripted channel and the TLS framing rule. Every fn has a handler and the totals are asserted. Encodings: {"$bytes": ...} bytes
# ({"$seed": label} the 32 bytes sha256("atlas-pca-conformance/" + label)); {"$rng": [...]} as the LAST argument the 32-byte values the reference drew, in
# draw order (the randomness seam of the call); {"$num": ...} a non-finite number; a stateSpec {id, t, n, sessionId, coefficients, popNonce} is rebuilt with
# dkg_round1. A refusal is {"$throws": message, ...}: a DkgChannelError compares code and peer exactly, any other message is informative.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefFrostDkg < Minitest::Test
  A = AtlasPca
  FD = AtlasPca::FrostDkg
  CH = AtlasPca::FrostDkgChannel
  MAIN = Ref.load('frost-dkg')
  GEN = Ref.load_gen('frost-dkg')
  CASES = Ref.merge_cases(MAIN, GEN)
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  PHASES = %w[round1 share complaints rebuttals echo].freeze

  def self.hydrate(v)
    case v
    when Hash then v.size == 1 && v.key?('$num') ? NUM.fetch(v['$num']) : v.transform_values { |x| hydrate(x) }
    when Array then v.map { |x| hydrate(x) }
    else v
    end
  end

  def self.split_rng(args)
    last = args.last
    return [args, nil] unless last.is_a?(Hash) && last.key?('$rng')

    [args[0...-1], queue(last['$rng'])]
  end

  def self.queue(values)
    q = values.dup
    ->(_n = 32) { q.shift || raise('a draw past the randomness script') }
  end

  def self.enc(v)
    case v
    when String then v.encoding == Encoding::BINARY ? { '$bytes' => Ref.b64e(v) } : v
    when Hash then v.transform_values { |x| enc(x) }
    when Array then v.map { |x| enc(x) }
    else v
    end
  end

  def self.err_out(e)
    o = { '$throws' => e.message }
    o.merge!('code' => e.code, 'class' => 'DkgChannelError', 'peer' => e.peer) if e.is_a?(CH::DkgChannelError)
    o
  end

  def self.capture
    enc(yield)
  rescue StandardError => e
    enc(err_out(e))
  end

  def self.eq(got, out)
    case out
    when Hash
      return false unless got.is_a?(Hash)
      return got.key?('$throws') && eq(got.reject { |k, _| k == '$throws' }, out.reject { |k, _| k == '$throws' }) if out.key?('$throws')

      got.keys.sort == out.keys.sort && out.all? { |k, v| eq(got[k], v) }
    when Array then got.is_a?(Array) && got.length == out.length && got.each_with_index.all? { |g, i| eq(g, out[i]) }
    else got == out
    end
  end

  # ---- handlers ----------------------------------------------------------------------------------------------------------------

  def self.state(spec)
    opts = {}
    opts['coefficients'] = spec['coefficients'] if spec['coefficients']
    opts['popNonce'] = spec['popNonce'] if spec['popNonce']
    FD.dkg_round1(spec['id'], spec['t'], spec['n'], spec['sessionId'], opts)['state']
  end

  def self.inbox_run(a)
    ib = CH::DkgInbox.new(a['sessionId'], a['peers'])
    a['ops'].map do |op|
      case op['op']
      when 'accept' then ib.accept(op['sender'], op['bytes'])
      when 'fail' then ib.fail(op['peer'], CH::DkgChannelError.new(op['code'], nil, op['message']))
      when 'peerGone' then ib.peer_gone(op['peer'])
      when 'close' then ib.close
      when 'collect'
        m = ib.collect(op['kind'], op['from'], op['timeoutMs'])
        next({ 'ok' => true, 'bodies' => m.transform_keys(&:to_s) })
      else raise 'bad op'
      end
      { 'ok' => true }
    rescue StandardError => e
      err_out(e)
    end
  end

  def self.net_run(a)
    intercept = nil
    if a['intercept']
      m = a['intercept']
      intercept = lambda do |d|
        hit = (!m.key?('kind') || m['kind'] == d['kind']) && (!m.key?('from') || m['from'] == d['from']) && (!m.key?('to') || m['to'] == d['to'])
        next d['bytes'] unless hit
        next nil if m['action'] == 'drop'
        next m['bytes'] if m['action'] == 'replace'

        d['bytes']
      end
    end
    net = CH.create_memory_dkg_network(a['ids'], a['sessionId'], intercept)
    out = [{ 'channels' => net['channels'].to_h { |id, ch| [id.to_s, { 'self' => ch.self_id, 'peers' => ch.peers }] } }]
    a['ops'].each do |op|
      ch = op.key?('at') ? net['channels'][op['at']] : nil
      case op['op']
      when 'broadcast'
        net['channels'][op['from']].broadcast(op['kind'], op['body'])
        out << { 'ok' => true }
      when 'send'
        net['channels'][op['from']].send_to(op['to'], op['kind'], op['body'])
        out << { 'ok' => true }
      when 'deliver'
        net['deliver'].call(op['from'], op['to'], op['bytes'])
        out << { 'ok' => true }
      when 'collect' then out << { 'ok' => true, 'bodies' => ch.collect(op['kind'], op['fromIds'], op['timeoutMs']).transform_keys(&:to_s) }
      when 'close'
        ch.close
        out << { 'ok' => true }
      else raise 'bad op'
      end
    rescue StandardError => e
      out << err_out(e)
    end
    out
  end

  # a scripted channel: records every outbound message, delivers each inbound entry of an earlier-or-equal phase before a collect
  class PartyChannel
    attr_reader :self_id, :peers, :outbound

    def initialize(spec)
      @sid = spec['sessionId']
      @self_id = spec['self']
      @peers = spec['peers'] || spec['participants'].reject { |p| p == spec['self'] }.sort
      @inbox = CH::DkgInbox.new(@sid, @peers)
      @pending = (spec['inbound'] || []).dup
      @outbound = []
      (spec['gone'] || []).each { |g| @inbox.peer_gone(g) }
    end

    def broadcast(kind, body)
      @outbound << { 'op' => 'broadcast', 'kind' => kind, 'bytes' => TestRefFrostDkg.enc(CH.encode_dkg_message(@sid, kind, body)) }
    end

    def send_to(to, kind, body)
      raise CH.err('identity', to, 'not a connected peer') unless @peers.include?(to)

      @outbound << { 'op' => 'send', 'kind' => kind, 'to' => to, 'bytes' => TestRefFrostDkg.enc(CH.encode_dkg_message(@sid, kind, body)) }
    end

    def collect(kind, from, timeout_ms)
      lim = PHASES.index(kind)
      keep = []
      @pending.each { |m| PHASES.index(m['kind']) <= lim ? @inbox.accept(m['from'], m['bytes']) : keep << m }
      @pending = keep
      @inbox.collect(kind, from, timeout_ms)
    end

    def close = @inbox.close
  end

  def self.party_run(spec, random)
    ch = PartyChannel.new(spec)
    begin
      r = CH.run_dkg_over_channel(ch, { 't' => spec['t'], 'participants' => spec['participants'], 'sessionId' => spec['sessionId'], 'timeoutMs' => spec['timeoutMs'] }, random: random)
      { 'outbound' => ch.outbound, 'result' => enc({ 'qualified' => r['qualified'], 'complaints' => r['complaints'], 'keyPackage' => r['keyPackage'] }) }
    rescue StandardError => e
      { 'outbound' => ch.outbound, 'error' => enc(err_out(e)) }
    end
  end

  HANDLERS = {
    'constants' => ->(*) { { 'DKG_WIRE_VERSION' => CH::DKG_WIRE_VERSION, 'DKG_MAX_MESSAGE_BYTES' => CH::DKG_MAX_MESSAGE_BYTES, 'DKG_MAX_PARTICIPANTS' => CH::DKG_MAX_PARTICIPANTS, 'DKG_MESSAGE_KINDS' => CH::DKG_MESSAGE_KINDS } },
    # the reference takes bytes (Uint8Array): a corpus value that is text (a UTF-8 String, not the binary of a {$bytes} member) is refused
    'dkgRound1' => lambda { |id, t, n, sid, opts, rng|
      raise ArgumentError, 'dkgRound1: sessionId must be a non-empty byte string' if sid.is_a?(String) && sid.encoding != Encoding::BINARY
      raise ArgumentError, 'ct-scalar: reduce takes 1..64 bytes' if opts.is_a?(Hash) && Array(opts['coefficients']).any? { |c| c.is_a?(String) && c.encoding != Encoding::BINARY }

      { 'package' => FD.dkg_round1(id, t, n, sid, opts || {}, random: rng)['package'] }
    },
    'dkgVerifyRound1' => ->(from, pkg, sid) { FD.dkg_verify_round1(from, pkg, sid) },
    'dkgSignShare' => ->(spec, to, share) { FD.dkg_sign_share(state(spec), to, share) },
    'dkgRound2' => ->(spec, pkgs) { FD.dkg_round2(state(spec), pkgs) },
    'dkgVerifyShare' => ->(recv, pkg, my, sid) { FD.dkg_verify_share(recv, pkg, my, sid) },
    'dkgFileComplaint' => ->(p) { FD.dkg_file_complaint(p) },
    'dkgVerifyComplaint' => ->(c, pkgs) { FD.dkg_verify_complaint(c, pkgs) },
    'dkgRebut' => ->(accused, c, spec) { FD.dkg_rebut(accused, c, state(spec)) },
    'dkgResolveBlame' => ->(c, reb, pkgs) { FD.dkg_resolve_blame(c, reb, pkgs) },
    'dkgQualifiedSet' => ->(parts, complaints, pkgs, reb = []) { FD.dkg_qualified_set(parts, complaints, pkgs, reb) },
    'dkgTranscriptDigest' => ->(a) { FD.dkg_transcript_digest(a) },
    'dkgEcho' => ->(a) { FD.dkg_echo(a) },
    'dkgCheckEchoes' => ->(q, e, sid) { FD.dkg_check_echoes(q, e, sid) },
    'dkgFinalize' => ->(id, spec, recv, pkgs, q, agreement) { FD.dkg_finalize(id, state(spec), recv, pkgs, q, agreement) },
    'frostDkgSimulate' => ->(t, n, opts, rng) { FD.frost_dkg_simulate(t, n, opts || {}, random: rng) },
    'encodeDkgMessage' => ->(sid, kind, body) { CH.encode_dkg_message(sid, kind, body) },
    'decodeDkgMessage' => ->(bytes, sid) { CH.decode_dkg_message(bytes, sid) },
    'decodeDkgRound1Package' => ->(body, t) { CH.decode_dkg_round1_package(body, t) },
    'decodeDkgShareMessage' => ->(body) { CH.decode_dkg_share_message(body) },
    'decodeDkgComplaints' => ->(body) { CH.decode_dkg_complaints(body) },
    'decodeDkgRebuttals' => ->(body) { CH.decode_dkg_rebuttals(body) },
    'decodeDkgEcho' => ->(body) { CH.decode_dkg_echo(body) },
    'dkgInbox' => ->(a) { inbox_run(a) },
    'memoryNetwork' => ->(a) { net_run(a) },
    'tlsFrameEncode' => ->(payload) { CH.tls_frame_encode(payload) },
    'tlsFrameDecode' => ->(a) { CH.tls_frame_decode(a['chunks']) },
    'runDkgOverChannel' => ->(spec, rng) { party_run(spec, rng) }
  }.freeze

  RNG_FNS = %w[dkgRound1 frostDkgSimulate runDkgOverChannel].freeze

  MAIN_TOTALS = { 'constants' => 1, 'dkgRound1' => 56, 'dkgVerifyRound1' => 36, 'dkgSignShare' => 20, 'dkgRound2' => 5, 'dkgVerifyShare' => 3, 'dkgFileComplaint' => 2,
                  'dkgVerifyComplaint' => 3, 'dkgResolveBlame' => 1, 'dkgQualifiedSet' => 13, 'dkgTranscriptDigest' => 10, 'dkgEcho' => 4, 'dkgCheckEchoes' => 18,
                  'dkgFinalize' => 1, 'frostDkgSimulate' => 13, 'encodeDkgMessage' => 18, 'decodeDkgMessage' => 56, 'decodeDkgRound1Package' => 32,
                  'decodeDkgShareMessage' => 27, 'decodeDkgComplaints' => 25, 'decodeDkgRebuttals' => 9, 'decodeDkgEcho' => 13, 'dkgInbox' => 24, 'memoryNetwork' => 11,
                  'tlsFrameEncode' => 5, 'tlsFrameDecode' => 17, 'runDkgOverChannel' => 16 }.freeze
  GEN_TOTALS = { 'dkgRound2' => 13, 'dkgVerifyShare' => 26, 'dkgFileComplaint' => 22, 'dkgVerifyComplaint' => 14, 'dkgRebut' => 10, 'dkgResolveBlame' => 18,
                 'dkgQualifiedSet' => 10, 'dkgTranscriptDigest' => 3, 'dkgEcho' => 1, 'dkgFinalize' => 38, 'frostDkgSimulate' => 18, 'encodeDkgMessage' => 3,
                 'runDkgOverChannel' => 110 }.freeze

  def test_every_fn_of_the_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal MAIN_TOTALS.keys.sort, MAIN.keys.sort
    assert_equal MAIN_TOTALS, MAIN.transform_values(&:length)
    assert_equal 439, MAIN.values.sum(&:length)
    assert_empty(MAIN.keys - HANDLERS.keys)
  end

  def test_the_generated_half_is_present_and_complete
    Ref.need_gen(self, 'frost-dkg') if GEN.nil?
    assert_equal GEN_TOTALS, GEN.transform_values(&:length)
    assert_equal 286, GEN.values.sum(&:length)
    assert_empty(GEN.keys - HANDLERS.keys)
  end

  (MAIN.keys + %w[dkgRebut]).uniq.each do |fn|
    define_method("test_replay_#{fn}") do
      cases = CASES[fn] || []
      Ref.need_gen(self, 'frost-dkg') if cases.empty?
      k = self.class
      handler = HANDLERS.fetch(fn)
      call = lambda do |*args|
        a = args.map { |x| k.hydrate(x) }
        a, rng = k.split_rng(a) if RNG_FNS.include?(fn)
        if fn == 'dkgRound1'
          a << nil while a.length < 5
          a << rng
        elsif RNG_FNS.include?(fn)
          a << nil while a.length < (fn == 'frostDkgSimulate' ? 3 : 1)
          a << rng
        end
        k.capture { handler.call(*a) }
      end
      Ref.run(self, cases, call, compare: ->(got, out, _c) { k.eq(got, out) }, refused: ->(got, c) { k.eq(got, c['out']) })
    end
  end
end
