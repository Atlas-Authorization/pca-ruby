# frozen_string_literal: true

require 'securerandom'
require_relative '../mpc_net'

module AtlasPca
  module Mpc
    module Net
      # Agreement on the joint choice-bit gadget seeds: a signed commit-reveal with an echo round, so that ONE corrupt party cannot
      # make the honest parties derive different gadgets and then blame each other.
      #
      # Every commitment and every opening is SIGNED by its sender with the sender's pinned TLS identity key. After the reveal each
      # party echoes, to every peer, the signed values it received from each third party (round gd-e). A receiver then checks each
      # echoed statement against what it received directly: a signature that does not verify is a forgery by the echoer (blame the
      # echoer); a statement that verifies but differs from the one received directly means the signer signed two different values
      # for one round (blame the signer, with both statements as TRANSFERABLE evidence). With n = 2 there is no third party, so the
      # echo round is skipped.
      module Gadget
        HEX64 = /\A[0-9a-f]{64}\z/
        HEXSIG = /\A[0-9a-f]{16,200}\z/

        # what the agreement needs from the transport: self_id, session_id, sign(bytes) and verify(peer, bytes, sig)
        # io responds to exchange(rd, mine, parse) (one un-echoed all-to-all round; mine = proc(peer), parse = proc(peer, raw)
        # returning a value) and bad(peer, what) (raises a malformed NetAbort naming the peer)
        # the transport view the agreement runs on: one un-echoed all-to-all round, and the malformed-peer abort
        class Io
          def initialize(exchange, bad)
            @exchange = exchange
            @bad = bad
          end

          def exchange(rd, mine, parse) = @exchange.call(rd, mine, parse)
          def bad(peer, what) = @bad.call(peer, what)
        end

        module_function

        def signed?(x, value_re)
          x.is_a?(Hash) && x['v'].is_a?(String) && value_re.match?(x['v']) && x['s'].is_a?(String) && HEXSIG.match?(x['s'])
        end

        # runs the signed commit / reveal / echo and returns every party's seed (binary String) in party order, mine included.
        # my_seed is injectable for tests; production passes nothing.
        def agree_gadget_seeds(net, n, io, my_seed = SecureRandom.random_bytes(32))
          id = net.self_id
          sid = net.session_id
          sign = lambda do |round, value|
            { 'v' => value, 's' => net.sign(NetCodec.gadget_statement(sid, round, id, value)).unpack1('H*') }
          end
          check = lambda do |signer, round, m|
            net.verify(signer, NetCodec.gadget_statement(sid, round, signer, m['v']), [m['s']].pack('H*'))
          end

          my_commit = NetCodec.gadget_commit(sid, id, my_seed)
          commits = io.exchange(
            'gd-c', ->(_peer) { sign.call('gd-c', my_commit) },
            lambda do |p, raw|
              return io.bad(p, 'bad gadget commitment') unless signed?(raw, HEX64)
              return io.bad(p, 'gadget commitment signature does not verify') unless check.call(p, 'gd-c', raw)

              raw
            end
          )
          my_seed_hex = my_seed.unpack1('H*')
          opens = io.exchange(
            'gd-o', ->(_peer) { sign.call('gd-o', my_seed_hex) },
            lambda do |p, raw|
              return io.bad(p, 'bad gadget seed') unless signed?(raw, HEX64)
              return io.bad(p, 'gadget seed signature does not verify') unless check.call(p, 'gd-o', raw)

              unless NetCodec.gadget_commit(sid, p, [raw['v']].pack('H*')) == commits[p]['v']
                raise NetWire::NetAbort.new('commitment', p, id, "party #{p} opened a gadget seed that does not match its commitment")
              end

              raw
            end
          )

          if n >= 3
            others = (0...n).reject { |i| i == id }
            io.exchange(
              'gd-e',
              ->(peer) { others.reject { |j| j == peer }.map { |j| { 'j' => j, 'c' => commits[j], 'o' => opens[j] } } },
              lambda do |p, raw|
                expect = others.reject { |j| j == p }
                return io.bad(p, 'bad gadget echo') unless raw.is_a?(Array) && raw.length == expect.length

                expect.each_with_index do |j, k|
                  e = raw[k]
                  return io.bad(p, 'bad gadget echo entry') unless e.is_a?(Hash) && e['j'] == j && signed?(e['c'], HEX64) && signed?(e['o'], HEX64)
                  # a statement that does not verify under j's pinned key was forged by the echoer p
                  unless check.call(j, 'gd-c', e['c']) && check.call(j, 'gd-o', e['o'])
                    return io.bad(p, "gadget echo carries a statement that party #{j} did not sign")
                  end

                  mine_c = commits[j]
                  mine_o = opens[j]
                  next if e['c']['v'] == mine_c['v'] && e['o']['v'] == mine_o['v']

                  # both statements verify under j's key and differ: j signed two values for one round
                  commits_differ = e['c']['v'] != mine_c['v']
                  raise NetWire::NetAbort.new(
                    'equivocation', j, id,
                    "party #{j} signed different gadget #{commits_differ ? 'commitments' : 'seeds'} for different parties (shown by party #{p}'s echo)",
                    nil, nil, nil,
                    { 'signer' => j, 'round' => commits_differ ? 'gd-c' : 'gd-o', 'statements' => commits_differ ? [mine_c, e['c']] : [mine_o, e['o']] }
                  )
                end
                true
              end
            )
          end
          Array.new(n) { |p| p == id ? my_seed.b : [opens[p]['v']].pack('H*') }
        end
      end
    end
  end
end
