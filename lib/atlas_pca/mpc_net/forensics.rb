# frozen_string_literal: true

require 'securerandom'
require_relative '../mpc_net'

module AtlasPca
  module Mpc
    module Net
      # The commit-first exchange of forensic disclosures (the pure parts, parse / audit / blame / commitment, are NetForensics).
      # Nobody opens before every commitment is in hand (the forensic-c exchange completes first), so no party's disclosure can depend
      # on another's; a late or absent party times out at the shared deadline.
      module Forensic
        HEX64 = /\A[0-9a-f]{64}\z/

        # exchange: proc(rd, mine, parse, timeout_ms) running one un-echoed all-to-all round with that receive deadline
        # bad: proc(peer, what) raising a malformed NetAbort
        ExchangeArgs = Struct.new(:session_id, :id, :n, :triple_index, :mine, :slots, :rows, :deadline_ms, :exchange, :bad, keyword_init: true)

        module_function

        # returns every OTHER party's verified disclosure as { party => [SlotDisclosure] }
        def exchange_disclosures(a)
          wire = NetForensics.wire_disclosure(a.mine)
          nonce = SecureRandom.hex(32)
          my_commit = NetForensics.disclosure_commit(a.session_id, a.id, a.triple_index, a.deadline_ms, nonce, wire)
          commits = a.exchange.call(
            'forensic-c', ->(_peer) { { 'c' => my_commit, 'd' => a.deadline_ms } },
            lambda do |p, raw|
              return a.bad.call(p, 'bad forensic commitment') unless raw.is_a?(Hash) && raw['c'].is_a?(String) && HEX64.match?(raw['c'])
              return a.bad.call(p, "forensic deadline #{raw['d'].inspect} differs from the agreed #{a.deadline_ms}") unless raw['d'] == a.deadline_ms

              raw['c']
            end,
            a.deadline_ms
          )
          a.exchange.call(
            'forensic-o', ->(_peer) { { 'w' => wire, 'nonce' => nonce } },
            lambda do |p, raw|
              return a.bad.call(p, 'bad forensic opening') unless raw.is_a?(Hash) && raw['nonce'].is_a?(String) && HEX64.match?(raw['nonce'])

              unless NetForensics.disclosure_commit(a.session_id, p, a.triple_index, a.deadline_ms, raw['nonce'], raw['w']) == commits[p]
                raise NetWire::NetAbort.new('commitment', p, a.id, "party #{p} opened a forensic disclosure that does not match its commitment")
              end

              NetForensics.parse_disclosure(raw['w'], a.slots, a.rows, (0...a.n).reject { |q| q == p })
            end,
            a.deadline_ms
          )
        end
      end
    end
  end
end
