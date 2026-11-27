# frozen_string_literal: true

require 'socket'
require_relative '../mpc_net'
require_relative 'mesh'

module AtlasPca
  module Mpc
    module Net
      # TEST-ONLY fault injection for the networked MPC. Two layers, deliberately separate:
      #  - Faults.tamper_for: a MALICIOUS SENDER rewriting its own outgoing frames at the application layer (duplicate, reorder,
      #    skipped sequence, garbage, truncation, wrong round or session, oversize length, drop, silence). The bytes still travel
      #    inside valid TLS, so the receiver's framing checks decide.
      #  - FaultProxy: a NETWORK adversary on the wire (a TCP middlebox): drop / delay / truncate / bit-flip / duplicate / reorder at
      #    the byte level. TLS 1.3 record authentication rejects tampering, so the expected outcome is a disconnect, never a silently
      #    corrupted value.
      module Faults
        FRAME_FAULT_KINDS = %w[duplicate reorder skip-seq garbage truncate bitflip wrong-round wrong-session oversize drop silent-from
                               extra-field false-accuse].freeze
        # kind: one of FRAME_FAULT_KINDS; round: the protocol round to attack; to: restrict to one recipient (nil = all);
        # accuse: for false-accuse, the honest party the forged abort frame names
        FrameFault = Struct.new(:kind, :round, :to, :accuse, keyword_init: true)

        module_function

        # builds FrameFault from a Hash with string or symbol keys (a config file's frameFault)
        def frame_fault(h)
          h = h.transform_keys(&:to_s)
          FrameFault.new(kind: h['kind'], round: h['round'], to: h['to'], accuse: h['accuse'])
        end

        # a tamper hook (proc(TamperEvent) -> [binary String]) for the spec; an unknown kind raises (fail closed)
        def tamper_for(spec)
          raise ArgumentError, "unknown frame fault #{spec.kind.inspect}" unless FRAME_FAULT_KINDS.include?(spec.kind)

          stash = {}
          silent = false
          lambda do |ev|
            return [] if silent

            hit = ev.frame.rd == spec.round && (spec.to.nil? || spec.to == ev.to)
            if spec.kind == 'reorder'
              held = stash.delete(ev.to)
              return [ev.raw, held] if held # the later frame first, then the held-back one

              if hit
                stash[ev.to] = ev.raw
                return []
              end
              return [ev.raw]
            end
            return [ev.raw] unless hit

            fr = ev.frame
            case spec.kind
            when 'duplicate' then [ev.raw, ev.raw]
            when 'skip-seq' then [NetWire.encode_frame(with(fr, seq: fr.seq + 1))]
            when 'garbage' then [[ev.raw.bytesize - 4].pack('N') + ("\x5a".b * (ev.raw.bytesize - 4))]
            when 'truncate' then [ev.raw.byteslice(0, [5, ev.raw.bytesize / 2].max)]
            when 'bitflip'
              b = ev.raw.dup
              i = (b.bytesize * 0.6).floor
              b.setbyte(i, b.getbyte(i) ^ 0x04)
              [b]
            when 'wrong-round' then [NetWire.encode_frame(with(fr, rd: "zzz-#{fr.rd}"))]
            when 'wrong-session' then [NetWire.encode_frame(with(fr, sid: 'not-this-session'))]
            when 'oversize' then [[0x7fffffff].pack('N')]
            when 'drop' then []
            when 'silent-from'
              silent = true
              []
            when 'false-accuse'
              [NetWire.encode_frame(with(fr, ty: 'abort', rd: 'abort',
                                            d: { 'kind' => 'timeout', 'blamed' => spec.accuse || 0, 'detail' => 'forged accusation' }))]
            when 'extra-field'
              body = Js.utf8(Js.json({ 'v' => fr.v, 'ty' => fr.ty, 'sid' => fr.sid, 'seq' => fr.seq, 'rd' => fr.rd, 'd' => fr.d, 'x' => 1 }))
              [[body.bytesize].pack('N') + body]
            end
          end
        end

        def with(frame, **changes)
          f = frame.dup
          changes.each { |k, v| f[k] = v }
          f
        end
      end

      # network fault kinds the proxy knows
      WIRE_FAULT_KINDS = %w[none drop delay truncate bitflip duplicate reorder].freeze
      # dir: 'c2s' (client to server) or 's2c'; after_bytes: the fault starts once this many bytes passed in that direction (skips
      # the TLS handshake); ms: delay milliseconds (kind delay)
      WireFault = Struct.new(:kind, :dir, :after_bytes, :ms, keyword_init: true)

      # A transparent TCP proxy that misbehaves once, after after_bytes bytes, in one direction.
      class FaultProxy
        attr_reader :listen_port, :log

        def initialize(listen_port, target_host, target_port, fault)
          raise ArgumentError, "unknown wire fault #{fault.kind.inspect}" unless WIRE_FAULT_KINDS.include?(fault.kind)

          @listen_port = listen_port
          @target = [target_host, target_port]
          @fault = fault
          @log = []
          @server = nil
        end

        def listen
          @server = TCPServer.new('127.0.0.1', @listen_port)
          Thread.new do
            loop { Thread.new(@server.accept) { |c| on_client(c) }.tap { |t| t.report_on_exception = false } }
          rescue IOError, SystemCallError
            nil
          end.tap { |t| t.report_on_exception = false }
          self
        end

        # the port this proxy really holds (a listen port of 0 lets the OS choose); -1 before listen
        def port = @server ? @server.addr[1] : -1

        def close = (@server&.close rescue nil) # rubocop:disable Style/RescueModifier

        private

        def on_client(c)
          up = TCPSocket.new(*@target)
          remaining = 2
          lock = Mutex.new
          done = lambda do
            lock.synchronize { remaining -= 1 }
            next unless remaining.zero?

            [c, up].each { |s| s.close rescue nil } # rubocop:disable Style/RescueModifier
          end
          # a closed side tears down the other, but only after that direction's delayed bytes are delivered
          [[c, up, 'c2s'], [up, c, 's2c']].each do |from, to, dir|
            Thread.new { pipe(from, to, dir, done) }.tap { |t| t.report_on_exception = false }
          end
        rescue SystemCallError, IOError
          c.close rescue nil # rubocop:disable Style/RescueModifier
        end

        def pipe(from, to, dir, done_cb)
          f = @fault
          active = f.kind != 'none' && f.dir == dir
          seen = 0
          fired = false
          done = false
          held = nil
          delayed = [] # delayed deliveries in flight: a half-close must not overtake them
          begin
            loop do
              chunk = from.readpartial(65_536)
              before = seen
              seen += chunk.bytesize
              if !active || done || before + chunk.bytesize <= f.after_bytes
                next if active && f.kind == 'drop' && fired # a black hole stays black

                to.write(chunk)
                next
              end
              unless fired
                fired = true
                @log << "fault #{f.kind} #{dir} after #{f.after_bytes}B"
              end
              case f.kind
              when 'drop' then next
              when 'delay'
                delayed << Thread.new(chunk) do |ch|
                  sleep((f.ms || 1000) / 1000.0)
                  begin
                    to.write(ch)
                  rescue StandardError
                    nil
                  end
                end
              when 'truncate'
                done = true
                to.write(chunk.byteslice(0, chunk.bytesize / 2))
                break
              when 'bitflip'
                done = true
                b = chunk.dup
                i = b.bytesize / 2
                b.setbyte(i, b.getbyte(i) ^ 0x01)
                to.write(b)
              when 'duplicate'
                done = true
                to.write(chunk)
                to.write(chunk)
              when 'reorder'
                if held.nil?
                  held = chunk
                else
                  done = true
                  to.write(chunk)
                  to.write(held)
                  held = nil
                end
              else to.write(chunk)
              end
            end
          rescue EOFError, IOError, SystemCallError
            nil
          ensure
            begin
              to.write(held) if held
            rescue StandardError
              nil
            end
            delayed.each(&:join)
            begin
              to.close_write
            rescue StandardError
              nil
            end
            done_cb.call
          end
        end
      end
    end
  end
end
