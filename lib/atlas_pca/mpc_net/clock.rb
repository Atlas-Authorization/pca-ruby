# frozen_string_literal: true

require 'socket'

module AtlasPca
  module Mpc
    # The distributed (mutual-TLS) MPC driver. This namespace holds the socket, TLS and protocol-orchestration layer; the pure codecs
    # and engines it runs on live in mpc_net.rb and the mpc_* files.
    module Net
      # Time source for every DECISION the mesh makes by time (receive deadlines, connect deadline). A clock answers now (ms) and can
      # schedule a wake-up; the wall clock needs no timer (the mesh waits on a condition variable with the remaining time).
      class WallClock
        def now = (Process.clock_gettime(Process::CLOCK_REALTIME) * 1000).to_i
        def set_timer(_ms, &_fn) = nil
        def clear_timer(_handle) = nil
      end

      WALL_CLOCK = WallClock.new

      # A virtual clock: time moves only when the caller says so; timers fire in order of due time during advance.
      class ManualClock
        def initialize
          @t = 0
          @seq = 0
          @timers = {}
          @lock = Mutex.new
        end

        def now = @t

        def set_timer(ms, &fn)
          @lock.synchronize do
            id = (@seq += 1)
            @timers[id] = [@t + ms, fn]
            id
          end
        end

        def clear_timer(handle) = @lock.synchronize { @timers.delete(handle) }

        # advances virtual time by ms, firing every timer that falls due (earliest first)
        def advance(ms)
          target = @t + ms
          loop do
            best = @lock.synchronize { @timers.select { |_, (due, _)| due <= target }.min_by { |_, (due, _)| due } }
            break if best.nil?

            @lock.synchronize { @timers.delete(best[0]) }
            @t = [@t, best[1][0]].max
            best[1][1].call
          end
          @t = target
        end

        def pending = @lock.synchronize { @timers.size }
      end

      # Timing helpers shared by the launcher and the tests: the one timeout-scale knob and distinct free loopback ports.
      module Timing
        module_function

        def scale
          v = Float(ENV.fetch('PCA_MPC_TEST_TIMEOUT_SCALE', '1'), exception: false)
          v && v.finite? && v.positive? ? v : 1.0
        end

        # scales a duration (ms) by the one timeout knob
        def t(ms) = (ms * scale).ceil

        # count DISTINCT free ephemeral ports, all held open at the same time and released together
        def reserve_ports(count)
          servers = Array.new(count) { TCPServer.new('127.0.0.1', 0) }
          ports = servers.map { |s| s.addr[1] }
          servers.each(&:close)
          ports
        end
      end
    end
  end
end
