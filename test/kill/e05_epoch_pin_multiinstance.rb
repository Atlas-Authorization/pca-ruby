# frozen_string_literal: true

# e05: H13 (automatic revocation-epoch rollback pin) and H16 (multi_instance vs process-scoped stores).
# AtlasPca is resolved at CALL time (the oracle re-evaluates it per mutant).
require 'timeout'

module MutationKill
  module E05
    FILES = %w[revocation_staleness.rb rack_middleware.rb authorize.rb].freeze
    PIN_MSG = 'revocation staleness needs a state store that implements pins (rollback protection)'
    MULTI_MSG = 'multiInstance requires a shared state store (a process-scoped store lets one PCActn replay once per instance)'

    module_function

    def skip?
      f = ENV['MUT_FILE']
      !(f.nil? || f.empty? || FILES.include?(f))
    end

    def eq(label, got, want)
      raise "#{label}: got #{got.inspect}, want #{want.inspect}" unless got == want

      true
    end

    def gid = MutationKill::C06.base['grant']['id']
    def pin_key = "#{gid}:epoch"

    # A memory store whose claim always succeeds (so one PCActn can be presented repeatedly); pins stay the real ones.
    def loose_store
      Class.new(AtlasPca::MemoryStateStore) { def claim(_k, _c) = AtlasPca::ClaimResult.new(true) }.new
    end

    # check_revocation_state stand-in: honours state['last_accepted_epoch'] like the real rollback rule.
    def run(store, epoch, host: nil, **kw)
      calls = []
      chk = lambda do |*a, **k|
        calls << a[1]
        last = a[1]['last_accepted_epoch']
        if !last.nil? && epoch < last
          { 'ok' => false, 'reason' => "revocation epoch #{epoch} is older than the last accepted #{last} (rollback)" }
        else
          { 'ok' => true, 'epoch' => { 'epoch' => epoch } }
        end
      end
      state = { 'kind' => 'epoch', 'epoch' => {} }
      state['last_accepted_epoch'] = host unless host.nil?
      r = MutationKill::Seam.with(AtlasPca, { check_revocation_state: chk }) do
        MutationKill::C06.go(state_store: store, context: ->(_p) { { 'revocation_state' => state } },
                             revocation_staleness: AtlasPca::RevocationStaleness.new, **kw)
      end
      [r, calls]
    end

    def shared_claim_only
      Class.new { def claim(_k, _c) = AtlasPca::ClaimResult.new(true) }.new
    end
  end

  t('e05 pin: epoch 5 allowed raises the pin; a valid epoch 4 is then a rollback; 6 is allowed and raises it') do
    next true if E05.skip?

    s = E05.loose_store
    r5, = E05.run(s, 5)
    E05.eq('5 allowed', r5.allow, true)
    E05.eq('pin 5', s.pin(E05.pin_key), 5)
    r4, = E05.run(s, 4)
    E05.eq('4 denied', r4.allow, false)
    E05.eq('freshness fail', r4.checks['freshness'], 'fail')
    E05.eq('reason', r4.reasons.include?('freshness: revocation epoch 4 is older than the last accepted 5 (rollback)'), true)
    E05.eq('pin stays 5', s.pin(E05.pin_key), 5)
    r5b, = E05.run(s, 5)
    E05.eq('equal epoch allowed', r5b.allow, true)
    r6, = E05.run(s, 6)
    E05.eq('6 allowed', r6.allow, true)
    E05.eq('pin 6', s.pin(E05.pin_key), 6)
  end

  t('e05 pin: the effective last accepted epoch is the larger of the host value and the stored pin') do
    next true if E05.skip?

    s = E05.loose_store
    s.raise_pin(E05.pin_key, 5)
    r, calls = E05.run(s, 7, host: 9)
    E05.eq('host larger denies', [r.allow, r.reasons.include?('freshness: revocation epoch 7 is older than the last accepted 9 (rollback)')], [false, true])
    E05.eq('state carries 9', calls[0]['last_accepted_epoch'], 9)
    r, calls = E05.run(s, 4, host: 3)
    E05.eq('pin larger denies', [r.allow, r.reasons.include?('freshness: revocation epoch 4 is older than the last accepted 5 (rollback)')], [false, true])
    E05.eq('state carries 5', calls[0]['last_accepted_epoch'], 5)
    r, calls = E05.run(s, 6)
    E05.eq('no host value: pin used', [r.allow, calls[0]['last_accepted_epoch']], [true, 5])
    r, calls = E05.run(E05.loose_store, 1)
    E05.eq('no pin, no host value: none', [r.allow, calls[0].key?('last_accepted_epoch')], [true, false])
  end

  t('e05 pin: a denied action never raises the pin') do
    next true if E05.skip?

    s = E05.loose_store
    s.raise_pin(E05.pin_key, 5)
    E05.run(s, 4)
    E05.eq('freshness denial', s.pin(E05.pin_key), 5)
    replay = Class.new(AtlasPca::MemoryStateStore) { def claim(_k, _c) = AtlasPca::ClaimResult.new(false, 1) }.new
    replay.raise_pin(E05.pin_key, 5)
    r, = E05.run(replay, 8)
    E05.eq('replay denial', [r.allow, r.checks['replay'], replay.pin(E05.pin_key)], [false, 'fail', 5])
  end

  t('e05 pin: a pin store that raises denies (fail closed) on read and on raise') do
    next true if E05.skip?

    rd = Class.new(AtlasPca::MemoryStateStore) do
      def claim(_k, _c) = AtlasPca::ClaimResult.new(true)
      def pin(_k) = raise('boom')
    end.new
    r, = E05.run(rd, 5)
    E05.eq('read raises', [r.allow, r.reasons.include?('freshness: the revocation pin store failed (fail closed)')], [false, true])
    wr = Class.new(AtlasPca::MemoryStateStore) do
      def claim(_k, _c) = AtlasPca::ClaimResult.new(true)
      def raise_pin(_k, _v) = raise('boom')
    end.new
    r, = E05.run(wr, 5)
    E05.eq('raise raises', [r.allow, r.reasons.include?('freshness: the revocation pin store failed (fail closed)')], [false, true])
  end

  t('e05 pin: MemoryStateStore pins are monotone and typed; concurrent raises keep the maximum') do
    next true if E05.skip?

    s = AtlasPca::MemoryStateStore.new
    E05.eq('absent', s.pin('k'), nil)
    s.raise_pin('k', 7)
    s.raise_pin('k', 6)
    E05.eq('7 then 6', s.pin('k'), 7)
    E05.eq('other key', s.pin('j'), nil)
    E05.eq('returns stored', s.raise_pin('k', 2), 7)
    err = begin
      s.raise_pin('k', 1.5)
    rescue ArgumentError => e
      e.message
    end
    E05.eq('non-integer', err, 'raise_pin: value must be an Integer')
    c = AtlasPca::MemoryStateStore.new
    [Thread.new { c.raise_pin('x', 7) }, Thread.new { c.raise_pin('x', 6) }].each(&:join)
    E05.eq('concurrent', c.pin('x'), 7)
  end

  t('e05 pin: SqlStateStore stores pins through the raise-only claim statement under a reserved key') do
    next true if E05.skip?

    log = []
    store = AtlasPca::SqlStateStore.new(execute: ->(sql, b) { log << [sql, b]; 1 },
                                        select: ->(sql, b) { log << [sql, b]; 7 })
    store.raise_pin('g:epoch', 7)
    E05.eq('claim sql + key', log[0], [store.claim_sql, ["\u001fpin:g:epoch", 7]])
    E05.eq('pin read', store.pin('g:epoch'), 7)
    E05.eq('pin select key', log[1][1], ["\u001fpin:g:epoch"])
    err = begin
      store.raise_pin('g:epoch', 'x')
    rescue ArgumentError => e
      e.message
    end
    E05.eq('type', err, 'raise_pin: value must be an Integer')
    E05.eq('scope', store.scope, :shared)
  end

  t('e05 pin: staleness with a store that cannot hold pins is a construction / config error') do
    next true if E05.skip?

    pol = AtlasPca::RevocationStaleness.new
    err = begin
      AtlasPca::AuthorizeOptions.new(state_store: E05.shared_claim_only, revocation_staleness: pol)
    rescue ArgumentError => e
      e.message
    end
    E05.eq('options', err, E05::PIN_MSG)
    only_pin = Class.new { def claim(_k, _c) = nil; def pin(_k) = nil }.new
    err = begin
      AtlasPca::AuthorizeOptions.new(state_store: only_pin, revocation_staleness: pol)
    rescue ArgumentError => e
      e.message
    end
    E05.eq('pin without raise_pin', err, E05::PIN_MSG)
    ok = AtlasPca::AuthorizeOptions.new(state_store: AtlasPca::MemoryStateStore.new, revocation_staleness: pol)
    E05.eq('memory ok', ok.revocation_staleness.equal?(pol), true)
    E05.eq('no staleness ok', AtlasPca::AuthorizeOptions.new(state_store: E05.shared_claim_only).revocation_staleness, nil)
    r = MutationKill::C06.go(state_store: E05.shared_claim_only, revocation_staleness: pol)
    E05.eq('authorize', [r.allow, r.reason], [false, "authorize_config: missing required component(s): #{E05::PIN_MSG} (fail closed)"])
  end

  t('e05 multi_instance: a process-scoped store is refused; default follows the store scope') do
    next true if E05.skip?

    mem = AtlasPca::MemoryStateStore.new
    E05.eq('scopes', [mem.scope, AtlasPca::StateStore.new.scope], %i[process shared])
    err = begin
      AtlasPca::AuthorizeOptions.new(state_store: mem, multi_instance: true)
    rescue ArgumentError => e
      e.message
    end
    E05.eq('process + true', err, E05::MULTI_MSG)
    E05.eq('process default off', AtlasPca::AuthorizeOptions.new(state_store: mem).multi_instance, false)
    E05.eq('process + false', AtlasPca::AuthorizeOptions.new(state_store: mem, multi_instance: false).multi_instance, false)
    sh = E05.shared_claim_only
    E05.eq('shared default on', AtlasPca::AuthorizeOptions.new(state_store: sh).multi_instance, true)
    E05.eq('shared + true', AtlasPca::AuthorizeOptions.new(state_store: sh, multi_instance: true).multi_instance, true)
    E05.eq('shared + false', AtlasPca::AuthorizeOptions.new(state_store: sh, multi_instance: false).multi_instance, false)
    declared = Class.new { def claim(_k, _c) = nil; def scope = 'process' }.new
    err = begin
      AtlasPca::AuthorizeOptions.new(state_store: declared, multi_instance: true)
    rescue ArgumentError => e
      e.message
    end
    E05.eq('string scope process', err, E05::MULTI_MSG)
    r = MutationKill::C06.go(state_store: mem, multi_instance: true)
    E05.eq('authorize', [r.allow, r.reason], [false, "authorize_config: missing required component(s): #{E05::MULTI_MSG} (fail closed)"])
    E05.eq('authorize shared ok', MutationKill::C06.go(state_store: E05.shared_claim_only, multi_instance: true).allow, true)
  end

  t('e05 multi_instance: the rack middleware refuses a process-scoped store with multi_instance') do
    next true if E05.skip?

    mk = ->(store, mi) { AtlasPca::RackMiddleware.new(->(_e) { [200, {}, []] }, audience: 'a', resolve_grant: ->(_r) { nil }, authorize: { state_store: store, multi_instance: mi }) }
    err = begin
      mk.call(AtlasPca::MemoryStateStore.new, true)
    rescue ArgumentError => e
      e.message
    end
    E05.eq('rack', err, E05::MULTI_MSG)
    E05.eq('rack shared', mk.call(E05.shared_claim_only, true).class, AtlasPca::RackMiddleware)
    E05.eq('rack process, default', mk.call(AtlasPca::MemoryStateStore.new, nil).class, AtlasPca::RackMiddleware)
  end
end
