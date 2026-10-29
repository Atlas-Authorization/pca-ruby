# frozen_string_literal: true
# Exact-outcome kill tests for intent_history.rb (the 3045 shared intent-state cases) and mesh.rb (the 133 mesh vectors plus the
# authority algebra helpers, which no vector reaches through a valid chain: a chain's caveats are append-only, so
# `hop widens authority` is defence in depth and is pinned here at the helper level).
module MutationKill
  module HistMesh
    module_function
    CONF = File.expand_path('../../conformance', __dir__)
    def state = (@state ||= AtlasPca::JsonParser.new(File.read(File.join(CONF, 'intent-state-vectors.json'), encoding: 'UTF-8'), true, true, json_text: true).parse_document['cases'])
    def mesh = (@mesh ||= AtlasPca.parse_json(File.read(File.join(CONF, 'mesh-vectors.json'), encoding: 'UTF-8'), loose: true)['mesh'])
    def n(x) = AtlasPca::V2JS.jsnorm(x)
    def opt(x) = x.nil? ? AtlasPca::V2JS::UNDEF : n(x)
    def hist
      yield
    rescue AtlasPca::HistoryError
      { 'throws' => true }
    end

    def run(c)
      a = c['args']
      case c['fn']
      when 'inWindow' then AtlasPca.in_window(n(a[0]), n(a[1]), n(a[2]))
      when 'accKeyOf' then AtlasPca.acc_key_of(n(a[0]), n(a[1]))
      when 'accPreState' then hist { AtlasPca.acc_pre_state(n(a[0]), n(a[1]), n(a[2]), opt(a[3])) }
      when 'accPost' then hist { AtlasPca.acc_post(n(a[0]), n(a[1]), n(a[2]), opt(a[3])) }
      when 'monitorStep' then AtlasPca.monitor_step(n(a[0]), a[1], n(a[2]))
      when 'monitorState' then AtlasPca.monitor_state(n(a[0]), n(a[1]))
      end
    end

    FNS = %w[inWindow accKeyOf accPreState accPost monitorStep monitorState].freeze

    def group_bad(fn)
      state.each do |c|
        next unless c['fn'] == fn

        got = begin
          run(c)
        rescue StandardError, SystemStackError => e
          "THREW #{e.class}"
        end
        return c['name'] unless DiffUtil.norm(got) == DiffUtil.norm(c['out'])
      end
      nil
    end

    def mesh_bad(from, to)
      mesh.each_with_index do |v, i|
        next unless i >= from && i < to

        e = v['expect']
        g = AtlasPca.verify_mesh_proof(v['proof'], v['trust'])
        return v['name'] if g.ok != e['ok']
        next if e['ok']

        want = e['reason']
        if want.start_with?('chain:')
          return v['name'] unless g.reason.start_with?('chain:')
        else
          return v['name'] if g.reason != want || g.hop != (e.key?('hop') ? e['hop'] : -1)
        end
      end
      nil
    end
  end

  HistMesh::FNS.each { |fn| t("intent history: #{fn} over the shared intent-state cases") { HistMesh.group_bad(fn).nil? } }
  4.times { |k| t("mesh: vectors slice #{k + 1}/4") { HistMesh.mesh_bad(k * 34, (k + 1) * 34).nil? } }
  t('mesh: authority algebra narrows / admits / effective (defence-in-depth branch)') do
    eff = ->(cv) { AtlasPca.mesh_effective(cv).first }
    wide = eff.call([{ 'type' => 'scope', 'actions' => %w[a b] }, { 'type' => 'max_amount', 'max' => 100 }])
    narrow = eff.call([{ 'type' => 'scope', 'actions' => %w[a b] }, { 'type' => 'max_amount', 'max' => 100 }, { 'type' => 'max_amount', 'max' => 10 }])
    wider_amount = eff.call([{ 'type' => 'scope', 'actions' => %w[a b] }, { 'type' => 'max_amount', 'max' => 500 }])
    wider_scope = eff.call([{ 'type' => 'scope', 'actions' => %w[a b c] }, { 'type' => 'max_amount', 'max' => 100 }])
    unconstrained = eff.call([])
    no_prefix = eff.call([])
    with_prefix = eff.call([{ 'type' => 'resource', 'prefix' => '/x' }])
    AtlasPca.mesh_narrows?(narrow, wide) && AtlasPca.mesh_narrows?(wide, wide) && !AtlasPca.mesh_narrows?(wider_amount, wide) &&
      !AtlasPca.mesh_narrows?(wider_scope, wide) && !AtlasPca.mesh_narrows?(unconstrained, wide) && AtlasPca.mesh_narrows?(wide, unconstrained) &&
      !AtlasPca.mesh_narrows?(no_prefix, with_prefix) && AtlasPca.mesh_narrows?(with_prefix, no_prefix) &&
      AtlasPca.mesh_effective([{ 'type' => 'mystery' }]) == [nil, 'unknown caveat type "mystery" (fail closed)'] &&
      AtlasPca.mesh_effective([{ 'type' => 'scope', 'actions' => 'x' }]) == [nil, 'malformed scope caveat'] &&
      AtlasPca.mesh_admits(wide, { 'type' => 'a', 'resource' => 'r', 'service_domain' => 's', 'amount' => 100 }, 0, 1).nil? &&
      AtlasPca.mesh_admits(wide, { 'type' => 'a', 'resource' => 'r', 'service_domain' => 's', 'amount' => 101 }, 0, 1) == 'amount exceeds ceiling 100' &&
      AtlasPca.mesh_admits(wide, { 'type' => 'z', 'resource' => 'r', 'service_domain' => 's', 'amount' => 1 }, 0, 1) == 'action "z" not in scope'
  end
  t('mesh: totality on garbage') do
    [nil, 5, 'x', [], {}].all? { |g| r = AtlasPca.verify_mesh_proof(g, g); !r.ok && r.hop == -1 }
  end
end
