# frozen_string_literal: true

# Action-kit conformance: every vector of packages/pca-conformance/vectors/actions (mirror: conformance/actions) must reproduce its
# `expect` exactly through AtlasPca::Actions (and the v2 conform path of the schema module). No skips, no vector left unread.
#   ruby -Ilib test/test_actions_vectors.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'
require 'json'

class TestActionsVectors < Minitest::Test
  A = AtlasPca::Actions
  R = AtlasPca::ActionsRegistry

  def self.vector_dir
    [%w[.. .. packages pca-conformance vectors actions], %w[conformance actions], %w[.. conformance actions]].each do |rel|
      d = File.expand_path(File.join(*rel), File.join(__dir__, '..'))
      return d if Dir.exist?(d)
    end
    raise 'the action-kit vectors are missing (a vector directory is never skipped)'
  end

  CASES = Dir.children(vector_dir).select { |f| f.end_with?('.json') }.sort.map do |f|
    AtlasPca.parse_json(File.read(File.join(vector_dir, f), encoding: 'UTF-8'), loose: true)
  end.freeze

  def code_of(e) = e.nil? ? { 'ok' => true } : { 'ok' => false, 'code' => e.split(':')[0].split(' ')[0] }

  def replay(c)
    i = c['input']
    case c['kind']
    when 'parse' then { 'ok' => A.validate_def(i['def']).nil? }
    when 'digest' then { 'digest' => A.def_digest(i['def']), 'normalized' => A.normalize(i['def']) }
    when 'effective'
      e = A.effective(i['def'], A::CORE_REGISTRY, i['pins'])
      { 'confirmed' => e['confirmed'], 'traits' => e['traits'], 'closure' => e['closure'], 'eff' => e['eff'] }
    when 'expand', 'schema_verb'
      begin
        reg = i['custom_traits'] ? A.extend_registry(A::CORE_REGISTRY, i['custom_traits']) : A::CORE_REGISTRY
        if c['kind'] == 'expand'
          { 'closure' => A.closure(reg, i['traits']), 'floor' => A.floor_of(reg, i['traits']) }
        else
          code_of(A.schema_verb_floor_error(i['verb'], reg, i['pins']))
        end
      rescue A::ActionKitError
        { 'error' => true }
      end
    when 'floor' then { 'decision' => A.floor_decision(i['grant'], i['call'], i['profile']) }
    when 'conform'
      r = AtlasPca.conform_action(i['schema'], i['verb'], i['params'])
      r['ok'] ? { 'ok' => true } : { 'ok' => false, 'code' => r['code'] }
    when 'pack'
      ds = i['digests']
      { 'root' => A.pack_root(ds), 'proof' => A.pack_proof(ds, ds[i['index']]) }
    when 'schema_shape' then { 'ok' => AtlasPca.action_schema_shape_error(i['doc'], signed: false).nil? }
    when 'rule22_schema' then R.rule22_integrity(i['doc'], i['pins'])
    when 'rule22'
      g = R.rule22_integrity(i['doc'], i['pins'])
      g['ok'] ? { 'integrity' => 'ok', 'decision' => R.rule22_decide(i['doc'], i['verb'], i['grant'], i['context']) } : { 'integrity' => g['code'], 'decision' => 'deny' }
    when 'pack_verify'
      v = R.verify_pack(i['pack'], i['keys'], i['shards'])
      v['ok'] ? { 'ok' => true, 'digest' => v['digest'], 'defs' => v['defs'].length } : { 'ok' => false }
    when 'evolution_verify'
      d = begin
        R.evolution_diff_digest(i['record'])
      rescue StandardError
        nil
      end
      { 'ok' => R.verify_evolution_record(i['record'], i['keys'])['ok'], 'diff' => d }
    when 'reapproval_verify'
      { 'ok' => R.reapproval_valid?(i['reapproval'], i['grant']['id'], i['grant']['issuer'], i['verb'], i['diff']) }
    when 'pin'
      d = R.decide_pin(i)
      if d['ok']
        { 'ok' => true, 'via' => d['via'] }
      else
        o = { 'ok' => false, 'code' => d['code'], 'escalate' => d['escalate'] }
        o['needs_reapproval'] = d['needs_reapproval'] if d.key?('needs_reapproval')
        o
      end
    when 'pack_proof_verify' then { 'ok' => A.verify_pack_proof(i['root'], i['proof'], i['digest']) }
    when 'tracker'
      t = R::PackTracker.new(i['keys'])
      i['steps'].map do |st|
        r = t.accept(st['pack'], st['shards'])
        r['ok'] ? { 'ok' => true, 'status' => r['status'] } : { 'ok' => false, 'code' => r['code'] }
      end
    when 'approval_render'
      begin
        r = AtlasPca.render_approval(i['def'], i['params'], i['confirmed'] == true)
        d = AtlasPca.approval_render_digest(r)
        { 'ok' => true, 'render' => r, 'digest' => d, 'words' => AtlasPca.binding_words(d) }
      rescue A::ActionKitError => e
        { 'ok' => false, 'code' => e.code }
      end
    when 'approval_digest'
      AtlasPca.approval_render_shape_error(i['render']) ? { 'ok' => false } : { 'ok' => true, 'digest' => AtlasPca.approval_render_digest(i['render']) }
    when 'approval_challenge'
      begin
        { 'ok' => true, 'challenge' => AtlasPca.approval_challenge(i['action_digest'], i['render_digest']) }
      rescue ArgumentError
        { 'ok' => false }
      end
    when 'approval_escalation'
      v = AtlasPca.verify_escalation_answer(i['answer'], i['principals'], i['bind'], i['now'])
      v[:ok] ? { 'ok' => true, 'decision' => v[:decision] } : { 'ok' => false, 'reason' => v[:reason] }
    when 'approval_psd2'
      begin
        { 'ok' => true, 'linking' => AtlasPca.psd2_linking(i['render']) }
      rescue A::ActionKitError => e
        { 'ok' => false, 'code' => e.code }
      end
    when 'approval_batch'
      begin
        b = AtlasPca.approval_batch(i['items'])
        { 'ok' => true, 'batch' => b['batch'], 'action_digest' => b['action_digest'], 'render_digest' => b['render_digest'], 'challenge' => b['challenge'], 'words' => b['words'] }
      rescue A::ActionKitError => e
        { 'ok' => false, 'code' => e.code }
      end
    else flunk "unknown vector kind #{c['kind']}"
    end
  end

  def norm(v) = AtlasPca::V2JS.jsnorm(v)

  def test_approval_profile_vectors
    d = [%w[.. .. packages pca-conformance vectors approval-profiles], %w[conformance approval-profiles], %w[.. conformance approval-profiles]]
        .map { |rel| File.expand_path(File.join(*rel), File.join(__dir__, '..')) }.find { |x| Dir.exist?(x) }
    flunk 'the approval profile vectors are missing (a vector directory is never skipped)' if d.nil?
    files = Dir.children(d).select { |f| f.end_with?('.json') }.sort
    assert_operator files.length, :>=, 12
    files.each do |f|
      c = AtlasPca.parse_json(File.read(File.join(d, f), encoding: 'UTF-8'), loose: true)
      assert_equal norm(c['expect']), norm(replay(c)), c['id']
    end
  end

  def test_every_vector_replays
    assert_operator CASES.length, :>=, 781
    kinds = Hash.new(0)
    CASES.each do |c|
      kinds[c['kind']] += 1
      assert_equal norm(c['expect']), norm(replay(c)), c['id']
    end
    %w[parse digest effective expand floor conform pack schema_verb schema_shape rule22 rule22_schema pack_verify evolution_verify reapproval_verify pin pack_proof_verify tracker approval_render approval_digest approval_challenge approval_escalation].each { |k| assert_operator kinds[k], :>=, 8, k }
  end

  def test_pinned_values
    assert_equal 'W2xe4TXZKavAeEpzGVYC8pp-ZhOxDv-_3TF76MveweM', A.traits_digest(A::CORE_REGISTRY)
    assert_equal 'I7nxRoiVhU18WNY_EaUqegG7KeBYtfP8gMmibsfXJtU', A.tables_digest
  end

  def test_pack_proof_verifies_and_tamper_fails
    c = CASES.find { |x| x['id'] == 'pack-builtin' }
    ds = c['input']['digests']
    root = c['expect']['root']
    ds.each { |d| assert A.verify_pack_proof(root, A.pack_proof(ds, d), d) }
    refute A.verify_pack_proof(root, A.pack_proof(ds, ds[0]), ds[1])
  end

  def test_whole_document_rule_22
    c = CASES.find { |x| x['id'] == 'schema-verb-adv-honest' }
    doc = { 'verbs' => [c['input']['verb']] }
    assert_nil A.schema_floor_error(doc)
    doc['traits_digest'] = 'A' * 43
    assert A.schema_floor_error(doc).start_with?('traits_digest_mismatch')
  end

  # k042-style differential oracle: the closure of any trait set equals eight rounds of one-step implication (the model the
  # Dafny file reasons about), and the floor is the join of the closure's floors.
  def test_expand_matches_one_step_oracle
    reg = A::CORE_REGISTRY
    ids = reg.keys
    rng = Random.new(42)
    300.times do
      s = ids.sample(rng.rand(0..4), random: rng)
      cur = s.dup
      8.times { cur = (cur + cur.flat_map { |t| reg[t]['implies'] }).uniq }
      assert_equal cur.sort, A.closure(reg, s)
      assert_equal A.join_all(cur.map { |t| reg[t]['floor'] }), A.floor_of(reg, s)
    end
  end

  def test_floor_decision_antitone
    rng = Random.new(7)
    g = { 'caveats' => %w[amount_cap window], 'max_esc' => 2, 'preauth_esc' => 1 }
    call = { 'context' => ['idempotency'] }
    rank = { 'deny' => 0, 'escalate' => 1, 'allow' => 2 }
    200.times do
      ps = Array.new(2) { A.profile('esc' => rng.rand(0..3), 'caveats' => A::CAVEAT_KINDS.sample(rng.rand(0..3), random: rng), 'context' => A::CONTEXT_KEYS.sample(rng.rand(0..2), random: rng)) }
      lo = ps[0]
      hi = A.join(ps[0], ps[1])
      assert_operator rank[A.floor_decision(g, call, hi)], :<=, rank[A.floor_decision(g, call, lo)]
    end
  end
end
