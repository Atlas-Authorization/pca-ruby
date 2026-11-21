# frozen_string_literal: true

# Differential oracles for the issuing side of the mesh (mesh_witness.rb): the domain's evidence, enroll and pin proofs
# (ref-core-mesh-domain-java), proof assembly and action signing over scripted multi-domain sequences (ref-core-mesh-proof-java) and the
# witness with its durable store (the `meshWitness` cases of ref-core-stores-java), all generated from the TypeScript reference.
require_relative 'support/ref_oracle'
require 'minitest/autorun'
require 'tmpdir'

class TestRefCoreMesh < Minitest::Test
  A = AtlasPca
  DOMAIN = Ref.load('core-mesh-domain-java')
  PROOF = Ref.load('core-mesh-proof-java')
  STORES = Ref.load('core-stores-java')

  def self.key(label) = A::KeyPair.new(Digest::SHA256.digest("atlas-pca-conformance/#{label}"))
  def self.cap(label) = { 'id' => label, 'issuer' => "iss-#{label}", 'holder' => 'h', 'caveats' => [{ 'type' => 'scope', 'actions' => [label] }] }
  def self.err(e, by_message) = { '$err' => by_message ? e.message : 'Error' }

  def self.domain_script(ops, prefix)
    doms = {}
    ws = {}
    heads = {}
    binds = {}
    ops.map do |op|
      k = op[0]
      v = nil
      case k
      when 'domain' then (d = A::MeshDomain.new(op[1], key("#{prefix}#{op[2]}"))) && (doms[op[1]] = d) && (v = d.id)
      when 'witness' then (w = A::MeshWitness.new(key("#{prefix}#{op[2]}"))) && (ws[op[1]] = w) && (v = w.id)
      when 'record' then v = doms[op[1]].record(cap(op[2]))
      when 'revoke' then doms[op[1]].revoke(op[2])
      when 'publish' then v = heads[op[2]] = doms[op[1]].publish_head(op[4].map { |w| ws[w] }, op[3], op[5])
      when 'fork' then heads[op[1]] = heads[op[2]].merge(op[3] => op[4])
      when 'enroll' then v = binds[op[2]] = doms[op[1]].enroll(op[3], op[4])
      when 'evidence' then v = doms[op[1]].evidence(cap(op[2]), heads[op[3]], op[4].nil? ? nil : binds[op[4]])
      when 'pinProof' then v = doms[op[1]].pin_proof(op[2].is_a?(String) ? heads[op[2]]['head'] : op[2], heads[op[3]])
      when 'nonMembership' then v = doms[op[1]].revocation_set_copy.non_membership_proof(op[2])
      else raise ArgumentError, 'op'
      end
      v
    rescue StandardError => e
      err(e, false)
    end
  end

  def self.proof_script(ops)
    doms = {}
    ws = {}
    store = {}
    ops.map do |op|
      k = op[0]
      v = nil
      case k
      when 'domain' then (d = A::MeshDomain.new(op[1], key("mesh-proof/#{op[2]}"))) && (doms[op[1]] = d) && (v = d.id)
      when 'witness' then (w = A::MeshWitness.new(key("mesh-proof/#{op[2]}"))) && (ws[op[1]] = w) && (v = w.id)
      when 'record' then v = doms[op[1]].record(cap(op[2]))
      when 'revoke' then doms[op[1]].revoke(op[2])
      when 'publish' then v = store[op[2]] = doms[op[1]].publish_head(op[4].map { |w| ws[w] }, op[3], op[5])
      when 'subcos'
        h = store[op[2]].dup
        h['cosigs'] = op[3].map { |i| h['cosigs'][i.to_i] }
        store[op[1]] = h
      when 'fork' then store[op[1]] = store[op[2]].merge(op[3] => op[4])
      when 'forkHead'
        h = store[op[2]].dup
        h['head'] = h['head'].merge(op[3] => op[4])
        store[op[1]] = h
      when 'enroll' then v = store[op[2]] = doms[op[1]].enroll(op[3], op[4])
      when 'ev' then v = store[op[2]] = doms[op[1]].evidence(cap(op[3]), store[op[4]], op[5].nil? ? nil : store[op[5]])
      when 'setEv'
        e = store[op[2]].dup
        val = op[4]
        if val.is_a?(Hash) && val.key?('$del') then e.delete(op[3])
        elsif op[3] == 'head' && val.is_a?(String) && store.key?(val) then e['head'] = store[val]
        else e[op[3]] = val
        end
        store[op[1]] = e
      when 'pinProofAs'
        pin = op[3]
        v = store[op[2]] = doms[op[1]].pin_proof(pin.is_a?(String) ? store[pin]['head'] : pin, store[op[4]])
      when 'assemble'
        pins = op[5].nil? ? nil : op[5].map { |n| store[n] }
        v = A.assemble_mesh_proof(op[1].map { |x| cap(x) }, op[2].map { |n| store[n] }, op[3], key("mesh-proof/#{op[4]}"), pin_proofs: pins)
      when 'sign' then v = A.sign_mesh_action(op[1].map { |x| cap(x) }, op[2], key("mesh-proof/#{op[3]}"))
      else raise ArgumentError, 'op'
      end
      v
    rescue StandardError => e
      err(e, false)
    end
  end

  def self.witness_script(ops)
    stores = {}
    ws = {}
    doms = {}
    ops.map do |op|
      k = op[0]
      v = nil
      case k
      when 'store'
        stores[op[1]] = A::MemoryMeshWitnessStore.new
        v = true
      when 'witness'
        w = A::MeshWitness.new(key(op[3]), store: op[2].nil? ? nil : stores[op[2]])
        ws[op[1]] = w
        v = w.id
      when 'witnessClock'
        now = op[3].to_f
        ws[op[1]] = A::MeshWitness.new(key(op[2]), clock: -> { now }, max_clock_skew_ms: op[4].nil? ? nil : op[4].to_f)
        v = true
      when 'restart'
        w = A::MeshWitness.new(key(op[3]), store: stores[op[2]])
        ws[op[1]] = w
        v = w.export_state
      when 'domain' then (d = A::MeshDomain.new(op[1], key(op[2]))) && (doms[op[1]] = d) && (v = d.id)
      when 'record' then v = doms[op[1]].record({ 'id' => op[2], 'caveats' => [{ 'type' => 'scope', 'actions' => [op[2]] }] })
      when 'revoke' then doms[op[1]].revoke(op[2])
      when 'publish' then v = doms[op[1]].publish_head(op[3].map { |w| ws[w] }, op[2], op[4])
      when 'lastSeen' then v = ws[op[1]].last_seen(op[2])
      when 'export' then v = ws[op[1]].export_state
      when 'import' then ws[op[1]].import_state(op[2])
      when 'load' then v = stores[op[1]].load
      when 'save' then stores[op[1]].save(op[2])
      when 'domainId' then v = doms[op[1]].id
      else raise ArgumentError, 'op'
      end
      v
    rescue StandardError => e
      err(e, true)
    end
  end

  def test_mesh_domain_matches_the_reference
    Ref.run(self, DOMAIN['meshDomain'], ->(ops) { TestRefCoreMesh.domain_script(ops, 'mesh-domain/') })
  end

  def test_mesh_proof_assembly_matches_the_reference
    Ref.run(self, PROOF['meshProof'], ->(ops) { TestRefCoreMesh.proof_script(ops) })
  end

  def test_mesh_witness_matches_the_reference
    Ref.run(self, STORES['meshWitness'], ->(ops) { TestRefCoreMesh.witness_script(ops) })
  end

  def test_non_membership_proofs_verify
    s = A::RevocationSet.new(%w[b d f h j])
    ['a', 'c', 'e', 'g', 'i', 'k', '', 'key:x'].each do |rid|
      assert A.mesh_non_membership?(s.root, s.non_membership_proof(rid), rid), rid
    end
    %w[b d j].each { |rid| assert_raises(ArgumentError) { s.non_membership_proof(rid) } }
    assert_equal 0, A::RevocationSet.new.non_membership_proof('a')['size']
  end

  def test_the_file_store_is_atomic_and_refuses_damage
    Dir.mktmpdir('pca-mesh') do |d|
      path = File.join(d, 'witness.json')
      s = A::FileMeshWitnessStore.new(path)
      assert_nil s.load
      st = { 'seen' => [] }
      s.save(st)
      assert_equal st, A::FileMeshWitnessStore.new(path).load
      File.write(path, File.read(path).sub('"seen":[]', '"seen":[1]'))
      assert_raises(ArgumentError) { s.load }
      File.write(path, 'not json')
      assert_raises(ArgumentError) { s.load }
    end
  end

  # the corpus is pinned: its fn set and every fn's case count (a fn the replay skips, or a changed corpus, fails here)
  def test_the_corpus_is_pinned_in_full
    assert_equal({ 'meshDomain' => 18 }, DOMAIN.transform_values(&:length))
    assert_equal({ 'meshProof' => 8 }, PROOF.transform_values(&:length))
    assert_equal({ 'ledgerStore' => 66, 'storedLedger' => 30, 'bondStore' => 60, 'budgetLedger' => 62, 'meshWitness' => 9 }, STORES.transform_values(&:length))
  end

end
