# frozen_string_literal: true
# The refusal checks restored as defence in depth (BRIEF: security guards stay), each made observable: a distinct reason
# reached with the later check bypassed through a seam, or the guard function itself on inputs only it decides.
module MutationKill
  module Restored
    module_function

    def sigstore_ok_case
      file = [File.expand_path('../../conformance/sigstore-vectors.json', __dir__),
              File.expand_path('../../conformance/sigstore-vectors.json', __dir__)].find { |p| File.exist?(p) }
      doc = JSON.parse(File.read(file, encoding: 'UTF-8'))
      c = doc['cases'].find { |x| x['expect']['ok'] }
      [c['bundle'], AtlasPca.parse_trusted_root(doc['roots'][c['roots']])]
    end

    def leaf_with(*exts) = AtlasPca::SigstoreBundle.parse_cert(NodeX509.cert(NodeX509.root, NodeX509.up_name, exts, NodeX509.b(0x11)))
  end

  t('Intel collateral: a signed body that parses to a non-object has its own reason (seam over the parser)') do
    c = AtlasPca::Attest::Common
    orig = c.method(:js_json_loads)
    text = %({"tcbInfo":{"a":1},"signature":"#{'0' * 128}"})
    Seam.with(c, { js_json_loads: ->(s) { s == '{"a":1}' ? [] : orig.call(s) }, ecdsa_verify_raw: ->(*) { true } }) do
      AtlasPca::Attest::Intel.verify_signed_json(text, 'tcbInfo', nil)
    end == { 'error' => 'tcbInfo is not an object' }
  end

  t('rule 22 traits: a schema step that did not succeed is reported as is, never decided (seam over schema_step)') do
    r = Rule22
    bad = { 'ok' => false, 'reason' => 'seamed schema failure', 'doc' => { 'v' => 2 } }
    out = Seam.with(AtlasPca::IntentV2, { schema_step: ->(*) { bad } }) { r.named(r.decide(r.grant('actions' => r.pin), r.ctx)) }
    out['pin'] == 'seamed schema failure' && out['traits'] == 'seamed schema failure'
  end

  t('sigstore: the leaf SAN shape check refuses on its own, and a refusal from it is a cert_chain refusal (seam)') do
    n = NodeX509
    s = AtlasPca::SigstoreBundle
    ok = [[n.x(0x13, n.tlv(0x30))], [n.x(0x11, n.tlv(0x30, n.uri))], [n.x(0x11, n.tlv(0x30))]]
    bad = [[n.x(0x11, n.tlv(0x04, n.b(1)))], [n.x(0x11, n.tlv(0x30, n.uri) + n.b(5, 0))], [n.x(0x11, n.tlv(0x30, n.tlv(0x89, n.b(1))))]]
    bundle, root = Restored.sigstore_ok_case
    good = AtlasPca.verify_sigstore_bundle_core(bundle, root)
    refused = Seam.with(s, { san_decodes?: ->(_c) { false } }) { AtlasPca.verify_sigstore_bundle_core(bundle, root) }
    ok.all? { |e| s.san_decodes?(Restored.leaf_with(*e)) == true } && bad.none? { |e| s.san_decodes?(Restored.leaf_with(*e)) } &&
      good[:ok] == true && refused[:ok] == false && refused[:code] == 'cert_chain'
  end
end
