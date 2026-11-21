# frozen_string_literal: true
require 'stringio'
# k05 provenance by default (arg_provenance.rb) against arg-provenance.ts + require-pca.ts defaultProvenanceBundle:
# test-data/k05-argprov.json.gz (tools/pca-audit/k05-oracles/argprov-oracle.mts).
module MutationKill
  module K05ArgProv
    module_function

    # decideArgProvenance input: the TS flags principalPlan / principalControl are the Ruby principal_plan / principal_control
    def decide_input(v)
      return v unless v.is_a?(Hash)

      v.to_h { |k, x| [{ 'principalPlan' => 'principal_plan', 'principalControl' => 'principal_control' }.fetch(k, k), x] }
    end

    # the oracle's recorder spec: {mediator, kid, sk, session, clock: [ms per append], steps} -> {pin, outs}; a step that throws
    # is {$throws} in outs (the message is the reference's own: only the refusal is compared)
    def recorder(spec)
      clock = spec['clock'].dup
      last = 0
      rec = AtlasPca::ProvenanceRecorder.new(mediator: spec['mediator'], kid: spec['kid'], key: AtlasPca::KeyPair.from_seed_b64u(spec['sk']),
                                             session: spec['session'], now: -> { clock.empty? ? last : (last = clock.shift) })
      outs = spec['steps'].map do |s|
        case s[0]
        when 'principal' then rec.principal(s[1])
        when 'tool' then rec.tool(s[1], s[2])
        when 'retrieval' then rec.retrieval(s[1], s[2])
        when 'web' then rec.web(s[1], s[2])
        when 'action' then rec.for_action(s[1])
        when 'direct' then AtlasPca.principal_direct_provenance(rec, s[1])
        end
      rescue StandardError
        { '$throws' => true }
      end
      { 'pin' => rec.pin, 'outs' => outs }
    end

    def read_bundle(a)
      env = {}
      env[AtlasPca::PROV_RACK_HEADER] = a['header'] if a.key?('header')
      env['rack.input'] = StringIO.new(a['body'].b) if a.key?('body')
      AtlasPca.default_provenance_bundle(env)
    end

    FNS = {
      'provReceiptWireError' => ->(a, _) { AtlasPca.prov_receipt_wire_error(a[0]) },
      'isProvMediatorPin' => ->(a, _) { AtlasPca.prov_mediator_pin?(a[0]) },
      'provActionInfoError' => ->(a, _) { AtlasPca.prov_action_info_error(a[0]) },
      'isReadOnlyAction' => ->(a, _) { AtlasPca.read_only_action?(a[0]) },
      'provEnvelopeError' => ->(a, _) { AtlasPca.prov_envelope_error(a[0]) },
      'occursAsToken' => ->(a, _) { AtlasPca.occurs_as_token(a[0], a[1]) },
      'provLeaves' => ->(a, _) { AtlasPca.prov_leaves(a[0]) },
      'decideArgProvenance' => ->(a, _) { AtlasPca.decide_arg_provenance(decide_input(a[0])) },
      'recorder' => ->(a, _) { recorder(a[0]) },
      'provActionDigest' => ->(a, _) { AtlasPca.prov_action_digest(a[0]) },
      'provReceiptRef' => ->(a, _) { AtlasPca.prov_receipt_ref(a[0]) },
      'defaultProvenanceBundle' => ->(a, _) { read_bundle(a[0]) }
    }.freeze
    # a throwing step inside the recorder's outs: both sides refused (messages are each port's own)
    THROWS = ->(x) { x.is_a?(Hash) && x.key?('$throws') ? { '$throws' => true } : x }
    REC = lambda do |got, out, c|
      norm = ->(r) { r.is_a?(Hash) && r['outs'].is_a?(Array) ? r.merge('outs' => r['outs'].map(&THROWS)) : r }
      K05::EXACT.call(norm.call(got), norm.call(out), c)
    end
    SPEC = K05::Spec.new(file: 'k05-argprov.json.gz', libs: %w[arg_provenance.rb], fns: FNS, cmp: { default: K05::EXACT, 'recorder' => REC },
                         title: 'arg provenance')
  end
  K05.register(K05ArgProv::SPEC, K05ArgProv::FNS.keys)
end
