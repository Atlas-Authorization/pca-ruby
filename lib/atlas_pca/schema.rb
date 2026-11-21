# frozen_string_literal: true

require_relative 'js_compat'

module AtlasPca
  # JSON Schema (draft 2020-12) documents for the PCA wire types plus a small dependency-free STRUCTURAL validator, mirroring the
  # TypeScript reference (@atlasauth/pca-schema). Passing means "well-formed", never "authorized". Only the keywords these schemas
  # use are implemented: type (incl. unions), enum, required, properties, additionalProperties:false, items, local '#/...' $ref.
  module Schema
    module_function

    DRAFT = 'https://json-schema.org/draft/2020-12/schema'
    STR = { 'type' => 'string' }.freeze
    ALG = { 'type' => 'string', 'enum' => %w[ed25519 ml-dsa-65 hybrid-ed25519-ml-dsa-65] }.freeze
    OPEN = { 'type' => 'object', 'additionalProperties' => true }.freeze
    INT = { 'type' => 'integer' }.freeze

    CAVEAT_DEF = { 'type' => 'object', 'required' => ['type'], 'properties' => { 'type' => STR }, 'additionalProperties' => true }.freeze

    CAPABILITY_DEF = {
      'type' => 'object',
      'required' => %w[id issuer holder caveats body_digest sig],
      'properties' => {
        'id' => STR, 'issuer' => STR, 'holder' => STR,
        'caveats' => { 'type' => 'array', 'items' => { '$ref' => '#/$defs/caveat' } },
        'parent' => STR, 'body_digest' => STR, 'sig' => STR, 'alg' => ALG, 'pq_pk' => STR, 'pq_sig' => STR
      },
      'additionalProperties' => true
    }.freeze

    ACTION_DEF = {
      'type' => 'object', 'required' => %w[verb resource params_digest reversibility_class],
      'properties' => { 'verb' => STR, 'resource' => STR, 'params_digest' => STR, 'reversibility_class' => STR },
      'additionalProperties' => true
    }.freeze

    INCLUSION_PROOF_DEF = {
      'type' => 'object', 'required' => %w[index size path],
      'properties' => { 'index' => INT, 'size' => INT, 'path' => { 'type' => 'array', 'items' => OPEN } },
      'additionalProperties' => true
    }.freeze

    PLAN_DEF = {
      'type' => 'object', 'required' => %w[root inclusion_proof node_id],
      'properties' => { 'root' => STR, 'inclusion_proof' => { '$ref' => '#/$defs/inclusionProof' }, 'node_id' => STR, 'conditions_digest' => STR },
      'additionalProperties' => true
    }.freeze

    RISK_CLAIM_DEF = {
      'type' => 'object', 'required' => %w[r inputs],
      'properties' => { 'r' => { 'type' => 'number' }, 'inputs' => OPEN }, 'additionalProperties' => true
    }.freeze

    ATTESTATION_DEF = {
      'type' => 'object', 'required' => %w[quote_digest epoch model_id measurement operator],
      'properties' => { 'quote_digest' => STR, 'epoch' => INT, 'model_id' => STR, 'measurement' => STR, 'operator' => STR },
      'additionalProperties' => true
    }.freeze

    PROVENANCE_DEF = {
      'type' => 'object', 'required' => %w[causal_hash taint_level trusted_refs],
      'properties' => { 'causal_hash' => STR, 'taint_level' => { 'type' => 'number' }, 'trusted_refs' => { 'type' => 'array', 'items' => STR } },
      'additionalProperties' => true
    }.freeze

    FRESHNESS_DEF = {
      'type' => 'object', 'required' => %w[beacon_ref epoch accumulator_witness],
      'properties' => { 'beacon_ref' => STR, 'epoch' => INT, 'accumulator_witness' => STR }, 'additionalProperties' => true
    }.freeze

    PCACTN_SCHEMA = {
      '$schema' => DRAFT,
      '$id' => 'https://atlasauth.net/schemas/pca/pcactn.schema.json',
      'title' => 'PCActn',
      'description' => 'Proof-Carrying Authority action object (spec §7, wire format v2).',
      'type' => 'object',
      'required' => %w[ver action grant_ref cap_chain plan attestation provenance freshness counter risk_claim aud iat exp sig],
      'properties' => {
        'ver' => INT, 'action' => { '$ref' => '#/$defs/action' }, 'grant_ref' => STR,
        'cap_chain' => { 'type' => 'array', 'minItems' => 1, 'items' => { '$ref' => '#/$defs/capability' } },
        'plan' => { '$ref' => '#/$defs/plan' }, 'attestation' => { '$ref' => '#/$defs/attestation' },
        'provenance' => { '$ref' => '#/$defs/provenance' }, 'freshness' => { '$ref' => '#/$defs/freshness' },
        'counter' => INT, 'risk_claim' => { '$ref' => '#/$defs/riskClaim' }, 'aud' => STR, 'iat' => INT, 'exp' => INT,
        'nonce' => STR, 'caution' => { 'type' => 'number' }, 'rationale_commitment' => STR, 'progress_step' => OPEN,
        'prohibition_evidence' => { 'type' => %w[object array] }, 'tool_binding' => STR, 'alg' => ALG, 'pq_pk' => STR,
        'sig' => STR, 'pq_sig' => STR, 'threshold' => OPEN,
        'zk_compliance' => { 'description' => 'Opaque zk-compliance proof; shape is verifier-defined.' }, 'bond_ref' => STR
      },
      'additionalProperties' => true,
      '$defs' => {
        'caveat' => CAVEAT_DEF, 'capability' => CAPABILITY_DEF, 'action' => ACTION_DEF, 'inclusionProof' => INCLUSION_PROOF_DEF,
        'plan' => PLAN_DEF, 'riskClaim' => RISK_CLAIM_DEF, 'attestation' => ATTESTATION_DEF, 'provenance' => PROVENANCE_DEF,
        'freshness' => FRESHNESS_DEF
      }
    }.freeze

    CAPABILITY_SCHEMA = {
      '$schema' => DRAFT,
      '$id' => 'https://atlasauth.net/schemas/pca/capability.schema.json',
      'title' => 'Capability',
      'description' => 'An attenuable capability chain hop (spec §5.2).'
    }.merge(CAPABILITY_DEF).merge('$defs' => { 'caveat' => CAVEAT_DEF }).freeze

    DISCOVERY_SCHEMA = {
      '$schema' => DRAFT,
      '$id' => 'https://atlasauth.net/schemas/pca/discovery.schema.json',
      'title' => 'PcaDiscoveryDocument',
      'description' => 'The .well-known/pca-configuration discovery document (internet-wide integration).',
      'type' => 'object',
      'required' => %w[audience pca_versions signature_suites action_header],
      'properties' => {
        'audience' => STR, 'pca_versions' => { 'type' => 'array', 'items' => INT },
        'signature_suites' => { 'type' => 'array', 'items' => STR }, 'action_header' => STR,
        'required_checks' => { 'type' => 'array', 'items' => STR }, 'endpoints' => { '$ref' => '#/$defs/endpoints' },
        'trusted_roots' => { 'type' => 'array', 'items' => STR }, 'metadata' => OPEN
      },
      'additionalProperties' => true,
      '$defs' => {
        'endpoints' => {
          'type' => 'object',
          'properties' => {
            'attestation_challenge' => STR, 'revocation_epoch' => STR, 'liveness_beacon' => STR, 'stepup' => STR, 'grant' => STR
          },
          'additionalProperties' => true
        }
      }
    }.freeze

    ALL_SCHEMAS = { 'PCActn' => PCACTN_SCHEMA, 'Capability' => CAPABILITY_SCHEMA, 'PcaDiscoveryDocument' => DISCOVERY_SCHEMA }.freeze

    def num?(v) = v.is_a?(Integer) || v.is_a?(Float)
    def integer?(v) = v.is_a?(Integer) || (v.is_a?(Float) && v.finite? && v == v.floor)
    def neg_zero?(v) = v.is_a?(Float) && v.zero? && (1.0 / v).negative?

    def json_type_of(v)
      case v
      when nil then 'null'
      when Array then 'array'
      when true, false then 'boolean'
      when Integer, Float then integer?(v) ? 'integer' : 'number'
      when String then 'string'
      else 'object'
      end
    end

    def matches_type?(expected, v)
      case expected
      when 'object' then v.is_a?(Hash)
      when 'array' then v.is_a?(Array)
      when 'string' then v.is_a?(String)
      when 'number' then num?(v) && !(v.is_a?(Float) && !v.finite?)
      when 'integer' then integer?(v) && !neg_zero?(v)
      when 'boolean' then v == true || v == false
      when 'null' then v.nil?
      else false
      end
    end

    # a local '#/...' pointer walked over own keys of objects only; nil when it does not name an object
    def resolve_ref(root, ref)
      return nil unless ref.start_with?('#/')

      cur = root
      ref[2..].split('/', -1).each do |t|
        return nil unless cur.is_a?(Hash) && cur.key?(t)

        cur = cur[t]
      end
      cur.is_a?(Hash) ? cur : nil
    end

    def label(path) = path.empty? ? '(root)' : path

    # JS === over decoded JSON: objects and arrays never match
    def strict_equal?(a, b)
      return a == b if (a == true || a == false || b == true || b == false)
      return a.nil? && b.nil? if a.nil? || b.nil?
      return a == b if num?(a) && num?(b)

      a.is_a?(String) && b.is_a?(String) && a == b
    end

    def join(path, key) = path.empty? ? key : "#{path}.#{key}"

    def check_node(schema, value, path, root, errors)
      raise TypeError, 'schema node is null' if schema.nil?
      return unless schema.is_a?(Hash)

      ref = schema['$ref']
      if ref.is_a?(String)
        resolved = resolve_ref(root, ref)
        if resolved.nil?
          errors << "#{label(path)}: unresolved $ref '#{ref}'"
          return
        end
        return check_node(resolved, value, path, root, errors)
      end

      if schema.key?('type')
        t = schema['type']
        types = t.is_a?(Array) ? t : [t]
        unless types.any? { |x| matches_type?(x, value) }
          errors << "#{label(path)}: expected type #{types.map { |x| Js.string(x) }.join('|')}, got #{json_type_of(value)}"
          return
        end
      end

      enum = schema['enum']
      if enum.is_a?(Array) && enum.none? { |e| strict_equal?(e, value) }
        errors << "#{label(path)}: value is not one of [#{enum.map { |e| Js.json(e) }.join(', ')}]"
      end

      if value.is_a?(Hash)
        req = schema['required']
        req.each { |k| errors << "#{join(path, Js.string(k))}: missing required property '#{Js.string(k)}'" unless value.key?(k) } if req.is_a?(Array)
        props = schema['properties']
        props_ok = Js.truthy?(props) && props.is_a?(Hash)
        props.each { |k, sub| check_node(sub, value[k], join(path, k), root, errors) if value.key?(k) } if props_ok
        value.each_key { |k| errors << "#{join(path, k)}: additional property not allowed" unless props.key?(k) } if schema['additionalProperties'] == false && props_ok
      end

      items = schema['items']
      value.each_with_index { |el, i| check_node(items, el, "#{path}[#{i}]", root, errors) } if value.is_a?(Array) && Js.truthy?(items)
    end

    # { 'valid' => bool, 'errors' => [str] }; never raises on a bad value
    def validate(schema, value)
      errors = []
      check_node(schema, value, '', schema, errors)
      { 'valid' => errors.empty?, 'errors' => errors }
    end
  end
end
