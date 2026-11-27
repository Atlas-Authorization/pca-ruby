# frozen_string_literal: true

require 'net/http'
require 'uri'

module AtlasPca
  # Resource-server discovery: the `.well-known/pca-configuration` document (the reference's `discovery`). A resource server publishes
  # its audience id, accepted signature suites, the header it reads the PCActn from and the URLs of its freshness / step-up endpoints;
  # a client fetches it once and auto-configures. The document is PUBLIC configuration: never put secrets in it. Documents are Hashes
  # with the reference's member names; every parser raises ArgumentError on anything malformed (fail closed).
  WELL_KNOWN_PCA_PATH = '/.well-known/pca-configuration'
  DISCOVERY_DEFAULT_SUITES = %w[ed25519 ml-dsa-65 hybrid-ed25519-ml-dsa-65].freeze
  DISCOVERY_INTENT_MEMBERS = %w[versions actions_uri schema_keys question_relay tiers evidence_uri].freeze

  module_function

  # Validate an `intent` discovery block (the intent versions the site verifies, its signed action schema and keys, question relay,
  # the access tier per verb and its evidence endpoint).
  def parse_discovery_intent(v)
    raise ArgumentError, 'parseDiscoveryDocument: intent must be an object' unless v.is_a?(Hash)

    v.each_key { |k| raise ArgumentError, "parseDiscoveryDocument: intent has unknown member '#{k}'" unless DISCOVERY_INTENT_MEMBERS.include?(k) }
    vs = v['versions']
    raise ArgumentError, 'parseDiscoveryDocument: intent.versions must list 1 and/or 2' unless vs.is_a?(Array) && !vs.empty? && vs.all? { |n| n.is_a?(Numeric) && [1, 2].include?(n) }

    out = { 'versions' => vs.dup }
    %w[actions_uri evidence_uri].each do |k|
      next unless v.key?(k)
      raise ArgumentError, "parseDiscoveryDocument: intent.#{k} must be a non-empty string" unless v[k].is_a?(String) && !v[k].empty?

      out[k] = v[k]
    end
    if v.key?('schema_keys')
      raise ArgumentError, 'parseDiscoveryDocument: intent.schema_keys must be an array' unless v['schema_keys'].is_a?(Array)

      out['schema_keys'] = v['schema_keys'].map do |e|
        ok = e.is_a?(Hash) && %w[kid alg pk].all? { |k| e[k].is_a?(String) } && (!e.key?('pq_pk') || e['pq_pk'].is_a?(String))
        raise ArgumentError, 'parseDiscoveryDocument: intent.schema_keys entries are {kid, alg, pk, pq_pk?}' unless ok

        e.key?('pq_pk') ? { 'kid' => e['kid'], 'alg' => e['alg'], 'pk' => e['pk'], 'pq_pk' => e['pq_pk'] } : { 'kid' => e['kid'], 'alg' => e['alg'], 'pk' => e['pk'] }
      end
    end
    if v.key?('question_relay')
      raise ArgumentError, 'parseDiscoveryDocument: intent.question_relay must be a boolean' unless [true, false].include?(v['question_relay'])

      out['question_relay'] = v['question_relay']
    end
    if v.key?('tiers')
      raise ArgumentError, 'parseDiscoveryDocument: intent.tiers must be an object' unless v['tiers'].is_a?(Hash)

      ok = v['tiers'].values.all? { |n| n.is_a?(Numeric) && n == n.floor && n.between?(0, 4) && !(n.is_a?(Float) && n.zero? && (1.0 / n).negative?) }
      raise ArgumentError, 'parseDiscoveryDocument: intent.tiers values must be integers 0..4' unless ok

      out['tiers'] = v['tiers'].dup
    end
    out
  end

  # Build a well-formed discovery document. `o` (String keys, snake_case): audience, pca_versions, signature_suites, action_header,
  # required_checks, endpoints, trusted_roots, metadata, intent, obligations_supported. Raises on an empty audience.
  def build_discovery_document(o)
    aud = o['audience']
    raise ArgumentError, 'buildDiscoveryDocument: audience is required' unless aud.is_a?(String) && !aud.empty?

    doc = { 'audience' => aud, 'pca_versions' => o['pca_versions'] || [2], 'signature_suites' => o['signature_suites'] || DISCOVERY_DEFAULT_SUITES.dup,
            'action_header' => o['action_header'] || 'PCA-Action', 'required_checks' => o['required_checks'] || STATEFUL_REQUIRED_CHECKS.dup }
    %w[endpoints trusted_roots metadata].each { |k| doc[k] = o[k] if Js.truthy?(o[k]) }
    doc['intent'] = parse_discovery_intent(o['intent']) if Js.truthy?(o['intent'])
    doc['obligations_supported'] = o['obligations_supported'].dup if Js.truthy?(o['obligations_supported'])
    doc
  end

  # Validate and narrow an untrusted value into a discovery document. Raises on anything malformed.
  def parse_discovery_document(v)
    v = {} if v.is_a?(Array) # an array is an object with no members
    raise ArgumentError, 'parseDiscoveryDocument: not an object' unless v.is_a?(Hash)
    raise ArgumentError, 'parseDiscoveryDocument: missing audience' unless v['audience'].is_a?(String) && !v['audience'].empty?
    raise ArgumentError, 'parseDiscoveryDocument: pca_versions must be a number[]' unless v['pca_versions'].is_a?(Array) && v['pca_versions'].all? { |n| n.is_a?(Numeric) }
    raise ArgumentError, 'parseDiscoveryDocument: signature_suites must be a string[]' unless Js.str_list?(v['signature_suites'])
    raise ArgumentError, 'parseDiscoveryDocument: missing action_header' unless v['action_header'].is_a?(String) && !v['action_header'].empty?

    doc = { 'audience' => v['audience'], 'pca_versions' => v['pca_versions'], 'signature_suites' => v['signature_suites'], 'action_header' => v['action_header'] }
    doc['required_checks'] = v['required_checks'] if Js.str_list?(v['required_checks'])
    doc['endpoints'] = v['endpoints'] if v['endpoints'].is_a?(Hash) || v['endpoints'].is_a?(Array) # `typeof === 'object'`: an array passes
    doc['trusted_roots'] = v['trusted_roots'] if Js.str_list?(v['trusted_roots'])
    doc['metadata'] = v['metadata'] if v['metadata'].is_a?(Hash) || v['metadata'].is_a?(Array)
    doc['intent'] = parse_discovery_intent(v['intent']) if v.key?('intent')
    if v.key?('obligations_supported')
      raise ArgumentError, 'parseDiscoveryDocument: obligations_supported must be a string[]' unless Js.str_list?(v['obligations_supported'])

      doc['obligations_supported'] = v['obligations_supported'].dup
    end
    doc
  end

  # Fetch and parse a resource server's discovery document. `base_url` is the server origin (`https://api.acme.com`); the well-known path is
  # appended. `fetch` is `->(url, headers) { {'ok' =>, 'status' =>, 'body' => String} }` (default Net::HTTP). Raises on a non-2xx response or
  # a malformed document.
  def fetch_discovery(base_url, fetch = nil)
    f = fetch || method(:discovery_http_get)
    url = base_url.sub(%r{/+\z}, '') + WELL_KNOWN_PCA_PATH
    res = f.call(url, { 'accept' => 'application/json' })
    raise ArgumentError, "fetchDiscovery: #{url} returned #{res['status']}" unless res['ok']

    parse_discovery_document(parse_json(res['body'].to_s, loose: true))
  end

  def discovery_http_get(url, headers)
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == 'https'
    http.open_timeout = http.read_timeout = 10
    res = http.request(Net::HTTP::Get.new(uri.request_uri, headers))
    { 'ok' => res.code.to_i.between?(200, 299), 'status' => res.code.to_i, 'body' => res.body }
  end

  # True iff this server (per its discovery doc) accepts a given signature suite.
  def accepts_suite?(doc, suite) = doc['signature_suites'].include?(suite)
end
