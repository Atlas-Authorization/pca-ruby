# frozen_string_literal: true

require 'digest'
require_relative 'intent_v2'

# Intent Layer v2 rule 19: the committed intent map. The verifier side (leaf shapes, the tree, the Z0 disclosure check) lives in
# IntentV2; this module adds the builder (the wallet side in the TypeScript reference, for hosts and tests): per-leaf salts, audit
# paths and the committed form with its disclosures. Native port of the reference (@atlasauth/pca).
module AtlasPca
  module IntentMap
    MAP_TAG_SALT = "atlas-pca/intent-map/salt/v1\x00" # informative: the wallet's per-leaf salt derivation
    MAP_FORM_COMMIT = 'commit'
    V2 = IntentV2

    module_function

    def map_leaf_hash(kind, salt, leaf) = V2.map_leaf_hash(kind, salt, leaf)
    def map_node_hash(left, right) = V2.map_node_hash(left, right)
    def map_commit_of(size, root) = V2.map_commit_of(size, root)
    def map_root_from_path(index, size, leaf_hash, path) = V2.map_root_from_path(index, size, leaf_hash, path)
    def map_num_cells(d) = V2.map_num_cells(d)
    def map_header_error(h) = V2.map_header_error(h)
    def map_cell_error(c) = V2.map_cell_error(c)
    def map_metrics_error(m) = V2.map_metrics_error(m)
    def map_learner_error(l) = V2.map_learner_error(l)
    def map_disclosure_error(d) = V2.map_disclosure_error(d)
    def map_cell_of(header, resource, params) = V2.map_cell_of(header, resource, params)
    def commit_leaves(leaves) = V2.map_commit_of_leaves(leaves)

    # Informative per-leaf salt derivation (wallet side).
    def map_leaf_salt(secret, index) = Digest::SHA256.digest(MAP_TAG_SALT.b + secret.b + [index].pack('Q>'))

    def map_tree_root(hashes)
      raise ArgumentError, 'map tree: empty' if hashes.empty?

      V2.map_tree_root(hashes)
    end

    def split_point(n)
      k = 1
      k *= 2 while k * 2 < n
      k
    end

    def tree_root(hs) = hs.length <= 1 ? hs[0] : V2.map_node_hash(tree_root(hs[0, split_point(hs.length)]), tree_root(hs[split_point(hs.length)..]))

    def audit_path_into(hs, idx, out)
      return if hs.length == 1

      k = split_point(hs.length)
      if idx < k
        audit_path_into(hs[0, k], idx, out)
        out << tree_root(hs[k..])
      else
        audit_path_into(hs[k..], idx - k, out)
        out << tree_root(hs[0, k])
      end
    end

    def map_audit_path(hashes, index)
      out = []
      audit_path_into(hashes, index, out)
      out.map { |h| AtlasPca.b64e(h) }
    end

    # Build the committed form (rule 19 leaf order) with per-leaf salts from `secret` (32 bytes). Returns
    # {map_commit, size, leaves: [{kind, leaf, salt}], disclose: ->(verb, resource, params)}. Raises on a malformed input.
    def commit_map(headers, cells, metrics, learner_digest, secret)
      raise ArgumentError, 'commit_map: the secret is 32 bytes' unless secret.bytesize == 32

      heads = headers.sort_by { |h| h['verb'].b }
      (1...heads.length).each { |i| raise ArgumentError, 'commit_map: duplicate verb' if heads[i]['verb'] == heads[i - 1]['verb'] }
      nxt = heads.length
      full = heads.map do |h|
        n = h['dims'].reduce(1) { |a, d| a * V2.map_dim_cells(d) }
        e = { 'verb' => h['verb'], 'first' => nxt, 'cells' => n, 'dims' => h['dims'] }
        nxt += n
        e
      end
      leaves = full.map { |h| ['header', h] }
      full.each do |h|
        cs = cells[h['verb']]
        raise ArgumentError, "commit_map: verb #{h['verb']} needs #{h['cells']} cell leaves" unless cs.is_a?(Array) && cs.length == h['cells']

        cs.each { |c| leaves << ['cell', { 'verb' => h['verb'], 'cell' => c['cell'], 'p_ppm' => c['p_ppm'], 'in_grant' => c['in_grant'] }] }
      end
      leaves << ['metrics', metrics]
      leaves << ['learner', { 'learner_digest' => learner_digest }]
      check = { 'header' => V2.method(:map_header_error), 'cell' => V2.method(:map_cell_error), 'metrics' => V2.method(:map_metrics_error),
                'learner' => V2.method(:map_learner_error) }
      leaves.each do |kind, leaf|
        e = check[kind].call(leaf)
        raise ArgumentError, "commit_map: #{e}" if e
      end
      size = leaves.length
      raise ArgumentError, 'commit_map: the map has too few or too many leaves' if size < 4 || size > V2::MAX_MAP_LEAVES

      salts = (0...size).map { |i| map_leaf_salt(secret, i) }
      hashes = leaves.each_with_index.map { |(k, leaf), i| V2.map_leaf_hash(k, salts[i], leaf) }
      root = V2.map_tree_root(hashes)
      entry = ->(i) { { 'index' => i, 'salt' => AtlasPca.b64e(salts[i]), 'leaf' => leaves[i][1], 'path' => map_audit_path(hashes, i) } }
      disclose = lambda do |verb, resource, params|
        hi = full.index { |h| h['verb'] == verb }
        raise ArgumentError, "commit_map.disclose: verb #{verb} is not in the map" if hi.nil?

        w = V2.map_cell_of(full[hi], resource, params)
        raise ArgumentError, "commit_map.disclose: #{w['error']}" if w.key?('error')

        { 'size' => size, 'header' => entry.call(hi), 'cell' => entry.call(full[hi]['first'] + w['flat']), 'metrics' => entry.call(size - 2) }
      end
      { 'map_commit' => V2.map_commit_of(size, root), 'size' => size,
        'leaves' => leaves.each_with_index.map { |(k, leaf), i| { 'kind' => k, 'leaf' => leaf, 'salt' => AtlasPca.b64e(salts[i]) } },
        'disclose' => disclose }
    end
  end
end
